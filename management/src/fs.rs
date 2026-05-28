//! Real-time filesystem operations for the management tool.
//!
//! All state comes from the live filesystem (no database).
//! - Directory tree is built on demand by walking the configured base paths.
//! - Permission changes (chown/chmod) are performed by the running container
//!   via `docker exec $CONTAINER chown ... && chmod ...` on the bind-mounted paths.
//!   The host tool stays unprivileged.
//! - Recursive option is supported exactly as the user described.
//!
//! Security: The tool itself should run as a low-privilege user.
//! Validation happens in the host UI; the actual mutations use the container's capabilities.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct DirectoryNode {
    pub path: PathBuf,
    pub name: String,
    pub owner: Option<u32>, // uid
    pub group: Option<u32>, // gid
    pub mode: u32,
    pub children: Vec<DirectoryNode>,
}

pub struct FsManager {
    pub config: crate::config::Config,
    /// Path to the central nfs-klldap.conf. Previously used to communicate with a
    /// Retained for potential future use with container-exec flows.
    #[allow(dead_code)]
    config_path: Option<PathBuf>,
}

impl FsManager {
    /// Construct with explicit config path.
    pub fn new_with_path(config: crate::config::Config, config_path: PathBuf) -> Self {
        Self {
            config,
            config_path: Some(config_path),
        }
    }

    /// Build a tree view of managed directories (real-time from FS).
    /// This powers the "drop-down tree menu system" the user described.
    pub fn build_tree(&self, root: &Path) -> Option<DirectoryNode> {
        if !self.is_allowed(root) {
            return None;
        }

        let meta = fs::metadata(root).ok()?;
        let mode = meta.permissions().mode();
        let owner = Some(meta.uid());
        let group = Some(meta.gid());

        let mut node = DirectoryNode {
            path: root.to_path_buf(),
            name: root
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            owner,
            group,
            mode,
            children: vec![],
        };

        // Recursively build children (directories only, as per user request)
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(child) = self.build_tree(&path) {
                        node.children.push(child);
                    }
                }
            }
        }

        Some(node)
    }

    /// Apply owner + group + permissions to a directory (and optionally recursive).
    /// This is the core action the visual GUI will call on "save and apply".
    ///
    /// All mutations are performed by the running container via `docker exec`
    /// (or equivalent). The container has the bind mounts and the necessary
    /// capabilities. The host-side management tool never needs a local
    /// privileged binary.
    pub fn apply_permissions(
        &self,
        path: &Path,
        owner_uid: u32,
        group_gid: u32,
        mode: u32,
        recursive: bool,
    ) -> Result<(), String> {
        if !self.is_allowed(path) {
            return Err("Path is outside allowed managed roots".into());
        }

        // Defense-in-depth policy (refuse dangerous operations before asking the container).
        if owner_uid == 0 || group_gid == 0 {
            return Err("Refusing to set UID or GID 0".into());
        }
        if mode & 0o7000 != 0 {
            return Err("Refusing mode with setuid/setgid/sticky bits".into());
        }

        let container_name = self
            .config
            .management
            .ganesha_container_name
            .clone()
            .unwrap_or_else(|| "nfs-klldap".to_string());

        let container_path = self.host_path_to_container_path(path)?;

        // Ask the container to perform the permission change.
        // The UI runs `docker exec $CONTAINER chown -R ... && chmod -R ...` (when recursive).
        self.perform_container_chown_chmod(
            &container_name,
            &container_path,
            owner_uid,
            group_gid,
            mode,
            recursive,
        )?;

        Ok(())
    }

    /// Map a host-side path (from the UI / config shares) to the equivalent
    /// path as seen inside the container.
    fn host_path_to_container_path(&self, host_path: &Path) -> Result<PathBuf, String> {
        let root = self.config.storage.container_root.trim_end_matches('/');

        for share in &self.config.shares {
            if host_path.starts_with(&share.host_path) {
                let rel = host_path.strip_prefix(&share.host_path).unwrap_or(Path::new(""));
                let mut cpath = PathBuf::from(root);
                cpath.push(&share.name);
                if !rel.as_os_str().is_empty() {
                    cpath.push(rel);
                }
                return Ok(cpath);
            }
        }

        Err(format!(
            "Path {} is not under any configured share host_path",
            host_path.display()
        ))
    }

    /// Ask the running container (via `docker exec`) to perform chown + chmod
    /// on the given container-internal path. This is the mechanism the host UI
    /// uses to change ownership/permissions on the bind-mounted export data.
    fn perform_container_chown_chmod(
        &self,
        container: &str,
        container_path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
        recursive: bool,
    ) -> Result<(), String> {
        let rec = if recursive { " -R" } else { "" };

        // Build a single command the UI effectively runs:
        //   docker exec $CONTAINER sh -c 'chown -R uid:gid /path && chmod -R mode /path'
        let cmd = format!(
            "chown{rec} {uid}:{gid} {path} && chmod{rec} {mode:o} {path}",
            rec = rec,
            uid = uid,
            gid = gid,
            mode = mode,
            path = container_path.display()
        );

        let output = Command::new("docker")
            .args(["exec", container, "sh", "-c", &cmd])
            .output()
            .map_err(|e| format!("failed to run docker exec for chown/chmod: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "docker exec chown/chmod failed inside container '{}': {}",
                container,
                stderr.trim()
            ));
        }

        Ok(())
    }

    pub(crate) fn is_allowed(&self, path: &Path) -> bool {
        // New central config: allowed = the host_path of every declared share
        crate::config::all_managed_roots(&self.config)
            .iter()
            .any(|root| path.starts_with(root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_test_config_with_shares(host_paths: &[&str]) -> crate::config::Config {
        crate::config::Config {
            shares: host_paths
                .iter()
                .enumerate()
                .map(|(i, p)| nfs_klldap_config::Share {
                    name: format!("share{}", i),
                    host_path: PathBuf::from(p),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    fn create_temp_tree(base: &std::path::Path, rel_paths: &[&str]) -> std::io::Result<()> {
        for rel in rel_paths {
            let full = base.join(rel);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if !rel.ends_with('/') {
                std::fs::write(&full, "test")?;
            } else {
                std::fs::create_dir_all(&full)?;
            }
        }
        Ok(())
    }

    #[test]
    fn is_allowed_respects_configured_shares() {
        let cfg = make_test_config_with_shares(&["/media/SSD/data", "/mnt/backups"]);
        let fs = FsManager::new_with_path(cfg, PathBuf::from("/tmp/dummy.conf"));

        assert!(fs.is_allowed(Path::new("/media/SSD/data")));
        assert!(fs.is_allowed(Path::new("/media/SSD/data/subdir")));
        assert!(fs.is_allowed(Path::new("/mnt/backups")));
        assert!(!fs.is_allowed(Path::new("/media/SSD/other")));
        assert!(!fs.is_allowed(Path::new("/root")));
    }

    #[test]
    fn build_tree_returns_none_for_disallowed_path() {
        let cfg = make_test_config_with_shares(&["/tmp/allowed"]);
        let fs = FsManager::new_with_path(cfg, PathBuf::from("/tmp/dummy.conf"));

        assert!(fs.build_tree(Path::new("/tmp/not-allowed")).is_none());
    }

    #[test]
    fn build_tree_walks_only_directories_and_respects_shares() {
        let tmp = TempDir::new().unwrap();
        let allowed_root = tmp.path().join("allowed");
        std::fs::create_dir_all(&allowed_root).unwrap();

        // Create a realistic tree
        let tree = [
            "movies/",
            "movies/action/",
            "movies/action/file1.mkv",
            "movies/drama/",
            "backups/",
            "backups/2024/",
        ];
        create_temp_tree(&allowed_root, &tree).unwrap();

        let cfg = make_test_config_with_shares(&[allowed_root.to_str().unwrap()]);
        let fs = FsManager::new_with_path(cfg, PathBuf::from("/tmp/dummy.conf"));

        // Root should be visible
        let root_node = fs
            .build_tree(&allowed_root)
            .expect("root should be allowed");
        assert_eq!(root_node.name, "allowed");
        assert_eq!(root_node.children.len(), 2); // movies + backups

        // Check one child
        let movies = root_node
            .children
            .iter()
            .find(|c| c.name == "movies")
            .expect("movies dir should exist");
        assert_eq!(movies.children.len(), 2); // action + drama
        assert!(movies.children.iter().any(|c| c.name == "action"));
    }

    #[test]
    fn build_tree_skips_files_and_only_includes_dirs() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("file.txt"), "data").unwrap();
        std::fs::create_dir_all(root.join("subdir")).unwrap();

        let cfg = make_test_config_with_shares(&[root.to_str().unwrap()]);
        let fs = FsManager::new_with_path(cfg, PathBuf::from("/tmp/dummy.conf"));

        let node = fs.build_tree(root).unwrap();
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.children[0].name, "subdir");
    }
}

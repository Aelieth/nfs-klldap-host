//! Real-time filesystem operations for the management tool.
//!
//! All state comes from the live filesystem (no database).
//! - Directory tree is built on demand by walking the configured base paths.
//! - Permission changes are applied via a secure backend (sudo by default).
//! - Recursive option is supported exactly as the user described.
//!
//! Security: The tool itself should run as a low-privilege user.
//! All chown/chmod operations go through narrow sudoers rules.

use std::fs;
use std::io::Write;
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
    /// Path to the central nfs-klldap.conf. Used to pass NFS_KLLDAP_CONF to the
    /// privileged helper on each invocation so it can derive live ALLOWED_ROOTS
    /// from the current shares (no hardcoded paths, no staleness after UI edits).
    config_path: Option<PathBuf>,
}

impl FsManager {
    /// Construct with explicit config path (preferred for helper env propagation
    /// so the privileged helper can derive live ALLOWED_ROOTS from current shares).
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
    /// This version routes all mutations through the small privileged helper
    /// (`nfs-perm-helper`) for safety. The main tool should run unprivileged.
    ///
    /// See docs/security.md and priv-helper/ for details.
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

        // Build request for the privileged helper
        let request = serde_json::json!({
            "path": path.to_string_lossy(),
            "uid": owner_uid,
            "gid": group_gid,
            "mode": mode,
            "recursive": recursive
        });

        // New central config shape: management section (with sensible defaults for the host UI)
        let helper_path = self
            .config
            .management
            .helper_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("/usr/local/bin/nfs-perm-helper"));
        let use_sudo = self.config.management.use_sudo.unwrap_or(true);

        let mut cmd = if use_sudo {
            let mut c = Command::new("sudo");
            c.arg(helper_path);
            c
        } else {
            Command::new(helper_path)
        };

        // Propagate the exact config path the UI is using so the helper can
        // load the current [[shares]] host_paths for its allow-list on this invocation.
        if let Some(p) = &self.config_path {
            cmd.env("NFS_KLLDAP_CONF", p);
        } else if let Ok(env_p) = std::env::var("NFS_KLLDAP_CONF") {
            cmd.env("NFS_KLLDAP_CONF", env_p);
        }

        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn helper: {}", e))?;

        // Write JSON request to stdin
        {
            let stdin = child.stdin.as_mut().ok_or("failed to open helper stdin")?;
            writeln!(stdin, "{}", request)
                .map_err(|e| format!("failed to write to helper: {}", e))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("helper execution failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("helper rejected operation: {}", stderr.trim()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("Helper response: {}", stdout.trim());

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

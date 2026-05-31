//! FsManager: host_path (logical) ↔ container_path translation + permission application.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

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
}

impl FsManager {
    /// Construct with explicit config path.
    pub fn new_with_path(config: crate::config::Config, _config_path: PathBuf) -> Self {
        Self { config }
    }

    /// Build tree using logical host_path namespace (for UI + is_allowed).
    /// Translation to real container path occurs only at the privileged operation boundary
    /// (see `privileged.rs`).
    pub fn build_tree(&self, root: &Path) -> Option<DirectoryNode> {
        // Normalize early so trailing slashes don't break matching or child synthesis.
        let normalized = self.normalize_for_matching(root);

        if !self.is_allowed(&normalized) {
            return None;
        }

        let real_root = match self.host_path_to_container_path(&normalized) {
            Ok(p) => p,
            Err(_) => return None,
        };

        let meta = fs::metadata(&real_root).ok()?;
        // Store only the permission bits (mask off file type like S_IFDIR).
        // This prevents "40755" style output in the UI.
        let mode = meta.permissions().mode() & 0o7777;
        let owner = Some(meta.uid());
        let group = Some(meta.gid());

        let mut node = DirectoryNode {
            path: normalized.clone(),
            name: normalized
                .file_name()
                .unwrap_or_else(|| normalized.as_os_str())
                .to_string_lossy()
                .into_owned(),
            owner,
            group,
            mode,
            children: vec![],
        };

        // Recursively build children (directories only). We read from the real
        // container path but synthesize child paths in the logical (host)
        // namespace so that subsequent HTMX calls and is_allowed checks
        // continue to work against the configured shares.
        if let Ok(entries) = fs::read_dir(&real_root) {
            for entry in entries.flatten() {
                if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                    let child_name = entry.file_name();
                    let logical_child = normalized.join(&child_name);
                    if let Some(child) = self.build_tree(&logical_child) {
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
    /// All mutations are performed directly inside the container as root.
    pub fn apply_permissions(
        &self,
        path: &Path,
        owner_uid: u32,
        group_gid: u32,
        mode: u32,
        recursive: bool,
    ) -> Result<(), String> {
        let normalized = self.normalize_for_matching(path);
        if !self.is_allowed(&normalized) {
            return Err("Path is outside allowed managed roots".into());
        }

        // Defense-in-depth policy (refuse dangerous operations before asking the container).
        if owner_uid == 0 || group_gid == 0 {
            return Err("Refusing to set UID or GID 0".into());
        }
        if mode & 0o7000 != 0 {
            return Err("Refusing mode with setuid/setgid/sticky bits".into());
        }

        let target_path = self.host_path_to_container_path(&normalized)?;

        // Perform chown + chmod directly (we run inside the container as root).
        self.apply_direct(&target_path, owner_uid, group_gid, mode, recursive)?;

        Ok(())
    }

    /// host_path (from config/UI) → real path under container_root + share.name.
    /// The single bind-mount contract used by both apply_permissions and build_tree.
    pub(crate) fn host_path_to_container_path(&self, host_path: &Path) -> Result<PathBuf, String> {
        let normalized = self.normalize_for_matching(host_path);
        let container_root = self.config.storage.container_root.trim_end_matches('/');

        for share in &self.config.shares {
            let share_normalized = self.normalize_for_matching(&share.host_path);
            if normalized.starts_with(&share_normalized) {
                let rel = normalized
                    .strip_prefix(&share_normalized)
                    .unwrap_or(Path::new(""));
                let mut cpath = PathBuf::from(container_root);
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

    /// Direct chown/chmod as root on host bind mounts.
    ///
    /// All privileged host-mutating operations are routed through `privileged`.
    /// See `privileged.rs` for rationale and security boundary.
    fn apply_direct(
        &self,
        path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
        recursive: bool,
    ) -> Result<(), String> {
        if recursive {
            self.apply_recursive(path, uid, gid, mode)
                .map_err(|e| format!("recursive chown/chmod failed: {}", e))?;
        } else {
            crate::privileged::chown(path, uid, gid).map_err(|e| e.to_string())?;
            crate::privileged::chmod(path, mode).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn apply_recursive(&self, path: &Path, uid: u32, gid: u32, mode: u32) -> std::io::Result<()> {
        crate::privileged::chown(path, uid, gid)?;
        crate::privileged::chmod(path, mode)?;

        if path.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                self.apply_recursive(&entry.path(), uid, gid, mode)?;
            }
        }
        Ok(())
    }

    pub(crate) fn is_allowed(&self, path: &Path) -> bool {
        let normalized = self.normalize_for_matching(path);
        // New central config: allowed = the host_path of every declared share
        crate::config::all_managed_roots(&self.config)
            .iter()
            .any(|root| normalized.starts_with(self.normalize_for_matching(root)))
    }

    /// Normalize a path for prefix matching: strip trailing slashes.
    /// This prevents issues when the UI (or config) has "/some/share/" vs "/some/share".
    fn normalize_for_matching(&self, p: &Path) -> PathBuf {
        let s = p.to_string_lossy();
        let trimmed = s.trim_end_matches('/');
        if trimmed.is_empty() {
            PathBuf::from("/")
        } else {
            PathBuf::from(trimmed)
        }
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

    /// Helper that creates a config exercising the host_path → container translation.
    /// The real on-disk tree lives at `container_root`/`share_name`.
    /// Calls to build_tree use the `host_path` (logical) and must return nodes
    /// whose .path values stay in the logical host namespace.
    fn make_test_config_with_container_mapping(
        host_path: &str,
        container_root: &str,
        share_name: &str,
    ) -> crate::config::Config {
        crate::config::Config {
            storage: nfs_klldap_config::StorageSection {
                container_root: container_root.to_string(),
            },
            shares: vec![nfs_klldap_config::Share {
                name: share_name.to_string(),
                host_path: PathBuf::from(host_path),
                ..Default::default()
            }],
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
        // This test now exercises the real host_path → container translation
        // that the WebUI tree browser relies on inside the container.
        let tmp = TempDir::new().unwrap();

        // Real tree lives under container_root + share.name (simulating the bind mount
        // layout /export/mydata that the container actually sees).
        let container_root = tmp.path().join("container-root");
        let real_share_dir = container_root.join("mydata");
        std::fs::create_dir_all(&real_share_dir).unwrap();

        let tree = [
            "movies/",
            "movies/action/",
            "movies/action/file1.mkv",
            "movies/drama/",
            "backups/",
            "backups/2024/",
        ];
        create_temp_tree(&real_share_dir, &tree).unwrap();

        // Logical host_path (what the admin puts in nfs-klldap.conf and sees in the UI)
        // is completely different from the container-visible location.
        let logical_host_path = "/host/media/mydata";
        let cfg = make_test_config_with_container_mapping(
            logical_host_path,
            container_root.to_str().unwrap(),
            "mydata",
        );
        let fs = FsManager::new_with_path(cfg, PathBuf::from("/tmp/dummy.conf"));

        // We ask for the logical root; build_tree must translate internally to the real dir.
        let root_node = fs
            .build_tree(Path::new(logical_host_path))
            .expect("root should be allowed and visible via translation");

        // Returned node uses the logical path + its basename for display
        assert_eq!(root_node.path, Path::new(logical_host_path));
        assert_eq!(root_node.name, "mydata");
        assert_eq!(root_node.children.len(), 2); // movies + backups

        // Children must also be reported with logical paths (host namespace) so the UI
        // can send them back in subsequent /tree and /directory requests.
        let movies = root_node
            .children
            .iter()
            .find(|c| c.name == "movies")
            .expect("movies dir should exist");
        assert_eq!(movies.children.len(), 2);
        assert!(movies.children.iter().any(|c| c.name == "action"));
        assert!(movies.path.starts_with(logical_host_path));
    }

    #[test]
    fn build_tree_skips_files_and_only_includes_dirs() {
        let tmp = TempDir::new().unwrap();
        let real_root = tmp.path();
        std::fs::write(real_root.join("file.txt"), "data").unwrap();
        std::fs::create_dir_all(real_root.join("subdir")).unwrap();

        // Make the translation land on the real_root we created:
        // container_root = real_root, share.name = "" (push of empty does nothing harmful here
        // because we only read the root itself in this test).
        let mut cfg = make_test_config_with_shares(&[real_root.to_str().unwrap()]);
        cfg.storage.container_root = real_root.to_string_lossy().into_owned();
        // Force the single share's name to empty so container_root + name == real_root
        cfg.shares[0].name.clear();

        let fs = FsManager::new_with_path(cfg, PathBuf::from("/tmp/dummy.conf"));

        let node = fs
            .build_tree(real_root)
            .expect("root should resolve (translation is identity in this setup)");
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.children[0].name, "subdir");
    }
}

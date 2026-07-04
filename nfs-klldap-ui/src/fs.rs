//! FsManager applies chown/chmod on allow-listed share paths.
//! It translates host paths to container paths via the bind-root model.

#![deny(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex as StdMutex;

use walkdir::{DirEntry, WalkDir};

#[derive(Debug, Clone)]
pub struct DirectoryNode {
    pub path: PathBuf,
    pub name: String,
    pub children: Vec<DirectoryNode>,
}

/// Options for apply (recursive policy, continue, dry).
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    pub recursive: bool,
    pub apply_to_dirs: bool,
    pub apply_to_files: bool,
    pub continue_on_error: bool,
    pub dry_run: bool,
}

/// Structured result from a (possibly partial) apply operation.
#[derive(Debug, Clone, Default)]
pub struct ApplyResult {
    /// Entries chown'd/chmod'd (or counted in dry-run).
    pub changed: usize,
    /// Collects per-path errors when continue_on_error keeps partial results.
    pub errors: Vec<(PathBuf, String)>,
    /// Skipped entries (symlinks, filtered types, or dry-run).
    pub skipped: usize,
}

/// Tracks live apply progress atomics the web poller reads during apply.
#[derive(Debug, Default)]
pub struct ApplyProgress {
    pub total: AtomicUsize,
    pub processed: AtomicUsize,
    pub changed: AtomicUsize,
    pub skipped: AtomicUsize,
    pub error_count: AtomicUsize,
    pub cancelled: AtomicBool,
    pub finished: AtomicBool,
    /// Phase string is scanning, applying, or done.
    pub phase: StdMutex<String>,
    pub cmd: StdMutex<Option<String>>,
    pub final_result_text: StdMutex<Option<String>>,
    /// Capped recent errors for live display.
    /// Full list appears in the final result text.
    pub recent_errors: StdMutex<Vec<(PathBuf, String)>>,
    /// Last path being processed when cancel was observed.
    /// Included in the CANCELLED-after-path user message.
    pub last_path: StdMutex<Option<String>>,
}

pub struct FsManager {
    pub config: crate::config::Config,
}

impl FsManager {
    pub fn new(config: crate::config::Config) -> Self {
        Self { config }
    }

    /// Builds the permission tree in host_path space before privileged work.
    pub fn build_tree(&self, root: &Path) -> Option<DirectoryNode> {
        // Normalize early so trailing slashes don't break matching or child.
        let normalized = self.normalize_for_matching(root);

        if !self.is_allowed(&normalized) {
            return None;
        }

        let real_root = match self.host_path_to_container_path(&normalized) {
            Ok(p) => p,
            Err(_) => return None,
        };

        let mut node = DirectoryNode {
            path: normalized.clone(),
            name: normalized
                .file_name()
                .unwrap_or_else(|| normalized.as_os_str())
                .to_string_lossy()
                .into_owned(),
            children: vec![],
        };

        // Builds child directories recursively by reading the container path.
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

    /// Stat-only lookup for one directory (lazy, no subtree walk).
    pub fn get_dir_meta(&self, path: &Path) -> Option<(u32, u32, u32)> {
        let normalized = self.normalize_for_matching(path);
        if !self.is_allowed(&normalized) {
            return None;
        }

        let real = self.host_path_to_container_path(&normalized).ok()?;
        let meta = fs::metadata(&real).ok()?;
        let mode = meta.permissions().mode() & 0o7777;
        Some((meta.uid(), meta.gid(), mode))
    }

    /// Returns *named* (non-base) ACL user/group entries for an allowed directory using the
    /// shipped get_acl (pure libc xattr). Used by ACL UI and direct unit tests.
    /// Empty list is valid (no named ACL entries). None if outside allowed roots.
    pub fn get_dir_acl(&self, path: &Path) -> Option<Vec<crate::privileged::AclEntry>> {
        let normalized = self.normalize_for_matching(path);
        if !self.is_allowed(&normalized) {
            return None;
        }
        let real = match self.host_path_to_container_path(&normalized) {
            Ok(p) => p,
            Err(_) => return None,
        };
        crate::privileged::get_acl(&real).ok()
    }

    /// Applies a single ACL modification (Set one entry or Remove one-or-more) to a real FS path
    /// under an allowed share root. Returns short success text or error string. Distinct from POSIX apply.
    /// Directly exercisable from tests and web ACL apply handler.
    pub fn apply_acl_mod(&self, path: &Path, modification: crate::privileged::AclModification) -> Result<String, String> {
        let normalized = self.normalize_for_matching(path);
        if !self.is_allowed(&normalized) {
            return Err("Path is outside allowed managed roots".into());
        }
        let real = self.host_path_to_container_path(&normalized).map_err(|e| e.to_string())?;
        crate::privileged::apply_acl(&real, modification)
            .map(|_| "ACL entry updated on disk".to_string())
            .map_err(|e| format!("ACL apply failed: {}", e))
    }

    /// Immediate child directories only (/fs/children HTMX lazy expand).
    pub fn list_children(&self, path: &Path) -> Option<Vec<DirectoryNode>> {
        let normalized = self.normalize_for_matching(path);
        if !self.is_allowed(&normalized) {
            return None;
        }

        let real = self.host_path_to_container_path(&normalized).ok()?;
        let read = fs::read_dir(&real).ok()?;

        let mut out = Vec::new();
        for entry in read.flatten() {
            if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                // Only directories are browsable in the lazy tree.
                continue;
            }
            let child_name = entry.file_name();
            let logical_child = normalized.join(&child_name);

            // We only need path name for the lazy tree UI (owner/mode come.
            out.push(DirectoryNode {
                path: logical_child.clone(),
                name: child_name.to_string_lossy().into_owned(),
                children: vec![],
            });
        }
        Some(out)
    }

    /// No-op hook for post-apply cache invalidation.
    pub fn invalidate_path(&self, _path: &Path) {}

    /// Count variant that increments progress.processed as scanned so far.
    /// Drives live Stand-by / scanned-N spinner feedback and honours cancel.
    pub fn count_applicable_with_live(
        &self,
        path: &Path,
        recursive: bool,
        progress: &ApplyProgress,
    ) -> Result<usize, String> {
        let normalized = self.normalize_for_matching(path);
        if !self.is_allowed(&normalized) {
            return Err("Path is outside allowed managed roots".into());
        }

        let target_path = self.host_path_to_container_path(&normalized)?;

        let opts = ApplyOptions {
            recursive,
            apply_to_dirs: true,
            apply_to_files: true,
            continue_on_error: true,
            dry_run: false,
        };

        self.count_tree(&target_path, &opts, progress)
            .map_err(|e| format!("count failed: {}", e))
    }

    /// Applies permissions with progress atomics after progress.total is set.
    pub fn apply_permissions_with_progress(
        &self,
        path: &Path,
        owner_uid: u32,
        group_gid: u32,
        mode: u32,
        recursive: bool,
        progress: &ApplyProgress,
    ) -> Result<ApplyResult, String> {
        let normalized = self.normalize_for_matching(path);
        if !self.is_allowed(&normalized) {
            return Err("Path is outside allowed managed roots".into());
        }

        if owner_uid == 0 || group_gid == 0 {
            return Err("Refusing to set UID or GID 0".into());
        }
        if mode & 0o7000 != 0 {
            return Err("Refusing mode with setuid/setgid/sticky bits".into());
        }

        let target_path = self.host_path_to_container_path(&normalized)?;

        let opts = ApplyOptions {
            recursive,
            apply_to_dirs: true,
            apply_to_files: true,
            continue_on_error: true,
            dry_run: false,
        };

        self.apply_direct_with_progress(&target_path, owner_uid, group_gid, mode, &opts, progress)
            .map_err(|e| format!("apply failed: {}", e))
    }

    /// Maps host_path to the container path for the matching share.
    /// See module docs for the bind-root model.
    pub(crate) fn host_path_to_container_path(&self, host_path: &Path) -> Result<PathBuf, String> {
        let normalized = self.normalize_for_matching(host_path);

        for share in &self.config.shares {
            let share_normalized = self.normalize_for_matching(&share.host_path);
            if normalized.starts_with(&share_normalized) {
                let rel = normalized
                    .strip_prefix(&share_normalized)
                    .unwrap_or(Path::new(""));
                let mut cpath = PathBuf::from(self.config.container_path_for(share));
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

    fn apply_direct_with_progress(
        &self,
        path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
        opts: &ApplyOptions,
        progress: &ApplyProgress,
    ) -> Result<ApplyResult, String> {
        self.apply_tree_with_progress(path, uid, gid, mode, opts, progress)
            .map_err(|e| format!("apply failed: {}", e))
    }

    /// Returns whether this walk entry gets chown/chmod under the options.
    fn should_apply_entry(entry: &DirEntry, opts: &ApplyOptions) -> bool {
        let ft = entry.file_type();
        if ft.is_symlink() {
            return false;
        }
        let is_dir = ft.is_dir();
        let is_file = ft.is_file();
        if opts.recursive {
            return (is_dir && opts.apply_to_dirs) || (is_file && opts.apply_to_files);
        }
        // Non-recursive mode updates the target dir and immediate files only.
        let depth = entry.depth();
        (is_dir && opts.apply_to_dirs && depth == 0)
            || (is_file && opts.apply_to_files && depth == 1)
    }

    /// Count-only walk that updates progress.processed and honors cancel.
    fn count_tree(
        &self,
        root: &Path,
        opts: &ApplyOptions,
        progress: &ApplyProgress,
    ) -> std::io::Result<usize> {
        let max_d = if opts.recursive { usize::MAX } else { 1 };

        let walker = WalkDir::new(root)
            .follow_links(false)
            .max_depth(max_d)
            .into_iter();

        let mut count = 0usize;
        for entry_res in walker {
            if progress.cancelled.load(Ordering::Relaxed) {
                break;
            }
            let entry: DirEntry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };
            if entry.file_type().is_symlink() {
                continue;
            }
            if Self::should_apply_entry(&entry, opts) {
                let p = entry.path().to_path_buf();
                *progress.last_path.lock().expect("last_path mutex poisoned") = Some(p.display().to_string());
                count += 1;
                progress.processed.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(count)
    }

    /// Applies WalkDir with progress atomics, cancel, and finished flag.
    fn apply_tree_with_progress(
        &self,
        root: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
        opts: &ApplyOptions,
        progress: &ApplyProgress,
    ) -> std::io::Result<ApplyResult> {
        let mut result = ApplyResult::default();

        let max_d = if opts.recursive { usize::MAX } else { 1 };

        let walker = WalkDir::new(root)
            .follow_links(false)
            .max_depth(max_d)
            .into_iter();

        for entry_res in walker {
            if progress.cancelled.load(Ordering::Relaxed) {
                break;
            }

            let entry: DirEntry = match entry_res {
                Ok(e) => e,
                Err(e) => {
                    let p = e.path().map(|pp| pp.to_path_buf()).unwrap_or_else(|| PathBuf::from("<unknown>"));
                    let msg = e.to_string();
                    result.errors.push((p.clone(), msg.clone()));
                    progress.error_count.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut errs) = progress.recent_errors.lock() {
                        errs.push((p, msg));
                        if errs.len() > 10 { errs.remove(0); }
                    }
                    if !opts.continue_on_error {
                        return Err(std::io::Error::other(
                            "aborted on walk error (continue_on_error=false)",
                        ));
                    }
                    continue;
                }
            };

            let p = entry.path().to_path_buf();
            let ft = entry.file_type();

            if ft.is_symlink() {
                result.skipped += 1;
                progress.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let should_apply = Self::should_apply_entry(&entry, opts);

            if !should_apply {
                result.skipped += 1;
                progress.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            // Record the path we are about to touch (for cancel reporting).
            *progress.last_path.lock().expect("last_path mutex poisoned") = Some(p.display().to_string());

            if opts.dry_run {
                result.changed += 1;
                progress.changed.fetch_add(1, Ordering::Relaxed);
                progress.processed.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            // Perform the actual privileged operations.
            if let Err(e) = crate::privileged::chown(&p, uid, gid) {
                result.errors.push((p.clone(), format!("chown: {}", e)));
                progress.error_count.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut errs) = progress.recent_errors.lock() {
                    errs.push((p.clone(), format!("chown: {}", e)));
                    if errs.len() > 10 { errs.remove(0); }
                }
                if !opts.continue_on_error {
                    return Err(e);
                }
            } else if let Err(e) = crate::privileged::chmod(&p, mode) {
                result.errors.push((p.clone(), format!("chmod: {}", e)));
                progress.error_count.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut errs) = progress.recent_errors.lock() {
                    errs.push((p.clone(), format!("chmod: {}", e)));
                    if errs.len() > 10 { errs.remove(0); }
                }
                if !opts.continue_on_error {
                    return Err(e);
                }
            } else {
                result.changed += 1;
                progress.changed.fetch_add(1, Ordering::Relaxed);
            }

            progress.processed.fetch_add(1, Ordering::Relaxed);
        }

        progress.finished.store(true, Ordering::Relaxed);
        Ok(result)
    }

    pub(crate) fn is_allowed(&self, path: &Path) -> bool {
        let normalized = self.normalize_for_matching(path);
        // New central config is allowed = the host_path of every declared.
        crate::config::all_managed_roots(&self.config)
            .iter()
            .any(|root| normalized.starts_with(self.normalize_for_matching(root)))
    }

    /// Normalizes a path for prefix matching by stripping trailing slashes.
    /// Avoids prefix mismatches from trailing slashes in UI or config.
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
#[allow(clippy::unwrap_used)]
mod tests {
    // Translation tests: host_path first dir = implicit bind root tail Maps.
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
        let fs = FsManager::new(cfg);

        assert!(fs.is_allowed(Path::new("/media/SSD/data")));
        assert!(fs.is_allowed(Path::new("/media/SSD/data/subdir")));
        assert!(fs.is_allowed(Path::new("/mnt/backups")));
        assert!(!fs.is_allowed(Path::new("/media/SSD/other")));
        assert!(!fs.is_allowed(Path::new("/root")));
    }

    #[test]
    fn build_tree_returns_none_for_disallowed_path() {
        let cfg = make_test_config_with_shares(&["/tmp/allowed"]);
        let fs = FsManager::new(cfg);

        assert!(fs.build_tree(Path::new("/tmp/not-allowed")).is_none());
    }

    #[test]
    fn build_tree_walks_only_directories_and_respects_shares() {
        let tmp = TempDir::new().unwrap();
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

        let logical_host_path = "/hostroot/mydata";
        let cfg = make_test_config_with_container_mapping(
            logical_host_path,
            container_root.to_str().unwrap(),
            "mydata",
        );
        let fs = FsManager::new(cfg);

        let root_node = fs
            .build_tree(Path::new(logical_host_path))
            .expect("root should be allowed and visible via translation");

        assert_eq!(root_node.path, Path::new(logical_host_path));
        assert_eq!(root_node.name, "mydata");
        // Expect movies and backups as the two root children.
        assert_eq!(root_node.children.len(), 2);

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

        let logical = Path::new("/rootbind");
        let mut cfg = make_test_config_with_shares(&[logical.to_str().unwrap()]);
        cfg.storage.container_root = real_root.to_string_lossy().into_owned();
        cfg.shares[0].name.clear();

        let fs = FsManager::new(cfg);

        let node = fs
            .build_tree(logical)
            .expect("root should resolve (translation is identity in this setup)");
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.children[0].name, "subdir");
    }

    #[test]
    fn host_path_to_container_path_exact_and_subpath() {
        let cfg = make_test_config_with_container_mapping(
            "/hostroot/myshare",
            "/container/root",
            "myshare",
        );
        let fs = FsManager::new(cfg);

        // Asserts mapping for the exact share root path.
        let root = fs.host_path_to_container_path(Path::new("/hostroot/myshare")).unwrap();
        assert_eq!(root, PathBuf::from("/container/root/myshare"));

        // Asserts mapping for a nested subdirectory path.
        let sub = fs.host_path_to_container_path(Path::new("/hostroot/myshare/sub/dir")).unwrap();
        assert_eq!(sub, PathBuf::from("/container/root/myshare/sub/dir"));
    }

    #[test]
    fn host_path_to_container_path_respects_explicit_export_path() {
        let mut cfg = make_test_config_with_container_mapping(
            "/media/HDD-RAID/media",
            "/export",
            "media",
        );
        cfg.shares[0].export_path = Some("/HDD-RAID/media".to_string());

        let fs = FsManager::new(cfg);

        // Root of the share.
        let root = fs
            .host_path_to_container_path(Path::new("/media/HDD-RAID/media"))
            .unwrap();
        assert_eq!(root, PathBuf::from("/export/HDD-RAID/media"));

        // Nested subdir must append the same relative tail.
        let sub = fs
            .host_path_to_container_path(Path::new("/media/HDD-RAID/media/videos/4k"))
            .unwrap();
        assert_eq!(sub, PathBuf::from("/export/HDD-RAID/media/videos/4k"));
    }

    #[test]
    fn host_path_to_container_path_derives_internal_from_first_dir_of_host_path() {
        let mut cfg = make_test_config_with_container_mapping(
            "/media/HDD-RAID/media",
            "/export",
            "media",
        );
        cfg.shares[0].export_path = Some("/short-movies".to_string());

        let fs = FsManager::new(cfg);

        let root = fs
            .host_path_to_container_path(Path::new("/media/HDD-RAID/media"))
            .unwrap();
        assert_eq!(root, PathBuf::from("/export/HDD-RAID/media"));

        let sub = fs
            .host_path_to_container_path(Path::new("/media/HDD-RAID/media/videos/4k"))
            .unwrap();
        assert_eq!(sub, PathBuf::from("/export/HDD-RAID/media/videos/4k"));

    }

    #[test]
    fn host_path_to_container_path_no_match() {
        let cfg = make_test_config_with_container_mapping("/host/allowed", "/c", "s");
        let fs = FsManager::new(cfg);

        assert!(fs.host_path_to_container_path(Path::new("/host/other")).is_err());
    }

    #[test]
    fn list_children_is_one_level_and_respects_shares() {
        let tmp = TempDir::new().unwrap();
        let container_root = tmp.path().join("cr");
        let real = container_root.join("s1");
        std::fs::create_dir_all(real.join("a")).unwrap();
        // Deeper paths should not appear in non-recursive listing.
        std::fs::create_dir_all(real.join("b/c")).unwrap();

        let cfg = make_test_config_with_container_mapping("/hostroot/s1", container_root.to_str().unwrap(), "s1");
        let fs = FsManager::new(cfg);

        let kids = fs.list_children(Path::new("/hostroot/s1")).expect("allowed");
        assert_eq!(kids.len(), 2);
        let names: Vec<_> = kids.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        // Children vectors must be empty (lazy).
        assert!(kids.iter().all(|n| n.children.is_empty()));
    }

    #[test]
    fn apply_tree_dry_run_and_symlink_skipping() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("tree");
        std::fs::create_dir_all(root.join("d1")).unwrap();
        std::fs::create_dir_all(root.join("d2")).unwrap();
        // Create a symlink to a dir (should be skipped, not descended).
        #[cfg(unix)]
        {
            use std::os::unix::fs as ufs;
            let _ = ufs::symlink("d1", root.join("link_to_d1"));
        }

        let logical = Path::new("/rootbind");
        let cfg = make_test_config_with_shares(&[logical.to_str().unwrap()]);
        let mut cfg = cfg;
        cfg.storage.container_root = root.to_string_lossy().into_owned();
        cfg.shares[0].name.clear();
        // One-segment host_path makes first-dir stripping yield empty tail.

        let fs = FsManager::new(cfg);

        let opts = ApplyOptions {
            recursive: true,
            apply_to_dirs: true,
            apply_to_files: true,
            continue_on_error: true,
            dry_run: true,
        };

        let res = fs.apply_tree_with_progress(&root, 1000, 1000, 0o755, &opts, &ApplyProgress::default()).expect("dry run");
        // Root + d1 + d2 = 3 changed. The symlink is skipped.
        assert!(res.changed >= 3);
        assert!(res.skipped >= 1, "symlink should have been counted as skipped");
        assert!(res.errors.is_empty());
    }

    #[test]
    fn apply_tree_non_recursive_changes_dir_and_immediate_files_only() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("target");
        std::fs::create_dir_all(root.join("subdir")).unwrap();
        std::fs::write(root.join("top.txt"), "a").unwrap();
        std::fs::write(root.join("subdir/nested.txt"), "b").unwrap();

        let logical = Path::new("/rootbind");
        let cfg = make_test_config_with_shares(&[logical.to_str().unwrap()]);
        let mut cfg = cfg;
        cfg.storage.container_root = root.to_string_lossy().into_owned();
        cfg.shares[0].name.clear();
        // One-segment host_path makes first-dir stripping yield empty tail.

        let fs = FsManager::new(cfg);

        let opts = ApplyOptions {
            recursive: false,
            apply_to_dirs: true,
            apply_to_files: true,
            continue_on_error: true,
            dry_run: true,
        };

        let res = fs
            .apply_tree_with_progress(&root, 1000, 1000, 0o755, &opts, &ApplyProgress::default())
            .expect("non-recursive dry run");

        // Target/ (dir) + top.txt — not subdir/ nor nested.txt.
        assert_eq!(res.changed, 2, "expected root dir and one immediate file");
        assert!(res.errors.is_empty());
    }

    // === ACL read/mutation unit tests (shipped entry points, real FS, temp trees) ===

    fn make_test_acl_config_for(tmp_root: &std::path::Path, logical: &str) -> crate::config::Config {
        let mut cfg = make_test_config_with_shares(&[logical]);
        cfg.storage.container_root = tmp_root.to_string_lossy().into_owned();
        if let Some(s0) = cfg.shares.first_mut() {
            s0.name.clear();
        }
        cfg
    }

    #[test]
    fn acl_get_returns_empty_for_new_dir_no_named_entries() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("aclroot");
        std::fs::create_dir_all(&root).unwrap();
        let logical = Path::new("/aclbind");
        let cfg = make_test_acl_config_for(&root, logical.to_str().unwrap());
        let fs = FsManager::new(cfg);

        let entries = fs.get_dir_acl(logical).expect("allowed");
        assert!(entries.is_empty(), "fresh dir has only base ACLs, named list must be empty");
    }

    #[test]
    fn acl_set_and_get_named_user_and_group_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("aclrt");
        std::fs::create_dir_all(&root).unwrap();
        let logical = Path::new("/aclbind2");
        let cfg = make_test_acl_config_for(&root, logical.to_str().unwrap());
        let fs = FsManager::new(cfg);

        // Set a user and a group ACL
        let mod_u = crate::privileged::AclModification::Set {
            kind: crate::privileged::AclEntryKind::User(12345),
            perms: crate::privileged::AclPerms::from_str("r-x"),
        };
        let mod_g = crate::privileged::AclModification::Set {
            kind: crate::privileged::AclEntryKind::Group(6789),
            perms: crate::privileged::AclPerms::from_str("rw-"),
        };
        let real = fs.host_path_to_container_path(logical).unwrap();
        // before
        #[cfg(unix)]
        if let Ok(out) = std::process::Command::new("getfacl").args(["-c","-n","--absolute-names",&real.to_string_lossy()]).output() {
            eprintln!("GETFACL_BEFORE_PURE_APPLY:\n{}", String::from_utf8_lossy(&out.stdout));
        }

        fs.apply_acl_mod(logical, mod_u).expect("set user acl via pure Rust xattr");
        fs.apply_acl_mod(logical, mod_g).expect("set group acl via pure Rust xattr");

        let entries = fs.get_dir_acl(logical).expect("list after set");
        assert_eq!(entries.len(), 2, "after two named Sets we must see exactly the named entries");
        let has_u = entries.iter().any(|e| matches!(e.kind, crate::privileged::AclEntryKind::User(12345)) && e.perms.r && e.perms.x && !e.perms.w);
        let has_g = entries.iter().any(|e| matches!(e.kind, crate::privileged::AclEntryKind::Group(6789)) && e.perms.r && e.perms.w && !e.perms.x);
        assert!(has_u, "user 12345 r-x must be present via shipped get_dir_acl after apply");
        assert!(has_g, "group 6789 rw- must be present via shipped get_dir_acl after apply");

        // Hard assert on full xattr bytes via pure read + parse: must contain bases + ver layout + named
        let raw = crate::privileged::read_acl_xattr_raw(&real).expect("raw xattr");
        let parsed = crate::privileged::parse_acl_bytes(&raw).expect("parse");
        assert!(parsed.iter().any(|(t,_,id)| *t == 1 && *id == 0xffffffff), "xattr must contain USER_OBJ base");
        assert!(parsed.iter().any(|(t,_,id)| *t == 4 && *id == 0xffffffff), "xattr must contain GROUP_OBJ base");
        assert!(parsed.iter().any(|(t,_,id)| *t == 32 && *id == 0xffffffff), "xattr must contain OTHER base");
        assert!(parsed.iter().any(|(t,_,id)| *t == 2 && *id == 12345), "xattr must contain named user 12345");
        assert!(parsed.iter().any(|(t,_,id)| *t == 8 && *id == 6789), "xattr must contain named group 6789");
        assert_eq!(&raw[0..4], &[2,0,0,0], "xattr must start with ver=2");

        // Verify on real FS via direct privileged read (no reimpl)
        let direct = crate::privileged::get_acl(&real).expect("direct");
        assert!(direct.iter().any(|e| e.id() == 12345 && e.is_user()));

        // Emit fresh getfacl output for transcript evidence (mechanical --nocapture capture)
        #[cfg(unix)]
        if let Ok(out) = std::process::Command::new("getfacl").args(["-c","-n","--absolute-names",&real.to_string_lossy()]).output() {
            eprintln!("GETFACL_AFTER_PURE_APPLY:\n{}", String::from_utf8_lossy(&out.stdout));
        }
    }

    #[test]
    fn acl_edit_and_delete_batch_on_real_tree() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("acledit");
        std::fs::create_dir_all(&root).unwrap();
        let logical = Path::new("/aclbind3");
        let cfg = make_test_acl_config_for(&root, logical.to_str().unwrap());
        let fs = FsManager::new(cfg);

        // Seed two
        fs.apply_acl_mod(logical, crate::privileged::AclModification::Set {
            kind: crate::privileged::AclEntryKind::User(2001), perms: crate::privileged::AclPerms::from_octal(0o7),
        }).expect("seed1");
        fs.apply_acl_mod(logical, crate::privileged::AclModification::Set {
            kind: crate::privileged::AclEntryKind::Group(3001), perms: crate::privileged::AclPerms::from_octal(0o5),
        }).expect("seed2");

        // Edit the user to r--
        let edit = crate::privileged::AclModification::Set {
            kind: crate::privileged::AclEntryKind::User(2001),
            perms: crate::privileged::AclPerms::from_str("r--"),
        };
        fs.apply_acl_mod(logical, edit).expect("edit via pure");

        let after_edit = fs.get_dir_acl(logical).expect("");
        let u = after_edit.iter().find(|e| matches!(e.kind, crate::privileged::AclEntryKind::User(2001))).unwrap();
        assert!(u.perms.r && !u.perms.w && !u.perms.x, "edit must have updated perms on disk");

        // Batch delete both
        let del = crate::privileged::AclModification::Remove {
            kinds: vec![
                crate::privileged::AclEntryKind::User(2001),
                crate::privileged::AclEntryKind::Group(3001),
            ],
        };
        fs.apply_acl_mod(logical, del).expect("batch delete via pure");

        let after_del = fs.get_dir_acl(logical).expect("list post del");
        assert!(after_del.is_empty(), "named entries must be gone after delete");
    }

    #[test]
    fn acl_outside_allowed_is_none_and_rejected() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("aclrej");
        std::fs::create_dir_all(&root).unwrap();
        let cfg = make_test_acl_config_for(&root, "/allowed");
        let fs = FsManager::new(cfg);

        assert!(fs.get_dir_acl(Path::new("/evil")).is_none());
        let res = fs.apply_acl_mod(Path::new("/evil"), crate::privileged::AclModification::Remove { kinds: vec![] });
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("outside allowed"));
    }
}

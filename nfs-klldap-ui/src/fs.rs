//! FsManager: allow-list (host_path from shares)
//! host<->container path translation, WalkDir-based chown/chmod.
//! Policy: follow_links(false), never descend symlinks, numeric ids only
//! refuse 0/set*id. Non-rec = dir+immediate files.
//!
//! Host<->container translation uses each share's host_path.
//! The first directory component after "/" is the per-share bind root.
//! That root plus container_root yields the internal path.
//! This keeps the permission tree and applies independent of the (editable)
//! share.export_path that is used only for the external/client Pseudo name.

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
    /// Number of entries successfully chown'd + chmod'd (or would have been
    /// in dry-run).
    pub changed: usize,
    /// Per-path errors encountered (path + message).
    /// Non-empty does not imply overall failure
    /// when `continue_on_error` was true.
    pub errors: Vec<(PathBuf, String)>,
    /// Entries that were deliberately skipped (symlinks under the current policy,
    /// entries filtered by apply_to_* flags, or everything in a dry-run).
    pub skipped: usize,
}

/// Live progress/cancel for async apply (atomics updated by walker
/// read by web poller).
/// Supports count phase (spinner) then apply phase
/// last_path for cancel messages.
#[derive(Debug, Default)]
pub struct ApplyProgress {
    pub total: AtomicUsize,
    pub processed: AtomicUsize,
    pub changed: AtomicUsize,
    pub skipped: AtomicUsize,
    pub error_count: AtomicUsize,
    pub cancelled: AtomicBool,
    pub finished: AtomicBool,
    /// "scanning" | "applying" | "done"
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

    /// Build tree using logical host_path namespace (for UI + is_allowed).
    /// Container translation runs in host_path_to_container_path.
    /// Called before privileged ops.
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

        let mut node = DirectoryNode {
            path: normalized.clone(),
            name: normalized
                .file_name()
                .unwrap_or_else(|| normalized.as_os_str())
                .to_string_lossy()
                .into_owned(),
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
                continue; // files and symlinks are not presented as browsable children
            }
            let child_name = entry.file_name();
            let logical_child = normalized.join(&child_name);

            // We only need path
            // name for the lazy tree UI (owner/mode come from
            // separate /dir-meta calls when the user selects a node).
            out.push(DirectoryNode {
                path: logical_child.clone(),
                name: child_name.to_string_lossy().into_owned(),
                children: vec![],
            });
        }
        Some(out)
    }

    /// No-op; reserved for post-apply cache invalidation.
    /// The web handler spawns a call to exercise the path; a real cache can be
    /// plugged in here later with no other changes.
    pub fn invalidate_path(&self, _path: &Path) {}

    /// Count variant that increments progress.processed as scanned so far.
    /// Drives live Stand-by / scanned-N spinner feedback and honours cancel.
    /// Returns the final count (which becomes total).
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

    /// Apply variant that drives the supplied progress atomics (and last_path) and
    /// honours cancellation.
    /// The caller is expected to have set (or let the count set)
    /// progress.total beforehand for accurate %
    /// if total is still 0 this pass will
    /// still run and update processed.
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

    /// host_path → container path for the matching share.
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

    /// Whether this walk entry should receive chown/chmod under the current options.
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
        // Non-recursive: target directory (depth 0)
        // immediate files (depth 1) only.
        let depth = entry.depth();
        (is_dir && opts.apply_to_dirs && depth == 0)
            || (is_file && opts.apply_to_files && depth == 1)
    }

    /// Count-only tree walk (used by count_applicable_with_live). Increments
    /// progress.processed as "scanned so far" (for spinner UX)
    /// updates last_path,
    /// and aborts early if cancelled. Does not perform any mutations.
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

    /// WalkDir apply with progress atomics, cancel, and finished flag.
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

            // Record the path we are about to touch (for cancel reporting)
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
        // New central config: allowed = the host_path of every declared share
        crate::config::all_managed_roots(&self.config)
            .iter()
            .any(|root| normalized.starts_with(self.normalize_for_matching(root)))
    }

    /// Normalize a path for prefix matching: strip trailing slashes.
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
    // Translation tests: host_path first dir = implicit bind root
    // tail maps under container_root.
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
        assert_eq!(root_node.children.len(), 2); // movies + backups

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

        // Exact share root
        let root = fs.host_path_to_container_path(Path::new("/hostroot/myshare")).unwrap();
        assert_eq!(root, PathBuf::from("/container/root/myshare"));

        // Subdirectory
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

        // Root of the share
        let root = fs
            .host_path_to_container_path(Path::new("/media/HDD-RAID/media"))
            .unwrap();
        assert_eq!(root, PathBuf::from("/export/HDD-RAID/media"));

        // Nested subdir must append the same relative tail
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
        std::fs::create_dir_all(real.join("b/c")).unwrap(); // deeper, should not appear

        let cfg = make_test_config_with_container_mapping("/hostroot/s1", container_root.to_str().unwrap(), "s1");
        let fs = FsManager::new(cfg);

        let kids = fs.list_children(Path::new("/hostroot/s1")).expect("allowed");
        assert_eq!(kids.len(), 2);
        let names: Vec<_> = kids.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        // Children vectors must be empty (lazy)
        assert!(kids.iter().all(|n| n.children.is_empty()));
    }

    #[test]
    fn apply_tree_dry_run_and_symlink_skipping() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("tree");
        std::fs::create_dir_all(root.join("d1")).unwrap();
        std::fs::create_dir_all(root.join("d2")).unwrap();
        // Create a symlink to a dir (should be skipped, not descended)
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
        // One-segment host_path: first-dir strip yields empty tail.
        // Internal path maps to container_root from the test tree.

        let fs = FsManager::new(cfg);

        let opts = ApplyOptions {
            recursive: true,
            apply_to_dirs: true,
            apply_to_files: true,
            continue_on_error: true,
            dry_run: true,
        };

        let res = fs.apply_tree_with_progress(&root, 1000, 1000, 0o755, &opts, &ApplyProgress::default()).expect("dry run");
        // root + d1 + d2 = 3 changed; the symlink is skipped
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
        // One-segment host_path: first-dir strip yields empty tail.
        // Internal path maps to container_root from the test tree.

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

        // target/ (dir) + top.txt — not subdir/ nor nested.txt
        assert_eq!(res.changed, 2, "expected root dir and one immediate file");
        assert!(res.errors.is_empty());
    }
}

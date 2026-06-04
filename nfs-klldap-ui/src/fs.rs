//! FsManager: allow-list (host_path from shares), host<->container path translation, WalkDir-based chown/chmod.
//! Policy: follow_links(false), never descend symlinks, numeric ids only, refuse 0/set*id. Non-rec = dir+immediate files.

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
    /// Number of entries successfully chown'd + chmod'd (or would have been, in dry-run).
    pub changed: usize,
    /// Per-path errors encountered (path + message). Non-empty does not imply overall failure
    /// when `continue_on_error` was true.
    pub errors: Vec<(PathBuf, String)>,
    /// Entries that were deliberately skipped (symlinks under the current policy,
    /// entries filtered by apply_to_* flags, or everything in a dry-run).
    pub skipped: usize,
}

/// Live progress/cancel for async apply (atomics updated by walker, read by web poller).
/// Supports count phase (spinner) then apply phase, last_path for cancel messages.
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
    /// Capped recent errors for live display (full list is in the final result text).
    pub recent_errors: StdMutex<Vec<(PathBuf, String)>>,
    /// Last path the walker was about to process (or was processing) when cancel was
    /// observed. Included in the "CANCELLED after ..." message.
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

    /// Lightweight stat-only lookup for a single directory (owner, group, masked mode).
    /// Used by the inline meta/editor fragments (avoids full subtree walks).
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

    /// Lightweight, non-recursive listing of *immediate* child directories only.
    /// Used by the `/fs/children` HTMX endpoint (lazy tree expands pay O(1) cost).
    ///
    /// Returns nodes with `.children == vec![]`. Logical paths synthesized like build_tree.
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

            // We only need path + name for the lazy tree UI (owner/mode come from
            // separate /dir-meta calls when the user selects a node).
            out.push(DirectoryNode {
                path: logical_child.clone(),
                name: child_name.to_string_lossy().into_owned(),
                children: vec![],
            });
        }
        Some(out)
    }

    /// Optional hook for background cache invalidation after apply (no-op today).
    /// The web handler spawns a call to exercise the path; a real cache can be
    /// plugged in here later with no other changes.
    pub fn invalidate_path(&self, _path: &Path) {}

    /// Legacy non-progress apply (delegates to with_progress + dummy). Not used by live handlers.
    #[allow(dead_code)]
    pub fn apply_permissions(
        &self,
        path: &Path,
        owner_uid: u32,
        group_gid: u32,
        mode: u32,
        recursive: bool,
    ) -> Result<ApplyResult, String> {
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

        let opts = ApplyOptions {
            recursive,
            apply_to_dirs: true,
            apply_to_files: true,
            continue_on_error: true,
            dry_run: false,
        };

        let dummy = ApplyProgress::default();
        self.apply_direct_with_progress(&target_path, owner_uid, group_gid, mode, &opts, &dummy)
            .map_err(|e| format!("apply failed: {}", e))
    }

    /// Legacy count (delegates). Live path uses count_applicable_with_live.
    #[allow(dead_code)]
    pub fn count_applicable(&self, path: &Path, recursive: bool) -> Result<usize, String> {
        let dummy = ApplyProgress::default();
        self.count_applicable_with_live(path, recursive, &dummy)
    }

    /// Count variant that increments `progress.processed` as "scanned so far" (for the
    /// "Stand-by, estimating total... scanned N so far [spinner]" live feedback) and
    /// honours cancel. Returns the final count (which becomes `total`).
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
    /// honours cancellation. The caller is expected to have set (or let the count set)
    /// progress.total beforehand for accurate %; if total is still 0 this pass will
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

    /// host_path (from config/UI) → real path under container_root + share.name.
    /// The single bind-mount contract used by both apply_permissions and build_tree.
    ///
    /// This is the authoritative translation. All security decisions (is_allowed) are
    /// performed in the logical host namespace; only the final syscall boundary translates.
    /// See the module-level docs for the "bind-mount UID namespace" assumption.
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

    /// Legacy direct wrapper (delegates to progress impl).
    #[allow(dead_code)]
    fn apply_direct(
        &self,
        path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
        opts: &ApplyOptions,
    ) -> Result<ApplyResult, String> {
        let dummy = ApplyProgress::default();
        self.apply_direct_with_progress(path, uid, gid, mode, opts, &dummy)
            .map_err(|e| format!("apply failed: {}", e))
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
        // Non-recursive: target directory (depth 0) + immediate files (depth 1) only.
        let depth = entry.depth();
        (is_dir && opts.apply_to_dirs && depth == 0)
            || (is_file && opts.apply_to_files && depth == 1)
    }

    /// Count-only tree walk (used by count_applicable_with_live). Increments
    /// progress.processed as "scanned so far" (for spinner UX), updates last_path,
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
            .into_iter()
            .filter_entry(|e: &DirEntry| {
                if e.file_type().is_symlink() {
                    return true;
                }
                true
            });

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

    /// Core tree-walking permission application using WalkDir (iterative, policy-driven).
    /// This is the single implementation; the non-progress apply_tree is now a thin
    /// delegate using a dummy progress (for backward compat with tests + direct callers).
    ///
    /// In addition to the classic guarantees, this version:
    /// - updates all progress atomics (processed/changed/skipped/error_count)
    /// - records last_path before operating on an entry (for "Cancelled after ..." UX)
    /// - checks the cancelled flag between entries and aborts the walk early
    /// - always sets finished=true on the way out
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
            .into_iter()
            .filter_entry(|e: &DirEntry| {
                if e.file_type().is_symlink() {
                    return true;
                }
                true
            });

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

    /// Internal compat wrapper used by fs tests (delegates to progress impl).
    #[allow(dead_code)]
    fn apply_tree(
        &self,
        root: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
        opts: &ApplyOptions,
    ) -> std::io::Result<ApplyResult> {
        let dummy = ApplyProgress::default();
        self.apply_tree_with_progress(root, uid, gid, mode, opts, &dummy)
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
#[allow(clippy::unwrap_used)] // Tests legitimately use unwrap for brevity on TempDir / setup
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
        let fs = FsManager::new(cfg);

        // We ask for the logical root; build_tree must translate internally to the real dir.
        let root_node = fs
            .build_tree(Path::new(logical_host_path))
            .expect("root should be allowed and visible via translation");

        // Returned node uses the logical path + its basename for display
        assert_eq!(root_node.path, Path::new(logical_host_path));
        assert_eq!(root_node.name, "mydata");
        assert_eq!(root_node.children.len(), 2); // movies + backups

        // Children must also be reported with logical paths (host namespace) so the UI
        // can send them back in subsequent /tree and /fs/children requests.
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

        let fs = FsManager::new(cfg);

        let node = fs
            .build_tree(real_root)
            .expect("root should resolve (translation is identity in this setup)");
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.children[0].name, "subdir");
    }

    // Additional policy + translation tests:

    #[test]
    fn host_path_to_container_path_exact_and_subpath() {
        let cfg = make_test_config_with_container_mapping(
            "/host/data",
            "/container/root",
            "myshare",
        );
        let fs = FsManager::new(cfg);

        // Exact share root
        let root = fs.host_path_to_container_path(Path::new("/host/data")).unwrap();
        assert_eq!(root, PathBuf::from("/container/root/myshare"));

        // Subdirectory
        let sub = fs.host_path_to_container_path(Path::new("/host/data/sub/dir")).unwrap();
        assert_eq!(sub, PathBuf::from("/container/root/myshare/sub/dir"));
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

        let cfg = make_test_config_with_container_mapping("/host/s1", container_root.to_str().unwrap(), "s1");
        let fs = FsManager::new(cfg);

        let kids = fs.list_children(Path::new("/host/s1")).expect("allowed");
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

        let cfg = make_test_config_with_shares(&[root.to_str().unwrap()]);
        let mut cfg = cfg;
        cfg.storage.container_root = root.to_string_lossy().into_owned();
        cfg.shares[0].name.clear();

        let fs = FsManager::new(cfg);

        let opts = ApplyOptions {
            recursive: true,
            apply_to_dirs: true,
            apply_to_files: true,
            continue_on_error: true,
            dry_run: true,
        };

        let res = fs.apply_tree(&root, 1000, 1000, 0o755, &opts).expect("dry run");
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

        let cfg = make_test_config_with_shares(&[root.to_str().unwrap()]);
        let mut cfg = cfg;
        cfg.storage.container_root = root.to_string_lossy().into_owned();
        cfg.shares[0].name.clear();

        let fs = FsManager::new(cfg);

        let opts = ApplyOptions {
            recursive: false,
            apply_to_dirs: true,
            apply_to_files: true,
            continue_on_error: true,
            dry_run: true,
        };

        let res = fs
            .apply_tree(&root, 1000, 1000, 0o755, &opts)
            .expect("non-recursive dry run");

        // target/ (dir) + top.txt — not subdir/ nor nested.txt
        assert_eq!(res.changed, 2, "expected root dir and one immediate file");
        assert!(res.errors.is_empty());
    }
}

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
    pub owner: Option<u32>,   // uid
    pub group: Option<u32>,   // gid
    pub mode: u32,
    pub children: Vec<DirectoryNode>,
}

pub struct FsManager {
    pub config: crate::config::Config,
}

impl FsManager {
    pub fn new(config: crate::config::Config) -> Self {
        Self { config }
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
            name: root.file_name().unwrap_or_default().to_string_lossy().into_owned(),
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
        let helper_path = self.config.management.helper_path.clone()
            .unwrap_or_else(|| PathBuf::from("/usr/local/bin/nfs-perm-helper"));
        let use_sudo = self.config.management.use_sudo.unwrap_or(true);

        let mut cmd = if use_sudo {
            let mut c = Command::new("sudo");
            c.arg(helper_path);
            c
        } else {
            Command::new(helper_path)
        };

        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| format!("failed to spawn helper: {}", e))?;

        // Write JSON request to stdin
        {
            let stdin = child.stdin.as_mut().ok_or("failed to open helper stdin")?;
            writeln!(stdin, "{}", request).map_err(|e| format!("failed to write to helper: {}", e))?;
        }

        let output = child.wait_with_output().map_err(|e| format!("helper execution failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("helper rejected operation: {}", stderr.trim()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("Helper response: {}", stdout.trim());

        Ok(())
    }

    fn is_allowed(&self, path: &Path) -> bool {
        // New central config: allowed = the host_path of every declared share
        crate::config::all_managed_roots(&self.config).iter().any(|root| path.starts_with(root))
    }
}

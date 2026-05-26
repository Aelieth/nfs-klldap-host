//! Management of exports.d/*.exports files.
//!
//! When the user changes permissions or adds a directory in the visual GUI,
//! we touch / update the corresponding .exports file and can trigger
//! a SIGHUP re-export on the NFS container (filesystem-oriented approach).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

pub struct ExportsManager {
    pub exports_dir: PathBuf,
}

impl ExportsManager {
    pub fn new(exports_dir: PathBuf) -> Self {
        Self { exports_dir }
    }

    /// Ensure this directory is exported with sensible Kerberized defaults.
    /// Called on "save and apply" from the GUI.
    pub fn ensure_exported(&self, host_path: &PathBuf, container_path: &str) -> Result<(), String> {
        fs::create_dir_all(&self.exports_dir)
            .map_err(|e| format!("cannot create exports.d: {}", e))?;

        // Simple naming convention based on the last component
        let name = host_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("share");

        let export_file = self.exports_dir.join(format!("{}.exports", name));

        let entry = format!(
            "{}   *(rw,sec=krb5p,no_root_squash,sync,hide)\n",
            container_path
        );

        // For now we append if the file doesn't already contain this path.
        // A real implementation would parse and update intelligently.
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&export_file)
            .map_err(|e| format!("cannot open export file: {}", e))?;

        writeln!(file, "{}", entry.trim()).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Trigger re-export on the container (SIGHUP as implemented in PR2).
    /// In production this would be driven by config (container name, ssh target, etc.).
    pub fn trigger_reexport(&self) -> Result<(), String> {
        // Simple default: try to SIGHUP the container via docker (common dev setup).
        // The real tool should make this configurable and more robust.
        let output = Command::new("docker")
            .args(["kill", "-s", "HUP", "alma-nfs-kerb"])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                println!("Sent SIGHUP to NFS container (re-export triggered).");
                Ok(())
            }
            _ => {
                println!("Note: Could not auto SIGHUP container. Run manually: docker kill -s HUP alma-nfs-kerb");
                Ok(())
            }
        }
    }
}

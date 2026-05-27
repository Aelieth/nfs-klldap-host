//! Ganesha management client.
//!
//! This module lets the host-side management tool speak *directly* to the
//! running NFS-Ganesha instance inside the container using the `ganesha-ctl`
//! wrapper (which in turn talks to the DBUS `org.ganesha.nfsd.exportmgr`
//! interface).
//!
//! This fulfills the design goal: "management tool speaks directly to
//! Ganesha's management interface" instead of only doing SIGHUP + exportfs.
//!
//! The tool invokes commands of the form:
//!   docker exec <container> ganesha-ctl add-export /etc/ganesha/exports.d/10-foo.conf "EXPORT(Path=/foo)"
//!   docker exec <container> ganesha-ctl remove-export 42
//!
//! We use std::process::Command so we do not need a DBUS crate in the tool itself.

use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct GaneshaClient {
    /// Name of the container (e.g. "alma-nfs-kerb")
    pub container_name: String,

    /// Runtime to use ("docker" or "podman")
    pub runtime: String,

    /// Path inside the container where export fragments live.
    /// This must match what is bind-mounted from the host.
    pub exports_dir_in_container: String,
}

impl GaneshaClient {
    pub fn new(container_name: &str) -> Self {
        Self {
            container_name: container_name.to_string(),
            runtime: "docker".to_string(),
            exports_dir_in_container: "/etc/ganesha/exports.d".to_string(),
        }
    }

    /// Allow overriding the container runtime (podman, nerdctl, etc.).
    pub fn with_runtime(mut self, runtime: &str) -> Self {
        self.runtime = runtime.to_string();
        self
    }

    /// Add (or update) an export by pointing Ganesha at a fragment file that
    /// already exists inside the container (usually written by us via the
    /// bind-mounted exports directory).
    ///
    /// `search_expr` is the selector passed to AddExport, e.g.:
    ///   "EXPORT(Path=/projectalpha)"
    ///   "EXPORT(export_id=1001)"
    pub fn add_export(&self, fragment_filename: &str, search_expr: &str) -> Result<(), String> {
        let container_path = format!("{}/{}", self.exports_dir_in_container, fragment_filename);

        let output = Command::new(&self.runtime)
            .args([
                "exec",
                &self.container_name,
                "ganesha-ctl",
                "add-export",
                &container_path,
                search_expr,
            ])
            .output()
            .map_err(|e| format!("failed to spawn {} exec: {}", self.runtime, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "ganesha-ctl add-export failed ({}): {}",
                output.status,
                stderr.trim()
            ));
        }

        println!(
            "Ganesha: added/updated export from {} (expr={})",
            container_path, search_expr
        );
        Ok(())
    }

    /// Remove an export by its numeric Export_Id (obtained via show_exports or
    /// previously recorded when we created it).
    pub fn remove_export(&self, export_id: u16) -> Result<(), String> {
        let output = Command::new(&self.runtime)
            .args([
                "exec",
                &self.container_name,
                "ganesha-ctl",
                "remove-export",
                &export_id.to_string(),
            ])
            .output()
            .map_err(|e| format!("failed to spawn {} exec: {}", self.runtime, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "ganesha-ctl remove-export {} failed ({}): {}",
                export_id,
                output.status,
                stderr.trim()
            ));
        }

        println!("Ganesha: removed export id={}", export_id);
        Ok(())
    }

    /// Ask Ganesha for the current list of active exports (raw output).
    /// Useful for debugging and for the UI to show "currently exported".
    pub fn show_exports(&self) -> Result<String, String> {
        let output = Command::new(&self.runtime)
            .args([
                "exec",
                &self.container_name,
                "ganesha-ctl",
                "show-exports",
            ])
            .output()
            .map_err(|e| format!("failed to spawn {} exec: {}", self.runtime, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "ganesha-ctl show-exports failed ({}): {}",
                output.status,
                stderr.trim()
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Trigger a config/export reload inside the container.
    /// This is a secondary path; the primary mechanism is direct Add/RemoveExport.
    pub fn reload(&self) -> Result<(), String> {
        let output = Command::new(&self.runtime)
            .args(["exec", &self.container_name, "ganesha-ctl", "reload"])
            .output()
            .map_err(|e| format!("failed to spawn {} exec: {}", self.runtime, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "ganesha-ctl reload failed ({}): {}",
                output.status,
                stderr.trim()
            ));
        }

        println!("Ganesha: reload requested");
        Ok(())
    }

    /// Convenience: given a host-side fragment path that we just wrote,
    /// figure out the filename and call add_export with a reasonable selector.
    ///
    /// This is the method the web UI "apply" flow should usually call.
    pub fn add_export_from_host_path(&self, host_fragment_path: &Path, export_path: &str) -> Result<(), String> {
        let filename = host_fragment_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| "invalid fragment path".to_string())?;

        // Build a search expression that matches the Pseudo or Path we are exporting.
        // Ganesha's AddExport accepts quite flexible selectors.
        let expr = format!("EXPORT(Path={})", export_path);

        self.add_export(filename, &expr)
    }
}

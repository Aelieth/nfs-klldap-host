//! Management of Ganesha exports (native EXPORT {} blocks).
//!
//! This is the clean long-term implementation:
//! - The tool writes proper Ganesha EXPORT {} fragments into the configured
//!   host-side directory (bind-mounted into the container at /etc/ganesha/exports.d/).
//! - On share add/update we call directly into Ganesha's management interface
//!   via the GaneshaClient (which execs `ganesha-ctl add-export ...` inside the container).
//!
//! This replaces the old kernel-style .exports + SIGHUP + exportfs path.

use std::fs;
use std::path::{Path, PathBuf};

use crate::config::Share;
use crate::ganesha::GaneshaClient;

pub struct ExportsManager {
    /// Host-side directory that gets bind-mounted into the container
    /// at /etc/ganesha/exports.d/. We write native Ganesha EXPORT blocks here.
    pub exports_dir: PathBuf,

    /// Client that can talk directly to the running Ganesha instance
    /// (via docker/podman exec + ganesha-ctl).
    pub ganesha: GaneshaClient,
}

impl ExportsManager {
    pub fn new(exports_dir: PathBuf, ganesha: GaneshaClient) -> Self {
        Self { exports_dir, ganesha }
    }

    /// Ensure the given share has a proper Ganesha EXPORT block on disk
    /// and is loaded into the running Ganesha daemon via the direct
    /// management interface (DBUS under the hood).
    ///
    /// This is the core "write native Ganesha blocks + speak directly" operation.
    pub fn ensure_share_exported(&self, share: &Share) -> Result<(), String> {
        fs::create_dir_all(&self.exports_dir)
            .map_err(|e| format!("cannot create ganesha exports directory {}: {}", self.exports_dir.display(), e))?;

        let filename = format!("{}.conf", sanitize_name(&share.name));
        let host_path = self.exports_dir.join(&filename);

        let export_id = share.export_id.unwrap_or_else(|| derive_export_id(&share.name));

        // Native Ganesha EXPORT block (VFS FSAL for bind-mounted host directories)
        let block = format!(
            r#"# Share: {}  (managed by nfs-kerb management tool)
EXPORT {{
    Export_Id = {};
    Path = {};
    Pseudo = {};
    Access_Type = RW;
    SecType = krb5p;
    Protocols = 4;

    FSAL {{
        Name = VFS;
    }}

    # Add CLIENT {{ ... }} blocks here for finer-grained access control if needed.
    # The default is strong Kerberos (krb5p) for all clients.
}}
"#,
            share.name, export_id, share.export_path, share.export_path
        );

        fs::write(&host_path, block)
            .map_err(|e| format!("failed to write Ganesha export block {}: {}", host_path.display(), e))?;

        // Now tell the running Ganesha to load it (direct management interface)
        self.ganesha
            .add_export_from_host_path(&host_path, &share.export_path)?;

        println!(
            "Exported share '{}' → {} (Export_Id={}, fragment={})",
            share.name,
            share.export_path,
            export_id,
            filename
        );

        Ok(())
    }

    /// Remove a share's export block from disk and from the running Ganesha.
    pub fn remove_share_export(&self, share: &Share) -> Result<(), String> {
        let filename = format!("{}.conf", sanitize_name(&share.name));
        let host_path = self.exports_dir.join(&filename);

        // Best effort: tell Ganesha to drop it
        if let Some(id) = share.export_id.or_else(|| Some(derive_export_id(&share.name))) {
            let _ = self.ganesha.remove_export(id);
        }

        if host_path.exists() {
            fs::remove_file(&host_path)
                .map_err(|e| format!("failed to remove export fragment {}: {}", host_path.display(), e))?;
            println!("Removed export fragment for share '{}'", share.name);
        }

        Ok(())
    }

    /// Write (or update) an export block for a raw path + export path.
    /// Used when the UI is working with ad-hoc directories that are not (yet) formal Shares.
    pub fn ensure_path_exported(&self, host_dir: &Path, export_path: &str, suggested_name: &str) -> Result<(), String> {
        fs::create_dir_all(&self.exports_dir)
            .map_err(|e| format!("cannot create exports dir: {}", e))?;

        let name = sanitize_name(suggested_name);
        let filename = format!("{}.conf", name);
        let host_path = self.exports_dir.join(&filename);

        let export_id = derive_export_id(&name);

        let block = format!(
            r#"# Ad-hoc export for {} (managed by nfs-kerb tool)
EXPORT {{
    Export_Id = {};
    Path = {};
    Pseudo = {};
    Access_Type = RW;
    SecType = krb5p;
    Protocols = 4;

    FSAL {{
        Name = VFS;
    }}
}}
"#,
            host_dir.display(), export_id, export_path, export_path
        );

        fs::write(&host_path, block)
            .map_err(|e| format!("failed to write export block: {}", e))?;

        self.ganesha.add_export_from_host_path(&host_path, export_path)?;

        Ok(())
    }

    /// Legacy compatibility helper (some old call sites still use this name).
    /// In the Ganesha world we treat the container_path as the desired Pseudo.
    pub fn ensure_exported(&self, host_path: &PathBuf, container_path: &str) -> Result<(), String> {
        let name = host_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("share")
            .to_string();

        self.ensure_path_exported(host_path, container_path, &name)
    }

    /// Legacy no-op for old SIGHUP callers. Direct management is preferred.
    /// We still support it as a fallback.
    pub fn trigger_reexport(&self) -> Result<(), String> {
        println!("Note: trigger_reexport called — preferring direct Ganesha management.");
        // As a last resort we can ask for a reload
        let _ = self.ganesha.reload();
        Ok(())
    }
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect()
}

/// Very simple stable ID derivation. For production you should assign
/// explicit Export_Ids in your config.toml so they never change.
fn derive_export_id(name: &str) -> u16 {
    let mut h: u32 = 0x811c9dc5;
    for b in name.as_bytes() {
        h = h.wrapping_mul(16777619) ^ (*b as u32);
    }
    1000 + (h % 55000) as u16
}

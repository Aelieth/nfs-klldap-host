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

    /// Write (or update) an export block for a raw path + export path.
    /// Used when the UI is working with ad-hoc directories that are not (yet) formal Shares.
    pub fn ensure_path_exported(&self, host_dir: &Path, export_path: &str, suggested_name: &str, export_id: Option<u16>) -> Result<(), String> {
        fs::create_dir_all(&self.exports_dir)
            .map_err(|e| format!("cannot create exports dir: {}", e))?;

        let name = sanitize_name(suggested_name);
        let filename = format!("{}.conf", name);
        let host_path = self.exports_dir.join(&filename);

        let export_id = export_id.unwrap_or_else(|| derive_export_id(&name));

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

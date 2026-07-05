//! Stable fingerprints of generated artifacts.

use std::fs;
use std::path::Path;

/// FNV-1a seed (shared with IdCache content fingerprint and file fingerprints).
pub const FNV1A_SEED: u64 = 0xcbf29ce484222325;

/// FNV-1a over raw bytes (shared by export-dir and identity-artifact helpers)
pub fn fingerprint_bytes(bytes: &[u8], mut h: u64) -> u64 {
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// FNV-1a over a single file (missing file → 0 contribution)
pub fn fingerprint_file(path: &Path) -> u64 {
    let Ok(bytes) = fs::read(path) else {
        return 0;
    };
    fingerprint_bytes(&bytes, FNV1A_SEED)
}

/// Combined fingerprint of SSSD/Kerberos/idmap derived configs.
pub fn fingerprint_identity_artifacts(
    sssd_conf: &Path,
    krb5_conf: &Path,
    idmap_conf: &Path,
) -> u64 {
    let mut h: u64 = FNV1A_SEED;
    for path in [sssd_conf, krb5_conf, idmap_conf] {
        let fp = fingerprint_file(path);
        h ^= fp;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// FNV-1a over sorted export fragment contents (empty dir → 0)
pub fn fingerprint_exports_dir(exports_dir: &Path) -> u64 {
    let mut h: u64 = FNV1A_SEED;
    let Ok(entries) = fs::read_dir(exports_dir) else {
        return 0;
    };
    let mut files: Vec<_> = entries
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "conf" || ext == "cfg")
        })
        .collect();
    files.sort_by_key(|e| e.file_name());
    for entry in files {
        if let Ok(bytes) = fs::read(entry.path()) {
            h = fingerprint_bytes(&bytes, h);
            h ^= 0xff;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_changes_when_fragment_content_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        fs::write(dir.join("10-a.conf"), b"Path = /export/a;\n").unwrap();
        let fp1 = fingerprint_exports_dir(dir);
        fs::write(dir.join("10-a.conf"), b"Path = /export/b;\n").unwrap();
        let fp2 = fingerprint_exports_dir(dir);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn identity_fingerprint_changes_when_sssd_conf_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let sssd = tmp.path().join("sssd.conf");
        let krb5 = tmp.path().join("krb5.conf");
        let idmap = tmp.path().join("idmapd.conf");
        fs::write(&sssd, b"[sssd]\n").unwrap();
        fs::write(&krb5, b"[libdefaults]\n").unwrap();
        fs::write(&idmap, b"[General]\n").unwrap();
        let fp1 = fingerprint_identity_artifacts(&sssd, &krb5, &idmap);
        fs::write(&sssd, b"[sssd]\nldap_uri = ldaps:// X\n").unwrap();
        let fp2 = fingerprint_identity_artifacts(&sssd, &krb5, &idmap);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_stable_for_same_content() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        fs::write(dir.join("10-a.conf"), b"Path = /export/a;\n").unwrap();
        assert_eq!(
            fingerprint_exports_dir(dir),
            fingerprint_exports_dir(dir)
        );
    }
}
//! Ganesha / SSSD / Kerberos config generation logic.
//!
//! This module is being built incrementally during Phase 5 of the
//! modularization. Currently contains only the small pure helpers.

/// Sanitize a share name for use in generated filenames.
/// Replaces any non-alphanumeric (except - and _) with '-'.
pub(crate) fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Deterministic export ID derivation from share name (FNV-1a variant).
pub(crate) fn derive_export_id(name: &str, base: u16) -> u16 {
    let mut h: u32 = 0x811c9dc5;
    for b in name.as_bytes() {
        h = h.wrapping_mul(16777619) ^ (*b as u32);
    }
    base + (h % 55000) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_name_replaces_invalid_chars() {
        assert_eq!(sanitize_name("my share!"), "my-share-");
        assert_eq!(sanitize_name("data_01"), "data_01");
        assert_eq!(sanitize_name("foo@bar#baz"), "foo-bar-baz");
    }

    #[test]
    fn derive_export_id_is_deterministic() {
        let id1 = derive_export_id("movies", 1000);
        let id2 = derive_export_id("movies", 1000);
        assert_eq!(id1, id2);

        // Different names should (almost always) produce different IDs
        assert_ne!(
            derive_export_id("movies", 1000),
            derive_export_id("data", 1000)
        );
    }
}

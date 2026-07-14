//! One per-share ACL/Non-ACL classification for every UI surface.
//!
//! The Share Permissions cards, the System Settings rows, the permissions
//! panel's share-level gate, and the client manifest must all agree, so they
//! all derive from this helper: the live cached write-probe verdict resolved
//! through the canonical `compute_effective_flags_probed` matrix. Surfaces
//! must never re-encode that matrix by hand.

use std::path::Path;

use nfs_klldap_config::{AclProbeVerdict, MountinfoSnapshot, NfsKlldapConfig, Share};

use super::acl_capability::AclCapabilityCache;

/// Per-share classification snapshot for cards, chips, and the manifest.
pub(crate) struct ShareAclStatus {
    /// The export actually serves ACLs: resolved mode on AND fs capable.
    pub effective_acl_capable: bool,
    /// Resolved enable_acl after auto promotion (pseudo editability, warnings).
    pub effective_enable_acl: bool,
    pub verdict: AclProbeVerdict,
    /// "capable" | "incapable" | "unverified" — the data-acl-probed value.
    pub probed: &'static str,
    /// Chip text: on / off / on (unverified) / on (unsupported) /
    /// auto (on) / auto (off).
    pub state_label: String,
}

/// Classifies one share exactly as Settings and generate do: the serve-root
/// verdict from the shared cache resolved through
/// `compute_effective_flags_probed`. force_refresh stays hardwired false so
/// unauthenticated surfaces (the manifest) can never drive the write probe
/// harder than the cache TTL; callers needing a fresh verdict (settings save,
/// the re-probe loop) keep calling `verdict_for_snapshot` directly.
pub(crate) fn share_acl_status(
    caps_cache: &AclCapabilityCache,
    snap: &MountinfoSnapshot,
    cfg: &NfsKlldapConfig,
    share: &Share,
) -> ShareAclStatus {
    let serve = cfg.serve_path_for(share);
    let serve = Path::new(&serve);
    let outcome = caps_cache.verdict_for_snapshot(
        snap,
        serve,
        serve,
        share.enable_acl == Some(false),
        false,
    );
    let eff =
        nfs_klldap_config::compute_effective_flags_probed(share, &outcome.caps, outcome.verdict);
    let probed = match outcome.verdict {
        AclProbeVerdict::Capable => "capable",
        AclProbeVerdict::Incapable => "incapable",
        AclProbeVerdict::Inconclusive => "unverified",
    };
    ShareAclStatus {
        effective_acl_capable: eff.enable_acl && outcome.caps.acl_capable,
        effective_enable_acl: eff.enable_acl,
        verdict: outcome.verdict,
        probed,
        state_label: share_acl_state_label(share.enable_acl, outcome.verdict),
    }
}

/// Human label for the share card chip and status dot, matching what generate
/// emits: explicit on/off, auto promoted or held, and the unverified states.
pub(crate) fn share_acl_state_label(
    enable_acl: Option<bool>,
    verdict: AclProbeVerdict,
) -> String {
    use AclProbeVerdict as V;
    match (enable_acl, verdict) {
        (Some(false), _) => "off",
        (Some(true), V::Capable) => "on",
        (Some(true), V::Inconclusive) => "on (unverified)",
        (Some(true), V::Incapable) => "on (unsupported)",
        (None, V::Capable) => "auto (on)",
        (None, _) => "auto (off)",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_label_covers_the_full_enable_acl_by_verdict_matrix() {
        use AclProbeVerdict as V;
        assert_eq!(share_acl_state_label(Some(false), V::Capable), "off");
        assert_eq!(share_acl_state_label(Some(false), V::Incapable), "off");
        assert_eq!(share_acl_state_label(Some(false), V::Inconclusive), "off");
        assert_eq!(share_acl_state_label(Some(true), V::Capable), "on");
        assert_eq!(
            share_acl_state_label(Some(true), V::Inconclusive),
            "on (unverified)"
        );
        assert_eq!(
            share_acl_state_label(Some(true), V::Incapable),
            "on (unsupported)"
        );
        assert_eq!(share_acl_state_label(None, V::Capable), "auto (on)");
        assert_eq!(share_acl_state_label(None, V::Inconclusive), "auto (off)");
        assert_eq!(share_acl_state_label(None, V::Incapable), "auto (off)");
    }
}

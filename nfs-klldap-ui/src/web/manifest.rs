//! Public share manifest for client provisioning.
//!
//! Clients cannot detect a share's ACL class over NFSv4 — GETATTR synthesizes
//! an ACL from mode and owner SETATTR-ACL lands on both classes (audit A8 in
//! docs/ganesha-architecture.md) — so the host declares it here and the client
//! setup script consumes it. Open by design: bootstrap data only (share name,
//! pseudo path, security flavor, rw, ACL class, Navahi exposure);
//! server-internal paths never appear in the payload. Probe load from anonymous hits is bounded by the
//! shared verdict cache because `share_acl_status` hardwires
//! force_refresh=false.

use axum::extract::State;
use axum::http::header::CACHE_CONTROL;
use axum::response::IntoResponse;
use axum::Json;

use super::AppState;

#[derive(serde::Serialize)]
struct ClientManifest {
    manifest_version: u32,
    server: String,
    generated_at: String,
    shares: Vec<ManifestShare>,
}

#[derive(serde::Serialize)]
struct ManifestShare {
    name: String,
    pseudo: String,
    security: String,
    rw: bool,
    /// "acl" | "noacl" — the same per-share classification the UI renders.
    acl: &'static str,
    /// Resolved enable_acl state label ("on", "auto (on)", …) for diagnostics.
    acl_state: String,
    /// True when the share is currently advertised over mDNS (global
    /// `navahi_discovery` && per-share `navahi_insecure`) — the same
    /// effective-exposure rule as the UI chip. Lets client tooling cross-check
    /// the advertised set it sees in avahi-browse against the flagged set.
    navahi: bool,
}

/// GET /client-manifest.json. Deliberately unauthenticated (never calls
/// require_auth) and exempt from the setup-wizard redirect: machine clients
/// need JSON, not a 303 to an HTML wizard.
pub(crate) async fn client_manifest(State(state): State<AppState>) -> impl IntoResponse {
    let snap =
        nfs_klldap_config::MountinfoSnapshot::capture(state.fs_probe_mountinfo_path.as_deref());
    // Poison-recover, never panic: this endpoint is unauthenticated, so a
    // poisoned config lock must not become an anonymous crash amplifier —
    // shares data is read-only here and safe to serve regardless.
    let cfg = state
        .config
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let shares: Vec<ManifestShare> = cfg
        .shares
        .iter()
        .map(|s| {
            let status = super::acl_status::share_acl_status(&state.acl_caps, &snap, &cfg, s);
            ManifestShare {
                name: s.name.clone(),
                pseudo: nfs_klldap_config::derive_share_pseudo(s),
                security: s
                    .security
                    .clone()
                    .unwrap_or_else(|| cfg.ganesha.default_security.clone()),
                rw: s.rw.unwrap_or(true),
                acl: if status.effective_acl_capable {
                    "acl"
                } else {
                    "noacl"
                },
                acl_state: status.state_label,
                navahi: nfs_klldap_config::share_navahi_effective(&cfg, s),
            }
        })
        .collect();
    let manifest = ClientManifest {
        manifest_version: 1,
        server: state.keytab_hostname.clone(),
        generated_at: now_rfc3339_utc(),
        shares,
    };
    // no-store: the classes are live-computed and no intermediary may pin a
    // stale one onto a freshly provisioned client.
    ([(CACHE_CONTROL, "no-store")], Json(manifest))
}

/// Hand-formatted RFC 3339 UTC stamp (the workspace `time` crate ships
/// without the `formatting` feature; matches format_mtime_utc's approach).
fn now_rfc3339_utc() -> String {
    let odt = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        odt.year(),
        u8::from(odt.month()),
        odt.day(),
        odt.hour(),
        odt.minute(),
        odt.second()
    )
}

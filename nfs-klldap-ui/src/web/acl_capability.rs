//! Per-mount ACL-capability cache shared by every UI surface.
//!
//! The write probe (`setfacl`/`getfacl` round trip) is the only thing that can
//! prove a filesystem stores POSIX ACLs, and it is comparatively expensive. The
//! panel, the tree "+" markers, the settings cards, and the `/acl-apply` gate
//! all need the same verdict, so caching it per mount keeps them coherent and
//! stops a subprocess firing on every request.
//!
//! Stage A (mountinfo classification) is cheap and re-run on every lookup, so a
//! remount that changes the filesystem type or options invalidates instantly;
//! only the write-probe verdict is cached, keyed by mount point.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use nfs_klldap_config::{
    acl_probe_verdict, verdict_from_caps, AclProbeVerdict, FsCapabilities, MountinfoSnapshot,
};

/// Default lifetime of a proven Capable/Incapable verdict before re-probing.
const DEFAULT_TTL_SECS: u64 = 300;
/// Inconclusive verdicts expire fast: the cause is often transient (an
/// unwritable probe dir, a missing tool) and cheap to retry.
const INCONCLUSIVE_TTL: Duration = Duration::from_secs(30);

/// Resolved capabilities for a path plus the write-probe verdict.
#[derive(Debug, Clone)]
pub(crate) struct ProbeOutcome {
    pub caps: FsCapabilities,
    pub mount_root: Option<String>,
    pub verdict: AclProbeVerdict,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    verdict: AclProbeVerdict,
    fstype: String,
    options: Vec<String>,
    probe_dir: PathBuf,
    probed_at: Instant,
}

/// Mount-keyed cache of write-probe verdicts.
pub struct AclCapabilityCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

impl AclCapabilityCache {
    /// Builds a cache with the TTL from `NFS_KLLDAP_ACL_PROBE_TTL_SECS`
    /// (seconds; default 300).
    pub fn new_from_env() -> Self {
        let ttl = std::env::var("NFS_KLLDAP_ACL_PROBE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TTL_SECS);
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(ttl),
        }
    }

    /// Drops every cached verdict (used when the config is reloaded).
    pub(crate) fn invalidate_all(&self) {
        if let Ok(mut e) = self.entries.write() {
            e.clear();
        }
    }

    /// Resolves the ACL verdict for a node, running Stage A live every call and
    /// the write probe only on a cache miss.
    ///
    /// `node_path` classifies the mount; `probe_dir` is the directory the write
    /// probe writes into (the node's own dir, or a file's parent). Set
    /// `skip_write_probe` for explicit-off shares and `force_refresh` when a
    /// decision must not ride a stale verdict (a settings save, the re-probe
    /// loop).
    /// Verdict over a caller-captured snapshot, so one request's several
    /// lookups share a single mountinfo read.
    pub(crate) fn verdict_for_snapshot(
        &self,
        snap: &MountinfoSnapshot,
        node_path: &Path,
        probe_dir: &Path,
        skip_write_probe: bool,
        force_refresh: bool,
    ) -> ProbeOutcome {
        let (caps, mount_root) = stage_a(snap, node_path);
        let verdict = self.verdict_cached(
            &caps,
            mount_root.as_deref(),
            probe_dir,
            skip_write_probe,
            force_refresh,
            |dir| acl_probe_verdict(&caps, dir),
        );
        ProbeOutcome {
            caps,
            mount_root,
            verdict,
        }
    }

    /// Cache core, generic over the probe so tests can count invocations
    /// without shelling out. Stage-A shortcuts (unknown, denylist, explicit
    /// off) are never cached — they are recomputed cheaply from `caps`.
    fn verdict_cached(
        &self,
        caps: &FsCapabilities,
        mount_root: Option<&str>,
        probe_dir: &Path,
        skip_write_probe: bool,
        force_refresh: bool,
        probe: impl FnOnce(&Path) -> AclProbeVerdict,
    ) -> AclProbeVerdict {
        if caps.fstype == "unknown" {
            return AclProbeVerdict::Inconclusive;
        }
        if !caps.acl_capable {
            return AclProbeVerdict::Incapable;
        }
        if skip_write_probe {
            return verdict_from_caps(caps);
        }
        // A capable mount with no resolved mount point cannot be keyed; probe
        // without caching rather than guess.
        let Some(root) = mount_root else {
            return probe(probe_dir);
        };
        if !force_refresh {
            if let Some(v) = self.cached_hit(root, caps, probe_dir) {
                return v;
            }
        }
        let verdict = probe(probe_dir);
        self.store(root, caps, probe_dir, verdict);
        verdict
    }

    fn ttl_for(&self, verdict: AclProbeVerdict) -> Duration {
        match verdict {
            AclProbeVerdict::Inconclusive => INCONCLUSIVE_TTL,
            _ => self.ttl,
        }
    }

    fn cached_hit(
        &self,
        root: &str,
        caps: &FsCapabilities,
        probe_dir: &Path,
    ) -> Option<AclProbeVerdict> {
        let entries = self.entries.read().ok()?;
        let entry = entries.get(root)?;
        // A remount that changed the filesystem invalidates the verdict.
        if entry.fstype != caps.fstype || entry.options != caps.mount_options {
            return None;
        }
        // An unwritable-dir Inconclusive must not mask a sibling that can be
        // probed, so a different target re-probes.
        if entry.verdict == AclProbeVerdict::Inconclusive && entry.probe_dir != probe_dir {
            return None;
        }
        if entry.probed_at.elapsed() < self.ttl_for(entry.verdict) {
            Some(entry.verdict)
        } else {
            None
        }
    }

    fn store(&self, root: &str, caps: &FsCapabilities, probe_dir: &Path, verdict: AclProbeVerdict) {
        if let Ok(mut entries) = self.entries.write() {
            // Orphan sweep: entries for mounts that vanished (unmounted
            // scratch share, removed share) are never looked up again — their
            // key stops matching — so age them out here instead of letting
            // the map grow until the next config reload. 8x TTL keeps every
            // live entry (they re-store on each re-probe) while bounding the
            // dead ones; the map is small, the sweep is O(entries).
            let horizon = self.ttl * 8;
            entries.retain(|_, e| e.probed_at.elapsed() < horizon);
            entries.insert(
                root.to_string(),
                CacheEntry {
                    verdict,
                    fstype: caps.fstype.clone(),
                    options: caps.mount_options.clone(),
                    probe_dir: probe_dir.to_path_buf(),
                    probed_at: Instant::now(),
                },
            );
        }
    }
}

/// Runs Stage A: mountinfo classification from the shared snapshot, falling
/// back to a fail-safe "unknown" when no mountinfo was readable (matches the
/// probe helpers' conservative default).
fn stage_a(snap: &MountinfoSnapshot, node_path: &Path) -> (FsCapabilities, Option<String>) {
    snap.probe_with_root(node_path).unwrap_or_else(|| {
        (
            FsCapabilities {
                fstype: "unknown".into(),
                mount_options: vec![],
                acl_capable: false,
            },
            None,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn capable(fstype: &str) -> FsCapabilities {
        FsCapabilities {
            fstype: fstype.into(),
            mount_options: vec![],
            acl_capable: true,
        }
    }

    fn cache() -> AclCapabilityCache {
        AclCapabilityCache {
            entries: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(300),
        }
    }

    #[test]
    fn second_lookup_within_ttl_does_not_reprobe() {
        let c = cache();
        let caps = capable("ext4");
        let calls = Cell::new(0);
        let probe = |_: &Path| {
            calls.set(calls.get() + 1);
            AclProbeVerdict::Capable
        };
        let v1 = c.verdict_cached(&caps, Some("/m"), Path::new("/m"), false, false, probe);
        let v2 = c.verdict_cached(&caps, Some("/m"), Path::new("/m"), false, false, probe);
        assert_eq!(v1, AclProbeVerdict::Capable);
        assert_eq!(v2, AclProbeVerdict::Capable);
        assert_eq!(calls.get(), 1, "the second lookup must hit the cache");
    }

    #[test]
    fn force_refresh_always_reprobes() {
        let c = cache();
        let caps = capable("ext4");
        let calls = Cell::new(0);
        let probe = |_: &Path| {
            calls.set(calls.get() + 1);
            AclProbeVerdict::Capable
        };
        c.verdict_cached(&caps, Some("/m"), Path::new("/m"), false, false, probe);
        c.verdict_cached(&caps, Some("/m"), Path::new("/m"), false, true, probe);
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn fstype_flip_on_same_mount_invalidates() {
        let c = cache();
        let calls = Cell::new(0);
        let probe = |_: &Path| {
            calls.set(calls.get() + 1);
            AclProbeVerdict::Capable
        };
        c.verdict_cached(&capable("ext4"), Some("/m"), Path::new("/m"), false, false, probe);
        // Same mount root, different fstype (a remount) must not reuse.
        let v = c.verdict_cached(&capable("xfs"), Some("/m"), Path::new("/m"), false, false, probe);
        assert_eq!(v, AclProbeVerdict::Capable);
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn denylist_and_unknown_never_probe() {
        let c = cache();
        let calls = Cell::new(0);
        let probe = |_: &Path| {
            calls.set(calls.get() + 1);
            AclProbeVerdict::Capable
        };
        let deny = FsCapabilities {
            fstype: "vfat".into(),
            mount_options: vec![],
            acl_capable: false,
        };
        let unknown = FsCapabilities {
            fstype: "unknown".into(),
            mount_options: vec![],
            acl_capable: false,
        };
        assert_eq!(
            c.verdict_cached(&deny, Some("/m"), Path::new("/m"), false, false, probe),
            AclProbeVerdict::Incapable
        );
        assert_eq!(
            c.verdict_cached(&unknown, None, Path::new("/m"), false, false, probe),
            AclProbeVerdict::Inconclusive
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn explicit_off_skips_write_probe() {
        let c = cache();
        let calls = Cell::new(0);
        let probe = |_: &Path| {
            calls.set(calls.get() + 1);
            AclProbeVerdict::Capable
        };
        // skip_write_probe=true on a capable mount stays Inconclusive (nothing
        // to prove) and never shells out.
        let v = c.verdict_cached(&capable("ext4"), Some("/m"), Path::new("/m"), true, false, probe);
        assert_eq!(v, AclProbeVerdict::Inconclusive);
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn inconclusive_reprobes_for_a_different_dir() {
        let c = cache();
        let calls = Cell::new(0);
        let probe = |_: &Path| {
            calls.set(calls.get() + 1);
            AclProbeVerdict::Inconclusive
        };
        let caps = capable("ext4");
        c.verdict_cached(&caps, Some("/m"), Path::new("/m/a"), false, false, probe);
        // Same mount, different probe dir: a cached Inconclusive must not mask a
        // sibling that might be writable.
        c.verdict_cached(&caps, Some("/m"), Path::new("/m/b"), false, false, probe);
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn capable_without_mount_root_probes_uncached() {
        let c = cache();
        let calls = Cell::new(0);
        let probe = |_: &Path| {
            calls.set(calls.get() + 1);
            AclProbeVerdict::Capable
        };
        let caps = capable("ext4");
        c.verdict_cached(&caps, None, Path::new("/m"), false, false, probe);
        c.verdict_cached(&caps, None, Path::new("/m"), false, false, probe);
        assert_eq!(calls.get(), 2, "no mount key means no caching");
    }
}

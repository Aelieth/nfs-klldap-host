//! Two-tier hostname: hostname(1) must match /proc/sys/kernel/hostname after normalization.
//! Mismatch -> rich diagnostic (used for keytab + cert SANs).

pub use nfs_klldap_identity::{
    format_nfs_principal_list, looks_like_docker_default_hostname, nfs_keytab_host_matches,
    nfs_keytab_host_variants,
};

use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostnameSource {
    Command,
    ProcSysKernel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostnameObservation {
    pub value: String,
    pub source: HostnameSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistentHostname {
    pub hostname: String,
    pub primary: HostnameObservation,
    pub secondary: HostnameObservation,
}

#[derive(Debug, Clone)]
pub struct HostnameInconsistency {
    pub primary: Option<HostnameObservation>,
    pub secondary: Option<HostnameObservation>,
    pub reason: String,
    pub remediation: String,
    pub detected_docker_default: bool,
}

impl std::fmt::Display for HostnameInconsistency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "HOSTNAME CONSISTENCY FAILURE")?;
        writeln!(f, "{}", "=".repeat(60))?;
        writeln!(f, "{}", self.reason)?;
        writeln!(f)?;

        if let Some(p) = &self.primary {
            writeln!(f, "  Primary   (hostname command)   : {:?}", p.value)?;
        } else {
            writeln!(f, "  Primary   (hostname command)   : <unavailable>")?;
        }
        if let Some(s) = &self.secondary {
            writeln!(f, "  Secondary (/proc/sys/kernel/hostname): {:?}", s.value)?;
        } else {
            writeln!(f, "  Secondary (/proc/sys/kernel/hostname): <unavailable>")?;
        }

        if self.detected_docker_default {
            writeln!(f)?;
            writeln!(f, "  *** This looks like a Docker default container ID ***")?;
            writeln!(
                f,
                "  (8-20 hex digits, no dot). You almost certainly started"
            )?;
            writeln!(
                f,
                "  the container without --uts=host and without --hostname."
            )?;
        }

        writeln!(f)?;
        writeln!(f, "Remediation:")?;
        writeln!(f, "{}", self.remediation)?;
        writeln!(f, "{}", "=".repeat(60))?;
        Ok(())
    }
}

impl std::error::Error for HostnameInconsistency {}

fn normalize_for_comparison(h: &str) -> String {
    h.trim().trim_matches('.').to_string()
}

/// Pure core of the two-tier check. Both inputs must match after normalization.
pub(crate) fn confirm_consistent_hostname(
    primary_raw: &str,
    secondary_raw: &str,
) -> Result<String, HostnameInconsistency> {
    let primary = normalize_for_comparison(primary_raw);
    let secondary = normalize_for_comparison(secondary_raw);

    let primary_obs = HostnameObservation {
        value: primary_raw.trim().to_string(),
        source: HostnameSource::Command,
    };
    let secondary_obs = HostnameObservation {
        value: secondary_raw.trim().to_string(),
        source: HostnameSource::ProcSysKernel,
    };

    if primary.is_empty() && secondary.is_empty() {
        return Err(HostnameInconsistency {
            primary: Some(primary_obs),
            secondary: Some(secondary_obs),
            reason: "Both hostname sources returned empty values.".to_string(),
            remediation:
                "This container has no usable hostname. Pass --hostname or use --uts=host."
                    .to_string(),
            detected_docker_default: false,
        });
    }

    if primary != secondary {
        let detected = looks_like_docker_default_hostname(&primary)
            || looks_like_docker_default_hostname(&secondary);

        let reason = if detected {
            "The two hostname sources disagree. One or both returned a Docker auto-generated container ID instead of your real host name.".to_string()
        } else {
            "The two hostname sources disagree after normalization. The container's UTS namespace view is inconsistent.".to_string()
        };

        let remediation = "\
Use one of the two supported ways to give the container a stable hostname:

1. Recommended: Add --uts=host (or uts: host in compose).
   The container will then see the real hostname of the Docker host.

2. Explicit override: Add --hostname your-chosen-name when starting the
   container AND set [server] hostname = \"your-chosen-name\" in
   nfs-klldap.conf (the override takes precedence for keytab reminders).

After fixing the container invocation, restart and verify that both sources
now report the identical name in the setup wizard and WebUI logs.";

        return Err(HostnameInconsistency {
            primary: Some(primary_obs),
            secondary: Some(secondary_obs),
            reason,
            remediation: remediation.to_string(),
            detected_docker_default: detected,
        });
    }

    // Both sources agree after normalization.
    Ok(primary)
}

/// Returns hostname when `hostname(1)` and /proc/sys/kernel/hostname agree after trim/trailing-dot normalization.
pub fn get_consistent_hostname() -> Result<ConsistentHostname, HostnameInconsistency> {
    let primary = match Command::new("hostname").output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Ok(out) => {
            // Command ran but exited non-zero — still capture stdout if any
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s.is_empty() {
                return Err(HostnameInconsistency {
                    primary: None,
                    secondary: None,
                    reason: format!(
                        "`hostname` command failed with status {:?}",
                        out.status.code()
                    ),
                    remediation:
                        "Ensure the `hostname` package is installed inside the container image."
                            .to_string(),
                    detected_docker_default: false,
                });
            }
            s
        }
        Err(e) => {
            return Err(HostnameInconsistency {
                primary: None,
                secondary: None,
                reason: format!("Failed to execute `hostname` command: {}", e),
                remediation:
                    "The container image must contain the `hostname` binary (provided by the runtime image packages; see Dockerfile)."
                        .to_string(),
                detected_docker_default: false,
            });
        }
    };

    let secondary = match std::fs::read_to_string("/proc/sys/kernel/hostname") {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            return Err(HostnameInconsistency {
                primary: Some(HostnameObservation {
                    value: primary,
                    source: HostnameSource::Command,
                }),
                secondary: None,
                reason: format!("Failed to read /proc/sys/kernel/hostname: {}", e),
                remediation:
                    "This is unexpected on any modern Linux kernel. Check that /proc is mounted (it almost always is in containers)."
                        .to_string(),
                detected_docker_default: false,
            });
        }
    };

    let confirmed = confirm_consistent_hostname(&primary, &secondary)?;

    Ok(ConsistentHostname {
        hostname: confirmed,
        primary: HostnameObservation {
            value: primary,
            source: HostnameSource::Command,
        },
        secondary: HostnameObservation {
            value: secondary,
            source: HostnameSource::ProcSysKernel,
        },
    })
}

/// Test-only constructor (feeds synthetic values to the pure checker).
#[cfg(test)]
pub fn get_consistent_hostname_from_values(
    primary: &str,
    secondary: &str,
) -> Result<ConsistentHostname, HostnameInconsistency> {
    let confirmed = confirm_consistent_hostname(primary, secondary)?;

    Ok(ConsistentHostname {
        hostname: confirmed,
        primary: HostnameObservation {
            value: primary.trim().to_string(),
            source: HostnameSource::Command,
        },
        secondary: HostnameObservation {
            value: secondary.trim().to_string(),
            source: HostnameSource::ProcSysKernel,
        },
    })
}

pub(crate) mod internal {
    /// Best-effort hostname for effective_hostname() fallback (not two-tier validated).
    pub fn get() -> Result<std::ffi::OsString, std::io::Error> {
        if let Ok(h) = std::env::var("HOSTNAME") {
            return Ok(h.into());
        }
        let p = "/proc/sys/kernel/hostname";
        if let Ok(s) = std::fs::read_to_string(p) {
            return Ok(s.trim().to_string().into());
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine hostname",
        ))
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consistent_happy_path_simple_name() {
        let c = get_consistent_hostname_from_values("aurora", "aurora").unwrap();
        assert_eq!(c.hostname, "aurora");
        assert_eq!(c.primary.source, HostnameSource::Command);
        assert_eq!(c.secondary.source, HostnameSource::ProcSysKernel);
    }

    #[test]
    fn consistent_happy_path_with_dot() {
        let c =
            get_consistent_hostname_from_values("aurora.testdomain.com", "aurora.testdomain.com")
                .unwrap();
        assert_eq!(c.hostname, "aurora.testdomain.com");
    }

    #[test]
    fn consistent_after_normalization_dots() {
        // Both sides have trailing dots — should still agree
        let c = get_consistent_hostname_from_values("myserver.", "myserver.").unwrap();
        assert_eq!(c.hostname, "myserver");
    }

    #[test]
    fn inconsistency_real_vs_docker_default_id() {
        let err = get_consistent_hostname_from_values("aurora", "d81b4e782f65").unwrap_err();
        assert!(err.detected_docker_default);
        assert!(err.reason.contains("Docker auto-generated"));
        assert!(err.primary.is_some());
        assert!(err.secondary.is_some());
        let msg = err.to_string();
        assert!(msg.contains("d81b4e782f65"));
        assert!(msg.contains("--uts=host"));
    }

    #[test]
    fn inconsistency_different_real_names() {
        let err = get_consistent_hostname_from_values("aurora", "orion").unwrap_err();
        assert!(!err.detected_docker_default);
        assert!(err.reason.contains("disagree after normalization"));
    }

    #[test]
    fn inconsistency_case_difference_is_flagged() {
        // Case must match exactly for keytab principals
        let err = get_consistent_hostname_from_values("Aurora", "aurora").unwrap_err();
        assert!(err.primary.is_some());
    }

    #[test]
    fn inconsistency_both_empty() {
        let err = get_consistent_hostname_from_values("", "").unwrap_err();
        assert!(err.reason.contains("empty"));
    }

    #[test]
    fn inconsistency_one_empty() {
        let err = get_consistent_hostname_from_values("aurora", "").unwrap_err();
        assert!(err.primary.is_some());
        assert!(err.secondary.is_some());
    }

    #[test]
    fn looks_like_docker_id_still_works_standalone() {
        assert!(looks_like_docker_default_hostname("d81b4e782f65"));
        assert!(looks_like_docker_default_hostname("3c896c1c2e24"));
        assert!(!looks_like_docker_default_hostname("aurora"));
        assert!(!looks_like_docker_default_hostname("aurora.testdomain.com"));
    }

    #[test]
    fn real_get_consistent_hostname_smoke() {
        // Real I/O path smoke (succeeds or well-formed inconsistency; never panic/garbage).
        let result = get_consistent_hostname();
        match result {
            Ok(c) => {
                assert!(!c.hostname.is_empty());
                assert_eq!(c.primary.source, HostnameSource::Command);
                assert_eq!(c.secondary.source, HostnameSource::ProcSysKernel);
                // On a normal test machine the two sources must have agreed
                assert_eq!(c.primary.value, c.secondary.value);
            }
            Err(e) => {
                // Acceptable in some CI sandboxes, but the error must be rich
                assert!(!e.reason.is_empty());
                assert!(!e.remediation.is_empty());
            }
        }
    }

    #[test]
    fn consistency_returns_raw_hostname_for_keytab() {
        let c = get_consistent_hostname_from_values("aurora.test.com", "aurora.test.com").unwrap();
        assert_eq!(c.hostname, "aurora.test.com");
        assert_eq!(
            nfs_keytab_host_variants(&c.hostname),
            vec!["aurora".to_string(), "aurora.test.com".to_string()]
        );
    }
}

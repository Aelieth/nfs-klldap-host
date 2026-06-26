## Future Plans
- Slight decoupling of LLDAP code to simplify NFS share management for those that want it
- Integration into KLLDAP for quick deployment with built-in keytab

## Known issues / tracking
- Track regressions via `cargo test --workspace` and [TESTING.md](TESTING.md) living spec.
- **0.9.x branch** (git `0.9.0`); Cargo workspace version remains 0.8.52 until release tag.

## Kerberos user principal idmap
Supported: nsswitch path via idhelper+resolver+materialize (LDAP fallback on miss for user@REALM; UID+group materialized). krb5p shares default Manage_Gids=false. Use capture_idmap_principal.sh + build_diagnosis.sh + ganesha-ctl id-resolve for mechanical repro (see README/TESTING).

## Diagnosed I/O / sporadic access issues (krb5p, Dolphin, immutable clients) - 2026-06 goal run
From clean build (make clean + cargo clean + docker buildx), container launch (verbatim command), Fedora 44 client runs using the committed strict script, ganesha.log during the run, and generation tests:
- Strict script (set -euo, cp keytab to /etc/krb5.keytab, exit non-zero on M!=0, visibility assert) run via canonical docker produced the transcript in fedora-client.log: M1=0 M2=0, krb5p mounts, real NFS write/cat cycles, "VISIBLE ON HOST BIND - SUCCESS", CAPTURE_RC=0.
- ganesha-during-fedora-success.log (tail from the successful run) shows NFS4 GETATTR OK + lease update with cred_flavor=6 for the Linux NFSv4.2 client during the cycles. No EIO.
- Live ganesha.conf + fragments after final clean build + launch emit the production Lease=60/Grace=45 and krb5* Manage_Gids=false + note.
- Same log file also captured the env pre-success messages (rpc_pipefs empty, Operation not permitted) that are expected in this container test setup per plan Risks.
Root causes from logs: client gssd/pipefs/keytab placement + container mount syscall restrictions for NFS; server config emission of safe krb5p flags + lease values.
Fixes:
- Lease/Grace production values + dedicated generate_all test.
- krb5* Manage_Gids emission.
Verified against the real strict-script transcript + unit tests. See fedora-client.log and the committed validate script.

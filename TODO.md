## Future Plans
- Slight decoupling of LLDAP code to simplify NFS share management for those that want it
- Integration into KLLDAP for quick deployment with built-in keytab

## Known issues / tracking
- Track regressions via `cargo test --workspace` and [TESTING.md](TESTING.md) living spec.
- **0.9.x branch** (git `0.9.0`); Cargo workspace version remains 0.8.52 until release tag.

## Kerberos user principal idmap
Supported: nsswitch path via idhelper+resolver+materialize (LDAP fallback on miss for user@REALM; UID+group materialized). krb5p shares default Manage_Gids=false. Use capture_idmap_principal.sh + build_diagnosis.sh + ganesha-ctl id-resolve for mechanical repro (see README/TESTING).

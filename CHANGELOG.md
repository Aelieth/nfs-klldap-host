## What's New in v0.4

- Major migration: the 4-step guided first-run experience, reachability tests, banner,
  and runtime diagnostics have moved from `entrypoint.sh` into the Rust binary
  `nfs-klldap-startup` (part of the `nfs-klldap-config` crate).
- Realm is now shown in the startup banner via best-effort derivation from `ldap_uri`.
- Hostname guidance now recommends the DNS-friendly insertion pattern
  (`testpc.example.com` → `testpc-nfs.example.com`) and the TUI suggests the correct name.
- Step progress in the guided TUI now correctly marks completed steps with `[√]`.
- Documentation (READMEs, architecture docs, compose examples) updated for the new
  startup flow and hostname convention.

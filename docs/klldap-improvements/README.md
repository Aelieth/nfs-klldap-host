# LDAPS Noisy Errors from External Sync Tools ("dirsync", "keycloaksync", etc.)

## Observed Symptoms (from your logs)
- `Login attempt for "dirsync"` / `"keycloaksync"`
- `Invalid DN syntax received from client ... dn: "dirsync" | error: ... "Missing DN value"`
- `[LDAPS] Service Error: ... peer closed connection without sending TLS close_notify`

## Root Cause (from klldap source)
1. `crates/ldap/src/dn.rs:parse_distinguished_name` + `make_dn_pair`:
   - When a client sends a bare name (`"dirsync"`) instead of a full DN in a `BindRequest.dn` or as a search base, splitting produces no `=` → "Missing DN value" → `InvalidDNSyntax` + the exact WARN log you see.

2. `crates/ldap/src/password.rs:do_bind`:
   - Always calls the strict `get_user_id_from_distinguished_name` (never the tolerant `*_or_plain_name` helpers that exist elsewhere in the crate).

3. `server/src/ldap_server.rs:handle_ldap_stream` + the actix service mapper:
   - Any error (including the client dropping after getting the DN error) that reaches the `requests.next()` over a `tokio_rustls` stream surfaces the rustls "no close_notify" message.
   - This is turned into `error!("[LDAPS] Service Error: {:#}", err)`.

These clients (Keycloak LDAP sync, various "DirSync" utilities, old Directory Studio sessions, misconfigured ldapsearch) are extremely common and almost never do a clean TLS shutdown when they receive an error or decide the server is "weird".

rustls is deliberately strict about this (see the link in your logs).

## What the Patch Does
- Tolerates bare names in the Bind path (many tools are configured with just the uid as "Bind DN").
- Downgrades the expected "client was rude on disconnect" cases from ERROR to DEBUG (while still logging the session).
- Keeps the protocol strict and secure.

## How to Apply
1. `cd` into your lldap-with-kerberos checkout.
2. `patch -p1 < docs/klldap-improvements/ldaps-client-error-tolerance.patch` (or apply manually — the diffs are small and commented).
3. Rebuild + restart KLLDAP.
4. The scary `[LDAPS] Service Error` lines for these tools should largely disappear (or move to debug).

The WARN about "Invalid DN syntax" for "dirsync" will remain (that's useful signal that a tool is misconfigured), but it won't be followed by a big ERROR stack from the connection drop.

## Longer-term Recommendations for Your Environment
- Fix the Bind DN / User DN format in Keycloak LDAP federation and any "dirsync" tool to use full DNs:
  `uid=dirsync,ou=people,dc=...` (or whatever your base is).
- For tools you can't fix easily, the tolerance above is the pragmatic server-side mitigation.

This matches the spirit of the work already done in nfs-klldap-host around ignored attributes (reducing the things that provoke bad clients into dropping connections).

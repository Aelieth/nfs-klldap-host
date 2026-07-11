# Mounting from Fedora Immutable clients (Bazzite / Silverblue)

Goal: a Bazzite or Silverblue machine with a valid machine keytab and a user Kerberos TGT
mounts a share with `sec=krb5p` and sees correct owners. These are the same steps the CI
harness (`scripts/fedora-krb5p-client-validate.sh`) automates in a container, written for a
real immutable host.

## Prerequisites

- The server runs nfs-klldap-host with a keytab containing `nfs/<server-fqdn>@REALM`
  (and short-hostname variant) — see the main README.
- The client host has a machine keytab from KLLDAP containing `host/<client-fqdn>@REALM`.
- Users exist in KLLDAP with POSIX attributes (uidNumber/gidNumber).
- Use DNS hostnames everywhere. Kerberos + `ldap_uri` with raw IPs will fail.

## One-time client setup

1. **Packages.** `nfs-utils` and `keyutils` ship with Fedora; layer the Kerberos tools if
   missing:

   ```sh
   rpm-ostree install krb5-workstation   # then reboot
   ```

2. **Kerberos.** `/etc/krb5.conf` pointing at the KLLDAP KDC, and the machine keytab at
   `/etc/krb5.keytab`, mode 0600 root:root. Verify:

   ```sh
   sudo klist -k /etc/krb5.keytab        # must list host/<client-fqdn>@REALM
   sudo kinit -k                          # machine cred sanity check, then kdestroy
   ```

3. **`/etc/idmapd.conf`** — same Domain the server generates (the Kerberos realm):

   ```ini
   [General]
   Domain = EXAMPLE.COM
   Local-Realms = EXAMPLE.COM
   [Translation]
   Method = nsswitch
   GSS-Methods = nsswitch
   ```

4. **gssd user credentials** — create `/etc/nfs.conf.d/nfs-klldap.conf`:

   ```ini
   [gssd]
   use-machine-creds=0
   ```

   With machine creds forced (the default), all I/O runs as the machine principal instead
   of the logged-in user's TGT.

5. **Enable the client services:**

   ```sh
   sudo systemctl enable --now rpc-gssd nfs-client.target
   ```

6. **Numeric-owner decoding (recommended).** The server emits `Only_Numeric_Owners`, and
   Ganesha 9.6 encodes them on the wire as `nss_id + 524287`. Without a decoder `ls -l`
   shows large numeric owners (e.g. `527288` for uid 3001) — permissions still enforce
   correctly; only the display is off. Install the helper from this repo:

   ```sh
   sudo install -m 0755 scripts/nfsidmap-client-helper /usr/local/bin/
   sudo tee /etc/request-key.d/id_resolver.conf <<'EOF'
   create id_resolver * * /usr/local/bin/nfsidmap-client-helper %k %d
   negate id_resolver * * /bin/keyctl negate %k 0 %c
   EOF
   ```

   (On ostree systems `/usr/local` is writable — it lives on `/var`.)

## Mounting

```sh
kinit alice@EXAMPLE.COM     # user TGT
sudo mount -t nfs4 -o vers=4.2,sec=krb5p server.example.com:/media /var/mnt/media
```

The path after the colon is the share's **Pseudo Path** (`pseudo_path`, defaults to
`/<share-name>`), not the server filesystem path. For a persistent mount, `/etc/fstab`:

```
server.example.com:/media  /var/mnt/media  nfs4  vers=4.2,sec=krb5p,_netdev,noauto,nofail,x-systemd.automount,x-systemd.idle-timeout=60s  0 0
```

The setup script emits a fuller option set (v5.5+): `nofail` so a boot-time
failure never blocks boot; `x-systemd.idle-timeout=60` so the share
auto-unmounts after 60 s idle — the mount stays `hard` (data-safe) while in
use but is never left mounted across sleep/idle to go stale and wedge
userspace; and, on GNOME only, `x-gvfs-show,x-gvfs-name=<share>` so the share
appears (click-to-mount) in the Files sidebar. KDE/Dolphin already lists fstab
mounts, so the gvfs options are GNOME-gated.

## Troubleshooting

Run the server with `GANESHA_DEBUG=TRUE` while reproducing — the debug LOG set includes
`RPCSEC_GSS` and `NFS_V4_ACL`, so GSS rejects and ACL-path failures are visible in
`ganesha.log`.

- **Mount fails, server log shows EXCHANGE_ID / CREATE_SESSION / RECLAIM_COMPLETE all
  `NFS4_OK` then immediate DESTROY_SESSION / DESTROY_CLIENTID with no PUTROOTFH/LOOKUP.**
  Server-side Kerberos and session setup succeeded; the abort is client-side, between
  trunking discovery and reading the export root. Check, in order:
  `journalctl -u rpc-gssd` during the mount attempt, `sudo mount -vvv ...` output,
  keytab permissions (0600) and `kinit -k`, forward+reverse DNS for both hosts, and that
  `use-machine-creds=0` didn't leave the mount without any usable credential (root needs
  the machine keytab present for the mount itself).
- **`ls -l` shows six-digit numeric owners** — the `+524287` wire offset; install the
  id_resolver helper (step 6). After changing it: `sudo nfsidmap -c` to clear the keyring.
- **Everything owned by `nobody`** — idmapd `Domain` mismatch with the server realm,
  `Method=nsswitch` missing, or the user lacks POSIX attributes in KLLDAP.
- **`mount.nfs4: access denied by server`** — `sec=` doesn't match the export `SecType`
  (default krb5p), or the client's clock is skewed beyond Kerberos tolerance.
- **Sporadic I/O errors / stale handles on suspend-resume laptops** — lease/grace are
  server-tuned (lease 60, grace 90 since 0.9.81). The v5.5 `x-systemd.idle-timeout=60`
  option largely removes this by auto-unmounting idle shares so nothing is mounted
  across a suspend to go stale; if you still hit a wedged mount, `sudo umount -f -l
  /var/mnt/<share>` releases it and the next access remounts fresh. A `hard` mount held
  open across a server outage still blocks (by design, for write integrity) — that is
  what the idle-unmount avoids.

Server-side verification: `verify-ganesha.sh` inside the container; end-to-end harness:
`scripts/fedora-krb5p-client-validate.sh`.

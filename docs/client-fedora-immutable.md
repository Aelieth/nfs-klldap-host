# Mounting from Fedora Immutable clients (Bazzite / Silverblue)

**Purpose:** host-side steps so a Bazzite/Silverblue client with machine keytab + user TGT
mounts `sec=krb5p` and sees correct owners. Mirrors `scripts/fedora-krb5p-client-validate.sh`
for a real immutable host.

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
   Ganesha (`Only_Numeric_Owners`) encodes them on the wire as `nss_id + 524287`. Without a decoder `ls -l`
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
server.example.com:/media  /var/mnt/media  nfs4  users,exec,vers=4.2,sec=krb5p,_netdev,noauto,nofail,x-systemd.automount,x-gvfs-show,x-gvfs-name=media,x-gvfs-symbolic-icon=folder-remote-symbolic  0 0
```

No ACL-related mount option exists or is needed: ACL and Non-ACL shares mount
identically on NFSv4.2 (`noacl` is an NFSv3 NFSACL-sideband knob, inert here).
The share's ACL class is server-declared — the WebUI publishes it at
`GET /client-manifest.json` and setup-script v5.10 consumes it
(`--manifest URL|FILE`) for the share list and post-mount guidance.

The setup script emits a fuller option set. The pieces that matter:

- **`users,exec`** — a file-manager click (GNOME Files / KDE Dolphin) presents an
  `x-gvfs-show`/Solid entry as a mountable volume and runs `mount.nfs4` **in the
  user session**; a non-root `mount.nfs4` returns EPERM (`failed to prepare mount:
  Operation not permitted`). `users` routes the click through setuid `/bin/mount`
  so the mount runs **as root** (using the primed machine credential), while
  per-user file I/O still runs as the logged-in user via the per-uid `rpc.gssd`
  context. `exec` overrides the `noexec` that `users` implies (so home dirs on
  `/mnt/users` can execute scripts); `nosuid,nodev` stay implied (safe on a
  network mount). Any local user can then mount/unmount, but mounting grants no
  file access without a valid Kerberos TGT.
- **`nofail`** so a boot-time failure never blocks boot; **`x-systemd.automount`**
  so the share mounts on first access (as root) and CLI access works.
- **GNOME only:** `x-gvfs-show,x-gvfs-name=<share>,x-gvfs-symbolic-icon=folder-remote-symbolic`
  so the share appears in the Files sidebar as a **network resource** (network
  icon, click-to-mount), persisting regardless of mount state. A plain folder
  bookmark was rejected: Nautilus sidebar bookmark icons are not customizable, so
  a bookmark could only ever show a folder icon. KDE/Dolphin needs no gvfs options
  — see below.

**Suspend/resume (v5.7):** the mount is left up during normal use — it comes
up on first access and stays mounted. `x-systemd.idle-timeout` is **off by
default** (the `IDLE_TIMEOUT` knob): auto-unmounting an idle share made the
root-context automount *remount* fail with an NFS "not authorized to mount"
error once the machine Kerberos credential in `/tmp/krb5cc_0` had lapsed since
boot (the mount runs as root; the user's own fresh TGT is not what authorizes
it). Stale-across-sleep is instead handled by `klldap-nfs-sleep.service` (a
unit ordered around `sleep.target`): it force-unmounts the `/var/mnt` krb5
shares before suspend and re-primes the machine ticket on resume, so nothing
goes stale and the first post-resume remount authenticates cleanly.

Since v5.6 the mounts also carry **`lookupcache=all`** (the kernel default),
set by the `LOOKUPCACHE` knob at the top of the script. Earlier versions forced
`lookupcache=none` to work around Ganesha 9.6 answering GET_DIR_DELEGATION with
OP_ILLEGAL and poisoning the dentry cache (`d??????????`, errno 121). Ganesha
9.13 returns `NFS4ERR_NOTSUPP` cleanly and runs with delegations off, so caching
is safe and much faster (no per-lookup server round trip). If `d??????????` ever
reappears on a share, set `LOOKUPCACHE=none` and re-run `--fstab`.

## KDE / Dolphin

The gvfs options above are GNOME-specific; KDE needs none of them. Our entries
carry `_netdev`, so KDE's **Solid** storage layer classifies them as network
shares and lists them in Dolphin's *Remote* group automatically — navigating into
one triggers the same `x-systemd.automount` root mount. Dolphin shares GNOME's
trap: clicking its auto-listed *device* entry while the share is cold can run the
mount in the user session and fail `Operation not permitted`. The **`users`**
option (above) now covers that path too, so a cold click mounts as root. No
per-user setup or Places seeding is required.

## Troubleshooting

Run the server with `GANESHA_DEBUG=TRUE` while reproducing — the debug LOG set raises
IDMAPPER/CLIENTID/SESSIONS and NFS4/NFS_V4_ACL/DISPATCH (Ganesha 9.13 has no
`RPCSEC_GSS` log component; GSS/cred flow appears under DISPATCH) so rejects and
ACL-path failures are visible in `ganesha.log`.

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
- **Clicking the share in Files/Dolphin fails `mount.nfs4: failed to prepare mount:
  Operation not permitted` (EPERM)** — the file manager tried to mount the
  `x-gvfs-show`/Solid entry **in your user session**, and a non-root `mount.nfs4` is
  always EPERM. The fix is the **`users`** fstab option (setup script ≥ v5.8): it
  routes the click through setuid `/bin/mount` so the mount runs as root. Confirm
  the line carries it — `grep /var/mnt/<share> /etc/fstab` should show `users,exec,…`
  — and if not, re-run `sudo ./klldap-client-setup.sh -f` then reboot. This is
  distinct from *access denied by server* below, which is an authorization/credential
  failure rather than a local privilege one.
- **`mount.nfs4: access denied by server` / "not authorized to mount" on an automount
  remount** — `sec=` doesn't match the export `SecType` (default krb5p), or the client's
  clock is skewed, or (the common case for a *remount* that used to work) the root-context
  mount had no fresh machine credential: `sudo klist -c /tmp/krb5cc_0` — if empty/expired,
  `sudo systemctl start klldap-nfs-machine-creds.service` to re-prime, then retry. v5.7
  turns `x-systemd.idle-timeout` off by default precisely to stop these arbitrary remounts
  during normal use.
- **Sporadic I/O errors / stale handles on suspend-resume laptops** — lease/grace are
  server-tuned (lease 60, grace 90 since 0.9.81). v5.7's `klldap-nfs-sleep.service`
  unmounts the krb5 shares before suspend and re-primes the machine cred on resume, so
  nothing is left stale across sleep; if you still hit a wedged mount, `sudo umount -f -l
  /var/mnt/<share>` releases it and the next access remounts fresh. A `hard` mount held
  open across a server outage still blocks (by design, for write integrity).

Server-side verification: `verify-ganesha.sh` inside the container; end-to-end harness:
`scripts/fedora-krb5p-client-validate.sh`.

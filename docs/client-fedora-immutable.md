# Mounting from Fedora Immutable clients (Bazzite / Silverblue)

**Purpose:** host-side steps so a client with machine keytab + user TGT mounts `sec=krb5p` and sees correct owners. Mirrors `scripts/fedora-krb5p-client-validate.sh`.

## Prerequisites

- Server keytab: `nfs/<server-fqdn>@REALM` (+ short name) — see main README
- Client machine keytab: `host/<client-fqdn>@REALM`
- Users in KLLDAP with POSIX attributes
- DNS hostnames everywhere (no raw IPs in Kerberos / `ldap_uri`)

## One-time client setup

1. **Packages**

   ```sh
   rpm-ostree install krb5-workstation   # reboot if layered
   ```

2. **Kerberos** — `/etc/krb5.conf` + `/etc/krb5.keytab` (0600 root:root)

   ```sh
   sudo klist -k /etc/krb5.keytab        # host/<client-fqdn>@REALM
   sudo kinit -k && sudo kdestroy
   ```

3. **`/etc/idmapd.conf`** — Domain = server realm

   ```ini
   [General]
   Domain = EXAMPLE.COM
   Local-Realms = EXAMPLE.COM
   [Translation]
   Method = nsswitch
   GSS-Methods = nsswitch
   ```

4. **gssd user credentials** — `/etc/nfs.conf.d/nfs-klldap.conf`:

   ```ini
   [gssd]
   use-machine-creds=0
   ```

   Without this, I/O runs as the machine principal instead of the user TGT.

5. **Services**

   ```sh
   sudo systemctl enable --now rpc-gssd nfs-client.target
   ```

6. **Numeric-owner decoding (recommended)** — server `Only_Numeric_Owners` encodes wire ids as `nss_id + 524287`. Without a decoder, `ls -l` shows large numbers (permissions still enforce).

   ```sh
   sudo install -m 0755 scripts/nfsidmap-client-helper /usr/local/bin/
   sudo tee /etc/request-key.d/id_resolver.conf <<'EOF'
   create id_resolver * * /usr/local/bin/nfsidmap-client-helper %k %d
   negate id_resolver * * /bin/keyctl negate %k 0 %c
   EOF
   ```

## Mounting

```sh
kinit alice@EXAMPLE.COM
sudo mount -t nfs4 -o vers=4.2,sec=krb5p server.example.com:/media /var/mnt/media
```

Path after `:` is the share **Pseudo** (`pseudo_path`, default `/<name>`), not the server FS path.

```
server.example.com:/media  /var/mnt/media  nfs4  users,exec,vers=4.2,sec=krb5p,_netdev,noauto,nofail,x-systemd.automount,x-gvfs-show,x-gvfs-name=media,x-gvfs-symbolic-icon=folder-remote-symbolic  0 0
```

| Option | Why |
|--------|-----|
| `users,exec` | File-manager click runs mount as root via setuid `/bin/mount` (user-session `mount.nfs4` → EPERM). `exec` overrides `users`’s implied `noexec`. |
| `nofail` + `x-systemd.automount` | Boot never blocks; mount on first access |
| `x-gvfs-*` | GNOME sidebar network entry (KDE Solid needs none — `_netdev` is enough) |
| `lookupcache=all` | Safe on Ganesha 9.13 (delegations off). If `d??????????` appears, try `lookupcache=none`. |

No ACL mount option on NFSv4.2 — class is server-declared (`GET /client-manifest.json`).

**Suspend/resume:** prefer a sleep unit that unmounts krb5 shares and re-primes the machine ticket (`/tmp/krb5cc_0`). Leaving idle-timeout on causes remount “not authorized” when the root machine cred lapsed.

**Credential persistence (kit v5.14):** the live ccache must stay `FILE:/tmp/krb5cc_<uid>` — rpc.gssd/gssproxy `%U` templates cannot search home paths. The kit hardens it in place instead: a tmpfiles drop-in exempts `/tmp/krb5cc_*` from the stock 10-day aging (which reaped idle caches on long uptimes), SSSD auto-renews TGTs (`krb5_renew_interval`, renewable 7d), and the prime timer/resume hook syncs valid user caches into `/var/lib/gssproxy/clients/` — the persistent fallback slot already second in gssproxy's cred chain — restoring them into `/tmp` when lost. Per-user login state (log, staged site script, TGT backup) lives in `~/.ldap-login`.

## Navahi (mDNS click-mount)

Optional guest path: server `navahi_discovery` + share `navahi_insecure` advertises over mDNS. GNOME Files / Dolphin list shares with **zero** fstab setup.

- Desktop clients use **NFSv3 + AUTH_SYS only** (no Kerberos): gvfs/kio ride libnfs defaults and list exports over the MOUNT protocol. Identity is the client-asserted numeric uid/gid and traffic is unencrypted — a guest tier for read-mostly media/guest shares. Kerberized `vers=4.2,sec=krb5p` (above) remains the data path; never flag krb5-only shares.
- Adverts carry the server **FQDN** as SRV target — clients resolve it over unicast DNS (`<host>.local` only as fallback when the server identity is unqualified), so the same name serves both tiers.
- Client packages are DE-split: GNOME layers `gvfs-nfs` (its click-mount backend); KDE relies on `kio-extras` (in the Kinoite/KDE base — gvfs-nfs is never layered there); both need `nss-mdns`, `avahi-daemon`, `avahi-tools`. The client kit's `-p` detects the desktop and layers only what it uses; `.local` resolution additionally needs authselect **`with-mdns4`** (kit `-o`) — layering nss-mdns alone does nothing on authselect-managed nsswitch.
- Client firewall: `mdns` (5353/udp) must be allowed in the active firewalld zone (Workstation-family defaults allow it).
- Verify: client kit `--discovery` runs the end-to-end probe (advert SRV/port/path asserts, manifest `navahi` cross-check, mountd tcp+udp, a real `gio mount`). Manual: `avahi-browse -rt _nfs._tcp`, `showmount -e <host>`, `gio mount nfs://<host>/<pseudo>`.

## Troubleshooting

| Symptom | Check |
|---------|--------|
| EXCHANGE_ID OK then immediate DESTROY_SESSION | Client-side: `rpc-gssd` journal, keytab 0600, DNS, `use-machine-creds=0` + machine keytab for root mount |
| Six-digit owners | Install id_resolver helper; `sudo nfsidmap -c` |
| Everything `nobody` | idmapd Domain vs realm; POSIX attrs missing |
| Click-mount EPERM | fstab needs `users` (not a server auth failure) |
| “not authorized to mount” on remount | Stale `/tmp/krb5cc_0` — re-prime machine creds |
| Stale handles after sleep | Force-unmount + remount; server lease 60 / grace 90 |

Server-side: `verify-ganesha.sh` in container; harness: `scripts/fedora-krb5p-client-validate.sh`. With `GANESHA_DEBUG=TRUE`, GSS/cred flow logs under DISPATCH (no `RPCSEC_GSS` component on 9.13).

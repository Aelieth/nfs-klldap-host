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

## Navahi (mDNS click-mount)

Optional guest path: server `navahi_discovery` + share `navahi_insecure` advertises over mDNS. GNOME Files / Dolphin list shares with **zero** fstab setup.

- Desktop clients use **NFSv3 + AUTH_SYS only** (no Kerberos). Identity = client numeric uid/gid; traffic unencrypted.
- Prefer for read-mostly media/guest shares. Kerberized `vers=4.2` remains the supported full-integrity path.
- Client packages: `gvfs-nfs`, `kio-extras`, `nss-mdns`, `avahi-daemon`.
- Debug: `avahi-browse -rt _nfs._tcp`, `showmount -e <host>`.

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

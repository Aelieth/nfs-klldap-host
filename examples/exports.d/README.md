# Ganesha Export Fragments

This directory (on the host) is bind-mounted into the container at `/etc/ganesha/exports.d/`.

Place files containing one or more `EXPORT { ... }` blocks here.

The management tool writes files named like `10-myshare.conf`.

You can also drop hand-written fragments for static exports.

Example minimal fragment (`10-example.conf`):

```
EXPORT {
    Export_Id = 1001;
    Path = /export/example;
    Pseudo = /example;
    Access_Type = RW;
    SecType = krb5p;
    Protocols = 4;

    FSAL {
        Name = VFS;
    }
}
```

After adding a file, either:
- Restart the container, or
- Run: `docker exec alma-nfs-kerb ganesha-ctl add-export /etc/ganesha/exports.d/10-example.conf "EXPORT(Path=/example)"`

The `ganesha-ctl` helper (shipped in the image) is now file-based (no DBUS). It lets operators inspect and remove export fragments from inside the container. The container's `ganesha-export-watcher` automatically restarts Ganesha when fragments are added or removed.

**Note:** The old kernel-style `*.exports` files are no longer used. This project is Ganesha-only.

# nfs-perm-helper

This is a tiny, security-critical binary whose **only job** is to perform `chown` and `chmod` on behalf of the unprivileged management tool.

## Build & Install

```bash
cd priv-helper
cargo build --release
sudo cp target/release/nfs-perm-helper /usr/local/bin/
sudo chown root:root /usr/local/bin/nfs-perm-helper
sudo chmod 4755 /usr/local/bin/nfs-perm-helper   # setuid root (or use sudoers instead)
```

## Security Notes

- This binary must be **extremely small** and auditable.
- All input is validated against an allow-list of base paths.
- It refuses UID/GID 0 and dangerous permission bits.
- In production, consider using a very narrow sudoers rule instead of setuid:
  ```
  nfs-mgmt ALL=(root) NOPASSWD: /usr/local/bin/nfs-perm-helper
  ```

The main management tool (running as `nfs-mgmt` or similar) talks to this helper instead of calling chown/chmod directly.

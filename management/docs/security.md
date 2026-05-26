# Security Model for the Management Tool

The management tool has significant power: it can change ownership and permissions on host directories that are exported via NFS.

## Core Principle

**Never run the management tool as root.**

## Recommended Simple Secure Setup (Sudoers)

Run the tool as a dedicated low-privilege user (example: `nfs-mgmt`).

Create very narrow sudoers rules that only allow this user to perform the exact operations the tool needs, limited to specific paths.

### Example sudoers rules (`/etc/sudoers.d/nfs-mgmt`)

```sudoers
# Allow nfs-mgmt user to change ownership only under managed shares
nfs-mgmt ALL=(root) NOPASSWD: /usr/bin/chown [0-9]*:[0-9]* /media/SSD-01/**
nfs-mgmt ALL=(root) NOPASSWD: /usr/bin/chown [0-9]*:[0-9]* /srv/nfs/**
nfs-mgmt ALL=(root) NOPASSWD: /usr/bin/chmod [0-7]* /media/SSD-01/**
nfs-mgmt ALL=(root) NOPASSWD: /usr/bin/chmod [0-7]* /srv/nfs/**

# Optional: allow the tool to send SIGHUP to the NFS container
nfs-mgmt ALL=(root) NOPASSWD: /usr/bin/docker kill -s HUP nfs-kerb
```

### How the tool uses it

The tool never calls `chown`/`chmod` directly. Instead it does:

```rust
Command::new("sudo")
    .arg("chown")
    .arg(format!("{}:{}", uid, gid))
    .arg(path)
    .status()?;
```

This way:
- The tool itself can run as an unprivileged user.
- All dangerous operations go through the kernel's sudoers policy.
- The attack surface is limited to the whitelisted paths and commands.

## Stronger Alternative (Small Privileged Helper)

If you want even tighter control, create a tiny Rust binary (or shell script) that:

1. Only accepts a very strict input format (e.g. JSON on stdin or command line with validated paths).
2. Re-validates that the target is under an allowed root.
3. Performs the chown/chmod.
4. Is the *only* thing granted sudo rights.

The main management tool (running unprivileged) communicates with this helper.

This is more code but gives you full auditing and input sanitization in one place.

## Current Implementation Status

The skeleton in `src/fs.rs` currently uses raw `Command::new("chown")`.

The next step is to introduce a `PermissionBackend` enum (or trait) that supports:
- `Direct` (only for testing / root — not recommended in production)
- `Sudo` (the default secure path)

Configuration will specify which backend to use and the allowed base paths.

## Additional Hardening Recommendations

- Run the tool behind authentication (if web UI) or as a desktop app that requires the admin to be logged in.
- Log every permission change (who, what, old vs new ownership).
- Consider making the tool read-only by default and require an explicit "apply" step.
- Never allow the tool to manage paths outside explicitly configured roots.

This model keeps the tool simple while respecting the principle that it should not run with broad root privileges.

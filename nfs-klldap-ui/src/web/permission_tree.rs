use askama::Template;
use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect},
};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::fs::ApplyProgress;

use super::{AppState, require_auth};

type Ldap = crate::ldap::LdapClient;

/// Fallback HTML when a blocking handler task panics (JoinError) — a graceful
/// alert instead of a bodyless 500.
fn render_500(what: &str) -> String {
    format!(
        r#"<div class="alert alert-danger"><strong>Internal error rendering the {what}.</strong> Please retry.</div>"#
    )
}

/// Sets `finished` on drop so a panic in a spawned apply task can never leave
/// the /apply-progress poller waiting forever (it only stops on finished).
struct FinishOnDrop(Arc<ApplyProgress>);
impl Drop for FinishOnDrop {
    fn drop(&mut self) {
        self.0.finished.store(true, Ordering::Relaxed);
    }
}

/// True when an apply is already in flight (its progress slot exists and has not
/// finished). A COURTESY pre-check only — two requests can both pass it; the
/// authoritative gate is `try_claim_apply_slot`, whose check and write share
/// one lock scope.
async fn apply_in_progress(state: &AppState) -> bool {
    state
        .apply_progress
        .lock()
        .await
        .as_ref()
        .is_some_and(|p| !p.finished.load(Ordering::Relaxed))
}

/// Atomically claim the single apply slot for this apply's progress. False =
/// another apply's slot is live; nothing was overwritten and the caller must
/// bail without spawning. Check-then-set under separate lock acquisitions
/// (the original 0.9.94 shape) let two applies race the gap and orphan the
/// first poller.
pub(crate) async fn try_claim_apply_slot(state: &AppState, progress: &Arc<ApplyProgress>) -> bool {
    let mut slot = state.apply_progress.lock().await;
    if slot
        .as_ref()
        .is_some_and(|p| !p.finished.load(Ordering::Relaxed))
    {
        return false;
    }
    *slot = Some(progress.clone());
    true
}

const APPLY_BUSY_NOTE: &str = r#"<div class="note-danger">Another permission apply is already running — wait for it to finish before starting a new one.</div>"#;
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    shares: Vec<ShareInfo>,
    current_user: Option<String>,
    keytab_alert: Option<String>,
    /// Banner from the ACL re-probe loop: an explicit-ACL share on a filesystem
    /// that can no longer store ACLs. None hides it.
    acl_alert: Option<String>,
    /// Initial Apply Log shell rendered by apply_log_shell so oob swaps match it exactly.
    apply_log_initial: String,
}
#[derive(Template)]
#[template(path = "tree_fragment.html")]
struct TreeFragmentTemplate {
    children: Vec<EntryView>,
}
/// Share root as top tree row with direct children (includes root perms).
#[derive(Template)]
#[template(path = "tree_root.html")]
struct TreeRootTemplate {
    root: DirNode,
    children: Vec<EntryView>,
}

/// The share-root row of the tree (always a directory).
#[derive(Debug, Clone)]
pub(crate) struct DirNode {
    pub path: String,
    pub name: String,
}

/// One row in the tree listing — a subdirectory or a file (tree_entry.html).
#[derive(Debug, Clone)]
pub(crate) struct EntryView {
    pub path: String,
    pub name: String,
    pub is_dir: bool,
    /// 📁 for directories, category emoji for files (file_kind).
    pub emoji: &'static str,
    /// Hover label naming the category ("directory", "audio", …).
    pub kind_label: &'static str,
    /// "YYYY-MM-DD HH:MM" UTC for files; empty for directories.
    pub mtime: String,
    /// True when the entry carries ACLs beyond the base permissions — the
    /// `+` in `ls -l` terms. Only populated on ACL-active shares.
    pub acl_plus: bool,
}

impl EntryView {
    fn from_fs_entry(e: crate::fs::FsEntry) -> Self {
        let is_dir = matches!(e.kind, crate::fs::FsEntryKind::Dir);
        let (emoji, kind_label) = if is_dir {
            ("📁", "directory")
        } else {
            file_kind(&e.name)
        };
        Self {
            path: e.path.to_string_lossy().into_owned(),
            emoji,
            kind_label,
            mtime: e.mtime.map(format_mtime_utc).unwrap_or_default(),
            acl_plus: false,
            name: e.name,
            is_dir,
        }
    }
}

/// Category (emoji, hover label) for a file row. ASCII-case-insensitive over
/// the whole name: well-known extensionless names (READMEs, build files,
/// shell dotfiles) and a few full-name pins match first, then the extension.
/// Anything unrecognized is the honest ❔.
fn file_kind(name: &str) -> (&'static str, &'static str) {
    const TEXT: (&str, &str) = ("📄", "text / document");
    const CODE: (&str, &str) = ("📜", "script / code");
    const IMAGE: (&str, &str) = ("🖼️", "image");
    const AUDIO: (&str, &str) = ("🎵", "audio");
    const VIDEO: (&str, &str) = ("🎬", "video");
    const DISC: (&str, &str) = ("💿", "disk image");
    const SOFT: (&str, &str) = ("📦", "software / binary");
    const WIN: (&str, &str) = ("🪟", "Windows / WINE");
    const DOS: (&str, &str) = ("💾", "DOS");
    const FONT: (&str, &str) = ("🔤", "font");
    const DATA: (&str, &str) = ("🗄️", "data / archive");
    const UNKNOWN: (&str, &str) = ("❔", "unknown type");

    let lower = name.to_ascii_lowercase();
    // Full-name pins: extensionless well-knowns, plus names whose extension
    // would mislead (config.sys is DOS, not a Windows driver; go.mod is Go
    // source, not tracker music).
    match lower.as_str() {
        "readme" | "license" | "licence" | "copying" | "changelog" | "changes" | "install"
        | "authors" | "contributors" | "news" | "todo" | "notice" | "version" | ".gitignore"
        | ".gitattributes" | ".gitconfig" | ".gitmodules" | ".editorconfig" | ".dockerignore"
        | ".env" | ".npmrc" => return TEXT,
        "makefile" | "gnumakefile" | "dockerfile" | "containerfile" | "vagrantfile"
        | "jenkinsfile" | "justfile" | "rakefile" | "gemfile" | "kconfig" | ".bashrc"
        | ".zshrc" | ".profile" | ".bash_profile" | ".bash_aliases" | ".vimrc" | "go.mod"
        | "go.sum" => return CODE,
        "config.sys" => return DOS,
        _ => {}
    }
    let ext = lower
        .rsplit_once('.')
        .filter(|(stem, _)| !stem.is_empty())
        .map(|(_, e)| e);
    let Some(ext) = ext else { return UNKNOWN };
    match ext {
        // Plain text, documents, office, and structured-config formats.
        "txt" | "text" | "md" | "markdown" | "mdown" | "rst" | "adoc" | "asciidoc" | "org"
        | "tex" | "log" | "rtf" | "pdf" | "doc" | "docx" | "odt" | "odp" | "ods" | "xls"
        | "xlsx" | "ppt" | "pptx" | "epub" | "mobi" | "csv" | "tsv" | "conf" | "cfg" | "cnf"
        | "ini" | "toml" | "yaml" | "yml" | "json" | "json5" | "jsonl" | "ndjson" | "xml"
        | "xsl" | "xslt" | "man" | "po" | "pot" | "ics" | "vcf"
        // Subtitles are editable text, not video.
        | "srt" | "sub" | "vtt" | "ass" | "ssa" | "idx" | "nfo"
        // PEM/armored key material is text on disk.
        | "pem" | "crt" | "cer" | "csr" | "key" | "pub" | "asc"
        // systemd/udev/packaging config lives on Linux shares as plain text.
        | "desktop" | "service" | "timer" | "socket" | "mount" | "automount" | "target"
        | "path" | "netdev" | "network" | "link" | "swap" | "rules" | "repo" | "list"
        | "spec" | "properties" | "env" => TEXT,

        // Shell + scripting languages (pwsh is cross-platform, so ps1 lives
        // here rather than under Windows).
        "sh" | "bash" | "zsh" | "ksh" | "csh" | "tcsh" | "fish" | "ps1" | "psm1" | "py"
        | "pyw" | "pyi" | "ipynb" | "rb" | "erb" | "pl" | "pm" | "php" | "phtml" | "lua"
        | "tcl" | "awk"
        // Compiled-language sources and headers.
        | "c" | "h" | "i" | "cpp" | "cxx" | "cc" | "hpp" | "hxx" | "hh" | "m" | "mm" | "cs"
        | "java" | "jsp" | "kt" | "kts" | "scala" | "groovy" | "go" | "rs" | "swift" | "dart"
        | "zig" | "nim" | "vala" | "d" | "jl" | "r" | "rmd" | "hs" | "lhs" | "ml" | "mli"
        | "erl" | "hrl" | "ex" | "exs" | "clj" | "cljs" | "edn" | "lisp" | "el" | "scm"
        | "rkt" | "f" | "f77" | "f90" | "f95" | "for" | "asm" | "s" | "pas" | "ada" | "adb"
        | "ads" | "cob" | "cbl"
        // Web sources: markup/styles are source files, not prose (tsx is
        // TypeScript; bare .ts stays video — MPEG-TS wins on media shares).
        | "js" | "mjs" | "cjs" | "jsx" | "tsx" | "vue" | "svelte" | "html" | "htm" | "xhtml"
        | "css" | "scss" | "sass" | "less"
        // Build/query/infra languages and patches.
        | "sql" | "psql" | "cmake" | "mk" | "mak" | "m4" | "gradle" | "sbt" | "bzl" | "nix"
        | "tf" | "tfvars" | "proto" | "thrift" | "graphql" | "gql" | "patch" | "diff"
        | "vim" => CODE,

        "jpg" | "jpeg" | "jpe" | "jfif" | "png" | "apng" | "gif" | "webp" | "svg" | "svgz"
        | "bmp" | "dib" | "tif" | "tiff" | "heic" | "heif" | "avif" | "jxl" | "ico" | "icns"
        | "eps" | "psd" | "xcf" | "tga" | "exr" | "hdr" | "qoi" | "jp2" | "j2k" | "xpm"
        | "xbm" | "pbm" | "pgm" | "ppm" | "pnm" | "emf" | "wmf"
        // Camera raw formats (vendor extensions; bare .raw is a disk image).
        | "cr2" | "cr3" | "nef" | "arw" | "orf" | "rw2" | "raf" | "dng" | "pef" => IMAGE,

        // dts here is DTS surround audio (devicetree sources are a kernel-dev
        // niche); .mod is tracker music — go.mod is pinned by name above.
        "mp3" | "flac" | "ogg" | "oga" | "opus" | "wav" | "aac" | "m4a" | "m4b" | "aiff"
        | "aif" | "aifc" | "ape" | "wv" | "wma" | "mid" | "midi" | "kar" | "mka" | "amr"
        | "ra" | "ram" | "au" | "snd" | "dsf" | "dff" | "spx" | "caf" | "ac3" | "dts" | "mpa"
        | "gsm" | "mpc" | "tta"
        // Tracker/chiptune formats + playlists live with the music.
        | "mod" | "xm" | "it" | "s3m" | "sid" | "m3u" | "m3u8" | "pls" => AUDIO,

        "mp4" | "mkv" | "avi" | "mov" | "webm" | "wmv" | "m4v" | "mpg" | "mpeg" | "mpe"
        | "m1v" | "m2v" | "ts" | "m2ts" | "mts" | "vob" | "ogv" | "ogm" | "3gp" | "3g2"
        | "asf" | "rm" | "rmvb" | "divx" | "f4v" | "flv" | "mxf" | "dv" | "y4m" => VIDEO,

        // Optical/VM/filesystem images (mdf/cue/raw read as disc artifacts
        // here, not SQL-Server files or camera raws).
        "iso" | "img" | "raw" | "qcow" | "qcow2" | "qed" | "vdi" | "vhd" | "vhdx" | "vmdk"
        | "dmg" | "wim" | "nrg" | "mdf" | "mds" | "cue" | "ccd" | "toast" | "squashfs"
        | "sqsh" | "sfs" | "erofs" | "sif" | "ova" | "ovf" | "box" | "ima" | "vfd" => DISC,

        // Linux/cross-platform packages, libraries, and runnable artifacts
        // (Windows installers/binaries have their own category below).
        "deb" | "rpm" | "appimage" | "flatpak" | "flatpakref" | "snap" | "apk" | "ipa"
        | "pkg" | "so" | "ko" | "o" | "a" | "run" | "efi" | "rom" | "fw" | "jar" | "war"
        | "ear" | "whl" | "egg" | "gem" | "class" | "pyc" | "crx" | "xpi" | "vsix" => SOFT,

        // Windows/WINE artifacts. cmd/vbs/wsf are NT-era scripting; bat is
        // DOS below. sys is a Windows driver unless the name is config.sys.
        "exe" | "dll" | "msi" | "msix" | "msp" | "msu" | "lnk" | "reg" | "cpl" | "ocx"
        | "scr" | "sys" | "drv" | "inf" | "cat" | "chm" | "hlp" | "cur" | "ani" | "theme"
        | "appx" | "cab" | "cmd" | "vbs" | "wsf" => WIN,

        "com" | "bat" | "pif" => DOS,

        "ttf" | "otf" | "ttc" | "woff" | "woff2" | "eot" | "pfb" | "pfa" | "fnt" => FONT,

        // Archives, databases, and datasets (.bin stays here — too generic
        // to claim for disk images or binaries).
        "zip" | "zipx" | "tar" | "gz" | "tgz" | "bz2" | "tbz" | "tbz2" | "xz" | "txz" | "lz"
        | "lzma" | "lzo" | "lz4" | "zst" | "tzst" | "br" | "7z" | "rar" | "cpio" | "lha"
        | "lzh" | "pak" | "db" | "db3" | "sqlite" | "sqlite3" | "mdb" | "accdb" | "dbf"
        | "bak" | "dump" | "dat" | "bin" | "parquet" | "orc" | "avro" | "arrow" | "feather"
        | "h5" | "hdf5" | "nc" | "npy" | "npz" | "pkl" | "pickle" | "rds" | "rdata" | "gguf"
        | "safetensors" | "onnx" | "pt" | "pth" | "ckpt" | "torrent" => DATA,

        _ => UNKNOWN,
    }
}

/// "YYYY-MM-DD HH:MM" in UTC. Component accessors only (no `formatting`
/// feature); UTC on purpose — the time crate's local-offset lookup is
/// environment-dependent and the row tooltip discloses the zone.
fn format_mtime_utc(t: std::time::SystemTime) -> String {
    let odt = time::OffsetDateTime::from(t);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        odt.year(),
        u8::from(odt.month()),
        odt.day(),
        odt.hour(),
        odt.minute()
    )
}
/// Share card row with client NFS path and RW/squash/cache labels.
#[derive(Debug, Clone)]
struct ShareInfo {
    pub name: String,
    /// Full client NFS path, e.g. "myhost:/data" or "myhost:/exports/foo".
    pub nfs_path: String,
    pub host_path: String,
    /// Access label is either RW or RO.
    pub access: String,
    /// Squash label uses official Ganesha Squash values; unset resolves to the
    /// generator's default (root_squash) so the card never mislabels a share.
    pub squash_label: String,
    pub cache_profile: String,
    pub warning: Option<String>,
    /// Effective security, only when it deviates from `[ganesha] default_security`
    /// — the card chips render non-conformity, not the whole option set.
    pub security_chip: Option<String>,
    /// Effective Navahi exposure (global navahi_discovery AND per-share navahi_insecure):
    /// the share is advertised over mDNS and accepts insecure NFSv3/AUTH_SYS mounts.
    /// Same effective-only rule as the Settings card chip — never a raw-key echo.
    pub navahi: bool,
    /// True when the share actually serves ACLs (resolved enable_acl — explicit or
    /// auto-promoted by the live write probe — AND a capable filesystem). Same rule as
    /// the Settings rows and generate; drives the share-card status dot.
    pub acl_capable: bool,
    /// Probe verdict string ("capable"/"incapable"/"unverified") for data-acl-probed.
    pub acl_probed: &'static str,
}

/// Panel body for the detached Permissions view (POSIX matrix + ACL/xattr), served by /dir-perms.
#[derive(Template)]
#[template(path = "dir_perms.html")]
pub(crate) struct DirPermsTemplate {
    path: String,
    owner_display: String,
    group_display: String,
    owner_uid_hidden: String,
    owner_gid_hidden: String,
    mode_octal: String,
    u_r: bool, u_w: bool, u_x: bool,
    g_r: bool, g_w: bool, g_x: bool,
    o_r: bool, o_w: bool, o_x: bool,
    setgid: bool, sticky: bool,
    /// False for a regular file: full rwx triad, no special bits, no recursive apply.
    is_dir: bool,
    /// False when the directory could not be stat'd; the template shows a full-width diagnostic
    /// (meta_hint + the paths below) instead of the POSIX/ACL editors.
    meta_available: bool,
    meta_hint: String,
    /// Serve (container) path shown in the diagnostic; empty when it could not be resolved.
    serve_path_display: String,
    acl_supported: bool,
    /// Pill label: "on" (explicit), "auto" (probe-promoted), "on (unverified)", "off".
    acl_pill: String,
    /// Pill colour class: "on" (green), "warn" (amber), "off" (grey).
    acl_pill_class: &'static str,
    acl_reason: String,
    /// Tooltip detail behind the short reason.
    acl_reason_long: String,
    users: Vec<AclEntryView>,
    groups: Vec<AclEntryView>,
    /// Access-layer mask row; None when the ACL carries no extended entries.
    mask: Option<AclMaskView>,
    /// Default (inheritance) layer — directories only; empty when no default ACL.
    default_users: Vec<AclEntryView>,
    default_groups: Vec<AclEntryView>,
    default_mask: Option<AclMaskView>,
    /// True when the access ACL is extended — the POSIX Group row then edits
    /// the mask, and the template says so.
    acl_extended: bool,
    /// Extended-ACL-on-NOACL detector (gate B6/A8): the share serves without
    /// ACL support but this directory carries extended POSIX ACLs on disk,
    /// which the kernel still enforces. Renders a warn note on the panel.
    acl_disk_note: bool,
}

/// One named ACL row for the panel (friendly name already LDAP-resolved).
/// `eff_*` are the mask-capped effective permissions; `capped` marks rows
/// where the mask withholds something the entry grants (dimmed in the UI).
#[derive(Clone)]
pub(crate) struct AclEntryView {
    name: String,
    id: u32,
    r: bool,
    w: bool,
    x: bool,
    eff_r: bool,
    eff_w: bool,
    eff_x: bool,
    capped: bool,
    /// True when the id resolved to no LDAP entity — the row renders
    /// "(unknown)" beside the numeric id while `name` (and data-name on the
    /// wire) stays the bare numeric string.
    unknown: bool,
}

/// The mask row of one ACL layer (group-class cap; chmod's group bits edit
/// the same object on the access layer).
#[derive(Clone)]
pub(crate) struct AclMaskView {
    r: bool,
    w: bool,
    x: bool,
}
/// Friendly label for permission editor / meta row.
/// Shows `display (uid)` when LDAP resolves. uid/gid 0 is a first-class
/// owner on shares (root on disk = the anonymous/nobody identity NFS
/// clients see under root-squash) and is labeled "nobody (0)".
async fn friendly_user_label(lldap: &Ldap, uid: u32) -> String {
    if uid == 0 {
        return "nobody (0)".to_string();
    }
    if let Some((id, display)) = lldap.resolve_user_by_uid(uid as i32).await {
        let label = if !display.is_empty() && display != id {
            display
        } else {
            id
        };
        return format!("{} ({})", label, uid);
    }
    uid.to_string()
}
async fn friendly_group_label(lldap: &Ldap, gid: u32) -> String {
    if gid == 0 {
        return "nobody (0)".to_string();
    }
    if let Some((id, display)) = lldap.resolve_group_by_gid(gid as i32).await {
        let label = if !display.is_empty() && display != id {
            display
        } else {
            id
        };
        return format!("{} ({})", label, gid);
    }
    gid.to_string()
}
/// Bare friendly name (no trailing "(id)") for ACL rows plus an unresolved
/// flag; falls back to the numeric id. uid 0 is never flagged: root on disk
/// is a known identity (the squash/nobody owner), not a stray ACE.
async fn friendly_user_name(lldap: &Ldap, uid: u32) -> (String, bool) {
    if uid != 0 {
        if let Some((id, display)) = lldap.resolve_user_by_uid(uid as i32).await {
            let name = if !display.is_empty() && display != id { display } else { id };
            return (name, false);
        }
    }
    (uid.to_string(), uid != 0)
}
async fn friendly_group_name(lldap: &Ldap, gid: u32) -> (String, bool) {
    if gid != 0 {
        if let Some((id, display)) = lldap.resolve_group_by_gid(gid as i32).await {
            let name = if !display.is_empty() && display != id { display } else { id };
            return (name, false);
        }
    }
    (gid.to_string(), gid != 0)
}
/// Resolved ACL editor gate: whether the editor is live, the pill label and
/// its colour class, and the short/long reasons the panel shows.
pub(crate) struct AclGateView {
    pub editable: bool,
    pub pill: String,
    /// "on" (green), "warn" (amber, editable-but-unverified), "off" (grey).
    pub pill_class: &'static str,
    pub short: String,
    pub long: String,
}

/// Prefers the most specific (longest host_path) matching share so nested
/// shares stay independent.
fn best_share_for<'a>(
    cfg: &'a nfs_klldap_config::NfsKlldapConfig,
    host_path: &std::path::Path,
) -> Option<&'a nfs_klldap_config::Share> {
    cfg.shares
        .iter()
        .filter(|s| host_path.starts_with(&s.host_path) || host_path == s.host_path.as_path())
        .max_by_key(|s| s.host_path.as_os_str().len())
}

fn gate_outside_shares() -> AclGateView {
    AclGateView {
        editable: false,
        pill: "off".into(),
        pill_class: "off",
        short: "Not under a configured share.".into(),
        long: String::new(),
    }
}

/// Share-level gate for the UI (panel, tree "+" markers): classifies by the
/// share serve-root verdict alone — per share, never per directory. Explicit
/// true/false wins; unset (auto) turns ACL on only when the write probe proves
/// the serve path — same decision generate makes.
fn share_acl_gate(state: &AppState, host_path: &std::path::Path) -> AclGateView {
    let cfg = state.config.read().unwrap_or_else(|p| p.into_inner());
    let Some(s) = best_share_for(&cfg, host_path) else {
        return gate_outside_shares();
    };
    let snap =
        nfs_klldap_config::MountinfoSnapshot::capture(state.fs_probe_mountinfo_path.as_deref());
    let status = super::acl_status::share_acl_status(&state.acl_caps, &snap, &cfg, s);
    let warn = nfs_klldap_config::share_fs_warning_message_snapshot(&cfg, s, &snap)
        .unwrap_or_default();
    let join = |base: String| {
        let mut long = base;
        if !warn.is_empty() {
            long.push(' ');
            long.push_str(&warn);
        }
        long
    };
    share_level_decision(s.enable_acl, status.verdict, &join)
}

/// /acl-apply endpoint gate: the share-level decision narrowed by the SELECTED
/// node's own mount. The UI classifies strictly per share; this endpoint alone
/// re-checks the node so an ACL write can never land on a divergent
/// (ACL-incapable or unverified) submount — the server-side 422 backstop.
fn acl_apply_gate(state: &AppState, host_path: &std::path::Path) -> AclGateView {
    let cfg = state.config.read().unwrap_or_else(|p| p.into_inner());
    let Some(s) = best_share_for(&cfg, host_path) else {
        return gate_outside_shares();
    };
    let snap =
        nfs_klldap_config::MountinfoSnapshot::capture(state.fs_probe_mountinfo_path.as_deref());
    let skip = s.enable_acl == Some(false);

    // The share's effective ACL mode is decided at its serve ROOT — that is what
    // generate emits Disable_ACL from.
    let serve = std::path::PathBuf::from(cfg.serve_path_for(s));
    let root = state
        .acl_caps
        .verdict_for_snapshot(&snap, &serve, &serve, skip, false);

    // The selected node's own mount then narrows it: a vfat/ntfs child under an
    // ACL share cannot store ACLs even though the share serves them. The write
    // probe needs a directory, so file targets probe their parent.
    let node_real = {
        let fs = state.fs.read().unwrap_or_else(|p| p.into_inner());
        fs.host_path_to_container_path(host_path).ok()
    };
    let node_path = node_real.unwrap_or_else(|| serve.clone());
    let node_dir = if node_path.is_dir() {
        node_path.clone()
    } else {
        node_path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| serve.clone())
    };
    let node = state
        .acl_caps
        .verdict_for_snapshot(&snap, &node_path, &node_dir, skip, false);
    // Only a genuinely different mount can override the share decision.
    let node_verdict = if node.mount_root != root.mount_root {
        Some(node.verdict)
    } else {
        None
    };

    let warn = nfs_klldap_config::share_fs_warning_message_snapshot(&cfg, s, &snap)
        .unwrap_or_default();
    acl_capability_decision(s.enable_acl, root.verdict, node_verdict, &warn)
}

/// Pure gate decision: share-level ACL mode (from the serve-root verdict), then
/// a submount override when the selected node is on a less-capable mount.
fn acl_capability_decision(
    enable_acl: Option<bool>,
    root_verdict: nfs_klldap_config::AclProbeVerdict,
    node_verdict: Option<nfs_klldap_config::AclProbeVerdict>,
    warn: &str,
) -> AclGateView {
    use nfs_klldap_config::AclProbeVerdict as V;
    let join = |base: String| {
        let mut long = base;
        if !warn.is_empty() {
            long.push(' ');
            long.push_str(warn);
        }
        long
    };
    let base = share_level_decision(enable_acl, root_verdict, &join);
    // A capable/served share is still blocked on a child that cannot store ACLs.
    if base.editable {
        match node_verdict {
            Some(V::Incapable) => {
                return AclGateView {
                    editable: false,
                    pill: "off".into(),
                    pill_class: "off",
                    short: "This folder is on a filesystem that can't store ACLs (submount)."
                        .into(),
                    long: join(
                        "The share serves ACLs, but this subtree is a mount (vfat/ntfs or \
                         similar) that cannot hold POSIX ACLs. Editing is disabled here."
                            .into(),
                    ),
                };
            }
            Some(V::Inconclusive) => {
                return AclGateView {
                    editable: false,
                    pill: "off".into(),
                    pill_class: "off",
                    short: "This submount's ACL support is unverified.".into(),
                    long: join(
                        "The share serves ACLs, but the POSIX ACL probe on this submount was \
                         inconclusive, so editing is disabled here until it is verified."
                            .into(),
                    ),
                };
            }
            _ => {}
        }
    }
    base
}

/// Share-level decision from the serve-root verdict alone (no submount view).
fn share_level_decision(
    enable_acl: Option<bool>,
    root_verdict: nfs_klldap_config::AclProbeVerdict,
    join: &dyn Fn(String) -> String,
) -> AclGateView {
    use nfs_klldap_config::AclProbeVerdict as V;
    let off_help = "Extended ACLs already on disk still enforce kernel-side on the 9.13 build; \
                    turn ACLs on for this share to manage them here.";
    let on_view = |pill: &str| AclGateView {
        editable: true,
        pill: pill.into(),
        pill_class: "on",
        short: String::new(),
        long: String::new(),
    };
    match (enable_acl, root_verdict) {
        (Some(false), _) => AclGateView {
            editable: false,
            pill: "off".into(),
            pill_class: "off",
            short: "ACL is off for this share.".into(),
            long: join(format!("enable_acl = false in the share config. {off_help}")),
        },
        (Some(true), V::Capable) => on_view("on"),
        (None, V::Capable) => on_view("auto"),
        // Explicit ACL on an unproven mount: generate still emits the ACL export
        // (with a warning), so respect the operator's choice and let them edit.
        (Some(true), V::Inconclusive) => AclGateView {
            editable: true,
            pill: "on (unverified)".into(),
            pill_class: "warn",
            short: "ACL on — filesystem support unverified.".into(),
            long: join(
                "The POSIX ACL write probe was inconclusive, but enable_acl = true so the \
                 export serves ACLs. Verify with verify-ganesha.sh."
                    .into(),
            ),
        },
        (Some(true), _) => AclGateView {
            editable: false,
            pill: "off".into(),
            pill_class: "off",
            short: "ACL is on in config, but this filesystem can't store ACLs.".into(),
            long: join(
                "The serve path failed the POSIX ACL probe, so the next config reload will \
                 refuse to generate exports. Stage onto an ACL-capable tree (source_path) or \
                 set enable_acl = false."
                    .into(),
            ),
        },
        (None, _) => AclGateView {
            editable: false,
            pill: "off".into(),
            pill_class: "off",
            short: "ACL auto: off — filesystem support unproven.".into(),
            long: join(format!(
                "enable_acl is unset (auto): ACL turns on automatically once the serve path \
                 passes the write probe. {off_help}"
            )),
        },
    }
}

#[derive(Deserialize)]
pub(crate) struct TreeParams {
    path: String,
    #[serde(default)]
    root: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DirPermsQuery {
    path: String,
}
#[derive(Deserialize)]
pub(crate) struct SearchParams {
    /// Owner field value from hx-include live search.
    #[serde(default)]
    owner_user: Option<String>,
    /// Group field value from hx-include live search.
    #[serde(default)]
    owner_group: Option<String>,
}

impl SearchParams {
    fn user_query_raw(&self) -> Option<&str> {
        let trimmed = self.owner_user.as_deref()?.trim();
        if trimmed.is_empty() { None } else { Some(trimmed) }
    }
    fn group_query_raw(&self) -> Option<&str> {
        let trimmed = self.owner_group.as_deref()?.trim();
        if trimmed.is_empty() { None } else { Some(trimmed) }
    }
}

#[derive(Deserialize)]
pub(crate) struct ApplyForm {
    path: String,
    owner_user: String,
    owner_group: String,
    mode: String,
    /// Apply reach for directory targets: "none" | "single" | "all".
    /// File targets carry no radios; anything else means the node only.
    #[serde(default)]
    recursive_scope: String,
    /// Explicit rwx octal for files in scope (recursive scopes only).
    #[serde(default)]
    file_mode: String,
    #[serde(default)]
    owner_user_uid: String,
    #[serde(default)]
    owner_group_gid: String,
    /// Staged ACL batch from the panel: a JSON array of AclOpSpec, committed
    /// after the chown/chmod pass under the same recursive_scope. Empty means
    /// a plain POSIX apply.
    #[serde(default)]
    acl_ops: String,
}

/// One staged ACL edit from the panel's `acl_ops` batch. Ops use the
/// /acl-apply vocabulary: "set" (add-or-update an entry), "delete", "mask".
#[derive(Debug, Deserialize)]
struct AclOpSpec {
    #[serde(default)]
    op: String,
    #[serde(default)]
    typ: String,
    #[serde(default)]
    id: String,
    /// Principal name to resolve via LDAP when a numeric id is absent.
    #[serde(default)]
    name: String,
    #[serde(default)]
    perms: String,
    /// "access" (default) or "default" — the Inherit layer, directories only.
    #[serde(default)]
    layer: String,
}
#[derive(Deserialize)]
pub(crate) struct AclApplyForm {
    path: String,
    #[serde(default)]
    op: String,
    #[serde(default)]
    typ: String,
    #[serde(default)]
    id: String,
    /// Optional principal name (or "name (id)") to resolve via LDAP when a numeric id is absent.
    #[serde(default)]
    name: String,
    #[serde(default)]
    perms: String,
    #[serde(default)]
    selected: String,
    /// ACL layer: "access" (default) or "default" — default entries are what
    /// new children inherit and exist on directories only (server-refused on
    /// files).
    #[serde(default)]
    layer: String,
    /// Apply reach for directory targets: "none" | "single" | "all" — same
    /// semantics as the POSIX apply scopes. File targets are braced to none.
    #[serde(default)]
    scope: String,
}

pub(crate) async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let user = require_auth(&state, &headers).await?;
    // Each share's ACL classification can drive a write-probe subprocess; keep
    // the whole dashboard build off the async runtime.
    let html = tokio::task::spawn_blocking(move || index_html(&state, user.0))
        .await
        .unwrap_or_else(|_| render_500("dashboard"));
    Ok(Html(html))
}

fn index_html(state: &AppState, current_user: String) -> String {
    let server = &state.keytab_hostname;
    let cfg = state.config.read().unwrap_or_else(|p| p.into_inner());
    let snap =
        nfs_klldap_config::MountinfoSnapshot::capture(state.fs_probe_mountinfo_path.as_deref());
    let display_shares: Vec<ShareInfo> = cfg
        .shares
        .iter()
        .enumerate()
        .map(|(idx, s)| {
            let pseudo = nfs_klldap_config::derive_share_pseudo(s);
            let nfs_path = format!("{}:{}", server, pseudo);
            let access = if s.rw.unwrap_or(true) {
                "RW".to_string()
            } else {
                "RO".to_string()
            };
            // Unset squash means the generator default (root_squash) — resolve the
            // same way fragments.rs does so a squash-less share never grows a
            // false no_root_squash warn chip.
            let squash_label = s
                .squash
                .as_deref()
                .unwrap_or(nfs_klldap_config::GANESHA_DEFAULT_SQUASH)
                .to_string();
            let cache_profile = s
                .cache_profile
                .clone()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "Default".to_string())
                .to_lowercase();
            // Effective security mirrors the generator (per-share override, else the
            // [ganesha] default); the chip renders only the deviation. A config with
            // no [ganesha] section derives an EMPTY default_security — read that as
            // the intended krb5p default, not as "everything deviates".
            let default_security = match cfg.ganesha.default_security.trim() {
                "" => nfs_klldap_config::GANESHA_DEFAULT_SECTYPE,
                v => v,
            };
            let security_chip = s
                .security
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty() && *v != default_security)
                .map(str::to_string);

            let warning = nfs_klldap_config::ShareFieldWarning::for_share(
                &cfg.share_warnings,
                idx,
                &s.name,
            )
            .map(|w| w.display_message());
            // Same probed classification as the Settings rows: the old inline
            // `enable_acl == Some(true)` rule could never see auto promotion, so
            // every default (auto) share rendered Non-ACL here while Settings
            // showed it as ACL.
            let status = super::acl_status::share_acl_status(&state.acl_caps, &snap, &cfg, s);
            ShareInfo {
                name: s.name.clone(),
                nfs_path,
                host_path: s.host_path.display().to_string(),
                access,
                squash_label,
                cache_profile,
                warning,
                security_chip,
                navahi: cfg.navahi_discovery && s.navahi_insecure.unwrap_or(false),
                acl_capable: status.effective_acl_capable,
                acl_probed: status.probed,
            }
        })
        .collect();
    let tpl = IndexTemplate {
        shares: display_shares,
        current_user: Some(current_user),
        keytab_alert: state.keytab_alert.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        acl_alert: state.acl_alert.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        apply_log_initial: apply_log_shell(
            r#"<em class="placeholder-note">No permission applies yet.</em>"#,
            false,
            false,
            false,
        ),
    };

    tpl.render().unwrap_or_else(|_| render_500("dashboard"))
}
/// Lazy-loads one level of a directory (HTMX partial): subdirectories first,
/// then files with a type emoji and modified date.
pub(crate) async fn tree_fragment(
    State(state): State<AppState>,
    Query(params): Query<TreeParams>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;
    // list_dir stats every entry and the "+" marker shells out to getfacl in
    // batches; run the whole blocking section off the async runtime.
    let html = tokio::task::spawn_blocking(move || tree_fragment_html(&state, &params))
        .await
        .unwrap_or_else(|_| render_500("directory tree"));
    Ok(Html(html))
}

/// Blocking body of `tree_fragment`: filesystem listing, ACL "+" markers, and
/// the diagnostic fallback. Returns the rendered HTML fragment.
fn tree_fragment_html(state: &AppState, params: &TreeParams) -> String {
    let path = std::path::Path::new(&params.path);
    // Snapshot the manager out of the lock: list_dir stats O(files) and the
    // "+" marker shells a batched getfacl — neither may hold the fs lock and
    // block writers (settings save, config reload) for a subprocess lifetime.
    let fs = state.fs.read().unwrap_or_else(|p| p.into_inner()).clone();
    if let Some(entries) = fs.list_dir(path) {
        let mut children: Vec<EntryView> = entries.into_iter().map(EntryView::from_fs_entry).collect();
        // The "+" marker runs one batched getfacl per fragment and only on
        // ACL-active shares — NOACL trees pay nothing.
        if share_acl_gate(state, path).editable {
            let names: Vec<String> = children.iter().map(|c| c.name.clone()).collect();
            let extended = fs.extended_acl_names(path, &names);
            for c in &mut children {
                c.acl_plus = extended.contains(&c.name);
            }
        }
        let is_root_request = params.root.is_some();
        if is_root_request {
            let normalized = nfs_klldap_config::normalize_path(&params.path);
            let name = std::path::Path::new(&normalized)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| normalized.clone());
            let root = DirNode { path: normalized, name };
            let tpl = TreeRootTemplate { root, children };
            return tpl.render().unwrap_or_else(|_| render_500("directory tree"));
        } else {
            let tpl = TreeFragmentTemplate { children };
            return tpl.render().unwrap_or_else(|_| render_500("directory tree"));
        }
    }

    let diag = fs.diagnose_path(path);
    let safe_path = params
        .path
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let mapped = diag
        .container_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(mapping failed)".into());
    let safe_mapped = mapped
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let hint: String = if !diag.allowed {
        "Path is outside configured share <code>host_path</code> roots.".to_string()
    } else if diag.container_path.is_none() {
        "Could not map this <code>host_path</code> to a container serve path.".to_string()
    } else if !diag.container_exists {
        format!(
            "Mapped container path <code>{safe_mapped}</code> does not exist (configured serve path <code>{}</code>). \
             Set <code>container_path</code> to the real directory under <code>storage.container_root</code> and ensure the volume is mounted.",
            diag.serve_path.replace('<', "&lt;"),
        )
    } else {
        "Directory exists but could not be read (permissions?).".to_string()
    };
    format!(
        r#"<div class="alert alert-danger">
            <strong>Cannot display directory tree.</strong><br>
            Logical path: <code>{safe_path}</code><br>
            {hint}
        </div>"#
    )
}
// GET /dir-perms?path=... — panel body: POSIX (owner/group + rwx matrix + setgid/sticky) and the
// named ACL list, both LDAP-resolved. Replaces the retired /dir-meta + /dir-editor + /dir-acl trio.
pub(crate) async fn dir_perms(
    State(state): State<AppState>,
    Query(q): Query<DirPermsQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;
    let path = q.path;
    // Stat, the mountinfo/ACL gate (which can write-probe), and getfacl are all
    // blocking; gather them in one hop off the runtime. LDAP name resolution
    // below stays async (the client offloads its own blocking work).
    let bundle = {
        let state = state.clone();
        let path = path.clone();
        tokio::task::spawn_blocking(move || {
            let host = std::path::Path::new(&path);
            let (meta, diag) = {
                let fs = state.fs.read().unwrap_or_else(|p| p.into_inner());
                (fs.get_node_meta(host), fs.diagnose_path(host))
            };
            let gate = share_acl_gate(&state, host);
            let table = {
                let fs = state.fs.read().unwrap_or_else(|p| p.into_inner());
                fs.get_acl_table(host).unwrap_or_default()
            };
            (meta, diag, gate, table)
        })
        .await
    };
    let (meta, diag, gate, table) = match bundle {
        Ok(b) => b,
        Err(_) => return Ok(Html(render_500("permissions panel"))),
    };

    let mut owner_display = "(unavailable)".to_string();
    let mut group_display = "(unavailable)".to_string();
    let mut owner_uid_hidden = String::new();
    let mut owner_gid_hidden = String::new();
    let mut mode_octal = "0755".to_string();
    let (mut u_r, mut u_w, mut u_x) = (false, false, false);
    let (mut g_r, mut g_w, mut g_x) = (false, false, false);
    let (mut o_r, mut o_w, mut o_x) = (false, false, false);
    let (mut setgid, mut sticky) = (false, false);
    let mut meta_available = false;
    let mut meta_hint = String::new();
    // Directory is the default: when meta is unavailable the diagnostic branch
    // renders instead, so the flag only matters for a node that was stat'd.
    let mut is_dir = true;

    if let Some(m) = meta {
        let (owner, group, mode) = (m.uid, m.gid, m.mode);
        is_dir = m.is_dir;
        let l = state.lldap.read().await.clone();
        owner_display = friendly_user_label(&l, owner).await;
        group_display = friendly_group_label(&l, group).await;
        drop(l);
        // Always carry the numeric ids — 0 included — so a root/nobody-owned
        // directory round-trips as 0:0 instead of decaying to "unset".
        owner_uid_hidden = owner.to_string();
        owner_gid_hidden = group.to_string();
        mode_octal = format!("{:04o}", mode & 0o7777);
        u_r = mode & 0o400 != 0; u_w = mode & 0o200 != 0; u_x = mode & 0o100 != 0;
        g_r = mode & 0o040 != 0; g_w = mode & 0o020 != 0; g_x = mode & 0o010 != 0;
        o_r = mode & 0o004 != 0; o_w = mode & 0o002 != 0; o_x = mode & 0o001 != 0;
        setgid = mode & 0o2000 != 0; sticky = mode & 0o1000 != 0;
        meta_available = true;
    } else {
        // Askama escapes {{ meta_hint }}, so keep it plain text (no manual HTML escaping).
        // Cover the distinct failure modes so the message names a cause and a fix; the paths
        // themselves are shown separately (host path + serve path) by the template.
        meta_hint = if !diag.allowed {
            "This directory is outside the managed share roots, so its permissions can't be read here.".to_string()
        } else if diag.container_path.is_none() {
            "This host path couldn't be mapped to a serve path. Check the share's host_path and container_path in System Settings.".to_string()
        } else if !diag.container_exists {
            "The serve path below doesn't exist. Create it, or set the share's container_path to the directory where this share is bind-mounted.".to_string()
        } else {
            "The serve path below exists, but its ownership and mode couldn't be read — the WebUI may lack permission to stat it.".to_string()
        };
    }

    // Panel state is the share-level classification; only /acl-apply re-checks
    // the selected node's own mount (422 backstop on divergent submounts).
    let acl_supported = gate.editable;
    let acl_pill = gate.pill;
    let acl_pill_class = gate.pill_class;
    let acl_reason = gate.short;
    let acl_reason_long = gate.long;

    // The full ACL table is always listed (resolved to friendly names); the
    // section greys when unsupported. Effective perms come from the layer's
    // mask so the rows show what actually applies, not just what's granted.
    let mut users: Vec<AclEntryView> = Vec::new();
    let mut groups: Vec<AclEntryView> = Vec::new();
    let mut default_users: Vec<AclEntryView> = Vec::new();
    let mut default_groups: Vec<AclEntryView> = Vec::new();
    {
        let l = state.lldap.read().await.clone();
        for (default, line) in table
            .access
            .iter()
            .map(|e| (false, e))
            .chain(table.default.iter().map(|e| (true, e)))
        {
            let eff = table.effective_perms(line, default);
            let capped = eff != line.perms;
            match line.tag {
                crate::privileged::AclTag::NamedUser(uid) => {
                    let (name, unknown) = friendly_user_name(&l, uid).await;
                    let view = AclEntryView {
                        name,
                        id: uid,
                        r: line.perms.r, w: line.perms.w, x: line.perms.x,
                        eff_r: eff.r, eff_w: eff.w, eff_x: eff.x,
                        capped,
                        unknown,
                    };
                    if default { default_users.push(view) } else { users.push(view) }
                }
                crate::privileged::AclTag::NamedGroup(gid) => {
                    let (name, unknown) = friendly_group_name(&l, gid).await;
                    let view = AclEntryView {
                        name,
                        id: gid,
                        r: line.perms.r, w: line.perms.w, x: line.perms.x,
                        eff_r: eff.r, eff_w: eff.w, eff_x: eff.x,
                        capped,
                        unknown,
                    };
                    if default { default_groups.push(view) } else { groups.push(view) }
                }
                // Base entries stay in the POSIX matrix above; the mask rows
                // are pulled out below.
                _ => {}
            }
        }
    }
    let mask = table.mask_of(false).map(|m| AclMaskView { r: m.r, w: m.w, x: m.x });
    let default_mask = table.mask_of(true).map(|m| AclMaskView { r: m.r, w: m.w, x: m.x });
    let acl_extended = table.is_extended();
    // is_extended() covers named entries, a bare mask, and default-only trees —
    // default entries keep shaping newborn files on a NOACL share, so they count.
    let acl_disk_note = !acl_supported && acl_extended;

    let tpl = DirPermsTemplate {
        path,
        owner_display,
        group_display,
        owner_uid_hidden,
        owner_gid_hidden,
        mode_octal,
        u_r, u_w, u_x, g_r, g_w, g_x, o_r, o_w, o_x,
        setgid, sticky,
        is_dir,
        meta_available,
        meta_hint,
        serve_path_display: diag
            .container_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| diag.serve_path.clone()),
        acl_supported,
        acl_pill,
        acl_pill_class,
        acl_reason,
        acl_reason_long,
        users,
        groups,
        mask,
        default_users,
        default_groups,
        default_mask,
        acl_extended,
        acl_disk_note,
    };
    // This render runs on the async handler (not behind a spawn_blocking join
    // like index/tree), so a template error must degrade, not panic the task.
    Ok(Html(
        tpl.render().unwrap_or_else(|_| render_500("permissions panel")),
    ))
}
/// True when the owner/group query should offer the synthetic "nobody (0)"
/// row. uid/gid 0 is not an LDAP entity but is a first-class share owner
/// (root on disk = the anonymous squash identity NFS clients see), so the
/// search must be able to surface it — including while LLDAP is down.
fn nobody_suggestion_matches(raw_query: Option<&str>) -> bool {
    let q = crate::ldap::LdapClient::normalize_editor_search_query(raw_query)
        .unwrap_or_default()
        .to_lowercase();
    q.is_empty() || "nobody".contains(&q) || "root".contains(&q) || q == "0"
}

fn nobody_user_suggestion() -> &'static str {
    r#"<div class="suggestion" data-user-id="nobody" data-uid="0">nobody (UID 0)</div>"#
}

fn nobody_group_suggestion() -> &'static str {
    r#"<div class="suggestion" data-group-id="nobody" data-gid="0">nobody (GID 0)</div>"#
}

pub(crate) async fn search_users(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return Html("<div class=\"suggestion\">Unauthorized</div>".to_string());
    }

    let mut html = String::new();
    if nobody_suggestion_matches(params.user_query_raw()) {
        html.push_str(nobody_user_suggestion());
    }
    let lldap = state.lldap.read().await.clone();
    // None = LDAP unavailable (unreachable / no service creds); Some(vec![]) = no match.
    let Some(users) = lldap.list_users(params.user_query_raw()).await else {
        html.push_str(r#"<div class="suggestion sugg-note">LLDAP search unavailable (server unreachable or service credentials not configured)</div>"#);
        return Html(html);
    };
    for user in users.into_iter().filter(|u| u.uid_number.is_some()) {
        let uid = user.uid_number.unwrap_or(0);
        let name = user.display_name.unwrap_or(user.id.clone());
        let safe_id = user.id.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        let safe_name = name.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
        let label = format!("{} (UID {})", safe_name, uid);
        html.push_str(&format!(
            r#"<div class="suggestion" data-user-id="{}" data-uid="{}">{}</div>"#,
            safe_id, uid, label
        ));
    }
    if html.is_empty() {
        html = r#"<div class="suggestion sugg-note">No matches found in LLDAP</div>"#.to_string();
    }
    Html(html)
}

pub(crate) async fn search_groups(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return Html("<div class=\"suggestion\">Unauthorized</div>".to_string());
    }
    let mut html = String::new();
    if nobody_suggestion_matches(params.group_query_raw()) {
        html.push_str(nobody_group_suggestion());
    }
    let lldap = state.lldap.read().await.clone();
    let Some(groups) = lldap.list_groups(params.group_query_raw()).await else {
        html.push_str(r#"<div class="suggestion sugg-note">LLDAP search unavailable (server unreachable or service credentials not configured)</div>"#);
        return Html(html);
    };

    for group in groups.into_iter().filter(|g| g.gid_number.is_some()) {
        let gid = group.gid_number.unwrap_or(0);
        let name = group.display_name.unwrap_or(group.id.clone());
        let safe_id = group.id.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        let safe_name = name.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
        let label = format!("{} (GID {})", safe_name, gid);
        html.push_str(&format!(
            r#"<div class="suggestion" data-group-id="{}" data-gid="{}">{}</div>"#,
            safe_id, gid, label
        ));
    }
    if html.is_empty() {
        html = r#"<div class="suggestion sugg-note">No matches found in LLDAP</div>"#.to_string();
    }
    Html(html)
}

/// Inline panel alert for a failed LDAP owner/group resolution, with a Retry
/// button that reloads the /dir-perms fragment. `kind` is "user" or "group".
fn ldap_resolve_failure_alert(kind: &str, name: &str, path: &str) -> String {
    let safe_name = name
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!(
        r##"<div class="alert alert-danger alert-compact">
                            Could not find {kind} <strong>{safe_name}</strong> in LLDAP (or invalid number).
                            <button type="button" hx-get="/dir-perms?path={path}" hx-target="#perm-panel .perm-body" hx-swap="innerHTML">Retry</button>
                        </div>"##,
        path = urlencoding::encode(path)
    )
}

pub(crate) async fn apply_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ApplyForm>,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;
    // One apply at a time: a second concurrent apply would clobber the single
    // progress slot and orphan the first apply's poller.
    if apply_in_progress(&state).await {
        return Ok(Html(APPLY_BUSY_NOTE.to_string()));
    }
    // Option-based resolution — uid/gid 0 (root on disk, the nobody/anonymous
    // identity NFS clients see under root-squash) is a first-class owner.
    // None = the field was left untouched, which keeps the current owner;
    // there is deliberately no default-uid fallback (a 0-sentinel here used
    // to silently rewrite 0:0 and unresolved names to 1000:1000).
    let mut owner_uid: Option<u32> = None;
    let mut group_gid: Option<u32> = None;
    // Typed values may arrive as "Display (3002)" / "nobody (0)" fragments;
    // normalize to the numeric part (or bare name) before interpreting.
    let typed_user = crate::ldap::LdapClient::normalize_editor_search_query(Some(&form.owner_user));
    let typed_group = crate::ldap::LdapClient::normalize_editor_search_query(Some(&form.owner_group));
    let name_is_zero = |s: &str| s.eq_ignore_ascii_case("nobody") || s.eq_ignore_ascii_case("root");

    let mut needs_lock = false;
    if let Ok(n) = form.owner_user_uid.trim().parse::<u32>() {
        owner_uid = Some(n);
    } else if let Some(t) = typed_user.as_deref() {
        if let Ok(n) = t.parse::<u32>() {
            owner_uid = Some(n);
        } else if name_is_zero(t) {
            owner_uid = Some(0);
        } else {
            needs_lock = true;
        }
    }
    if let Ok(n) = form.owner_group_gid.trim().parse::<u32>() {
        group_gid = Some(n);
    } else if let Some(t) = typed_group.as_deref() {
        if let Ok(n) = t.parse::<u32>() {
            group_gid = Some(n);
        } else if name_is_zero(t) {
            group_gid = Some(0);
        } else {
            needs_lock = true;
        }
    }
    if needs_lock {
        let lldap = state.lldap.read().await.clone();
        if owner_uid.is_none() && typed_user.is_some() {
            match lldap.resolve_user(&form.owner_user).await {
                Some((uid, _)) => owner_uid = Some(uid as u32),
                None => {
                    return Ok(Html(ldap_resolve_failure_alert(
                        "user",
                        &form.owner_user,
                        &form.path,
                    )));
                }
            }
        }
        if group_gid.is_none() && typed_group.is_some() {
            match lldap.resolve_group(&form.owner_group).await {
                Some((gid, _)) => group_gid = Some(gid as u32),
                None => {
                    return Ok(Html(ldap_resolve_failure_alert(
                        "group",
                        &form.owner_group,
                        &form.path,
                    )));
                }
            }
        }
    }
    // Untouched fields keep the directory's current ownership.
    if owner_uid.is_none() || group_gid.is_none() {
        let meta = {
            let fs = state.fs.read().unwrap_or_else(|p| p.into_inner());
            fs.get_dir_meta(std::path::Path::new(&form.path))
        };
        match meta {
            Some((cur_uid, cur_gid, _)) => {
                owner_uid = owner_uid.or(Some(cur_uid));
                group_gid = group_gid.or(Some(cur_gid));
            }
            None => {
                return Ok(Html(
                    r#"<div class="note-danger">Owner/group left blank and the directory's current ownership could not be read — nothing was changed.</div>"#
                        .to_string(),
                ));
            }
        }
    }
    let (owner_uid, group_gid) = (owner_uid.unwrap(), group_gid.unwrap());
    let mode = u32::from_str_radix(&form.mode, 8).unwrap_or(0o770);
    // A file target never recurses and never gets the fused-directory advisory.
    // The file panel exposes no scope radios; this is the server-side belt for
    // hand-crafted POSTs.
    let target_is_file = {
        let fs = state.fs.read().unwrap_or_else(|p| p.into_inner());
        fs.get_node_meta(std::path::Path::new(&form.path))
            .map(|m| !m.is_dir)
            .unwrap_or(false)
    };
    let scope = if target_is_file {
        crate::fs::ApplyScope::DirOnly
    } else {
        match form.recursive_scope.as_str() {
            "all" => crate::fs::ApplyScope::All,
            "single" => crate::fs::ApplyScope::ImmediateFiles,
            _ => crate::fs::ApplyScope::DirOnly,
        }
    };
    // Files in a recursive scope get the explicit File-options bits; a missing
    // or malformed value falls back to the directory's r/w without execute
    // (the safe default). Special bits never belong on files.
    let file_mode = if scope != crate::fs::ApplyScope::DirOnly {
        let fm = u32::from_str_radix(&form.file_mode, 8).unwrap_or(mode & 0o666);
        if fm & !0o777 != 0 {
            return Ok(Html(
                r#"<div class="note-danger">File mode may only contain read/write/execute bits — special bits (setuid/setgid/sticky) are not allowed on files; nothing was changed.</div>"#
                    .to_string(),
            ));
        }
        Some(fm)
    } else {
        None
    };
    // Staged ACL batch: parsed, capability-gated, and LDAP-resolved BEFORE any
    // mutation, so a bad op rejects the whole apply — chown/chmod included.
    // Each prepared op carries (dir spec, literal file spec, log line, label).
    let mut acl_batch: Vec<(
        crate::privileged::AclModification,
        crate::privileged::AclModification,
        String,
        String,
    )> = Vec::new();
    if !form.acl_ops.trim().is_empty() {
        let specs: Vec<AclOpSpec> = match serde_json::from_str(form.acl_ops.trim()) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Html(
                    r#"<div class="note-danger">Staged ACL edits could not be parsed — nothing was changed.</div>"#
                        .to_string(),
                ));
            }
        };
        if !specs.is_empty() {
            // Same server-side backstop as /acl-apply: NOACL/incapable paths
            // refuse ACL mutations outright, probed on the node's own mount —
            // a stale panel or hand-built POST can never smuggle ACL writes
            // into a POSIX apply.
            let gate = acl_apply_gate(&state, std::path::Path::new(&form.path));
            if !gate.editable {
                return Ok(Html(format!(
                    r#"<div class="note-danger">ACL editing is not available here: {} — nothing was changed.</div>"#,
                    gate.short.replace('<', "&lt;").replace('>', "&gt;")
                )));
            }
        }
        for spec in specs {
            let op = spec.op.trim().to_lowercase();
            let is_user = {
                let t = spec.typ.trim().to_lowercase();
                t == "user" || t == "u"
            };
            let default_layer = spec.layer.trim().eq_ignore_ascii_case("default");
            if default_layer && target_is_file {
                return Ok(Html(
                    r#"<div class="note-danger">Default (inheritance) ACL entries apply to directories only — nothing was changed.</div>"#
                        .to_string(),
                ));
            }
            // Principal resolution mirrors /acl-apply: numeric id wins, then
            // the typed name via LDAP; the mask op has no principal at all.
            let mut id: u32 = spec.id.trim().parse().unwrap_or(0);
            if id == 0 && op != "mask" && !spec.name.trim().is_empty() {
                if let Some(stripped) =
                    crate::ldap::LdapClient::normalize_editor_search_query(Some(&spec.name))
                {
                    let lldap = state.lldap.read().await.clone();
                    if let Ok(n) = stripped.parse::<u32>() {
                        id = n;
                    } else if is_user {
                        if let Some((uid, _)) = lldap.resolve_user(&stripped).await {
                            id = uid as u32;
                        }
                    } else if let Some((gid, _)) = lldap.resolve_group(&stripped).await {
                        id = gid as u32;
                    }
                }
            }
            if id == 0 && op != "mask" {
                let safe_name = spec
                    .name
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
                    .replace('"', "&quot;");
                return Ok(Html(format!(
                    r#"<div class="note-danger">Could not resolve ACL principal "{}" (unknown name or invalid id) — nothing was changed.</div>"#,
                    safe_name
                )));
            }
            let Some((modification, file_modification, op_cmd)) = build_acl_modification(
                AclOpInput {
                    op: &op,
                    is_user,
                    id,
                    delete_kinds: vec![],
                    perms: &spec.perms,
                    default_layer,
                },
                !target_is_file,
                &form.path,
            ) else {
                return Ok(Html(
                    r#"<div class="note-danger">Unknown op in the staged ACL batch — nothing was changed.</div>"#
                        .to_string(),
                ));
            };
            acl_batch.push((modification, file_modification, op_cmd, op));
        }
    }
    // Directories are normalized r-implies-x at apply time (fs.rs) — an
    // r-without-x directory lists as EMPTY over NFS, so for directories the
    // two bits are one concept. Surface the normalization in the apply log.
    let dir_mode = crate::fs::dir_mode_r_implies_x(mode);
    let mode_warning = (!target_is_file && dir_mode != mode).then(|| {
        format!(
            "note: the directory mode applies as {dir_mode:o} — read implies execute on directories (r-without-x lists as empty over NFS)"
        )
    });
    let cmd = if target_is_file {
        format!(
            "chown {uid}:{gid} {path}\nchmod {mode:o} {path}",
            uid = owner_uid,
            gid = group_gid,
            path = form.path,
            mode = mode
        )
    } else {
        match scope {
            crate::fs::ApplyScope::All => format!(
                "chown {uid}:{gid} -R {path}\nchmod -R dirs={mode:o} files={fm:o} {path}",
                uid = owner_uid,
                gid = group_gid,
                path = form.path,
                mode = mode,
                fm = file_mode.unwrap_or(mode & 0o666)
            ),
            crate::fs::ApplyScope::ImmediateFiles => format!(
                "chown {uid}:{gid} {path} (+ files directly inside)\nchmod dirs={mode:o} files={fm:o} {path} (single directory)",
                uid = owner_uid,
                gid = group_gid,
                path = form.path,
                mode = mode,
                fm = file_mode.unwrap_or(mode & 0o666)
            ),
            crate::fs::ApplyScope::DirOnly => format!(
                "chown {uid}:{gid} {path}\nchmod {mode:o} {path} (directory only)",
                uid = owner_uid,
                gid = group_gid,
                path = form.path,
                mode = mode
            ),
        }
    };
    let cmd = match mode_warning {
        Some(w) => format!("{cmd}\n{w}"),
        None => cmd,
    };
    // The staged setfacl lines land in the Apply Log alongside chown/chmod;
    // recursive reaches name the literal file spec like /acl-apply does.
    let cmd = if acl_batch.is_empty() {
        cmd
    } else {
        let scope_name = match scope {
            crate::fs::ApplyScope::All => "all",
            crate::fs::ApplyScope::ImmediateFiles => "single",
            crate::fs::ApplyScope::DirOnly => "none",
        };
        let lines: Vec<String> = acl_batch
            .iter()
            .map(|(_, file_modf, op_cmd, _)| {
                if scope == crate::fs::ApplyScope::DirOnly {
                    op_cmd.clone()
                } else if let crate::privileged::AclModification::Set { perms, .. } = file_modf {
                    format!("{} [scope: {}, files: {}]", op_cmd, scope_name, perms.to_str())
                } else {
                    format!("{} [scope: {}]", op_cmd, scope_name)
                }
            })
            .collect();
        format!("{cmd}\n{}", lines.join("\n"))
    };
    let progress = Arc::new(ApplyProgress::default());
    if !try_claim_apply_slot(&state, &progress).await {
        return Ok(Html(APPLY_BUSY_NOTE.to_string()));
    }
    {
        let mut c = progress.cmd.lock().unwrap_or_else(|p| p.into_inner());
        *c = Some(cmd.clone());
    }
    let fs = state.fs.read().unwrap_or_else(|p| p.into_inner()).clone();
    let pth = form.path.clone();
    let uid = owner_uid;
    let gid = group_gid;
    let sc = scope;
    let spec = crate::fs::ApplySpec { mode, scope, file_mode };
    let prog = progress.clone();
    tokio::spawn(async move {
        // Guarantees the poller is released even if the task panics mid-apply.
        let _finish = FinishOnDrop(prog.clone());
        *prog.phase.lock().unwrap_or_else(|p| p.into_inner()) = "scanning".to_string();
        let pth1 = pth.clone();
        let fs1 = fs.clone();
        let prog1 = prog.clone();
        let count_res = tokio::task::spawn_blocking(move || {
            fs1.count_applicable_with_live(std::path::Path::new(&pth1), sc, &prog1)
        }).await;
        match count_res {
            Ok(Ok(_)) | Ok(Err(_)) => { /* count fn itself pushes errors to progress on problems */ }
            Err(_) => {
                prog.finished.store(true, Ordering::Relaxed);
                return;
            }
        }
        let total = prog.processed.load(Ordering::Relaxed);
        prog.total.store(total, Ordering::Relaxed);
        prog.processed.store(0, Ordering::Relaxed);
        *prog.phase.lock().unwrap_or_else(|p| p.into_inner()) = "applying".to_string();

        let pth2 = pth.clone();
        let fs2 = fs.clone();
        let prog2 = prog.clone();
        let apply_res = match tokio::task::spawn_blocking(move || {
            fs2.apply_permissions_with_progress(std::path::Path::new(&pth2), uid, gid, spec, &prog2)
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                prog.error_count.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut errs) = prog.recent_errors.lock() {
                    errs.push((PathBuf::from(&pth), e.clone()));
                }
                let err_text = format!("Apply error during walk: {}", e);
                *prog.final_result_text.lock().unwrap_or_else(|p| p.into_inner()) = Some(err_text);
                prog.finished.store(true, Ordering::Relaxed);
                return;
            }
            Err(_e) => {
                prog.finished.store(true, Ordering::Relaxed);
                return;
            }
        };
        // No server-side invalidation to trigger post-apply: Ganesha 9.13 has
        // no DBus attribute purge; change visibility rides the per-export
        // Attr_Expiration_Time window (docs/ganesha-architecture.md).
        let mut rtext = format!(
            "Result: {} changed, {} skipped, {} errors",
            apply_res.changed, apply_res.skipped, apply_res.errors.len()
        );
        if prog.cancelled.load(Ordering::Relaxed) {
            let last = prog.last_path.lock().unwrap_or_else(|p| p.into_inner()).clone().unwrap_or_else(|| pth.clone());
            rtext = format!("CANCELLED after {}\n{}", last, rtext);
        }
        if !apply_res.errors.is_empty() {
            rtext.push_str("\n\nErrors:\n");
            for (pp, msg) in apply_res.errors.iter().take(5) {
                rtext.push_str(&format!("  {} — {}\n", pp.display(), msg));
            }
            if apply_res.errors.len() > 5 {
                rtext.push_str(&format!("  ... and {} more\n", apply_res.errors.len() - 5));
            }
        }
        if apply_res.skipped > 0 {
            rtext.push_str("\n(skipped entries were typically symlinks — never followed for safety)");
        }
        // Requirement: the panel shows disk truth after apply, so when the
        // r-implies-x fuse changed what landed vs what was requested, say so
        // per directory (capped list; the count covers the rest).
        if apply_res.fused_dir_count > 0 {
            rtext.push('\n');
            for pp in &apply_res.fused_dirs {
                rtext.push_str(&format!(
                    "\nDirectory {} set with {:o} to allow traversal (read implies execute on directories).",
                    pp.display(),
                    dir_mode & 0o7777
                ));
            }
            let more = apply_res.fused_dir_count - apply_res.fused_dirs.len();
            if more > 0 {
                rtext.push_str(&format!("\n… and {} more directories.", more));
            }
        }
        // Staged ACL batch: runs after the POSIX pass under the same scope
        // (the hard-error walk paths above return before reaching it). A
        // cancel skips it; a failing op stops the rest — the panel reloads
        // getfacl truth afterwards either way, never optimistic state.
        if !acl_batch.is_empty() {
            if prog.cancelled.load(Ordering::Relaxed) {
                rtext.push_str("\n\nStaged ACL edits skipped (apply cancelled).");
            } else {
                let total_ops = acl_batch.len();
                for (i, (modf, file_modf, _op_cmd, op_label)) in acl_batch.into_iter().enumerate() {
                    if prog.cancelled.load(Ordering::Relaxed) {
                        rtext.push_str(&format!(
                            "\nACL batch CANCELLED — {} of {} ops not applied.",
                            total_ops - i,
                            total_ops
                        ));
                        break;
                    }
                    *prog.phase.lock().unwrap_or_else(|p| p.into_inner()) =
                        format!("applying ACLs ({}/{})", i + 1, total_ops);
                    // The dir/file modification pair differs exactly when the
                    // r-implies-x fuse fired on this op; name it in the log so
                    // the refreshed panel (disk truth) is explained.
                    let fusion_note = match (&modf, &file_modf) {
                        (
                            crate::privileged::AclModification::Set { perms: d, .. },
                            crate::privileged::AclModification::Set { perms: f, .. },
                        ) if d != f => Some(format!(
                            " — directories fused to {} for traversal",
                            d.to_str()
                        )),
                        (
                            crate::privileged::AclModification::SetMask { perms: d, .. },
                            crate::privileged::AclModification::SetMask { perms: f, .. },
                        ) if d != f => Some(format!(
                            " — directory mask fused to {} for traversal",
                            d.to_str()
                        )),
                        _ => None,
                    };
                    let (op_ok, op_note) = if sc == crate::fs::ApplyScope::DirOnly {
                        let fs3 = fs.clone();
                        let pth3 = pth.clone();
                        let r = tokio::task::spawn_blocking(move || {
                            fs3.apply_acl_mod(std::path::Path::new(&pth3), modf)
                        })
                        .await
                        .unwrap_or_else(|e| Err(format!("apply task failed: {e}")));
                        match r {
                            Ok(m) => (true, m),
                            Err(e) => (false, e),
                        }
                    } else {
                        // Count-then-apply per op — the same two-phase shape as
                        // /acl-apply's scoped branch.
                        let scan = {
                            let fs3 = fs.clone();
                            let pth3 = pth.clone();
                            let m3 = modf.clone();
                            let prog3 = prog.clone();
                            tokio::task::spawn_blocking(move || {
                                fs3.count_acl_applicable_with_live(
                                    std::path::Path::new(&pth3),
                                    &m3,
                                    sc,
                                    &prog3,
                                )
                            })
                            .await
                        };
                        match scan {
                            Ok(Ok(n)) => {
                                prog.total.store(n, Ordering::Relaxed);
                                prog.processed.store(0, Ordering::Relaxed);
                                let fs3 = fs.clone();
                                let pth3 = pth.clone();
                                let m3 = modf.clone();
                                let f3 = file_modf.clone();
                                let prog3 = prog.clone();
                                let applied = tokio::task::spawn_blocking(move || {
                                    fs3.apply_acl_with_progress(
                                        std::path::Path::new(&pth3),
                                        &m3,
                                        &f3,
                                        sc,
                                        &prog3,
                                    )
                                })
                                .await;
                                match applied {
                                    Ok(Ok(res)) => {
                                        let ok = res.errors.is_empty();
                                        let mut note =
                                            format!("{} changed, {} skipped", res.changed, res.skipped);
                                        if !ok {
                                            note.push_str(&format!(
                                                ", {} errors (first: {})",
                                                res.errors.len(),
                                                res.errors[0].1
                                            ));
                                        }
                                        (ok, note)
                                    }
                                    Ok(Err(e)) => (false, e),
                                    Err(e) => (false, format!("apply task failed: {e}")),
                                }
                            }
                            Ok(Err(e)) => (false, format!("scan failed: {e}")),
                            Err(e) => (false, format!("scan task failed: {e}")),
                        }
                    };
                    if op_ok {
                        rtext.push_str(&format!(
                            "\nACL {} ({}/{}) OK: {}{}",
                            op_label,
                            i + 1,
                            total_ops,
                            op_note,
                            fusion_note.as_deref().unwrap_or("")
                        ));
                    } else {
                        prog.error_count.fetch_add(1, Ordering::Relaxed);
                        if let Ok(mut errs) = prog.recent_errors.lock() {
                            errs.push((PathBuf::from(&pth), op_note.clone()));
                        }
                        rtext.push_str(&format!(
                            "\nACL {} ({}/{}) FAILED: {} — remaining staged ACL edits skipped.",
                            op_label,
                            i + 1,
                            total_ops,
                            op_note
                        ));
                        break;
                    }
                }
            }
        }
        {
            let mut ft = prog.final_result_text.lock().unwrap_or_else(|p| p.into_inner());
            *ft = Some(rtext);
        }
        prog.finished.store(true, Ordering::Relaxed);
    });
    // Lands in #perm-panel .perm-body; the poller drives the Apply Log and, on finish, permissions.js
    // refetches /dir-perms for this data-path. data-attrs are the coordination points for the client.
    let safe_path = form.path.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
    let placeholder = format!(
        r#"<div class="perm-applying" data-path="{}" data-applying="1">
    <span>⏳ Applying permissions — see the Apply Log below. Navigation locked until complete.</span>
</div>"#,
        safe_path
    );

    let status_html = render_apply_status_oob(&cmd, "Stand-by, estimating total... (live updates below)", true);
    Ok(Html(format!("{}\n{}", placeholder, status_html)))
}
/// Single source for the #apply-status shell (index initial state, oob updates, empty state).
/// The ids, the apply-status-content/apply-log-content class pair and the exact
/// data-apply-finished="true" spelling are contracts with base.html's poller JS.
fn apply_log_shell(inner_html: &str, active_cancel: bool, finished: bool, oob: bool) -> String {
    let cancel_btn = if active_cancel {
        r#"<button type="button" onclick="if (window.PermUI) window.PermUI.cancelCurrentApply();" class="btn apply-cancel">Cancel Apply</button>"#
    } else {
        r#"<button type="button" disabled class="btn apply-cancel">Cancel Apply</button>"#
    };
    let oob_attr = if oob { r#" hx-swap-oob="true""# } else { "" };
    let finished_attr = if finished { r#" data-apply-finished="true""# } else { "" };
    format!(
        r#"<div id="apply-status"{oob_attr} class="apply-status"{finished_attr}>
    <div class="apply-status-hd">
      <span>Apply Log</span>
      {cancel_btn}
    </div>
    <div id="apply-status-content" class="apply-status-content apply-log-content">
{inner_html}
    </div>
</div>"#
    )
}
fn render_apply_status_oob(cmd: &str, result_or_live: &str, active_cancel: bool) -> String {
    let body = format!(
        "<strong>Command</strong>\n{cmd}\n\n<strong>Status</strong>\n{result_or_live}"
    );
    apply_log_shell(&body, active_cancel, !active_cancel, true)
}
pub(crate) async fn apply_progress(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;
    let (html, stop_polling) = {
        let guard = state.apply_progress.lock().await;
        if let Some(prog) = guard.as_ref() {
            let total = prog.total.load(Ordering::Relaxed);
            let proc = prog.processed.load(Ordering::Relaxed);
            let ch = prog.changed.load(Ordering::Relaxed);
            let sk = prog.skipped.load(Ordering::Relaxed);
            let errc = prog.error_count.load(Ordering::Relaxed);
            let phase = prog.phase.lock().unwrap_or_else(|p| p.into_inner()).clone();
            let finished = prog.finished.load(Ordering::Relaxed);

            let cmd = prog.cmd.lock().unwrap_or_else(|p| p.into_inner()).clone().unwrap_or_default();
            let live_or_final = if finished {
                prog.final_result_text.lock().unwrap_or_else(|p| p.into_inner()).clone().unwrap_or_else(|| "Finished.".into())
            } else if total == 0 {
                let spin_chars = ["|", "/", "-", "\\"];
                let spin = spin_chars[proc % 4];
                format!("Stand-by, estimating total... scanned {} so far {}", proc, spin)
            } else {
                let pct = if total > 0 { ((proc as f64 * 100.0) / total as f64) as u32 } else { 0 };
                format!(
                    "Phase: {}\nProcessed: {}/{} ({}%)\nchanged: {}  skipped: {}  errors: {}",
                    phase, proc, total, pct, ch, sk, errc
                )
            };
            (render_apply_status_oob(&cmd, &live_or_final, !finished), finished)
        } else {
            // A poller with no progress slot at all is stray — stop it too.
            (
                apply_log_shell(
                    r#"<em class="placeholder-note">No permission apply in progress.</em>"#,
                    false,
                    false,
                    true,
                ),
                true,
            )
        }
    };
    // htmx only cancels an `every ...` poll loop on HTTP 286; a plain 200 keeps it running.
    // 286 still performs the oob #apply-status swap, so the final result text lands.
    let code = if stop_polling {
        StatusCode::from_u16(286).expect("286 is a valid status code")
    } else {
        StatusCode::OK
    };
    Ok((code, Html(html)))
}
pub(crate) async fn cancel_apply(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;
    if let Some(prog) = state.apply_progress.lock().await.as_ref() {
        prog.cancelled.store(true, Ordering::Relaxed);
    }
    Ok(Html(r#"<span class="note-danger">Cancel requested.</span>"#.to_string()))
}

/// Inputs for one ACL op, shared by /acl-apply and the /apply staged batch.
struct AclOpInput<'a> {
    op: &'a str,
    is_user: bool,
    id: u32,
    /// Pre-parsed principals for delete (may be empty — a lone id falls back).
    delete_kinds: Vec<crate::privileged::AclEntryKind>,
    perms: &'a str,
    default_layer: bool,
}

/// Builds the modification pair for one ACL op — the (possibly fused)
/// directory spec, the literal file spec for recursive sweeps, and the
/// human-readable setfacl line for the Apply Log. Shared by /acl-apply and
/// the /apply staged batch so both paths mutate identically. Returns None
/// for an unknown op.
fn build_acl_modification(
    input: AclOpInput<'_>,
    node_is_dir: bool,
    path: &str,
) -> Option<(
    crate::privileged::AclModification,
    crate::privileged::AclModification,
    String,
)> {
    let AclOpInput { op, is_user, id, mut delete_kinds, perms, default_layer } = input;
    let dflag = if default_layer { "-d " } else { "" };
    // Directory targets fuse r→x exactly like the POSIX dir matrix: the
    // submitted triad is what the user checked (Exec is a real stored bit),
    // the selected dir (and dirs in scope) take the fused perms while files
    // in scope take the literal triad. The pair differing is what the /apply
    // log keys its "fused for traversal" note on.
    let fuse_dir = |p: crate::privileged::AclPerms| {
        if node_is_dir { p.dir_r_implies_x() } else { p }
    };
    let kind = if is_user {
        crate::privileged::AclEntryKind::User(id)
    } else {
        crate::privileged::AclEntryKind::Group(id)
    };
    if op == "mask" {
        let pstr = if perms.trim().is_empty() { "r--".to_string() } else { perms.trim().to_string() };
        let lit = crate::privileged::AclPerms::from_str(&pstr);
        let fused = fuse_dir(lit.clone());
        let c = format!("setfacl {}-m m::{} {}", dflag, fused.to_str(), path);
        Some((
            crate::privileged::AclModification::SetMask { perms: fused, default: default_layer },
            crate::privileged::AclModification::SetMask { perms: lit, default: default_layer },
            c,
        ))
    } else if op == "add" || op == "edit" || op == "set" {
        let pstr = if perms.trim().is_empty() { "r--".to_string() } else { perms.trim().to_string() };
        let lit = crate::privileged::AclPerms::from_str(&pstr);
        let fused = fuse_dir(lit.clone());
        let c = format!(
            "setfacl {}-m {}:{}:{} {}",
            dflag,
            if is_user { "u" } else { "g" },
            id,
            fused.to_str(),
            path
        );
        Some((
            crate::privileged::AclModification::Set { kind: kind.clone(), perms: fused, default: default_layer },
            crate::privileged::AclModification::Set { kind, perms: lit, default: default_layer },
            c,
        ))
    } else if op == "delete" || op == "del" {
        if delete_kinds.is_empty() && id > 0 {
            delete_kinds.push(kind);
        }
        let c = if delete_kinds.is_empty() {
            format!("setfacl {}-x (no-op) {}", dflag, path)
        } else {
            let specs: Vec<String> = delete_kinds
                .iter()
                .map(|k| match k {
                    crate::privileged::AclEntryKind::User(u) => format!("u:{}", u),
                    crate::privileged::AclEntryKind::Group(g) => format!("g:{}", g),
                })
                .collect();
            format!("setfacl {}-x {} {}", dflag, specs.join(","), path)
        };
        let rm = crate::privileged::AclModification::Remove { kinds: delete_kinds, default: default_layer };
        Some((rm.clone(), rm, c))
    } else {
        None
    }
}

pub(crate) async fn acl_apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AclApplyForm>,
) -> Result<impl IntoResponse, Redirect> {
    let _user = require_auth(&state, &headers).await?;
    // One apply at a time: a second concurrent apply would clobber the single
    // progress slot and orphan the first apply's poller.
    if apply_in_progress(&state).await {
        return Ok((StatusCode::CONFLICT, Html(APPLY_BUSY_NOTE.to_string())).into_response());
    }
    let _p = std::path::Path::new(&form.path);
    let op = form.op.trim().to_lowercase();
    let typ = form.typ.trim().to_lowercase();
    let is_user = typ == "user" || typ == "u";
    // The capability decision gates the endpoint itself, not just the UI:
    // NOACL/incapable paths refuse ACL mutations outright (matches the
    // default-on-file 422 pattern), so a stale panel or hand-built POST can
    // never write ACLs the export model does not carry. This is the one place
    // that still checks the selected node's mount, not just the share.
    let gate = acl_apply_gate(&state, std::path::Path::new(&form.path));
    let (acl_ok, acl_short) = (gate.editable, gate.short);
    if !acl_ok {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!(
                r#"<div class="note-danger">ACL editing is not available here: {}</div>"#,
                acl_short.replace('<', "&lt;").replace('>', "&gt;")
            )),
        )
            .into_response());
    }
    let default_layer = form.layer.trim().eq_ignore_ascii_case("default");
    let node_is_dir = {
        let fs = state.fs.read().unwrap_or_else(|p| p.into_inner());
        fs.get_node_meta(std::path::Path::new(&form.path))
            .map(|m| m.is_dir)
    };
    if default_layer && node_is_dir != Some(true) {
        // POSIX has no default ACL for files: refuse rather than let setfacl
        // fail with a raw tool error.
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(r#"<div class="note-danger">Default (inheritance) ACL entries apply to directories only.</div>"#.to_string()),
        )
            .into_response());
    }
    // Scope mirrors the POSIX apply semantics; file targets stay single-node.
    let scope = if node_is_dir == Some(true) {
        match form.scope.trim() {
            "all" => crate::fs::ApplyScope::All,
            "single" => crate::fs::ApplyScope::ImmediateFiles,
            _ => crate::fs::ApplyScope::DirOnly,
        }
    } else {
        crate::fs::ApplyScope::DirOnly
    };

    let mut id: u32 = form.id.trim().parse().or_else(|_| {
        if let Some(first) = form.selected.split(',').next() {
            if let Some(num) = first.split(':').next_back() {
                return num.trim().parse();
            }
        }
        Ok(0u32)
    }).unwrap_or(0);
    // No numeric id but a typed principal name: resolve it via LDAP (same name translation as POSIX).
    // The mask op has no principal at all.
    if id == 0 && op != "delete" && op != "mask" && !form.name.trim().is_empty() {
        if let Some(stripped) = crate::ldap::LdapClient::normalize_editor_search_query(Some(&form.name)) {
            let lldap = state.lldap.read().await.clone();
            if let Ok(n) = stripped.parse::<u32>() {
                id = n;
            } else if is_user {
                if let Some((uid, _)) = lldap.resolve_user(&stripped).await { id = uid as u32; }
            } else if let Some((gid, _)) = lldap.resolve_group(&stripped).await {
                id = gid as u32;
            }
        }
    }
    if id == 0 && op != "delete" && op != "mask" {
        // 422 so the client's fetch treats this as a rejection and surfaces it inline
        // (a 200 here used to read as success and silently reload the panel).
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(r#"<div class="note-danger">Could not resolve that user/group (unknown name or invalid id).</div>"#.to_string()),
        )
            .into_response());
    }
    // Delete may carry several principals at once (comma list "u:1001,g:3001").
    let mut delete_kinds: Vec<crate::privileged::AclEntryKind> = vec![];
    if (op == "delete" || op == "del") && !form.selected.trim().is_empty() {
        for tok in form.selected.split(',') {
            let t = tok.trim();
            if t.is_empty() { continue; }
            let num: u32 = t.split(':').next_back().unwrap_or("0").trim().parse().unwrap_or(0);
            if num > 0 {
                if t.starts_with('g') || t.starts_with("group") {
                    delete_kinds.push(crate::privileged::AclEntryKind::Group(num));
                } else {
                    delete_kinds.push(crate::privileged::AclEntryKind::User(num));
                }
            }
        }
    }
    let Some((modification, file_modification, cmd)) = build_acl_modification(
        AclOpInput {
            op: &op,
            is_user,
            id,
            delete_kinds,
            perms: &form.perms,
            default_layer,
        },
        node_is_dir == Some(true),
        &form.path,
    ) else {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(r#"<div class="note-danger">Unknown ACL op</div>"#.to_string()),
        )
            .into_response());
    };
    let cmd = if scope == crate::fs::ApplyScope::DirOnly {
        cmd
    } else if let crate::privileged::AclModification::Set { ref perms, .. } = file_modification {
        // Name the file-side spec in the Apply Log: dirs take the fused
        // perms shown in the main spec, files exactly this triad.
        format!("{} [scope: {}, files: {}]", cmd, form.scope.trim(), perms.to_str())
    } else {
        format!("{} [scope: {}]", cmd, form.scope.trim())
    };
    let progress = Arc::new(ApplyProgress::default());
    if !try_claim_apply_slot(&state, &progress).await {
        return Ok((StatusCode::CONFLICT, Html(APPLY_BUSY_NOTE.to_string())).into_response());
    }
    {
        let mut c = progress.cmd.lock().unwrap_or_else(|p| p.into_inner());
        *c = Some(cmd.clone());
    }
    *progress.phase.lock().unwrap_or_else(|p| p.into_inner()) = "applying".to_string();
    progress.total.store(1, Ordering::Relaxed);
    progress.processed.store(0, Ordering::Relaxed);

    let fs = state.fs.read().unwrap_or_else(|p| p.into_inner()).clone();
    let pth = form.path.clone();
    let prog = progress.clone();
    let modf = modification;
    let file_modf = file_modification;
    let op_for_log = op.clone();
    tokio::spawn(async move {
        // Guarantees the poller is released even if the task panics mid-apply.
        let _finish = FinishOnDrop(prog.clone());
        if scope == crate::fs::ApplyScope::DirOnly {
            prog.processed.store(1, Ordering::Relaxed);
            // setfacl is a subprocess; keep it off the async runtime like the
            // scoped branches below already do.
            let res = {
                let fs = fs.clone();
                let pth = pth.clone();
                tokio::task::spawn_blocking(move || {
                    fs.apply_acl_mod(std::path::Path::new(&pth), modf)
                })
                .await
                .unwrap_or_else(|e| Err(format!("apply task failed: {e}")))
            };
            let (ok, msg) = match res {
                Ok(m) => (true, m),
                Err(e) => (false, e),
            };
            let rtext = if ok {
                format!("ACL {} OK: {}", op_for_log, msg)
            } else {
                format!("ACL {} failed: {}", op_for_log, msg)
            };
            if !ok {
                prog.error_count.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut errs) = prog.recent_errors.lock() {
                    errs.push((PathBuf::from(&pth), msg.clone()));
                }
            }
            prog.changed.fetch_add(1, Ordering::Relaxed);
            {
                let mut ft = prog.final_result_text.lock().unwrap_or_else(|p| p.into_inner());
                *ft = Some(rtext);
            }
            prog.finished.store(true, Ordering::Relaxed);
            return;
        }

        // Scoped apply: scan for the total first, then chunked setfacl —
        // the same two-phase shape as the POSIX recursive apply.
        *prog.phase.lock().unwrap_or_else(|p| p.into_inner()) = "scanning".to_string();
        let scan = {
            let fs = fs.clone();
            let pth = pth.clone();
            let modf = modf.clone();
            let prog = prog.clone();
            tokio::task::spawn_blocking(move || {
                fs.count_acl_applicable_with_live(std::path::Path::new(&pth), &modf, scope, &prog)
            })
            .await
        };
        let total = match scan {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                finish_acl_progress(&prog, format!("ACL {} failed during scan: {}", op_for_log, e));
                return;
            }
            Err(e) => {
                finish_acl_progress(&prog, format!("ACL {} scan task failed: {}", op_for_log, e));
                return;
            }
        };
        prog.total.store(total, Ordering::Relaxed);
        prog.processed.store(0, Ordering::Relaxed);
        *prog.phase.lock().unwrap_or_else(|p| p.into_inner()) = "applying".to_string();
        let applied = {
            let fs = fs.clone();
            let pth = pth.clone();
            let modf = modf.clone();
            let file_modf = file_modf.clone();
            let prog2 = prog.clone();
            tokio::task::spawn_blocking(move || {
                fs.apply_acl_with_progress(std::path::Path::new(&pth), &modf, &file_modf, scope, &prog2)
            })
            .await
        };
        let rtext = match applied {
            Ok(Ok(res)) => {
                let cancelled = prog.cancelled.load(Ordering::Relaxed);
                let mut t = format!(
                    "ACL {} {}: {} changed, {} skipped",
                    op_for_log,
                    if cancelled { "CANCELLED (partial)" } else if res.errors.is_empty() { "OK" } else { "finished with errors" },
                    res.changed,
                    res.skipped
                );
                if !res.errors.is_empty() {
                    t.push_str(&format!(", {} errors (first: {})", res.errors.len(), res.errors[0].1));
                }
                t
            }
            Ok(Err(e)) => format!("ACL {} failed: {}", op_for_log, e),
            Err(e) => format!("ACL {} apply task failed: {}", op_for_log, e),
        };
        finish_acl_progress(&prog, rtext);
    });

    let fb = format!(
        r#"<div class="note-success">ACL {} submitted — see Apply Log.</div>"#,
        op
    );
    let oob = render_apply_status_oob(&cmd, "Stand-by (ACL op)...", true);
    Ok(Html(format!("{}\n{}", fb, oob)).into_response())
}

/// Stamps the final Apply-Log text and flips the finished gate for an ACL
/// apply task (both the error shortcuts and the success path use it).
fn finish_acl_progress(prog: &ApplyProgress, text: String) {
    {
        let mut ft = prog
            .final_result_text
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        *ft = Some(text);
    }
    prog.finished.store(true, Ordering::Relaxed);
}

#[cfg(test)]
mod acl_capability_tests {
    use super::acl_capability_decision;
    use nfs_klldap_config::AclProbeVerdict as V;

    #[test]
    fn explicit_on_with_proven_probe_is_supported() {
        let g = acl_capability_decision(Some(true), V::Capable, None, "");
        assert!(g.editable && g.short.is_empty() && g.long.is_empty());
        assert_eq!(g.pill, "on");
        assert_eq!(g.pill_class, "on");
    }

    #[test]
    fn auto_with_proven_probe_is_supported_as_auto() {
        let g = acl_capability_decision(None, V::Capable, None, "");
        assert!(g.editable && g.short.is_empty(), "auto + proven probe must enable the editor");
        assert_eq!(g.pill, "auto");
        assert_eq!(g.pill_class, "on");
    }

    #[test]
    fn explicit_on_inconclusive_is_editable_and_amber() {
        // Generate still emits the ACL export on an inconclusive probe, so the
        // editor must respect the operator's choice instead of blocking.
        let g = acl_capability_decision(Some(true), V::Inconclusive, None, "");
        assert!(g.editable, "explicit ACL on must stay editable when unproven");
        assert_eq!(g.pill_class, "warn");
        assert!(g.pill.contains("unverified"), "pill flags the unverified state: {}", g.pill);
        assert!(g.long.contains("verify-ganesha.sh"), "long points at verification: {}", g.long);
    }

    #[test]
    fn enabled_but_incapable_fs_reverts_to_non_acl_with_reason() {
        let g = acl_capability_decision(
            Some(true),
            V::Incapable,
            None,
            "share \"x\": vfat limited filesystem",
        );
        assert!(!g.editable, "enable_acl on an incapable FS must NOT be supported");
        assert_eq!(g.pill, "off");
        assert!(g.short.contains("can't store ACLs"), "short names the cause: {}", g.short);
        assert!(g.long.contains("refuse to generate"), "long warns of the reload refusal: {}", g.long);
        assert!(g.long.contains("limited filesystem"), "long carries the fs warning: {}", g.long);
        assert!(g.long.contains("source_path"), "long names the staging escape: {}", g.long);
    }

    // The node-override matrix below is the /acl-apply 422 backstop only: the
    // panel and tree classify strictly per share (share_acl_gate never passes
    // a node verdict), so acl_apply_gate is the sole caller that can hit it.
    #[test]
    fn capable_share_blocks_incapable_submount() {
        // Share serves ACLs (root Capable) but the write target is on a vfat
        // child mount: the apply gate must refuse with a submount reason.
        let g = acl_capability_decision(None, V::Capable, Some(V::Incapable), "");
        assert!(!g.editable, "an incapable submount must block the apply gate");
        assert_eq!(g.pill_class, "off");
        assert!(g.short.contains("submount"), "short names the submount: {}", g.short);
    }

    #[test]
    fn capable_share_blocks_unverified_submount() {
        let g = acl_capability_decision(Some(true), V::Capable, Some(V::Inconclusive), "");
        assert!(!g.editable);
        assert!(g.short.contains("unverified"), "short flags the unverified submount: {}", g.short);
    }

    #[test]
    fn capable_share_allows_capable_submount() {
        let g = acl_capability_decision(None, V::Capable, Some(V::Capable), "");
        assert!(g.editable, "a capable submount must not block the apply gate");
        assert_eq!(g.pill, "auto");
    }

    #[test]
    fn disabled_reports_enable_acl_false_in_long() {
        let g = acl_capability_decision(Some(false), V::Capable, None, "");
        assert!(!g.editable);
        assert_eq!(g.pill, "off");
        assert!(g.short.len() < 60, "short reason stays one compact line: {}", g.short);
        assert!(g.long.contains("enable_acl = false"), "long names the setting: {}", g.long);
    }

    #[test]
    fn auto_unproven_reports_auto_off_not_false() {
        let g = acl_capability_decision(None, V::Inconclusive, None, "");
        assert!(!g.editable);
        assert_eq!(g.pill, "off");
        assert!(g.short.contains("auto"), "short names auto mode: {}", g.short);
        assert!(!g.short.contains("enable_acl = false"));
        assert!(g.long.contains("write probe"), "long explains the promotion rule: {}", g.long);
    }

    #[test]
    fn disabled_and_limited_appends_fs_warning_to_long() {
        let g = acl_capability_decision(
            Some(false),
            V::Incapable,
            None,
            "share \"x\": ntfs limited filesystem",
        );
        assert!(!g.editable);
        assert!(g.long.contains("limited filesystem"), "long cites the FS warning: {}", g.long);
    }
}

#[cfg(test)]
mod search_params_tests {
    use super::SearchParams;
    #[test]
    fn user_query_uses_owner_user_field_from_htmx_include() {
        let p = SearchParams {
            owner_user: Some("  alice  ".into()),
            owner_group: None,
        };
        assert_eq!(p.user_query_raw(), Some("alice"));
    }

    #[test]
    fn empty_owner_user_means_show_all() {
        let p = SearchParams {
            owner_user: Some("   ".into()),
            owner_group: None,
        };
        assert_eq!(p.user_query_raw(), None);
    }

    #[test]
    fn group_query_uses_owner_group_field() {
        let p = SearchParams {
            owner_user: None,
            owner_group: Some("admins".into()),
        };
        assert_eq!(p.group_query_raw(), Some("admins"));
    }
}

#[cfg(test)]
mod tree_row_tests {
    use super::*;

    #[test]
    fn file_kind_maps_categories_case_insensitively() {
        let e = |n: &str| file_kind(n).0;
        // Original five categories still hold.
        assert_eq!(e("a.TXT"), "📄");
        assert_eq!(e("b.Jpeg"), "🖼️");
        assert_eq!(e("c.iso"), "💿");
        assert_eq!(e("d.img"), "💿");
        assert_eq!(e("e.MKV"), "🎬");
        assert_eq!(e("f.tar.gz"), "🗄️");
        // New categories.
        assert_eq!(e("x.sh"), "📜");
        assert_eq!(e("X.SH"), "📜");
        assert_eq!(e("a.py"), "📜");
        assert_eq!(e("song.MP3"), "🎵");
        assert_eq!(e("track.flac"), "🎵");
        assert_eq!(e("pkg.deb"), "📦");
        assert_eq!(e("lib.so"), "📦");
        assert_eq!(e("f.ttf"), "🔤");
        assert_eq!(e("u.service"), "📄");
        // WINE / DOS split.
        assert_eq!(e("Game.EXE"), "🪟");
        assert_eq!(e("setup.msi"), "🪟");
        assert_eq!(e("driver.sys"), "🪟");
        assert_eq!(e("s.cmd"), "🪟");
        assert_eq!(e("runme.bat"), "💾");
        assert_eq!(e("player.COM"), "💾");
        assert_eq!(e("CONFIG.SYS"), "💾"); // name pin beats the .sys driver rule
        // Ambiguity pins.
        assert_eq!(e("v.ts"), "🎬");
        assert_eq!(e("w.tsx"), "📜");
        assert_eq!(e("z.mdf"), "💿");
        assert_eq!(e("go.mod"), "📜"); // name pin beats tracker-music .mod
        assert_eq!(e("music.mod"), "🎵");
        // Extensionless well-known names (previously ❔).
        assert_eq!(e("README"), "📄");
        assert_eq!(e("Makefile"), "📜");
        assert_eq!(e(".bashrc"), "📜");
        // Still honestly unknown.
        assert_eq!(e(".hidden"), "❔");
        assert_eq!(e("trailingdot."), "❔");
        assert_eq!(e("blob.xyz"), "❔");
    }

    #[test]
    fn file_kind_labels_name_the_category() {
        assert_eq!(file_kind("a.sh").1, "script / code");
        assert_eq!(file_kind("a.exe").1, "Windows / WINE");
        assert_eq!(file_kind("a.bat").1, "DOS");
        assert_eq!(file_kind("a.mp3").1, "audio");
        assert_eq!(file_kind("a.ttf").1, "font");
        assert_eq!(file_kind("a.xyz").1, "unknown type");
    }

    #[test]
    fn format_mtime_utc_formats_known_instants() {
        use std::time::{Duration, UNIX_EPOCH};
        assert_eq!(format_mtime_utc(UNIX_EPOCH), "1970-01-01 00:00");
        assert_eq!(
            format_mtime_utc(UNIX_EPOCH + Duration::from_secs(86_460)),
            "1970-01-02 00:01"
        );
    }
}

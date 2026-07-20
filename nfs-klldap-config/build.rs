//! Stamps NFS_KLLDAP_BUILD_VERSION into the config/startup/idhelper binaries
//! (--version and banners). Logic lives in build-support/version-stamp.rs,
//! shared with nfs-klldap-ui so every surface reports the same version.

include!("../build-support/version-stamp.rs");

fn main() {
    emit_version_stamp();
}

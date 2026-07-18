//! Stamps NFS_KLLDAP_BUILD_VERSION for the Overview "version" row. Logic
//! lives in build-support/version-stamp.rs, shared with nfs-klldap-config so
//! every surface reports the same version.

include!("../build-support/version-stamp.rs");

fn main() {
    emit_version_stamp();
}

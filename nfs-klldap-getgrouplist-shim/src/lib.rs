//! LD_PRELOAD `getgrouplist` shim for Ganesha 9.6: idhelper socket backstop + ret==0 normalization.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::OnceLock;

use libc::{dlsym, RTLD_NEXT};
use nfs_klldap_config::{
    normalize_linux_getgrouplist_ret, principal_query_for_shortname, query_idhelper_socket_gids,
    should_intercept_getgrouplist,
};

type GidT = u32;
type GetgrouplistFn = unsafe extern "C" fn(*const c_char, GidT, *mut GidT, *mut c_int) -> c_int;

fn next_getgrouplist() -> Option<GetgrouplistFn> {
    static NEXT: OnceLock<Option<GetgrouplistFn>> = OnceLock::new();
    *NEXT.get_or_init(|| {
        let sym = unsafe { dlsym(RTLD_NEXT, b"getgrouplist\0".as_ptr() as *const c_char) };
        if sym.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute::<*mut c_void, GetgrouplistFn>(sym) })
        }
    })
}

fn fill_groups(groups: *mut GidT, ngroups: *mut c_int, gids: &[u32]) -> c_int {
    if groups.is_null() || ngroups.is_null() {
        return -1;
    }
    let cap = unsafe { *ngroups } as usize;
    if cap < gids.len() {
        unsafe { *ngroups = gids.len() as c_int };
        return -1;
    }
    for (i, &g) in gids.iter().enumerate() {
        unsafe {
            *groups.add(i) = g;
        }
    }
    unsafe { *ngroups = gids.len() as c_int };
    0
}

fn intercept_via_socket(user: &str) -> Option<Vec<u32>> {
    let socket = nfs_klldap_config::idhelper_socket_path();
    let query = principal_query_for_shortname(user);
    query_idhelper_socket_gids(&socket, "GROUPLIST", &query)
        .or_else(|| query_idhelper_socket_gids(&socket, "GRPS", &query))
}

/// Exported `getgrouplist` — prepended in LD_PRELOAD before libnss_wrapper.
#[no_mangle]
pub unsafe extern "C" fn getgrouplist(
    user: *const c_char,
    group: GidT,
    groups: *mut GidT,
    ngroups: *mut c_int,
) -> c_int {
    if user.is_null() {
        return -1;
    }
    let user_s = match CStr::from_ptr(user).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    if should_intercept_getgrouplist(user_s) {
        if let Some(gids) = intercept_via_socket(user_s) {
            return fill_groups(groups, ngroups, &gids);
        }
    }

    let Some(next) = next_getgrouplist() else {
        return -1;
    };
    let raw = next(user, group, groups, ngroups);
    normalize_linux_getgrouplist_ret(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_groups_returns_zero_on_success() {
        let mut buf = [0u32; 8];
        let mut ng: c_int = 8;
        let gids = vec![0u32, 3005, 3007];
        let ret = fill_groups(buf.as_mut_ptr(), &mut ng, &gids);
        assert_eq!(ret, 0);
        assert_eq!(ng, 3);
        assert_eq!(&buf[..3], &[0, 3005, 3007]);
    }

    #[test]
    fn fill_groups_returns_neg_one_when_buffer_too_small() {
        let mut buf = [0u32; 1];
        let mut ng: c_int = 1;
        let gids = vec![0u32, 3005];
        let ret = fill_groups(buf.as_mut_ptr(), &mut ng, &gids);
        assert_eq!(ret, -1);
        assert_eq!(ng, 2);
    }
}
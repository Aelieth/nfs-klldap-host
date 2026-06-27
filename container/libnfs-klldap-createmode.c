// LD_PRELOAD shims for Ganesha 9.6 hybrid krb5p user TGT on Debian trixie.
// Strip RTLD_DEEPBIND so FSAL VFS openat64/fchmodat resolve through this library.
// Bump execute bits on create/chmod so NFSv4 ACCESS grants EXECUTE to owners.
// getgrouplist: return 0 on success; ganesha uid2grp treats nonzero as failure.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef RTLD_DEEPBIND
#define RTLD_DEEPBIND 0x00008
#endif

static void *(*real_dlopen)(const char *, int);
static int (*real_openat)(int, const char *, int, ...);
static int (*real_openat64)(int, const char *, int, ...);
static int (*real___openat64_2)(int, const char *, int);
static int (*real_open)(const char *, int, ...);
static int (*real_fchmod)(int, mode_t);
static int (*real_fchmodat)(int, const char *, mode_t, int);
static int (*real_chmod)(const char *, mode_t);
static int (*real_getgrouplist)(const char *, gid_t, gid_t *, int *);

static void init(void) {
    if (!real_dlopen)
        real_dlopen = dlsym(RTLD_NEXT, "dlopen");
    if (!real_openat)
        real_openat = dlsym(RTLD_NEXT, "openat");
    if (!real_openat64)
        real_openat64 = dlsym(RTLD_NEXT, "openat64");
    if (!real___openat64_2)
        real___openat64_2 = dlsym(RTLD_NEXT, "__openat64_2");
    if (!real_open)
        real_open = dlsym(RTLD_NEXT, "open");
    if (!real_fchmod)
        real_fchmod = dlsym(RTLD_NEXT, "fchmod");
    if (!real_fchmodat)
        real_fchmodat = dlsym(RTLD_NEXT, "fchmodat");
    if (!real_chmod)
        real_chmod = dlsym(RTLD_NEXT, "chmod");
    if (!real_getgrouplist)
        real_getgrouplist = dlsym(RTLD_NEXT, "getgrouplist");
}

static mode_t bump_mode(mode_t mode) {
    return mode | (S_IXUSR | S_IXGRP | S_IXOTH);
}

void *dlopen(const char *filename, int flags) {
    if (!real_dlopen)
        init();
    return real_dlopen(filename, flags & ~RTLD_DEEPBIND);
}

static int openat_common(int (*fn)(int, const char *, int, ...), int dirfd,
                         const char *pathname, int flags, mode_t mode,
                         int with_mode) {
    if (!fn)
        init();
    if (with_mode && (flags & O_CREAT))
        return fn(dirfd, pathname, flags, bump_mode(mode));
    return fn(dirfd, pathname, flags);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    if (!real_openat)
        init();
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = va_arg(ap, mode_t);
        va_end(ap);
        return openat_common(real_openat, dirfd, pathname, flags, mode, 1);
    }
    return real_openat(dirfd, pathname, flags);
}

int openat64(int dirfd, const char *pathname, int flags, ...) {
    if (!real_openat64)
        init();
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = va_arg(ap, mode_t);
        va_end(ap);
        return openat_common(real_openat64, dirfd, pathname, flags, mode, 1);
    }
    return real_openat64(dirfd, pathname, flags);
}

int __openat64_2(int dirfd, const char *pathname, int flags) {
    if (!real___openat64_2)
        init();
    return real___openat64_2(dirfd, pathname, flags);
}

int open(const char *pathname, int flags, ...) {
    if (!real_open)
        init();
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = va_arg(ap, mode_t);
        va_end(ap);
        return real_open(pathname, flags, bump_mode(mode));
    }
    return real_open(pathname, flags);
}

int fchmod(int fd, mode_t mode) {
    if (!real_fchmod)
        init();
    return real_fchmod(fd, bump_mode(mode));
}

int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {
    if (!real_fchmodat)
        init();
    return real_fchmodat(dirfd, pathname, bump_mode(mode), flags);
}

int chmod(const char *pathname, mode_t mode) {
    if (!real_chmod)
        init();
    return real_chmod(pathname, bump_mode(mode));
}

int getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups) {
    if (!real_getgrouplist)
        init();
    int ret = real_getgrouplist(user, group, groups, ngroups);
    if (ret > 0)
        return 0;
    return ret;
}
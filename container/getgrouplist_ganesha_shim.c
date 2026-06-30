// Ganesha 9.6 my_getgrouplist_alloc expects getgrouplist() ret == 0 and ngroups set.
// nss_wrapper hooks NSS but does not export getgrouplist; an earlier LD_PRELOAD shim
// would bypass it via RTLD_NEXT. Resolve groups from nss_wrapper/extrausers files.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <grp.h>
#include <pwd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*getgrouplist_fn)(const char *, gid_t, gid_t *, int *);

static getgrouplist_fn libc_getgrouplist(void)
{
	static getgrouplist_fn fn;
	if (!fn)
		fn = (getgrouplist_fn)dlsym(RTLD_NEXT, "getgrouplist");
	return fn;
}

static bool member_list_contains(const char *members, const char *user)
{
	const size_t ulen = strlen(user);

	if (ulen == 0)
		return false;

	for (const char *p = members; p && *p; ) {
		const char *comma = strchr(p, ',');
		size_t len = comma ? (size_t)(comma - p) : strlen(p);

		if (len == ulen && strncmp(p, user, ulen) == 0)
			return true;
		p = comma ? comma + 1 : NULL;
	}
	return false;
}

static bool parse_group_line(const char *line, const char *user, gid_t *out_gid)
{
	char *copy = strdup(line);
	char *save = NULL;
	char *gidstr = NULL;
	char *members = NULL;

	if (!copy)
		return false;

	(void)strtok_r(copy, ":", &save); /* name */
	(void)strtok_r(NULL, ":", &save); /* pass */
	gidstr = strtok_r(NULL, ":", &save);
	members = strtok_r(NULL, ":", &save);
	if (!gidstr || !members) {
		free(copy);
		return false;
	}

	if (!member_list_contains(members, user)) {
		free(copy);
		return false;
	}

	*out_gid = (gid_t)strtoul(gidstr, NULL, 10);
	free(copy);
	return true;
}

static void scan_group_file(const char *path, const char *user,
			    gid_t **groups, int *count, int *capacity)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;

	if (!path || !*path)
		return;

	f = fopen(path, "r");
	if (!f)
		return;

	while ((n = getline(&line, &cap, f)) > 0) {
		gid_t gid;
		bool seen;
		int i;

		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (n > 0 && line[n - 1] == '\n')
			line[n - 1] = '\0';
		if (!parse_group_line(line, user, &gid))
			continue;

		seen = false;
		for (i = 0; i < *count; i++) {
			if ((*groups)[i] == gid) {
				seen = true;
				break;
			}
		}
		if (seen)
			continue;

		if (*count >= *capacity) {
			int newcap = (*capacity == 0) ? 8 : (*capacity * 2);
			gid_t *tmp = realloc(*groups, (size_t)newcap * sizeof(gid_t));

			if (!tmp)
				break;
			*groups = tmp;
			*capacity = newcap;
		}
		(*groups)[(*count)++] = gid;
	}

	free(line);
	fclose(f);
}

static bool lookup_primary_gid(const char *user, gid_t *gid)
{
	const char *path = getenv("NSS_WRAPPER_PASSWD");
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	bool found = false;

	if (!path || !*path)
		return false;

	f = fopen(path, "r");
	if (!f)
		return false;

	while ((n = getline(&line, &cap, f)) > 0) {
		char *copy = strdup(line);
		char *save = NULL;
		char *login = NULL;
		char *gidstr = NULL;

		if (!copy)
			break;
		if (n > 0 && copy[strlen(copy) - 1] == '\n')
			copy[strlen(copy) - 1] = '\0';
		login = strtok_r(copy, ":", &save);
		(void)strtok_r(NULL, ":", &save);
		gidstr = strtok_r(NULL, ":", &save);
		if (login && gidstr && strcmp(login, user) == 0) {
			*gid = (gid_t)strtoul(gidstr, NULL, 10);
			found = true;
		}
		free(copy);
		if (found)
			break;
	}

	free(line);
	fclose(f);
	return found;
}

static int getgrouplist_from_nss_files(const char *user, gid_t group,
				       gid_t *groups, int *ngroups)
{
	gid_t *merged = NULL;
	int count = 0;
	int capacity = 0;
	const char *paths[3];
	int i;

	if (!ngroups)
		return -1;

	paths[0] = getenv("NSS_WRAPPER_GROUP");
	paths[1] = getenv("NSS_EXTRAUSERS_GROUP");
	paths[2] = NULL;

	for (i = 0; paths[i]; i++)
		scan_group_file(paths[i], user, &merged, &count, &capacity);

	if (group != 0) {
		bool seen = false;
		for (i = 0; i < count; i++) {
			if (merged[i] == group) {
				seen = true;
				break;
			}
		}
		if (!seen) {
			if (count >= capacity) {
				int newcap = (capacity == 0) ? 4 : (capacity * 2);
				gid_t *tmp = realloc(merged, (size_t)newcap * sizeof(gid_t));
				if (!tmp) {
					free(merged);
					errno = ENOMEM;
					return -1;
				}
				merged = tmp;
				capacity = newcap;
			}
			merged[count++] = group;
		}
	}

	/* glibc sizing pass: set required count; Ganesha allocates ngroups=1000 first. */
	if (!groups || *ngroups == 0) {
		*ngroups = count;
		free(merged);
		return (count == 0) ? 0 : -1;
	}

	if (count > *ngroups) {
		*ngroups = count;
		free(merged);
		return -1;
	}

	if (count > 0 && merged)
		memcpy(groups, merged, (size_t)count * sizeof(gid_t));
	*ngroups = count;
	free(merged);
	return 0;
}

int getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups)
{
	getgrouplist_fn next = libc_getgrouplist();
	gid_t primary = group;
	int ret;

	if (!user || !ngroups) {
		errno = EINVAL;
		return -1;
	}

	if (getenv("NSS_WRAPPER_PASSWD") != NULL) {
		if (group == 0)
			(void)lookup_primary_gid(user, &primary);
		return getgrouplist_from_nss_files(user, primary, groups, ngroups);
	}

	if (!next) {
		errno = ENOSYS;
		return -1;
	}

	ret = next(user, group, groups, ngroups);
	if (ret > 0) {
		*ngroups = ret;
		return 0;
	}
	if (ret == 0)
		return 0;
	return ret;
}
/* Probe for Ganesha 9.6 my_getgrouplist_alloc contract under LD_PRELOAD shim.
 * Exercises both glibc call shapes: sizing (groups=NULL, ngroups=0) then fill (ng=32). */
#include <grp.h>
#include <stdio.h>

int main(void)
{
	const char *user = "testuser1";
	gid_t primary = 3005;
	int n;
	int r;

	/* Sizing pass — Ganesha allocates after learning required count. */
	n = 0;
	r = getgrouplist(user, primary, NULL, &n);
	printf("size ret=%d ng=%d\n", r, n);

	/* Fill pass — Ganesha expects ret==0 and ngroups set. */
	{
		gid_t g[32];
		n = 32;
		r = getgrouplist(user, primary, g, &n);
		printf("fill ret=%d ng=%d", r, n);
		for (int i = 0; i < n; i++)
			printf(" %u", (unsigned)g[i]);
		printf("\n");
	}
	return 0;
}
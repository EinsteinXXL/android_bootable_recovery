/*
**  Copyright 1998-2003 University of Illinois Board of Trustees
**  Copyright 1998-2003 Mark D. Roth
**  All rights reserved.
**
**  wrapper.c - libtar high-level wrapper code
**
**  Mark D. Roth <roth@uiuc.edu>
**  Campus Information Technologies and Educational Services
**  University of Illinois at Urbana-Champaign
*/

#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>   /* write() for the DFP-R1 DFP signal in tar_extract_all() */

#ifdef STDC_HEADERS
# include <string.h>
#endif


/* Upstream-libtar built paths via `snprintf("%s/%s", prefix, filename)`
 * without normalising consecutive slashes. With our restore-demo prefix
 * `/data/TestRestore` + tar entries starting with '/', that produced
 * 100k+ lines of `/data/TestRestore//data/...` log noise. Linux treats
 * '//' like '/' so the bug is cosmetic, but worth fixing. Same defect
 * exists in upstream TWRP (`/mnt/android-ext4/twrp-original-ref`). */
int
libtar_path_join(char *buf, size_t bufsz,
                 const char *prefix, const char *filename)
{
	int written;
	if (buf == NULL || bufsz == 0)
		return -1;
	if (prefix != NULL && *prefix != '\0')
		written = snprintf(buf, bufsz, "%s/%s",
		                   prefix, filename != NULL ? filename : "");
	else
		written = snprintf(buf, bufsz, "%s", filename != NULL ? filename : "");

	/* snprintf truncation detector: glibc/bionic return the total bytes that
	 * would have been written (excluding NUL), independent of truncation.
	 * `written >= bufsz` means the result was truncated to fit. `written < 0`
	 * is an encoding error (extremely unlikely on plain C strings). */
	int truncated = (written < 0 || (size_t)written >= bufsz);

	/* Collapse runs of '/' in-place. Trailing '/' is preserved
	 * (directory tar entries rely on it). The collapse never grows the
	 * string, so it cannot turn a non-truncated result into a truncated one. */
	char *r = buf;
	char *w = buf;
	int prev_slash = 0;
	while (*r) {
		if (*r == '/') {
			if (!prev_slash) {
				*w++ = '/';
				prev_slash = 1;
			}
		} else {
			*w++ = *r;
			prev_slash = 0;
		}
		r++;
	}
	*w = '\0';

	return truncated ? -1 : 0;
}


int
tar_extract_glob(TAR *t, char *globname, char *prefix)
{
	char *filename;
	char buf[MAXPATHLEN];
	int i, fd = 0;

	while ((i = th_read(t)) == 0)
	{
		filename = th_get_pathname(t);
		if (fnmatch(globname, filename, FNM_PATHNAME | FNM_PERIOD))
		{
			if (TH_ISREG(t) && tar_skip_regfile(t))
				return -1;
			continue;
		}
		if (t->options & TAR_VERBOSE)
			th_print_long_ls(t);
		/* Slash-normalising join (collapse '//' from upstream-libtar).
		 * On truncation, abort to avoid silently extracting into a wrong
		 * path (potential data corruption). */
		if (libtar_path_join(buf, sizeof(buf), prefix, filename) != 0) {
			fprintf(stderr,
			        "tar_extract_glob(): joined path truncated (cap %zu B) for '%s' -- aborting\n",
			        sizeof(buf), filename != NULL ? filename : "(null)");
			return -1;
		}
		if (tar_extract_file(t, buf, prefix, &fd) != 0)
			return -1;
	}

	return (i == 1 ? 0 : -1);
}


/* Restore-side extract exclusion: true when `path` EQUALS `base` or lies BELOW it
 * (boundary via '/'), e.g. base="/media/0/Android". */
static int
path_is_under(const char *path, const char *base)
{
	size_t bl = strlen(base);
	if (strncmp(path, base, bl) != 0)
		return 0;
	return path[bl] == '\0' || path[bl] == '/';
}


int
tar_extract_all(TAR *t, char *prefix, const int *progress_fd, int dfp_done_fd, const char *exclude_relpath)
{
	char *filename;
	char buf[MAXPATHLEN];
	int i;
	/* Directory-First-Processing signal (DFP-R1): with dfp_done_fd >= 0 the first
	 * non-DIR header of this archive sends 1 byte once -- by that point all
	 * preceding directories (the full directory pre-run in win000) are already
	 * extracted + policed. The restore parent then releases the file pipes. */
	int dfp_signaled = 0;

#ifdef DEBUG
	printf("==> tar_extract_all(TAR *t, \"%s\")\n",
	       (prefix ? prefix : "(null)"));
#endif

	while ((i = th_read(t)) == 0)
	{
#ifdef DEBUG
		puts("    tar_extract_all(): calling th_get_pathname()");
#endif
		if (dfp_done_fd >= 0 && !dfp_signaled && !TH_ISDIR(t)) {
			char one = 1;
			(void)!write(dfp_done_fd, &one, 1);
			dfp_signaled = 1;
		}
		filename = th_get_pathname(t);
		/* Restore-side exclusion: skip entries ==/below exclude_relpath (REG data via
		 * tar_skip_regfile), e.g. "/media/0/Android" when the ext-app checkbox is
		 * deselected. AFTER the DFP signal so the wave-B release (first non-DIR) stays
		 * intact. */
		if (exclude_relpath != NULL && filename != NULL && path_is_under(filename, exclude_relpath)) {
			if (TH_ISREG(t) && tar_skip_regfile(t) != 0)
				return -1;
			continue;
		}
		if (t->options & TAR_VERBOSE)
			th_print_long_ls(t);
		/* Slash-normalising join (collapse '//' from upstream-libtar).
		 * On truncation, abort to avoid silently extracting into a wrong
		 * path (potential data corruption). */
		if (libtar_path_join(buf, sizeof(buf), prefix, filename) != 0) {
			fprintf(stderr,
			        "tar_extract_all(): joined path truncated (cap %zu B) for '%s' -- aborting\n",
			        sizeof(buf), filename != NULL ? filename : "(null)");
			return -1;
		}
#ifdef DEBUG
		printf("    tar_extract_all(): calling tar_extract_file(t, "
		       "\"%s\")\n", buf);
#endif
		if (tar_extract_file(t, buf, prefix, progress_fd) != 0)
			return -1;
	}

	return (i == 1 ? 0 : -1);
}


int
tar_append_tree(TAR *t, char *realdir, char *savedir)
{
	char realpath[MAXPATHLEN];
	char savepath[MAXPATHLEN];
	struct dirent *dent;
	DIR *dp;
	struct stat s;

#ifdef DEBUG
	printf("==> tar_append_tree(0x%lx, \"%s\", \"%s\")\n",
	       t, realdir, (savedir ? savedir : "[NULL]"));
#endif

	if (tar_append_file(t, realdir, savedir) != 0)
		return -1;

#ifdef DEBUG
	puts("    tar_append_tree(): done with tar_append_file()...");
#endif

	dp = opendir(realdir);
	if (dp == NULL)
	{
		if (errno == ENOTDIR)
			return 0;
		return -1;
	}
	while ((dent = readdir(dp)) != NULL)
	{
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;

		snprintf(realpath, MAXPATHLEN, "%s/%s", realdir,
			 dent->d_name);
		if (savedir)
			snprintf(savepath, MAXPATHLEN, "%s/%s", savedir,
				 dent->d_name);

		if (lstat(realpath, &s) != 0)
			return -1;

		if (S_ISDIR(s.st_mode))
		{
			if (tar_append_tree(t, realpath,
					    (savedir ? savepath : NULL)) != 0)
				return -1;
			continue;
		}

		if (tar_append_file(t, realpath,
				    (savedir ? savepath : NULL)) != 0)
			return -1;
	}

	closedir(dp);

	return 0;
}


int
tar_find(TAR *t, char *searchstr)
{
	if (!searchstr)
		return 0;

	char *filename;
	int i, entryfound = 0;
#ifdef DEBUG
	printf("==> tar_find(0x%lx, %s)\n", (long unsigned int)t, searchstr);
#endif
	while ((i = th_read(t)) == 0) {
		filename = th_get_pathname(t);
		if (fnmatch(searchstr, filename, FNM_FILE_NAME | FNM_PERIOD) == 0) {
			entryfound++;
#ifdef DEBUG
			printf("Found matching entry: %s\n", filename);
#endif
			break;
		}
	}
#ifdef DEBUG
	if (!entryfound)
		printf("No matching entry found.\n");
#endif

	return entryfound;
}

/*
**  Copyright 1998-2003 University of Illinois Board of Trustees
**  Copyright 1998-2003 Mark D. Roth
**  All rights reserved.
**
**  append.c - libtar code to append files to a tar archive
**
**  Mark D. Roth <roth@uiuc.edu>
**  Campus Information Technologies and Educational Services
**  University of Illinois at Urbana-Champaign
*/

#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/param.h>
#include <sys/types.h>
#include <stdbool.h>

#include <sys/capability.h>
#include <sys/xattr.h>
#include <linux/fs.h>
#include <linux/xattr.h>

#ifdef STDC_HEADERS
#include <stdlib.h>
#include <string.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <selinux/selinux.h>

#ifdef USE_FSCRYPT
#include "fscrypt_policy.h"
#endif

#include "android_utils.h"

#ifdef TW_LIBTAR_DEBUG
#define DEBUG 1
#endif

/* TAR_DATA_BUF_SIZE (128 KB) is defined in libtar/libtar.h and shared with
   extract.c, so the backup write path and the restore read path use the same
   chunk size. */

struct tar_dev
{
	dev_t td_dev;
	libtar_hash_t *td_h;
};
typedef struct tar_dev tar_dev_t;

struct tar_ino
{
	ino_t ti_ino;
	char ti_name[MAXPATHLEN];
};
typedef struct tar_ino tar_ino_t;


/* free memory associated with a tar_dev_t */
void
tar_dev_free(tar_dev_t *tdp)
{
	libtar_hash_free(tdp->td_h, free);
	free(tdp);
}


/* appends a file to the tar archive */
int
tar_append_file(TAR *t, const char *realname, const char *savename)
{
	struct stat s;
	int i;
	libtar_hashptr_t hp;
	tar_dev_t *td = NULL;
	tar_ino_t *ti = NULL;
	char path[MAXPATHLEN];

#ifdef DEBUG
	printf("==> tar_append_file(TAR=0x%p (\"%s\"), realname=\"%s\", "
	       "savename=\"%s\")\n", (void*) t, t->pathname, realname,
	       (savename ? savename : "[NULL]"));
#endif

	if (lstat(realname, &s) != 0)
	{
#ifdef DEBUG
		perror("lstat()");
#endif
		return -1;
	}

	/* set header block */
#ifdef DEBUG
	puts("tar_append_file(): setting header block...");
#endif
	memset(&(t->th_buf), 0, sizeof(struct tar_header));
	th_set_from_stat(t, &s);

	/* set the header path */
#ifdef DEBUG
	puts("tar_append_file(): setting header path...");
#endif
	th_set_path(t, (savename ? savename : realname));

	/* get selinux context */
	if (t->options & TAR_STORE_SELINUX)
	{
		if (t->th_buf.selinux_context != NULL)
		{
			free(t->th_buf.selinux_context);
			t->th_buf.selinux_context = NULL;
		}

		security_context_t selinux_context = NULL;
		if (lgetfilecon(realname, &selinux_context) >= 0)
		{
			t->th_buf.selinux_context = strdup(selinux_context);
#ifdef DEBUG
			printf("  ==> set selinux context: %s\n", selinux_context);
#endif
			freecon(selinux_context);
		}
		else
		{
#ifdef DEBUG
			perror("Failed to get selinux context");
#endif
		}
	}

#ifdef USE_FSCRYPT
	if (TH_ISDIR(t) && t->options & TAR_STORE_FSCRYPT_POL)
	{
		if (t->th_buf.fep != NULL)
		{
			free(t->th_buf.fep);
			t->th_buf.fep = NULL;
		}
#ifdef USE_FSCRYPT_POLICY_V1
		t->th_buf.fep = (struct fscrypt_policy_v1 *)malloc(sizeof(struct fscrypt_policy_v1));
#else
		t->th_buf.fep = (struct fscrypt_policy_v2 *)malloc(sizeof(struct fscrypt_policy_v2));
#endif
		if (!t->th_buf.fep) {
			printf("malloc fs_encryption_policy\n");
			return -1;
		}

		if (fscrypt_policy_get_struct(realname, t->th_buf.fep)) {
#ifdef USE_FSCRYPT_POLICY_V1
			uint8_t tar_policy[FS_KEY_DESCRIPTOR_SIZE];
			char policy_hex[FS_KEY_DESCRIPTOR_SIZE_HEX];
#else
			uint8_t tar_policy[FSCRYPT_KEY_IDENTIFIER_SIZE];
			char policy_hex[FSCRYPT_KEY_IDENTIFIER_HEX_SIZE];
#endif
			memset(tar_policy, 0, sizeof(tar_policy));
#ifdef USE_FSCRYPT_POLICY_V1
			bytes_to_hex(t->th_buf.fep->master_key_descriptor, FS_KEY_DESCRIPTOR_SIZE, policy_hex);
#else
			bytes_to_hex(t->th_buf.fep->master_key_identifier, FSCRYPT_KEY_IDENTIFIER_SIZE, policy_hex);
#endif
			if (lookup_ref_key(t->th_buf.fep,  &tar_policy[0])) {
				if (strncmp((char *) tar_policy, USER_CE_FSCRYPT_POLICY, sizeof(USER_CE_FSCRYPT_POLICY) - 1) == 0 
				|| strncmp((char *) tar_policy, USER_DE_FSCRYPT_POLICY, sizeof(USER_DE_FSCRYPT_POLICY) - 1) == 0 
				|| strncmp((char *) tar_policy, SYSTEM_DE_FSCRYPT_POLICY, sizeof(SYSTEM_DE_FSCRYPT_POLICY)) == 0) {
#ifdef USE_FSCRYPT_POLICY_V1
					memcpy(t->th_buf.fep->master_key_descriptor, tar_policy, FS_KEY_DESCRIPTOR_SIZE);
					// Verbose log: the "found policy" line only under TAR_TW_VERBOSE_LOG (a dedicated
					// bit, NOT TAR_VERBOSE); the "failed to ..." cases below always stay visible.
					if (t->options & TAR_TW_VERBOSE_LOG)
						printf("found fscrypt policy '%s' - '%s' - '%s'\n", realname, t->th_buf.fep->master_key_descriptor, policy_hex);
#else
					memcpy(t->th_buf.fep->master_key_identifier, tar_policy, FSCRYPT_KEY_IDENTIFIER_SIZE);
					if (t->options & TAR_TW_VERBOSE_LOG)   // Verbose log: see V1 branch above
						printf("found fscrypt policy '%s' - '%s' - '%s'\n", realname, t->th_buf.fep->master_key_identifier, policy_hex);
#endif
				} else {
					printf("failed to match fscrypt tar policy for '%s' - '%s'\n", realname, policy_hex);
					free(t->th_buf.fep);
					t->th_buf.fep = NULL;
				}
			} else {
				printf("failed to lookup fscrypt tar policy for '%s' - '%s'\n", realname, policy_hex);
				free(t->th_buf.fep);
				t->th_buf.fep = NULL;
			}
		}
		else {
			// no policy found, but this is not an error as not all dirs will have a policy
			free(t->th_buf.fep);
			t->th_buf.fep = NULL;
		}
	}
#endif

	/* get posix file capabilities */
	if (TH_ISREG(t) && t->options & TAR_STORE_POSIX_CAP)
	{
		if (t->th_buf.has_cap_data)
		{
			memset(&t->th_buf.cap_data, 0, sizeof(struct vfs_cap_data));
			t->th_buf.has_cap_data = 0;
		}

		if (getxattr(realname, XATTR_NAME_CAPS, &t->th_buf.cap_data, sizeof(struct vfs_cap_data)) >= 0)
		{
			t->th_buf.has_cap_data = 1;
#ifdef DEBUG
			print_caps(&t->th_buf.cap_data);
#endif
		}
	}

	/* get android user.default xattr */
	if (TH_ISDIR(t) && t->options & TAR_STORE_ANDROID_USER_XATTR)
	{
		if (getxattr(realname, "user.default", NULL, 0) >= 0)
		{
			t->th_buf.has_user_default = 1;
#ifdef DEBUG
			printf("storing xattr user.default\n");
#endif
		}
		if (getxattr(realname, "user.inode_cache", NULL, 0) >= 0)
		{
			t->th_buf.has_user_cache = 1;
#ifdef DEBUG
			printf("storing xattr user.inode_cache\n");
#endif
		}
		if (getxattr(realname, "user.inode_code_cache", NULL, 0) >= 0)
		{
			t->th_buf.has_user_code_cache = 1;
#ifdef DEBUG
			printf("storing xattr user.inode_code_cache\n");
#endif
		}
	}

	/* check if it's a hardlink */
#ifdef DEBUG
	puts("tar_append_file(): checking inode cache for hardlink...");
#endif
	libtar_hashptr_reset(&hp);
	if (libtar_hash_getkey(t->h, &hp, &(s.st_dev),
			       (libtar_matchfunc_t)dev_match) != 0)
		td = (tar_dev_t *)libtar_hashptr_data(&hp);
	else
	{
#ifdef DEBUG
		printf("+++ adding hash for device (0x%x, 0x%x)...\n",
		       major(s.st_dev), minor(s.st_dev));
#endif
		td = (tar_dev_t *)calloc(1, sizeof(tar_dev_t));
		td->td_dev = s.st_dev;
		td->td_h = libtar_hash_new(256, (libtar_hashfunc_t)ino_hash);
		if (td->td_h == NULL)
			return -1;
		if (libtar_hash_add(t->h, td) == -1)
			return -1;
	}
	libtar_hashptr_reset(&hp);
	if (libtar_hash_getkey(td->td_h, &hp, &(s.st_ino),
			       (libtar_matchfunc_t)ino_match) != 0)
	{
		ti = (tar_ino_t *)libtar_hashptr_data(&hp);
#ifdef DEBUG
		printf("    tar_append_file(): encoding hard link \"%s\" "
		       "to \"%s\"...\n", realname, ti->ti_name);
#endif
		t->th_buf.typeflag = LNKTYPE;
		th_set_link(t, ti->ti_name);
	}
	else
	{
#ifdef DEBUG
		printf("+++ adding entry: device (0x%d,0x%x), inode %lu"
		       "(\"%s\")...\n", major(s.st_dev), minor(s.st_dev),
		       (unsigned long) s.st_ino, realname);
#endif
		ti = (tar_ino_t *)calloc(1, sizeof(tar_ino_t));
		if (ti == NULL)
			return -1;
		ti->ti_ino = s.st_ino;
		snprintf(ti->ti_name, sizeof(ti->ti_name), "%s",
			 savename ? savename : realname);
		libtar_hash_add(td->td_h, ti);
	}

	/* check if it's a symlink */
	if (TH_ISSYM(t))
	{
		i = readlink(realname, path, sizeof(path));
		if (i == -1)
			return -1;
		if (i >= MAXPATHLEN)
			i = MAXPATHLEN - 1;
		path[i] = '\0';
#ifdef DEBUG
		printf("tar_append_file(): encoding symlink \"%s\" -> "
		       "\"%s\"...\n", realname, path);
#endif
		th_set_link(t, path);
	}

	/* print file info */
	if (t->options & TAR_VERBOSE)
		printf("%s\n", th_get_pathname(t));

#ifdef DEBUG
	puts("tar_append_file(): writing header");
#endif
	/* write header */
	if (th_write(t) != 0)
	{
#ifdef DEBUG
		printf("t->fd = %ld\n", t->fd);
#endif
		return -1;
	}
#ifdef DEBUG
	puts("tar_append_file(): back from th_write()");
#endif

	/* if it's a regular file, write the contents as well */
	if (TH_ISREG(t) && tar_append_regfile(t, realname) != 0)
		return -1;

	return 0;
}


/* write EOF indicator */
int
tar_append_eof(TAR *t)
{
	int i, j;
	char block[T_BLOCKSIZE];

	memset(&block, 0, T_BLOCKSIZE);
	for (j = 0; j < 2; j++)
	{
		i = tar_block_write(t, &block);
		if (i != T_BLOCKSIZE)
		{
			if (i != -1)
				errno = EINVAL;
			return -1;
		}
	}

	return 0;
}


/* Bulk I/O: the source read goes through the central tar_io_read (block.c); the
 * archive write goes through t->type->writefunc like every header block
 * (tar_block_write macro) -- REQUIRED for ring-backed tar handles (a pseudo-fd,
 * with no real fd behind t->fd). Behavior-neutral for all fd-backed types:
 * default_type.writefunc AND write_tar_no_buffer both delegate to tar_io_write. */

/* add file contents to a tarchive */
int
tar_append_regfile(TAR *t, const char *realname)
{
	// __thread-qualified -- consistent with basename.c/dirname.c in the same libtar.
	// Unchanged in the fork() model (1 slot/process) but robust if libtar is ever
	// called from a thread context.
	static __thread char data_buf[TAR_DATA_BUF_SIZE];
	int filefd;
	int64_t i, size;
	ssize_t j, padded;
	int rv = -1;

#if defined(O_BINARY)
	filefd = open(realname, O_RDONLY|O_BINARY);
#else
	filefd = open(realname, O_RDONLY);
#endif
	if (filefd == -1)
	{
#ifdef DEBUG
		perror("open()");
#endif
		return -1;
	}

	/* Sequential read hint: a pure hint, no I/O. WILLNEED deliberately NOT set --
	 * across thousands of /data smallfiles the syscall overhead would outweigh the
	 * benefit, and a WILLNEED over the whole file can trash the page cache.
	 * DONTNEED after success is kept below. */
	posix_fadvise64(filefd, 0, 0, POSIX_FADV_SEQUENTIAL);

	size = th_get_size(t);
	/* TWRP in-file cache trim: on large files both the read input (source) AND the
	 * output written asynchronously via zstd would otherwise accumulate untrimmed
	 * until addFile returns -> transient page-cache spikes (~active-pipes x file
	 * size). So trim every 128 MB INLINE, not only between files (twrpTar tarList
	 * hook). */
	off64_t in_trim_off = 0;       /* input: dropped via FADV_DONTNEED up to here */
	int64_t since_trim  = 0;       /* bytes written since the last trim */
	for (i = size; i > TAR_DATA_BUF_SIZE; i -= TAR_DATA_BUF_SIZE)
	{
		j = tar_io_read(filefd, data_buf, TAR_DATA_BUF_SIZE);
		if (j != TAR_DATA_BUF_SIZE)
		{
			if (j != -1)
				errno = EIO;   /* short read = source file truncated mid-archive */
			goto fail;
		}
		if ((*(t->type->writefunc))(t->fd, data_buf, TAR_DATA_BUF_SIZE) != TAR_DATA_BUF_SIZE)
			goto fail;
		since_trim += TAR_DATA_BUF_SIZE;
		if (since_trim >= (128LL << 20))   /* 128 MB */
		{
			/* Input: read source pages are clean (read-only) -> drop directly, no
			 * sync needed. Output: self-paced via TWFunc (sync_file_range +
			 * FADV_DONTNEED, always behind the write head); no-op when output_fd<=0. */
			posix_fadvise64(filefd, in_trim_off, since_trim, POSIX_FADV_DONTNEED);
			in_trim_off += since_trim;
			since_trim = 0;
			if (t->output_fd > 0 && t->output_trim_cb)
				t->output_trim_cb(t->output_fd, t->output_trim_offset);
		}
	}

	if (i > 0)
	{
		j = tar_io_read(filefd, data_buf, i);
		/* Same rule as the bulk loop above: a short read means the source file
		 * shrank after its header was written (live /data), so the archive entry
		 * cannot be filled honestly. Upstream libtar only tested for -1 here and
		 * padded the gap, which with this shared 128 KB buffer would ship bytes of
		 * the PREVIOUSLY read file inside the entry. Fail instead. */
		if (j != i)
		{
			if (j != -1)
				errno = EIO;
			goto fail;
		}
		/* pad last chunk to T_BLOCKSIZE boundary (tar format requirement) */
		padded = ((i + T_BLOCKSIZE - 1) / T_BLOCKSIZE) * T_BLOCKSIZE;
		memset(&(data_buf[i]), 0, padded - i);
		if ((*(t->type->writefunc))(t->fd, data_buf, padded) != padded)
			goto fail;
	}

	/* success! */
	rv = 0;

	/* Backup progress = the content bytes ACTUALLY written (size), symmetric to
	 * tar_extract_regfile (which sums to_write == size). Symlinks (SYMTYPE) and
	 * hardlink duplicates (LNKTYPE) do NOT run through this function
	 * (tar_append_file calls tar_append_regfile only for TH_ISREG) -> they report 0,
	 * exactly like the restore. This makes the backup_size stored in the .info ==
	 * the content sum the restore extracts -> both 100%. progress_fd == 0 ->
	 * disabled (restore/get_size). Best-effort: an EPIPE (parent read end closed) is
	 * harmless via SIG_IGN, no backup data loss. */
	if (t->progress_fd > 0 && size > 0)
	{
		unsigned long long ps = (unsigned long long)size;
		(void)write(t->progress_fd, &ps, sizeof(ps));
	}
fail:
	/* Drop the page cache only on success -- on a read/write error the drop
	 * achieves nothing and blocks possible retry reads. */
	if (rv == 0)
		posix_fadvise64(filefd, 0, 0, POSIX_FADV_DONTNEED);
	close(filefd);

	return rv;
}


/* add file contents to a tarchive */
int
tar_append_file_contents(TAR *t, const char *savename, mode_t mode,
                         uid_t uid, gid_t gid, void *buf, size_t len)
{
	struct stat st;

	memset(&st, 0, sizeof(st));
	st.st_mode = S_IFREG | mode;
	st.st_uid = uid;
	st.st_gid = gid;
	st.st_mtime = time(NULL);
	st.st_size = len;

	th_set_from_stat(t, &st);
	th_set_path(t, savename);

	/* write header */
	if (th_write(t) != 0)
	{
#ifdef DEBUG
		fprintf(stderr, "tar_append_file_contents(): could not write header, t->fd = %ld\n", t->fd);
#endif
		return -1;
	}

	return tar_append_buffer(t, buf, len);
}

int
tar_append_buffer(TAR *t, void *buf, size_t len)
{
	char block[T_BLOCKSIZE];
	int i;
	size_t size = len;

	for (i = size; i > T_BLOCKSIZE; i -= T_BLOCKSIZE)
	{
		if (tar_block_write(t, buf) == -1)
			return -1;
		buf = (char *)buf + T_BLOCKSIZE;
	}

	if (i > 0)
	{
		memcpy(block, buf, i);
		memset(&(block[i]), 0, T_BLOCKSIZE - i);
		if (tar_block_write(t, &block) == -1)
			return -1;
	}

	return 0;
}


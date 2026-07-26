/*
**  Copyright 1998-2003 University of Illinois Board of Trustees
**  Copyright 1998-2003 Mark D. Roth
**  All rights reserved.
**
**  extract.c - libtar code to extract a file from a tar archive
**
**  Mark D. Roth <roth@uiuc.edu>
**  Campus Information Technologies and Educational Services
**  University of Illinois at Urbana-Champaign
*/

#include <internal.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <utime.h>

#include <sys/capability.h>
#include <sys/xattr.h>
#include <linux/xattr.h>

#ifdef STDC_HEADERS
# include <stdlib.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <selinux/selinux.h>

#ifdef USE_FSCRYPT
#include "fscrypt_policy.h"
#endif

#ifdef TW_LIBTAR_DEBUG
#define DEBUG 1
#endif

#include "android_utils.h"

#include <sys/resource.h>   /* fd ring: getrlimit/setrlimit */
#include <stdlib.h>         /* fd ring: malloc/free */

/* sync_file_range is declared in bionic <fcntl.h> only under _GNU_SOURCE; libtar builds C99.
 * _GNU_SOURCE globally would be RISKY here (would pull GNU basename/dirname instead of POSIX --
 * extract.c uses dirname()). So declare it manually: the symbol exists in libc (__INTRODUCED_IN(26),
 * hotdog API 30); the SYNC_FILE_RANGE_* macros are unconditionally in <fcntl.h> (only the function
 * is gated). Signature exactly as in bionic. */
extern ssize_t sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags);

/* ---------------------------------------------------------------------------
 * fd ring (restore write side) -- "defer instead of wait".
 * Do NOT close extracted fds immediately, keep them in a ring -> when they fall
 * out the file is written back (clean) -> posix_fadvise64(DONTNEED) REALLY drops
 * it (instead of fizzling at close because smallfiles are still dirty).
 * Per-segment (fresh per tar_open, drained at tar_close). File-based restore
 * only; ADB -> fd_ring=NULL -> old behavior; dd-image/super never go through
 * tar_extract_regfile. Cleanup net = the worker's _exit invariant (the kernel
 * closes the fds).
 * --------------------------------------------------------------------------- */

/* Ring entry with deferred FADV+close: evict the oldest when full, then push fd. */
static void fd_ring_push(TAR *t, int fd)
{
	if (t->fd_ring_count == t->fd_ring_cap)
	{
		int old = t->fd_ring[t->fd_ring_head];
		posix_fadvise64(old, 0, 0, POSIX_FADV_DONTNEED);   /* now clean -> really drops */
		close(old);
		t->fd_ring_head = (t->fd_ring_head + 1) % t->fd_ring_cap;
		t->fd_ring_count--;
	}
	t->fd_ring[(t->fd_ring_head + t->fd_ring_count) % t->fd_ring_cap] = fd;
	t->fd_ring_count++;
}

/* Raise RLIMIT_NOFILE to hard (free, no privilege) + allocate the ring. A malloc
 * failure -> fd_ring stays NULL -> old posix_fadvise64+close in tar_extract_regfile (safe). */
void fd_ring_setup(TAR *t, int cap)
{
	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max)
	{
		rl.rlim_cur = rl.rlim_max;
		setrlimit(RLIMIT_NOFILE, &rl);
	}
	t->fd_ring = (int *) malloc((size_t)cap * sizeof(int));
	if (t->fd_ring == NULL)
		return;
	t->fd_ring_cap   = cap;
	t->fd_ring_count = 0;
	t->fd_ring_head  = 0;
}

/* FADV+close + free all remaining ring fds. On ALL extractTar return paths
 * before tar_close. NULL-safe; a double close (drain + later _exit) is harmless (EBADF). */
void fd_ring_drain(TAR *t)
{
	int i;
	if (t->fd_ring == NULL)
		return;
	for (i = 0; i < t->fd_ring_count; i++)
	{
		int fd = t->fd_ring[(t->fd_ring_head + i) % t->fd_ring_cap];
		posix_fadvise64(fd, 0, 0, POSIX_FADV_DONTNEED);
		close(fd);
	}
	free(t->fd_ring);
	t->fd_ring       = NULL;
	t->fd_ring_count = 0;
	t->fd_ring_cap   = 0;
	t->fd_ring_head  = 0;
}

/* No global progress_size here: tar_extract_regfile() computes the chunk size
   per aggregate write and sends it as a byte count to the progress pipe, which
   avoids a 512-byte progress-write syscall per extracted tar block. */

static int
tar_set_file_perms(TAR *t, const char *realname)
{
	mode_t mode;
	uid_t uid;
	gid_t gid;
	struct utimbuf ut;
	const char *filename;
	char *pn;

	pn = th_get_pathname(t);
	filename = (realname ? realname : pn);
	mode = th_get_mode(t);
	uid = th_get_uid(t);
	gid = th_get_gid(t);
	ut.modtime = ut.actime = th_get_mtime(t);

#ifdef DEBUG
	printf("tar_set_file_perms(): setting perms: %s (mode %04o, uid %d, gid %d)\n",
		filename, mode, uid, gid);
#endif

	/* change owner/group */
	if (geteuid() == 0)
#ifdef HAVE_LCHOWN
		if (lchown(filename, uid, gid) == -1)
		{
# ifdef DEBUG
			fprintf(stderr, "lchown(\"%s\", %d, %d): %s\n",
				filename, uid, gid, strerror(errno));
# endif
#else /* ! HAVE_LCHOWN */
		if (!TH_ISSYM(t) && chown(filename, uid, gid) == -1)
		{
# ifdef DEBUG
			fprintf(stderr, "chown(\"%s\", %d, %d): %s\n",
				filename, uid, gid, strerror(errno));
# endif
#endif /* HAVE_LCHOWN */
			return -1;
		}

	/* change access/modification time */
	if (!TH_ISSYM(t) && utime(filename, &ut) == -1)
	{
#ifdef DEBUG
		perror("utime()");
#endif
		return -1;
	}

	/* change permissions */
	if (!TH_ISSYM(t) && chmod(filename, mode) == -1)
	{
#ifdef DEBUG
		perror("chmod()");
#endif
		return -1;
	}

	return 0;
}


/* switchboard */
int
tar_extract_file(TAR *t, const char *realname, const char *prefix, const int *progress_fd)
{
	int i;
#ifdef LIBTAR_FILE_HASH
	char *lnp;
	char *pn;
	int pathname_len;
	int realname_len;
#endif

	if (t->options & TAR_NOOVERWRITE)
	{
		struct stat s;

		if (lstat(realname, &s) == 0 || errno != ENOENT)
		{
			errno = EEXIST;
			return -1;
		}
	}

	if (TH_ISDIR(t))
	{
		i = tar_extract_dir(t, realname);
		if (i == 1)
			i = 0;
	}
	else if (TH_ISLNK(t))
		i = tar_extract_hardlink(t, realname, prefix);
	else if (TH_ISSYM(t))
		i = tar_extract_symlink(t, realname);
	else if (TH_ISCHR(t))
		i = tar_extract_chardev(t, realname);
	else if (TH_ISBLK(t))
		i = tar_extract_blockdev(t, realname);
	else if (TH_ISFIFO(t))
		i = tar_extract_fifo(t, realname);
	else /* if (TH_ISREG(t)) */
		i = tar_extract_regfile(t, realname, progress_fd);

	if (i != 0) {
		fprintf(stderr, "tar_extract_file(): failed to extract %s !!!\n", realname);
		return i;
	}

	i = tar_set_file_perms(t, realname);
	if (i != 0) {
		fprintf(stderr, "tar_extract_file(): failed to set permissions on %s !!!\n", realname);
		return i;
	}

	if((t->options & TAR_STORE_SELINUX) && t->th_buf.selinux_context != NULL)
	{
#ifdef DEBUG
		printf("tar_extract_file(): restoring SELinux context %s to file %s\n", t->th_buf.selinux_context, realname);
#endif
		if (lsetfilecon(realname, t->th_buf.selinux_context) < 0)
			fprintf(stderr, "tar_extract_file(): failed to restore SELinux context %s to file %s !!!\n", t->th_buf.selinux_context, realname);
	}

	if((t->options & TAR_STORE_POSIX_CAP) && t->th_buf.has_cap_data)
	{
#ifdef DEBUG
		printf("tar_extract_file(): restoring posix capabilities to file %s\n", realname);
		print_caps(&t->th_buf.cap_data);
#endif
		if (setxattr(realname, XATTR_NAME_CAPS, &t->th_buf.cap_data, sizeof(struct vfs_cap_data), 0) < 0)
			fprintf(stderr, "tar_extract_file(): failed to restore posix capabilities to file %s !!!\n", realname);
	}

#ifdef LIBTAR_FILE_HASH
	pn = th_get_pathname(t);
	pathname_len = strlen(pn) + 1;
	realname_len = strlen(realname) + 1;
	lnp = (char *)calloc(1, pathname_len + realname_len);
	if (lnp == NULL)
		return -1;
	strcpy(&lnp[0], pn);
	strcpy(&lnp[pathname_len], realname);
#ifdef DEBUG
	printf("tar_extract_file(): calling libtar_hash_add(): key=\"%s\", "
	       "value=\"%s\"\n", pn, realname);
#endif
	if (libtar_hash_add(t->h, lnp) != 0)
		return -1;
	free(lnp);
#endif

	return 0;
}


/* extract regular file
 *
 * Reads tar blocks into a TAR_DATA_BUF_SIZE-sized aggregate buffer and writes
 * them with one write() per chunk to the output fd. Short-read tolerance does
 * NOT come from this loop but from the tartype_t readfunc (tar_io_read in
 * block.c): each tar_block_read() demands exactly T_BLOCKSIZE; this loop only
 * aggregates blocks into bundled writes. The progress pipe gets the actual
 * payload byte count per chunk, so the parent accumulation stays correct.
 *
 * The buffer is static: in the fork() model each pipe is its own process, so
 * there is no reentrancy problem; it saves the 128-KB stack allocation per call.
 * Additionally __thread-qualified -- consistent with basename.c / dirname.c.
 * Unchanged in the fork() model (1 slot/process) but robust if libtar is ever
 * called from a thread context.
 */
int
tar_extract_regfile(TAR *t, const char *realname, const int *progress_fd)
{
	int64_t size, remaining;
	int fdout;
	static __thread char buf[TAR_DATA_BUF_SIZE];
	const char *filename;
	char *pn;

#ifdef DEBUG
	printf("  ==> tar_extract_regfile(realname=\"%s\")\n", realname);
#endif

	if (!TH_ISREG(t))
	{
		errno = EINVAL;
		return -1;
	}

	pn = th_get_pathname(t);
	filename = (realname ? realname : pn);
	size = th_get_size(t);

	if (mkdirhier(dirname(filename)) == -1)
		return -1;

	/* Privacy log (tw_verbose_log): success print per entry only with
	 * TAR_TW_VERBOSE_LOG (applies to all "==> extracting" prints in this file);
	 * error paths (fprintf(stderr)/failed prints) still log the name
	 * unconditionally. */
	if (t->options & TAR_TW_VERBOSE_LOG)
		printf("  ==> extracting: %s (file size %" PRId64 " bytes)\n",
				filename, size);

	fdout = open(filename, O_WRONLY | O_CREAT | O_TRUNC
#ifdef O_BINARY
		     | O_BINARY
#endif
		    , 0666);
	if (fdout == -1)
	{
#ifdef DEBUG
		perror("open()");
#endif
		return -1;
	}

	/* extract the file -- 128 KB aggregate chunks (TAR_DATA_BUF_SIZE) */
	/* TWRP restore output cache trim: otherwise the extracted files are NEVER
	 * dropped from the page cache -> the cache grows to the RAM limit during
	 * restore. Trim large files every 128 MB inline (via output_trim_cb ->
	 * TWFunc::Trim_Output_Cache; the worker writes fdout sequentially itself ->
	 * lseek64 = the write position); small files via FADV_DONTNEED at close (no sync). */
	off64_t out_trim   = 0;   /* in-file trim offset (per extracted file) */
	int64_t since_trim = 0;   /* bytes written since the last in-file trim */
	remaining = size;
	while (remaining > 0)
	{
		/* Fill buffer: up to TAR_DATA_BUF_SIZE / T_BLOCKSIZE blocks (= 256) */
		ssize_t blocks_to_fill = (remaining > (int64_t)TAR_DATA_BUF_SIZE)
		                          ? (TAR_DATA_BUF_SIZE / T_BLOCKSIZE)
		                          : (ssize_t)((remaining + T_BLOCKSIZE - 1) / T_BLOCKSIZE);
		/* ONE robust read per chunk instead of blocks_to_fill x 512 B. The readfunc
		 * (= tar_io_read, block.c) fills up to chunk or a real EOF -- saves up to 255
		 * read() syscalls per 128-KB chunk on the restore pipe (data path; headers
		 * stay 512 B via th_read). chunk = blocks_to_fill*512 <= TAR_DATA_BUF_SIZE (no
		 * overflow of buf). errno semantics unchanged: EINVAL on truncation (got>=0),
		 * readfunc errno on -1. */
		ssize_t chunk = blocks_to_fill * T_BLOCKSIZE;
		ssize_t got = (*(t->type->readfunc))(t->fd, buf, (size_t)chunk);
		if (got != chunk)
		{
			if (got != -1)
				errno = EINVAL;
			close(fdout);
			return -1;
		}

		/* Padding-correction: tar pads the last block of a file to T_BLOCKSIZE
		   with zero bytes; we must not write that padding to the output file. */
		ssize_t to_write = (chunk > remaining) ? (ssize_t)remaining : chunk;

		/* Robust tar_io_write instead of bare write -- EINTR- and partial-write-safe
		   (symmetric to the backup side, which already uses tar_io_write in
		   tar_append_regfile). tar_io_write returns count on success / -1 on a real
		   error -> the (!= to_write) comparison is unchanged; ENOSPC/EIO still run
		   into the return -1 path. */
		if (tar_io_write(fdout, buf, to_write) != to_write)
		{
			/* write() partial or -1 -- ENOSPC, EIO etc. Error handling in caller. */
			close(fdout);
			return -1;
		}

		if (progress_fd != NULL && *progress_fd != 0)
		{
			unsigned long long ps = (unsigned long long)to_write;
			write(*progress_fd, &ps, sizeof(ps));
		}

		remaining -= to_write;

		/* In-file trim for LARGE files every 128 MB (self-paced in TWFunc: trims only
		 * when fdout has grown >= 128 MB since out_trim). For small files this never
		 * fires -> only the FADV at close below. */
		since_trim += to_write;
		if (since_trim >= (128LL << 20) && t->output_trim_cb)
		{
			t->output_trim_cb(fdout, &out_trim);
			since_trim = 0;
		}
		/* Part 2: .win input trim, 128-MB-gated (symmetric to the backup
		 * tar_append_regfile). The counter is cumulative over files (TAR struct) ->
		 * covers smallfile streams too. RAW (input_fd<=0): the .win IS t->fd, the
		 * worker reads it itself -> counter-based FADV (no lseek, like the backup).
		 * Pipeline (input_fd>0): zstd/aes reads the .win via the shared OFD -> ONE
		 * lseek64 at the gate (only ~every 128 MB -> no f_pos_lock contention) gives
		 * the real read head. FADV-only (read pages clean, no sync). */
		t->input_since += to_write;
		if (t->input_since >= (128LL << 20))
		{
			if (t->input_fd > 0)
			{
				off64_t pos = lseek64(t->input_fd, 0, SEEK_CUR);
				if (pos > t->input_trim_off)
				{
					posix_fadvise64(t->input_fd, t->input_trim_off, pos - t->input_trim_off, POSIX_FADV_DONTNEED);
					t->input_trim_off = pos;
				}
			}
			else
			{
				posix_fadvise64(t->fd, t->input_trim_off, t->input_since, POSIX_FADV_DONTNEED);
				t->input_trim_off += t->input_since;
			}
			t->input_since = 0;
		}
	}

	/* fd ring: when active (not ADB), do NOT close fdout immediately -- start an
	 * async writeback and put it in the ring; FADV+close happens deferred when it
	 * falls out (then clean -> really drops, instead of fizzling at close because
	 * smallfiles are dirty). Ring off (ADB/alloc error) -> old behavior: per-file
	 * FADV (WITHOUT sync) + close. */
	if (t->fd_ring != NULL)
	{
		sync_file_range(fdout, 0, 0, SYNC_FILE_RANGE_WRITE);   /* async, NO wait */
		fd_ring_push(t, fdout);
	}
	else
	{
		posix_fadvise64(fdout, 0, 0, POSIX_FADV_DONTNEED);
		if (close(fdout) == -1)
			return -1;
	}

#ifdef DEBUG
	printf("### done extracting %s\n", filename);
#endif

	return 0;
}


/* skip regfile */
int
tar_skip_regfile(TAR *t)
{
	int64_t size, i;
	ssize_t k;
	char buf[T_BLOCKSIZE];

	if (!TH_ISREG(t))
	{
		errno = EINVAL;
		return -1;
	}

	size = th_get_size(t);
	for (i = size; i > 0; i -= T_BLOCKSIZE)
	{
		k = tar_block_read(t, buf);
		if (k != T_BLOCKSIZE)
		{
			if (k != -1)
				errno = EINVAL;
			return -1;
		}
	}

	return 0;
}


/* hardlink */
int
tar_extract_hardlink(TAR * t, const char *realname, const char *prefix)
{
	const char *filename;
	char *pn;
	char *linktgt = NULL;
	char *lnp;
	libtar_hashptr_t hp;
	/* Local buffer for the prefix-joined link target. Replaces upstream
	 * libtar's `strdup(linktgt) + sprintf(linktgt, ...)` pattern, which
	 * (a) mutated either the fixed 100-byte th_buf.linkname field or the
	 * gnu_longlink heap buffer in-place — unbounded write, classic
	 * upstream buffer-overflow — and (b) corrupted hash-stored realnames
	 * when the same target was re-used by multiple hardlinks. We build
	 * the joined path here, no longer touch upstream storage, and warn
	 * on MAXPATHLEN truncation. Upstream-bug in twrp-original-ref. */
	char joined[MAXPATHLEN];

	if (!TH_ISLNK(t))
	{
		errno = EINVAL;
		return -1;
	}

	pn = th_get_pathname(t);
	filename = (realname ? realname : pn);
	if (mkdirhier(dirname(filename)) == -1)
		return -1;
	if (unlink(filename) == -1 && errno != ENOENT)
		return -1;
	libtar_hashptr_reset(&hp);
	if (libtar_hash_getkey(t->h, &hp, th_get_linkname(t),
			       (libtar_matchfunc_t)libtar_str_match) != 0)
	{
		lnp = (char *)libtar_hashptr_data(&hp);
		linktgt = &lnp[strlen(lnp) + 1];
	}
	else
		linktgt = th_get_linkname(t);

	/* Slash-normalising join into a bounded local buffer. Exact truncation
	 * detection via snprintf return value inside libtar_path_join (no more
	 * length heuristic — the previous `need = prefix_len+1+link_len+1`
	 * estimator could false-positive when libtar_path_join collapsed
	 * adjacent slashes, and false-negative was impossible only because the
	 * estimator was strictly conservative). Soft-fail on truncation, same
	 * style as the link()-failure branch below. */
	if (libtar_path_join(joined, sizeof(joined), prefix, linktgt) != 0)
	{
		fprintf(stderr,
		        "tar_extract_hardlink(): joined link target truncated "
		        "(cap %zu B); link to '%s' skipped\n",
		        sizeof(joined), filename);
		t->hardlink_fail_count++;
		return 0;
	}
	linktgt = joined;

	if (t->options & TAR_TW_VERBOSE_LOG)
		printf("  ==> extracting: %s (link to %s)\n", filename, linktgt);

	if (link(linktgt, filename) == -1)
	{
		fprintf(stderr, "tar_extract_hardlink(): failed restore of hardlink '%s' but returning as if nothing bad happened\n", filename);
		t->hardlink_fail_count++;
		return 0; // Used to be -1
	}

	return 0;
}


/* symlink */
int
tar_extract_symlink(TAR *t, const char *realname)
{
	const char *filename;
	char *pn;

	if (!TH_ISSYM(t))
	{
		errno = EINVAL;
		return -1;
	}

	pn = th_get_pathname(t);
	filename = (realname ? realname : pn);
	if (mkdirhier(dirname(filename)) == -1)
		return -1;

	if (unlink(filename) == -1 && errno != ENOENT)
		return -1;

	if (t->options & TAR_TW_VERBOSE_LOG)
		printf("  ==> extracting: %s (symlink to %s)\n",
		       filename, th_get_linkname(t));

	if (symlink(th_get_linkname(t), filename) == -1)
	{
#ifdef DEBUG
		perror("symlink()");
#endif
		return -1;
	}

	return 0;
}


/* character device */
int
tar_extract_chardev(TAR *t, const char *realname)
{
	mode_t mode;
	unsigned long devmaj, devmin;
	const char *filename;
	char *pn;

	if (!TH_ISCHR(t))
	{
		errno = EINVAL;
		return -1;
	}

	pn = th_get_pathname(t);
	filename = (realname ? realname : pn);
	mode = th_get_mode(t);
	devmaj = th_get_devmajor(t);
	devmin = th_get_devminor(t);

	if (mkdirhier(dirname(filename)) == -1)
		return -1;

	if (t->options & TAR_TW_VERBOSE_LOG)
		printf("  ==> extracting: %s (character device %ld,%ld)\n",
		       filename, devmaj, devmin);

	if (mknod(filename, mode | S_IFCHR,
		  compat_makedev(devmaj, devmin)) == -1)
	{
		fprintf(stderr, "tar_extract_chardev(): failed restore of character device '%s' but returning as if nothing bad happened\n", filename);
		return 0; // Used to be -1
	}

	return 0;
}


/* block device */
int
tar_extract_blockdev(TAR *t, const char *realname)
{
	mode_t mode;
	unsigned long devmaj, devmin;
	const char *filename;
	char *pn;

	if (!TH_ISBLK(t))
	{
		errno = EINVAL;
		return -1;
	}

	pn = th_get_pathname(t);
	filename = (realname ? realname : pn);
	mode = th_get_mode(t);
	devmaj = th_get_devmajor(t);
	devmin = th_get_devminor(t);

	if (mkdirhier(dirname(filename)) == -1)
		return -1;

	if (t->options & TAR_TW_VERBOSE_LOG)
		printf("  ==> extracting: %s (block device %ld,%ld)\n",
		       filename, devmaj, devmin);

	if (mknod(filename, mode | S_IFBLK,
		  compat_makedev(devmaj, devmin)) == -1)
	{
		fprintf(stderr, "tar_extract_blockdev(): failed restore of block device '%s' but returning as if nothing bad happened\n", filename);
		return 0; // Used to be -1
	}

	return 0;
}

/* directory */
int
tar_extract_dir(TAR *t, const char *realname)
{
	mode_t mode;
	const char *filename;
	char *pn;

	if (!TH_ISDIR(t))
	{
		errno = EINVAL;
		return -1;
	}
	pn = th_get_pathname(t);
	filename = (realname ? realname : pn);
	mode = th_get_mode(t);

	if (mkdirhier(dirname(filename)) == -1)
		return -1;

	if (t->options & TAR_TW_VERBOSE_LOG)
		printf("  ==> extracting: %s (mode %04o, directory)\n", filename,
		       mode);

	if (mkdir(filename, mode) == -1)
	{
		if (errno == EEXIST)
		{
			if (chmod(filename, mode) == -1)
			{
#ifdef DEBUG
				perror("chmod()");
#endif
				return -1;
			}
#ifdef DEBUG
			puts("  *** using existing directory -- applying stored metadata");
#endif
			// Fall-through: the TAR_STORE_ANDROID_USER_XATTR setters and the fscrypt
			// block must run for already-existing directories too, otherwise
			// policy/xattrs are lost on a cross-pipe DIR race (pipe X creates the
			// parent dir via mkdirhier() from tar_extract_regfile(), pipe Y later
			// processes the DIR entry and without this would hit EEXIST + return 1
			// before the setter block).
		}
		else
		{
#ifdef DEBUG
			perror("mkdir()");
#endif
			return -1;
		}
	}

	if (t->options & TAR_STORE_ANDROID_USER_XATTR)
	{
		if (t->th_buf.has_user_default) {
#ifdef DEBUG
			printf("tar_extract_file(): restoring android user.default xattr to %s\n", realname);
#endif
			if (setxattr(realname, "user.default", NULL, 0, 0) < 0) {
				fprintf(stderr, "tar_extract_file(): failed to restore android user.default to file %s !!!\n", realname);
				return -1;
			}
		}
		if (t->th_buf.has_user_cache) {
#ifdef DEBUG
			printf("tar_extract_file(): restoring android user.inode_cache xattr to %s\n", realname);
#endif
			if (write_path_inode(realname, "cache", "user.inode_cache"))
				return -1;
		}
		if (t->th_buf.has_user_code_cache) {
#ifdef DEBUG
			printf("tar_extract_file(): restoring android user.inode_code_cache xattr to %s\n", realname);
#endif
			if (write_path_inode(realname, "code_cache", "user.inode_code_cache"))
				return -1;
		}
	}

#ifdef USE_FSCRYPT
	if(t->th_buf.fep != NULL)
	{
#ifdef USE_FSCRYPT_POLICY_V1
		char policy_hex[FS_KEY_DESCRIPTOR_SIZE_HEX];
#else
		char policy_hex[FSCRYPT_KEY_IDENTIFIER_HEX_SIZE];
#endif
#ifdef DEBUG
#ifdef USE_FSCRYPT_POLICY_V1
		bytes_to_hex(t->th_buf.fep->master_key_descriptor, FS_KEY_DESCRIPTOR_SIZE, policy_hex);
#else
		bytes_to_hex(t->th_buf.fep->master_key_identifier, FSCRYPT_KEY_IDENTIFIER_SIZE, policy_hex);
#endif
		printf("tar_extract_dir(): restoring fscrypt policy %s to dir %s\n", (char *)policy_hex, realname);
#endif
		bool policy_lookup_error = false;
#ifdef USE_FSCRYPT_POLICY_V1
		uint8_t binary_policy[FS_KEY_DESCRIPTOR_SIZE];
		memset(&binary_policy, 0, FS_KEY_DESCRIPTOR_SIZE);
#else
		uint8_t binary_policy[FSCRYPT_KEY_IDENTIFIER_SIZE];
		memset(&binary_policy, 0, FSCRYPT_KEY_IDENTIFIER_SIZE);
#endif

#ifdef USE_FSCRYPT_POLICY_V1
		if (!lookup_ref_tar(t->th_buf.fep->master_key_descriptor, &binary_policy[0])) {
			printf("error looking up fscrypt policy for '%s' - %s\n", realname, t->th_buf.fep->master_key_descriptor);
			policy_lookup_error = true;
		}
		memcpy(&t->th_buf.fep->master_key_descriptor, binary_policy, FS_KEY_DESCRIPTOR_SIZE);
		bytes_to_hex(t->th_buf.fep->master_key_descriptor, FS_KEY_DESCRIPTOR_SIZE, policy_hex);
#else
		if (!lookup_ref_tar(t->th_buf.fep->master_key_identifier, &binary_policy[0])) {
			printf("error looking up fscrypt policy for '%s' - %s\n", realname, t->th_buf.fep->master_key_identifier);
			policy_lookup_error = true;
		}
		memcpy(&t->th_buf.fep->master_key_identifier, binary_policy, FSCRYPT_KEY_IDENTIFIER_SIZE);
		bytes_to_hex(t->th_buf.fep->master_key_identifier, FSCRYPT_KEY_IDENTIFIER_SIZE, policy_hex);
#endif
		if (!policy_lookup_error) 
		{
			if (t->options & TAR_TW_VERBOSE_LOG)
				printf("attempting to restore policy: %s\n", policy_hex);
			if (!fscrypt_policy_set_struct(realname, t->th_buf.fep))
			{
				printf("tar_extract_file(): failed to restore fscrypt policy to dir '%s' '%s'!!!\n", realname, policy_hex);
				//return -1; // This may not be an error in some cases, so log and ignore
			}
		} else
			printf("No policy was found. Continuing restore.");
	}
	else if (t->options & TAR_TW_VERBOSE_LOG)
		printf("NULL FSCRYPT\n");
#endif

	return 0;
}


/* FIFO */
int
tar_extract_fifo(TAR *t, const char *realname)
{
	mode_t mode;
	const char *filename;
	char *pn;

	if (!TH_ISFIFO(t))
	{
		errno = EINVAL;
		return -1;
	}

	pn = th_get_pathname(t);
	filename = (realname ? realname : pn);
	mode = th_get_mode(t);

	if (mkdirhier(dirname(filename)) == -1)
		return -1;


	if (t->options & TAR_TW_VERBOSE_LOG)
		printf("  ==> extracting: %s (fifo)\n", filename);

	if (mkfifo(filename, mode) == -1)
	{
#ifdef DEBUG
		perror("mkfifo()");
#endif
		return -1;
	}

	return 0;
}

/* extract file contents from a tarchive */
int
tar_extract_file_contents(TAR *t, void *buf, size_t *lenp)
{
	char block[T_BLOCKSIZE];
	int64_t size, i;
	ssize_t k;

#ifdef DEBUG
	printf("  ==> tar_extract_file_contents\n");
#endif

	if (!TH_ISREG(t))
	{
		errno = EINVAL;
		return -1;
	}

	size = th_get_size(t);
	if ((uint64_t)size > *lenp)
	{
		errno = ENOSPC;
		return -1;
	}

	/* extract the file */
	for (i = size; i >= T_BLOCKSIZE; i -= T_BLOCKSIZE)
	{
		k = tar_block_read(t, buf);
		if (k != T_BLOCKSIZE)
		{
			if (k != -1)
				errno = EINVAL;
			return -1;
		}
		buf = (char *)buf + T_BLOCKSIZE;
	}
	if (i > 0) {
		k = tar_block_read(t, block);
		if (k != T_BLOCKSIZE)
		{
			if (k != -1)
				errno = EINVAL;
			return -1;
		}
		memcpy(buf, block, i);
	}
	*lenp = (size_t)size;

#ifdef DEBUG
	printf("### done extracting contents\n");
#endif
	return 0;
}

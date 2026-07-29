/*
**  Copyright 1998-2003 University of Illinois Board of Trustees
**  Copyright 1998-2003 Mark D. Roth
**  All rights reserved.
**
**  libtar.h - header file for libtar library
**
**  Mark D. Roth <roth@uiuc.edu>
**  Campus Information Technologies and Educational Services
**  University of Illinois at Urbana-Champaign
*/

#ifndef LIBTAR_H
#define LIBTAR_H

#include <sys/types.h>
#include <sys/stat.h>
#include <linux/capability.h>
#include "tar.h"

#include "libtar_listhash.h"

#ifdef USE_FSCRYPT
#include "fscrypt_policy.h"
#endif

#ifdef __cplusplus
extern "C"
{
#endif


/* useful constants */
/* see FIXME note in block.c regarding T_BLOCKSIZE */
#define T_BLOCKSIZE		512
#define T_NAMELEN		100
#define T_PREFIXLEN		155
#define T_MAXPATHLEN		(T_NAMELEN + T_PREFIXLEN)

/* Data buffer for file content reads/writes — 128 KB matches zstd's
   ZSTD_CStreamInSize(), which keeps the compression API call count low and hits
   the optimal input chunk for the (de)compressor. Used by both append.c
   (backup write path) and extract.c (restore read path). */
#define TAR_DATA_BUF_SIZE	131072

/* GNU extensions for typeflag */
#define GNU_LONGNAME_TYPE	'L'
#define GNU_LONGLINK_TYPE	'K'

/* extended metadata for next file - used to store selinux_context */
#define TH_EXT_TYPE		'x'
#define TH_POL_TYPE_DO_NOT_USE		'p'

/* POSIX pax GLOBAL extended header (archive-wide records). Used by the
 * self-describing-backup work to mark new RAW (type 4, vs. legacy type 0) and
 * to carry the external-app-data flag, written as standard pax
 * "<len> key=value\n" records so stock gzip/tar/zstd tools still open the
 * archive (they ignore the vendor keys). Defined here -- not file-local in
 * block.c like the 'x' tags -- because the WRITER lives in twrpTar.cpp; reader
 * (block.c) and writer share these constants. */
#define TH_GLOBAL_TYPE		'g'
#define TWRP_TARTYPE_TAG	"TWRP.tartype="
#define TWRP_TARTYPE_TAG_LEN	strlen(TWRP_TARTYPE_TAG)
#define TWRP_EAD_TAG		"TWRP.ead="
#define TWRP_EAD_TAG_LEN	strlen(TWRP_EAD_TAG)

/* our version of the tar header structure */
struct tar_header
{
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char linkname[100];
	char magic[6];
	char version[2];
	char uname[32];
	char gname[32];
	char devmajor[8];
	char devminor[8];
	char prefix[155];
	char padding[12];
	char *gnu_longname;
	char *gnu_longlink;
	char *selinux_context;
#ifdef USE_FSCRYPT
#ifdef USE_FSCRYPT_POLICY_V1
	struct fscrypt_policy_v1 *fep;
#else
	struct fscrypt_policy_v2  *fep;
#endif
#endif
	int has_cap_data;
	struct vfs_cap_data cap_data;
	int has_user_default;
	int has_user_cache;
	int has_user_code_cache;
	/* Parsed from a PAX GLOBAL ('g') header's TWRP.* records. In-memory only
	 * (they live past the on-disk 512-byte block, so they are never serialised).
	 * -1 = the record was absent in the archive; reset in the th_read prologue. */
	int global_tartype;
	int global_ead;
};


/***** handle.c ************************************************************/

typedef int (*openfunc_t)(const char *, int, ...);
typedef int (*closefunc_t)(int);
typedef ssize_t (*readfunc_t)(int, void *, size_t);
typedef ssize_t (*writefunc_t)(int, const void *, size_t);

/* Robust block-I/O primitives (block.c) -- EINTR-/short-read-/partial-write-safe.
 * default_type (handle.c) and all TWRP tartype_t instances point here because a
 * tar fd is not always a regular file: on the ADB paths it is a FIFO, where a
 * bare read() returns transient short reads that would abort th_read. */
ssize_t tar_io_read(int fd, void *buf, size_t count);
ssize_t tar_io_write(int fd, const void *buf, size_t count);

/* TWRP in-file cache trim: C wrapper around TWFunc::Trim_Output_Cache (defined in
 * twrp-functions.cpp). tar_append_regfile calls it every 128 MB for the output fd;
 * trim_offset points to the shared twrpTar member. NULL/fd<=0 -> no-op. */
void twrp_trim_output_cache(int fd, off64_t *trim_offset);

typedef struct
{
	openfunc_t openfunc;
	closefunc_t closefunc;
	readfunc_t readfunc;
	writefunc_t writefunc;
}
tartype_t;

typedef struct
{
	tartype_t *type;
	const char *pathname;
	long fd;
	int oflags;
	int options;
	struct tar_header th_buf;
	libtar_hash_t *h;

	/* introduced in libtar 1.2.21 */
	char *th_pathname;

	/* Progress pipe fd for the backup append path. 0 = disabled (default via
	 * calloc in tar_init); only the backup worker sets it (twrpTar::addFile ->
	 * progress_pipe_fd). tar_append_regfile reports the content bytes ACTUALLY
	 * written through it -- symmetric to tar_extract_regfile. So backup counts the
	 * same as restore (no symlink lengths / hardlink duplicates) -> .info
	 * backup_size == restore content sum -> progress honestly reaches 100%.
	 * Restore/get_size TARs leave it 0. */
	int progress_fd;

	/* Counts failed hardlink restores (link() error OR path truncation in
	 * tar_extract_hardlink). Soft-fail stays (return 0); extractTar() reads the
	 * field after tar_extract_all and reports >0 ONCE, aggregated, via LOGERR
	 * (log + GUI). Auto-0 via calloc in tar_init. */
	int hardlink_fail_count;

	/* TWRP in-file cache trim: write-behind output trim ALSO within large files
	 * (tar_append_regfile), not only between files. output_fd = the chosen seekable
	 * output fd (0 = disabled, pattern like progress_fd; ADB/restore leave it 0 ->
	 * no trim). output_trim_offset points to the twrpTar member output_trim_offset
	 * (shared with the tarList hook). output_trim_cb = function pointer to
	 * twrp_trim_output_cache; libtar calls it via the POINTER (like
	 * tartype_t::openfunc/readfunc/writefunc) because libtar.so cannot link a symbol
	 * from the recovery binary directly (reverse dependency). Auto-0/NULL via calloc
	 * in tar_init -> NULL = no trim. */
	int output_fd;
	off64_t *output_trim_offset;
	void (*output_trim_cb)(int fd, off64_t *trim_offset);

	/* TWRP restore input cache trim (part 2): write-behind .win read trim,
	 * 128-MB-gated, symmetric to the backup logic (tar_append_regfile; FADV direct,
	 * no callback). input_fd: pipeline (ZSTD/AES) = the .win fd read by zstd/aes via
	 * the shared OFD (>0 -> extract.c lseek64's it at the gate); RAW = -1/0 -> the
	 * .win IS t->fd, the worker reads it itself (purely counter-based, no lseek).
	 * input_trim_off = last dropped .win offset; input_since = bytes read since the
	 * last drop. Both cumulative over files (smallfile streams), auto-0 via
	 * calloc/tar_init. */
	int input_fd;
	off64_t input_trim_off;
	off64_t input_since;

	/* TWRP restore input read-ahead (RAW plain tar only): rolling WILLNEED
	 * window kept queued ahead of the sequential .win read position, re-armed
	 * by extract.c every ~8 MB read. input_ra_window = budget in bytes, set by
	 * openTar() ONLY for the seekable plain-tar FILE restore (stays 0 for the
	 * ADB FIFO and the engine modes -- those prefetch in the stage reader,
	 * stage_io_fd_ra); input_ra_pos = cumulative content bytes read (heuristic
	 * position, same approximation as input_since); input_ra_frontier =
	 * absolute offset up to which WILLNEED is queued. Auto-0 via calloc in
	 * tar_init. */
	off64_t input_ra_window;
	off64_t input_ra_pos;
	off64_t input_ra_frontier;

	/* fd ring (restore write side): do NOT close extracted fds immediately, keep
	 * them in a ring -> when they fall out they are written back (clean) -> FADV
	 * really drops (instead of fizzling at close because smallfiles are still dirty).
	 * fd_ring = malloc'd array (NULL = off -> tar_extract_regfile falls back to an
	 * immediate posix_fadvise64+close; that is the ADB and allocation-failure
	 * case). cap=R, count, head (circular). Auto-0/NULL via calloc in tar_init.
	 * dd-image/super never run through here. */
	int *fd_ring;
	int fd_ring_cap;
	int fd_ring_count;
	int fd_ring_head;
}
TAR;

/* constant values for the TAR options field */
#define TAR_GNU			 1	/* use GNU extensions */
#define TAR_VERBOSE		 2	/* output file info to stdout */
#define TAR_NOOVERWRITE		 4	/* don't overwrite existing files */
#define TAR_IGNORE_EOT		 8	/* ignore double zero blocks as EOF */
#define TAR_CHECK_MAGIC		16	/* check magic in file header */
#define TAR_CHECK_VERSION	32	/* check version in file header */
#define TAR_IGNORE_CRC		64	/* ignore CRC in file header */
#define TAR_STORE_SELINUX	128	/* store selinux context */
#define TAR_USE_NUMERIC_ID	256	/* favor numeric owner over names */

#ifdef USE_FSCRYPT
#define TAR_STORE_FSCRYPT_POL 512 /* store fscrypt crypto policy */
#endif

#define TAR_STORE_POSIX_CAP	1024	/* store posix file capabilities */
#define TAR_STORE_ANDROID_USER_XATTR	2048	/* store android user.* xattr */
/* TWRP privacy log (tw_verbose_log): success prints per extracted entry
 * ("==> extracting: ..." etc. in extract.c) only with this bit. Deliberately a
 * dedicated bit instead of TAR_VERBOSE: that would also enable th_print_long_ls
 * in tar_extract_all/-glob (wrapper.c) -> double output. Error prints stay
 * independent of this bit (always active). */
#define TAR_TW_VERBOSE_LOG	4096	/* TWRP: log each extracted entry to stdout */

/* this is obsolete - it's here for backwards-compatibility only */
#define TAR_IGNORE_MAGIC	0

extern const char libtar_version[];


/* open a new tarfile handle */
int tar_open(TAR **t, const char *pathname, tartype_t *type,
	     int oflags, int mode, int options);

/* make a tarfile handle out of a previously-opened descriptor */
int tar_fdopen(TAR **t, int fd, const char *pathname, tartype_t *type,
	       int oflags, int mode, int options);

/* returns the descriptor associated with t */
int tar_fd(TAR *t);

/* close tarfile handle */
int tar_close(TAR *t);

/* fd ring (restore write side): deferred output FADV. fd_ring_setup() raises
 * RLIMIT_NOFILE to hard + allocates the ring (cap fds); the worker calls it after
 * openTar (only !adbbackup). fd_ring_drain() FADVs + closes all remaining fds +
 * frees, on all extractTar return paths before tar_close. Definitions in extract.c. */
void fd_ring_setup(TAR *t, int cap);
void fd_ring_drain(TAR *t);


/***** append.c ************************************************************/

/* forward declaration to appease the compiler */
struct tar_dev;

/* cleanup function */
void tar_dev_free(struct tar_dev *tdp);

/* Appends a file to the tar archive.
 * Arguments:
 *    t        = TAR handle to append to
 *    realname = path of file to append
 *    savename = name to save the file under in the archive
 */
int tar_append_file(TAR *t, const char *realname, const char *savename);

/* write EOF indicator */
int tar_append_eof(TAR *t);

/* add file contents to a tarchive */
int tar_append_regfile(TAR *t, const char *realname);

/* Appends in-memory file contents to a tarchive.
 * Arguments:
 *    t        = TAR handle to append to
 *    savename = name to save the file under in the archive
 *    mode     = mode
 *    uid, gid = owner
 *    buf, len = in-memory buffer
 */
int tar_append_file_contents(TAR *t, const char *savename, mode_t mode,
                             uid_t uid, gid_t gid, void *buf, size_t len);

/* add buffer to a tarchive */
int tar_append_buffer(TAR *t, void *buf, size_t len);

/***** block.c *************************************************************/

/* macros for reading/writing tarchive blocks */
#define tar_block_read(t, buf) \
	(*((t)->type->readfunc))((t)->fd, (char *)(buf), T_BLOCKSIZE)
#define tar_block_write(t, buf) \
	(*((t)->type->writefunc))((t)->fd, (char *)(buf), T_BLOCKSIZE)

/* read/write a header block */
int th_read(TAR *t);
int th_write(TAR *t);
/* write a POSIX pax GLOBAL extended header (typeflag 'g') carrying one record
 * "keyword=value" (keyword must include the trailing '='). Self-contained: it
 * builds a clean "pax_global_header" block, so callers may invoke it once at
 * archive start before any file. Returns 0 on success, -1 on error. */
int th_write_global(TAR *t, const char *keyword, const char *value);


/***** decode.c ************************************************************/

/* determine file type */
#define TH_ISREG(t)	((t)->th_buf.typeflag == REGTYPE \
			 || (t)->th_buf.typeflag == AREGTYPE \
			 || (t)->th_buf.typeflag == CONTTYPE \
			 || (S_ISREG((mode_t)oct_to_int((t)->th_buf.mode, sizeof((t)->th_buf.mode))) \
			     && (t)->th_buf.typeflag != LNKTYPE))
#define TH_ISLNK(t)	((t)->th_buf.typeflag == LNKTYPE)
#define TH_ISSYM(t)	((t)->th_buf.typeflag == SYMTYPE \
			 || S_ISLNK((mode_t)oct_to_int((t)->th_buf.mode, sizeof((t)->th_buf.mode))))
#define TH_ISCHR(t)	((t)->th_buf.typeflag == CHRTYPE \
			 || S_ISCHR((mode_t)oct_to_int((t)->th_buf.mode, sizeof((t)->th_buf.mode))))
#define TH_ISBLK(t)	((t)->th_buf.typeflag == BLKTYPE \
			 || S_ISBLK((mode_t)oct_to_int((t)->th_buf.mode, sizeof((t)->th_buf.mode))))
#define TH_ISDIR(t)	((t)->th_buf.typeflag == DIRTYPE \
			 || S_ISDIR((mode_t)oct_to_int((t)->th_buf.mode, sizeof((t)->th_buf.mode))) \
			 || ((t)->th_buf.typeflag == AREGTYPE \
			     && strnlen((t)->th_buf.name, T_NAMELEN) \
			     && ((t)->th_buf.name[strnlen((t)->th_buf.name, T_NAMELEN) - 1] == '/')))
#define TH_ISFIFO(t)	((t)->th_buf.typeflag == FIFOTYPE \
			 || S_ISFIFO((mode_t)oct_to_int((t)->th_buf.mode, sizeof((t)->th_buf.mode))))
#define TH_ISLONGNAME(t)	((t)->th_buf.typeflag == GNU_LONGNAME_TYPE)
#define TH_ISLONGLINK(t)	((t)->th_buf.typeflag == GNU_LONGLINK_TYPE)
#define TH_ISEXTHEADER(t)	((t)->th_buf.typeflag == TH_EXT_TYPE)
#define TH_ISPOLHEADER(t)	((t)->th_buf.typeflag == TH_POL_TYPE_DO_NOT_USE)
#define TH_ISGLOBALHEADER(t)	((t)->th_buf.typeflag == TH_GLOBAL_TYPE)

/* decode tar header info */
#define th_get_crc(t) oct_to_int((t)->th_buf.chksum, sizeof((t)->th_buf.chksum))
#define th_get_size(t) oct_to_int_ex((t)->th_buf.size, sizeof((t)->th_buf.size))
#define th_get_mtime(t) oct_to_int_ex((t)->th_buf.mtime, sizeof((t)->th_buf.mtime))
#define th_get_devmajor(t) oct_to_int((t)->th_buf.devmajor, sizeof((t)->th_buf.devmajor))
#define th_get_devminor(t) oct_to_int((t)->th_buf.devminor, sizeof((t)->th_buf.devminor))
#define th_get_linkname(t) ((t)->th_buf.gnu_longlink \
                            ? (t)->th_buf.gnu_longlink \
                            : (t)->th_buf.linkname)
char *th_get_pathname(TAR *t);
mode_t th_get_mode(TAR *t);
uid_t th_get_uid(TAR *t);
gid_t th_get_gid(TAR *t);


/***** encode.c ************************************************************/

/* encode file info in th_header */
void th_set_type(TAR *t, mode_t mode);
void th_set_path(TAR *t, const char *pathname);
void th_set_link(TAR *t, const char *linkname);
void th_set_device(TAR *t, dev_t device);
void th_set_user(TAR *t, uid_t uid);
void th_set_group(TAR *t, gid_t gid);
void th_set_mode(TAR *t, mode_t fmode);
#define th_set_mtime(t, fmtime) \
	int_to_oct_ex((fmtime), (t)->th_buf.mtime, sizeof((t)->th_buf.mtime))
#define th_set_size(t, fsize) \
	int_to_oct_ex((fsize), (t)->th_buf.size, sizeof((t)->th_buf.size))

/* encode everything at once (except the pathname and linkname) */
void th_set_from_stat(TAR *t, struct stat *s);

/* encode magic, version, and crc - must be done after everything else is set */
void th_finish(TAR *t);


/***** extract.c ***********************************************************/

/* sequentially extract next file from t */
int tar_extract_file(TAR *t, const char *realname, const char *prefix, const int *progress_fd);

/* extract different file types */
int tar_extract_dir(TAR *t, const char *realname);
int tar_extract_hardlink(TAR *t, const char *realname, const char *prefix);
int tar_extract_symlink(TAR *t, const char *realname);
int tar_extract_chardev(TAR *t, const char *realname);
int tar_extract_blockdev(TAR *t, const char *realname);
int tar_extract_fifo(TAR *t, const char *realname);

/* for regfiles, we need to extract the content blocks as well */
int tar_extract_regfile(TAR *t, const char *realname, const int *progress_fd);
int tar_skip_regfile(TAR *t);

/* extract regfile to buffer */
int tar_extract_file_contents(TAR *t, void *buf, size_t *lenp);

/***** output.c ************************************************************/

/* print the tar header */
void th_print(TAR *t);

/* print "ls -l"-like output for the file described by th */
void th_print_long_ls(TAR *t);


/***** util.c *************************************************************/

/* hashing function for pathnames */
int path_hashfunc(char *key, int numbuckets);

/* matching function for dev_t's */
int dev_match(dev_t *dev1, dev_t *dev2);

/* matching function for ino_t's */
int ino_match(ino_t *ino1, ino_t *ino2);

/* hashing function for dev_t's */
int dev_hash(dev_t *dev);

/* hashing function for ino_t's */
int ino_hash(ino_t *inode);

/* create any necessary dirs */
int mkdirhier(char *path);

/* calculate header checksum */
int th_crc_calc(TAR *t);

/* calculate a signed header checksum */
int th_signed_crc_calc(TAR *t);

/* compare checksums in a forgiving way */
#define th_crc_ok(t) (th_get_crc(t) == th_crc_calc(t) || th_get_crc(t) == th_signed_crc_calc(t))

/* string-octal to integer conversion */
int64_t oct_to_int(char *oct, size_t len);

/* string-octal or binary to integer conversion */
int64_t oct_to_int_ex(char *oct, size_t len);

/* integer to NULL-terminated string-octal conversion */
void int_to_oct(int64_t num, char *oct, size_t octlen);

/* integer to string-octal conversion, or binary as necessary */
void int_to_oct_ex(int64_t num, char *oct, size_t octlen);

/* prints posix file capabilities */
void print_caps(struct vfs_cap_data *cap_data);


/***** wrapper.c **********************************************************/

/* extract groups of files */
int tar_extract_glob(TAR *t, char *globname, char *prefix);
/* dfp_done_fd: directory-first-processing signal. If >= 0,
 * tar_extract_all() writes 1 byte once to this fd on the FIRST non-DIR header
 * (= all directories of this archive extracted). The restore parent then
 * releases the file pipes. -1 = no signal. */
int tar_extract_all(TAR *t, char *prefix, const int *progress_fd, int dfp_done_fd, const char *exclude_relpath);

/* add a whole tree of files */
int tar_append_tree(TAR *t, char *realdir, char *savedir);

/* find an entry */
int tar_find(TAR *t, char *searchstr);

/* Join prefix + "/" + filename into buf and collapse any run of consecutive
 * '/'. Handles NULL/empty prefix or filename, prefix ending in '/', filename
 * starting with '/'. Trailing '/' on filename is preserved (directory
 * entries). Cosmetic fix for upstream libtar's double-slash log spam in
 * tar_extract_all() / tar_extract_hardlink(); Linux already normalises '//'
 * → '/' so semantics are unchanged.
 *
 * Returns 0 on success, -1 on (a) NULL buf or bufsz==0, or (b) snprintf
 * truncation (joined result wouldn't fit in bufsz including NUL). Caller can
 * use the return value to detect path-length overflow exactly, instead of
 * relying on length heuristics that can false-positive on slash-normalisation. */
int  libtar_path_join(char *buf, size_t bufsz,
                      const char *prefix, const char *filename);

#ifdef __cplusplus
}
#endif

#endif /* ! LIBTAR_H */


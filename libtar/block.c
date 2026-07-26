/*
**  Copyright 1998-2003 University of Illinois Board of Trustees
**  Copyright 1998-2003 Mark D. Roth
**  All rights reserved.
**
**  block.c - libtar code to handle tar archive header blocks
**
**  Mark D. Roth <roth@uiuc.edu>
**  Campus Information Technologies and Educational Services
**  University of Illinois at Urbana-Champaign
*/

#include <internal.h>
#include <errno.h>
#include <unistd.h>

#ifdef STDC_HEADERS
# include <string.h>
# include <stdlib.h>
#endif

#ifdef TW_LIBTAR_DEBUG
#define DEBUG 1
#endif

#ifdef USE_FSCRYPT
#include "fscrypt_policy.h"
#endif

#define BIT_ISSET(bitmask, bit) ((bitmask) & (bit))

// Used to identify selinux_context in extended ('x')
// metadata. From RedHat implementation.
#define SELINUX_TAG "RHT.security.selinux="
#define SELINUX_TAG_LEN strlen(SELINUX_TAG)

// Used to identify fscrypt_policy in extended ('x')
#define FSCRYPT_TAG "TWRP.security.fscrypt="
#define FSCRYPT_TAG_LEN strlen(FSCRYPT_TAG)

// Used to identify Posix capabilities in extended ('x')
#define CAPABILITIES_TAG "SCHILY.xattr.security.capability="
#define CAPABILITIES_TAG_LEN strlen(CAPABILITIES_TAG)

// Used to identify Android user.default xattr in extended ('x')
#define ANDROID_USER_DEFAULT_TAG "ANDROID.user.default"
#define ANDROID_USER_DEFAULT_TAG_LEN strlen(ANDROID_USER_DEFAULT_TAG)

// Used to identify Android user.inode_cache xattr in extended ('x')
#define ANDROID_USER_CACHE_TAG "ANDROID.user.inode_cache"
#define ANDROID_USER_CACHE_TAG_LEN strlen(ANDROID_USER_CACHE_TAG)

// Used to identify Android user.inode_code_cache xattr in extended ('x')
#define ANDROID_USER_CODE_CACHE_TAG "ANDROID.user.inode_code_cache"
#define ANDROID_USER_CODE_CACHE_TAG_LEN strlen(ANDROID_USER_CODE_CACHE_TAG)

/* ---------------------------------------------------------------------------
 * tar_io_read / tar_io_write -- the central robust block-I/O primitive for
 * FD-BACKED tar handles. Single source of truth for both the backup AND restore
 * direction (default_type in handle.c, tar_type in twrpTar.cpp, the bulk path in
 * append.c, write_tar_no_buffer in tarWrite.c). Ring-backed tar handles do not
 * pass through here — they use the ring callbacks in stage_engine.cpp, which
 * honour the same full-read contract.
 *
 * A tar fd is not always a regular file: on the ADB paths it is a FIFO, and POSIX
 * allows read() on a FIFO to return short reads (< requested bytes) whenever the
 * writer has not filled it yet. All libtar callers (th_read_internal,
 * tar_extract_regfile, tar_skip_regfile, ...) treat any result != T_BLOCKSIZE as
 * EOF/truncation -> restore abort, so the refill below is what keeps a partially
 * filled FIFO from looking like a truncated archive.
 *
 * tar_io_read:  fills buf up to count; returns count, and 0..count-1 only on a
 *               real EOF (the writer closed the fd), -1 on error. EINTR-safe.
 *               Transient short reads are refilled (a blocking read on an open
 *               FIFO waits for data).
 * tar_io_write: writes all count bytes; returns count or -1. EINTR- and
 *               partial-write-safe (needed for bulk writes > PIPE_BUF in
 *               tar_append_regfile).
 *
 * Happy path (the fd delivers full blocks) = 1 syscall per call, byte-identical
 * to bare read/write -- no performance loss.
 */
ssize_t
tar_io_read(int fd, void *buf, size_t count)
{
	size_t total = 0;

	while (total < count)
	{
		ssize_t n = read(fd, (char *)buf + total, count - total);
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;	/* real EOF: writer closed fd/pipe */
		total += n;
	}
	return (ssize_t)total;
}

ssize_t
tar_io_write(int fd, const void *buf, size_t count)
{
	size_t total = 0;

	while (total < count)
	{
		ssize_t n = write(fd, (const char *)buf + total, count - total);
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			return -1;
		}
		total += n;
	}
	return (ssize_t)count;
}


/* read a header block */
/* FIXME: the return value of this function should match the return value
	  of tar_block_read(), which is a macro which references a prototype
	  that returns a ssize_t.  So far, this is safe, since tar_block_read()
	  only ever reads 512 (T_BLOCKSIZE) bytes at a time, so any difference
	  in size of ssize_t and int is of negligible risk.  BUT, if
	  T_BLOCKSIZE ever changes, or ever becomes a variable parameter
	  controllable by the user, all the code that calls it,
	  including this function and all code that calls it, should be
	  fixed for security reasons.
	  Thanks to Chris Palmer for the critique.
*/
int
th_read_internal(TAR *t)
{
	int i;
	int num_zero_blocks = 0;

#ifdef DEBUG
	printf("==> th_read_internal(TAR=\"%s\")\n", t->pathname);
#endif

	while ((i = tar_block_read(t, &(t->th_buf))) == T_BLOCKSIZE)
	{
		/* two all-zero blocks mark EOF */
		if (t->th_buf.name[0] == '\0')
		{
			num_zero_blocks++;
			if (!BIT_ISSET(t->options, TAR_IGNORE_EOT)
			    && num_zero_blocks >= 2)
				return 0;	/* EOF */
			else
				continue;
		}

		/* verify magic and version */
		if (BIT_ISSET(t->options, TAR_CHECK_MAGIC)
		    && strncmp(t->th_buf.magic, TMAGIC, TMAGLEN - 1) != 0)
		{
#ifdef DEBUG
			puts("!!! unknown magic value in tar header");
#endif
			return -2;
		}

		if (BIT_ISSET(t->options, TAR_CHECK_VERSION)
		    && strncmp(t->th_buf.version, TVERSION, TVERSLEN) != 0)
		{
#ifdef DEBUG
			puts("!!! unknown version value in tar header");
#endif
			return -2;
		}

		/* check chksum */
		if (!BIT_ISSET(t->options, TAR_IGNORE_CRC)
		    && !th_crc_ok(t))
		{
#ifdef DEBUG
			puts("!!! tar header checksum error");
#endif
			return -2;
		}

		break;
	}

#ifdef DEBUG
	printf("<== th_read_internal(): returning %d\n", i);
#endif
	return i;
}


/* wrapper function for th_read_internal() to handle GNU extensions */
int
th_read(TAR *t)
{
	int i;
	size_t sz, j, blocks;
	char *ptr;

#ifdef DEBUG
	printf("==> th_read(t=0x%p)\n", (void *)t);
#endif

	if (t->th_buf.gnu_longname != NULL)
		free(t->th_buf.gnu_longname);
	if (t->th_buf.gnu_longlink != NULL)
		free(t->th_buf.gnu_longlink);
	if (t->th_buf.selinux_context != NULL)
		free(t->th_buf.selinux_context);

#ifdef USE_FSCRYPT
	if (t->th_buf.fep != NULL)
		free(t->th_buf.fep);
#endif

	if (t->th_buf.has_cap_data)
	{
		memset(&t->th_buf.cap_data, 0, sizeof(struct vfs_cap_data));
		t->th_buf.has_cap_data = 0;
	}
	t->th_buf.has_user_default = 0;
	t->th_buf.has_user_cache = 0;
	t->th_buf.has_user_code_cache = 0;

	memset(&(t->th_buf), 0, sizeof(struct tar_header));
	/* -1 = "PAX global TWRP.* record absent". Set once per th_read here; the
	 * skip loop below overwrites it if a 'g' header carries the record, and the
	 * value then persists onto the file header this call ultimately returns. */
	t->th_buf.global_tartype = -1;
	t->th_buf.global_ead = -1;

	i = th_read_internal(t);
	if (i == 0)
		return 1;
	else if (i != T_BLOCKSIZE)
	{
		if (i != -1)
			errno = EINVAL;
		return -1;
	}

	/* Special headers (GNU 'K'/'L', ext 'x'/'p', PAX-global 'g') may precede
	 * the real file header in ANY order. POSIX places 'g' records at archive
	 * start, i.e. our TWRP.* segment-start records sit BEFORE the first
	 * file's 'K'/'L' header. The ladder below is one-way (K -> L -> x/p/g
	 * loop), so after the x/p/g loop we jump back here if it stopped on a
	 * K/L block; otherwise a >=100-char first path lost its longname and
	 * was extracted under the truncated 100-byte name field. */
read_special_headers:
	/* check for GNU long link extention */
	if (TH_ISLONGLINK(t))
	{
		sz = th_get_size(t);
		blocks = (sz / T_BLOCKSIZE) + (sz % T_BLOCKSIZE ? 1 : 0);
		if (blocks > ((size_t)-1 / T_BLOCKSIZE))
		{
			errno = E2BIG;
			return -1;
		}
#ifdef DEBUG
		printf("    th_read(): GNU long linkname detected "
		       "(%zu bytes, %zu blocks)\n", sz, blocks);
#endif
		if (t->th_buf.gnu_longlink != NULL)
			free(t->th_buf.gnu_longlink);	/* malformed double-'K' -- don't leak */
		t->th_buf.gnu_longlink = (char *)malloc(blocks * T_BLOCKSIZE);
		if (t->th_buf.gnu_longlink == NULL)
			return -1;

		for (j = 0, ptr = t->th_buf.gnu_longlink; j < blocks;
		     j++, ptr += T_BLOCKSIZE)
		{
#ifdef DEBUG
			printf("    th_read(): reading long linkname "
			       "(%zu blocks left, ptr == %p)\n", blocks-j, (void *) ptr);
#endif
			i = tar_block_read(t, ptr);
			if (i != T_BLOCKSIZE)
			{
				if (i != -1)
					errno = EINVAL;
				return -1;
			}
#ifdef DEBUG
			printf("    th_read(): read block == \"%s\"\n", ptr);
#endif
		}
#ifdef DEBUG
		printf("    th_read(): t->th_buf.gnu_longlink == \"%s\"\n",
		       t->th_buf.gnu_longlink);
#endif

		i = th_read_internal(t);
		if (i != T_BLOCKSIZE)
		{
			if (i != -1)
				errno = EINVAL;
			return -1;
		}
	}

	/* check for GNU long name extention */
	if (TH_ISLONGNAME(t))
	{
		sz = th_get_size(t);
		blocks = (sz / T_BLOCKSIZE) + (sz % T_BLOCKSIZE ? 1 : 0);
		if (blocks > ((size_t)-1 / T_BLOCKSIZE))
		{
			errno = E2BIG;
			return -1;
		}
#ifdef DEBUG
		printf("    th_read(): GNU long filename detected "
		       "(%zu bytes, %zu blocks)\n", sz, blocks);
#endif
		if (t->th_buf.gnu_longname != NULL)
			free(t->th_buf.gnu_longname);	/* malformed double-'L' -- don't leak */
		t->th_buf.gnu_longname = (char *)malloc(blocks * T_BLOCKSIZE);
		if (t->th_buf.gnu_longname == NULL)
			return -1;

		for (j = 0, ptr = t->th_buf.gnu_longname; j < blocks;
		     j++, ptr += T_BLOCKSIZE)
		{
#ifdef DEBUG
			printf("    th_read(): reading long filename "
			       "(%zu blocks left, ptr == %p)\n", blocks-j, (void *) ptr);
#endif
			i = tar_block_read(t, ptr);
			if (i != T_BLOCKSIZE)
			{
				if (i != -1)
					errno = EINVAL;
				return -1;
			}
#ifdef DEBUG
			printf("    th_read(): read block == \"%s\"\n", ptr);
#endif
		}
#ifdef DEBUG
		printf("    th_read(): t->th_buf.gnu_longname == \"%s\"\n",
		       t->th_buf.gnu_longname);
#endif

		i = th_read_internal(t);
		if (i != T_BLOCKSIZE)
		{
			if (i != -1)
				errno = EINVAL;
			return -1;
		}
	}

	// Extended headers (selinux contexts, posix file capabilities and encryption policies)
	while(TH_ISEXTHEADER(t) || TH_ISPOLHEADER(t) || TH_ISGLOBALHEADER(t))
	{
		sz = th_get_size(t);

		if(sz >= T_BLOCKSIZE) // Not supported
		{
#ifdef DEBUG
			printf("    th_read(): Extended header is too long!\n");
#endif
		}
		else
		{
			char buf[T_BLOCKSIZE];
			i = tar_block_read(t, buf);
			if (i != T_BLOCKSIZE)
			{
				if (i != -1)
					errno = EINVAL;
				return -1;
			}

			// To be sure
			buf[T_BLOCKSIZE-1] = 0;

			int len = strlen(buf);
			// posix capabilities
			char *start = strstr(buf, CAPABILITIES_TAG);
			if (start && start+CAPABILITIES_TAG_LEN < buf+len)
			{
				start += CAPABILITIES_TAG_LEN;
				memcpy(&t->th_buf.cap_data, start, sizeof(struct vfs_cap_data));
				t->th_buf.has_cap_data = 1;
#ifdef DEBUG
				printf("    th_read(): Posix capabilities detected\n");
#endif
			} // end posix capabilities
			// selinux contexts
			start = strstr(buf, SELINUX_TAG);
			if (start && start+SELINUX_TAG_LEN < buf+len)
			{
				start += SELINUX_TAG_LEN;
				char *end = strchr(start, '\n');
				if(end)
				{
					t->th_buf.selinux_context = strndup(start, end-start);
#ifdef DEBUG
					printf("    th_read(): SELinux context xattr detected: %s\n", t->th_buf.selinux_context);
#endif
				}
			} // end selinux contexts
			// android user.default xattr
			start = strstr(buf, ANDROID_USER_DEFAULT_TAG);
			if (start)
			{
				t->th_buf.has_user_default = 1;
#ifdef DEBUG
				printf("    th_read(): android user.default xattr detected\n");
#endif
			} // end android user.default xattr
			// android user.inode_cache xattr
			start = strstr(buf, ANDROID_USER_CACHE_TAG);
			if (start)
			{
				t->th_buf.has_user_cache = 1;
#ifdef DEBUG
				printf("    th_read(): android user.inode_cache xattr detected\n");
#endif
			} // end android user.inode_cache xattr
			// android user.inode_code_cache xattr
			start = strstr(buf, ANDROID_USER_CODE_CACHE_TAG);
			if (start)
			{
				t->th_buf.has_user_code_cache = 1;
#ifdef DEBUG
				printf("    th_read(): android user.inode_code_cache xattr detected\n");
#endif
			} // end android user.inode_code_cache xattr

#ifdef USE_FSCRYPT
			start = strstr(buf, FSCRYPT_TAG);
			if (start && start+FSCRYPT_TAG_LEN < buf+len) {
#ifdef USE_FSCRYPT_POLICY_V1
				t->th_buf.fep = (struct fscrypt_policy_v1*)malloc(sizeof(struct fscrypt_policy_v1));
#else
				t->th_buf.fep = (struct fscrypt_policy_v2*)malloc(sizeof(struct fscrypt_policy_v2));
#endif
				if (!t->th_buf.fep) {
					printf("malloc failed for fscrypt policy\n");
					return -1;
				}
				start += FSCRYPT_TAG_LEN;
				if (*start == '0') {
					start++;
#ifdef USE_FSCRYPT_POLICY_V1
					char *newline_check = start + sizeof(struct fscrypt_policy_v1);
#else
					char *newline_check = start + sizeof(struct fscrypt_policy_v2);
#endif
					if (*newline_check != '\n')
						printf("did not find newline char in expected location, continuing anyway...\n");
#ifdef USE_FSCRYPT_POLICY_V1
					memcpy(t->th_buf.fep, start, sizeof(struct fscrypt_policy_v1));
#else
					memcpy(t->th_buf.fep, start, sizeof(struct fscrypt_policy_v2));
#endif
#ifdef DEBUG
					printf("    th_read(): FSCrypt policy detected: %i %i %i %i %s\n",
						(int)t->th_buf.fep->version,
						(int)t->th_buf.fep->contents_encryption_mode,
						(int)t->th_buf.fep->filenames_encryption_mode,
						(int)t->th_buf.fep->flags,
#ifdef USE_FSCRYPT_POLICY_V1
						t->th_buf.fep->master_key_descriptor);
#else
						t->th_buf.fep->master_key_identifier);
#endif
#endif
				}
				else {
					printf("     invalid fscrypt header found\n");
				}
			}
#endif // USE_FSCRYPT

			/* PAX GLOBAL header (typeflag 'g'): TWRP self-describing markers
			 * (TWRP.tartype/TWRP.ead) are parsed here into t->th_buf.global_*
			 * (archive-wide, in-memory, never serialised). The fields are
			 * currently unread: the archive type has to be known BEFORE the first
			 * th_read (it selects the restore pipeline), so BackupHeaderManager
			 * peeks the records itself. Kept as libtar-level self-describing
			 * infrastructure. Guarded on 'g' so an 'x' payload cannot false-match
			 * "TWRP.*". */
			if (TH_ISGLOBALHEADER(t))
			{
				start = strstr(buf, TWRP_TARTYPE_TAG);
				if (start)
					t->th_buf.global_tartype = atoi(start + TWRP_TARTYPE_TAG_LEN);
				start = strstr(buf, TWRP_EAD_TAG);
				if (start)
					t->th_buf.global_ead = atoi(start + TWRP_EAD_TAG_LEN);
			}
		}

		i = th_read_internal(t);
		if (i != T_BLOCKSIZE)
		{
			if (i != -1)
				errno = EINVAL;
			return -1;
		}
	}

	/* The x/p/g skip loop stopped on a GNU 'K'/'L' block (segment-start 'g'
	 * records preceded it) -> collect it too before returning a file header. */
	if (TH_ISLONGLINK(t) || TH_ISLONGNAME(t))
		goto read_special_headers;

	return 0;
}

/* write an extended block */
static int
th_write_extended(TAR *t, char* buf, uint64_t sz)
{
	char type2;
	uint64_t sz2;
	int i;

	/* save old size and type */
	type2 = t->th_buf.typeflag;
	sz2 = th_get_size(t);

	/* write out initial header block with fake size and type */
	t->th_buf.typeflag = TH_EXT_TYPE;

	if(sz >= T_BLOCKSIZE) // impossible
	{
		errno = EINVAL;
		return -1;
	}

	th_set_size(t, sz);
	th_finish(t);
	i = tar_block_write(t, &(t->th_buf));
	if (i != T_BLOCKSIZE)
	{
		if (i != -1)
			errno = EINVAL;
		return -1;
	}

	i = tar_block_write(t, buf);
	if (i != T_BLOCKSIZE)
	{
		if (i != -1)
			errno = EINVAL;
		return -1;
	}

	/* reset type and size to original values */
	t->th_buf.typeflag = type2;
	th_set_size(t, sz2);
	memset(buf, 0, T_BLOCKSIZE);
	return 0;
}

/* write a POSIX pax GLOBAL extended header (archive-wide). keyword must include
 * the trailing '=' (e.g. "TWRP.tartype="). Standard pax "<len> keyword=value\n"
 * framing -> GNU/bsdtar parse it and ignore unknown vendor keys, so the archive
 * stays openable with stock tools. Single 512-byte payload block (same limit as
 * the th_read extended-header reader). Side-effect-free on t->th_buf (saved and
 * restored), so it may be called once at archive start before any file. */
int
th_write_global(TAR *t, const char *keyword, const char *value)
{
	struct tar_header save = t->th_buf;
	char buf[T_BLOCKSIZE];
	size_t body, len;
	int i;

	memset(buf, 0, T_BLOCKSIZE);
	/* record length counts its own ascii digits: <len> + ' ' + key + value + '\n' */
	body = 1 + strlen(keyword) + strlen(value) + 1;
	len  = body + 1;
	if (len >= 10)  len = body + 2;
	if (len >= 100) len = body + 3;
	if (len >= T_BLOCKSIZE)
	{
		errno = EINVAL;
		return -1;
	}
	snprintf(buf, T_BLOCKSIZE, "%d %s%s\n", (int)len, keyword, value);

	/* build a clean global header from scratch (deterministic regardless of any
	 * prior th_buf state) */
	memset(&t->th_buf, 0, sizeof(t->th_buf));
	t->th_buf.typeflag = TH_GLOBAL_TYPE;
	th_set_mode(t, 0644);
	th_set_path(t, "pax_global_header");
	th_set_user(t, 0);
	th_set_group(t, 0);
	th_set_mtime(t, 0);
	th_set_size(t, len);
	th_finish(t);

	i = tar_block_write(t, &(t->th_buf));
	if (i == T_BLOCKSIZE)
		i = tar_block_write(t, buf);

	t->th_buf = save;
	if (i != T_BLOCKSIZE)
	{
		if (i != -1)
			errno = EINVAL;
		return -1;
	}
	return 0;
}

/* write a header block */
int
th_write(TAR *t)
{
	int i, j;
	char type2;
	uint64_t sz, sz2, total_sz = 0;
	char *ptr;
	char buf[T_BLOCKSIZE];

#ifdef DEBUG
	printf("==> th_write(TAR=\"%s\")\n", t->pathname);
	th_print(t);
#endif

	if ((t->options & TAR_GNU) && t->th_buf.gnu_longlink != NULL)
	{
#ifdef DEBUG
		printf("th_write(): using gnu_longlink (\"%s\")\n",
		       t->th_buf.gnu_longlink);
#endif
		/* save old size and type */
		type2 = t->th_buf.typeflag;
		sz2 = th_get_size(t);

		/* write out initial header block with fake size and type */
		t->th_buf.typeflag = GNU_LONGLINK_TYPE;
		sz = strlen(t->th_buf.gnu_longlink);
		th_set_size(t, sz);
		th_finish(t);
		i = tar_block_write(t, &(t->th_buf));
		if (i != T_BLOCKSIZE)
		{
			if (i != -1)
				errno = EINVAL;
			return -1;
		}

		/* write out extra blocks containing long name */
		for (j = (sz / T_BLOCKSIZE) + (sz % T_BLOCKSIZE ? 1 : 0),
		     ptr = t->th_buf.gnu_longlink; j > 1;
		     j--, ptr += T_BLOCKSIZE)
		{
			i = tar_block_write(t, ptr);
			if (i != T_BLOCKSIZE)
			{
				if (i != -1)
					errno = EINVAL;
				return -1;
			}
		}
		memset(buf, 0, T_BLOCKSIZE);
		strncpy(buf, ptr, T_BLOCKSIZE);
		i = tar_block_write(t, &buf);
		if (i != T_BLOCKSIZE)
		{
			if (i != -1)
				errno = EINVAL;
			return -1;
		}

		/* reset type and size to original values */
		t->th_buf.typeflag = type2;
		th_set_size(t, sz2);
	}

	if ((t->options & TAR_GNU) && t->th_buf.gnu_longname != NULL)
	{
#ifdef DEBUG
		printf("th_write(): using gnu_longname (\"%s\")\n",
		       t->th_buf.gnu_longname);
#endif
		/* save old size and type */
		type2 = t->th_buf.typeflag;
		sz2 = th_get_size(t);

		/* write out initial header block with fake size and type */
		t->th_buf.typeflag = GNU_LONGNAME_TYPE;
		sz = strlen(t->th_buf.gnu_longname);
		th_set_size(t, sz);
		th_finish(t);
		i = tar_block_write(t, &(t->th_buf));
		if (i != T_BLOCKSIZE)
		{
			if (i != -1)
				errno = EINVAL;
			return -1;
		}

		/* write out extra blocks containing long name */
		for (j = (sz / T_BLOCKSIZE) + (sz % T_BLOCKSIZE ? 1 : 0),
		     ptr = t->th_buf.gnu_longname; j > 1;
		     j--, ptr += T_BLOCKSIZE)
		{
			i = tar_block_write(t, ptr);
			if (i != T_BLOCKSIZE)
			{
				if (i != -1)
					errno = EINVAL;
				return -1;
			}
		}
		memset(buf, 0, T_BLOCKSIZE);
		strncpy(buf, ptr, T_BLOCKSIZE);
		i = tar_block_write(t, &buf);
		if (i != T_BLOCKSIZE)
		{
			if (i != -1)
				errno = EINVAL;
			return -1;
		}

		/* reset type and size to original values */
		t->th_buf.typeflag = type2;
		th_set_size(t, sz2);
	}

	memset(buf, 0, T_BLOCKSIZE);
	ptr = buf;

	if((t->options & TAR_STORE_SELINUX) && t->th_buf.selinux_context != NULL)
	{
#ifdef DEBUG
		printf("th_write(): using selinux_context (\"%s\")\n",
		       t->th_buf.selinux_context);
#endif
		/* setup size - EXT header has format "*size of this whole tag as ascii numbers* *space* *content* *newline* */
		//                                                       size   newline
		sz = SELINUX_TAG_LEN + strlen(t->th_buf.selinux_context) + 3  +    1;

		if(sz >= 100) // another ascci digit for size
			++sz;

		total_sz += sz;
		snprintf(ptr, T_BLOCKSIZE, "%d "SELINUX_TAG"%s\n", (int)sz, t->th_buf.selinux_context);
		ptr += sz;
	}

#ifdef USE_FSCRYPT
	if((t->options & TAR_STORE_FSCRYPT_POL) && t->th_buf.fep != NULL)
	{
#ifdef DEBUG
#ifdef USE_FSCRYPT_POLICY_V1
		printf("th_write(): using fscrypt_policy %s\n",
		       t->th_buf.fep->master_key_descriptor);
#else
		printf("th_write(): using fscrypt_policy %s\n",
		       t->th_buf.fep->master_key_identifier);
#endif
#endif
		/* setup size - EXT header has format "*size of this whole tag as ascii numbers* *space* *version code* *content* *newline* */
		//                                                       size   newline
#ifdef USE_FSCRYPT_POLICY_V1
		sz = FSCRYPT_TAG_LEN + sizeof(struct fscrypt_policy_v1) + 1 + 3  +    1;
#else
		sz = FSCRYPT_TAG_LEN + sizeof(struct fscrypt_policy_v2) + 1 + 3  +    1;
#endif

		if(sz >= 100) // another ascci digit for size
			++sz;

		if (total_sz + sz >= T_BLOCKSIZE)
		{
			if (th_write_extended(t, &buf[0], total_sz))
				return -1;
			ptr = buf;
			total_sz = sz;
		}
		else
			total_sz += sz;

		snprintf(ptr, T_BLOCKSIZE, "%d "FSCRYPT_TAG"0", (int)sz);
#ifdef USE_FSCRYPT_POLICY_V1
		memcpy(ptr + sz - sizeof(struct fscrypt_policy_v1) - 1, t->th_buf.fep, sizeof(struct fscrypt_policy_v1));
#else
		memcpy(ptr + sz - sizeof(struct fscrypt_policy_v2) - 1, t->th_buf.fep, sizeof(struct fscrypt_policy_v2));
#endif
		char *nlptr = ptr + sz - 1;
		*nlptr = '\n';
		ptr += sz;
	}
#endif

	if((t->options & TAR_STORE_POSIX_CAP) && t->th_buf.has_cap_data)
	{
#ifdef DEBUG
		printf("th_write(): has a posix capability\n");
#endif
		sz = CAPABILITIES_TAG_LEN + sizeof(struct vfs_cap_data) + 3 + 1;

		if(sz >= 100) // another ascci digit for size
			++sz;

		if (total_sz + sz >= T_BLOCKSIZE)
		{
			if (th_write_extended(t, &buf[0], total_sz))
				return -1;
			ptr = buf;
			total_sz = sz;
		}
		else
			total_sz += sz;

		snprintf(ptr, T_BLOCKSIZE, "%d "CAPABILITIES_TAG, (int)sz);
		memcpy(ptr + CAPABILITIES_TAG_LEN + 3, &t->th_buf.cap_data, sizeof(struct vfs_cap_data));
		char *nlptr = ptr + sz - 1;
		*nlptr = '\n';
		ptr += sz;
	}
	if (t->options & TAR_STORE_ANDROID_USER_XATTR)
	{
		if (t->th_buf.has_user_default) {
#ifdef DEBUG
			printf("th_write(): has android user.default xattr\n");
#endif
			sz = ANDROID_USER_DEFAULT_TAG_LEN + 3 + 1;

			if (total_sz + sz >= T_BLOCKSIZE)
			{
				if (th_write_extended(t, &buf[0], total_sz))
					return -1;
				ptr = buf;
				total_sz = sz;
			}
			else
				total_sz += sz;

			snprintf(ptr, T_BLOCKSIZE, "%d "ANDROID_USER_DEFAULT_TAG, (int)sz);
			char *nlptr = ptr + sz - 1;
			*nlptr = '\n';
			ptr += sz;
		}
		if (t->th_buf.has_user_cache) {
#ifdef DEBUG
			printf("th_write(): has android user.inode_cache xattr\n");
#endif
			sz = ANDROID_USER_CACHE_TAG_LEN + 3 + 1;

			if (total_sz + sz >= T_BLOCKSIZE)
			{
				if (th_write_extended(t, &buf[0], total_sz))
					return -1;
				ptr = buf;
				total_sz = sz;
			}
			else
				total_sz += sz;

			snprintf(ptr, T_BLOCKSIZE, "%d "ANDROID_USER_CACHE_TAG, (int)sz);
			char *nlptr = ptr + sz - 1;
			*nlptr = '\n';
			ptr += sz;
		}
		if (t->th_buf.has_user_code_cache) {
#ifdef DEBUG
			printf("th_write(): has android user.inode_code_cache xattr\n");
#endif
			sz = ANDROID_USER_CODE_CACHE_TAG_LEN + 3 + 1;

			if (total_sz + sz >= T_BLOCKSIZE)
			{
				if (th_write_extended(t, &buf[0], total_sz))
					return -1;
				ptr = buf;
				total_sz = sz;
			}
			else
				total_sz += sz;

			snprintf(ptr, T_BLOCKSIZE, "%d "ANDROID_USER_CODE_CACHE_TAG, (int)sz);
			char *nlptr = ptr + sz - 1;
			*nlptr = '\n';
			ptr += sz;
		}
	}
	if (total_sz > 0 && th_write_extended(t, &buf[0], total_sz)) // write any outstanding tar extended header
		return -1;

	th_finish(t);

#ifdef DEBUG
	/* print tar header */
	th_print(t);
#endif

	i = tar_block_write(t, &(t->th_buf));
	if (i != T_BLOCKSIZE)
	{
		if (i != -1)
			errno = EINVAL;
		return -1;
	}

#ifdef DEBUG
	puts("th_write(): returning 0");
#endif
	return 0;
}



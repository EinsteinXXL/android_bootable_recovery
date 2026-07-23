/*
 * fscrypt_policy_reader — read fscrypt v1/v2 policy of a directory via ioctl
 * and emit it as a hex string. Companion to /hash_files and /listxattr for the
 * verify_backup.py tool: lets the device side fill the `fscrypt_policy`
 * column instead of the previous stub `-`.
 *
 * The PAX record `TWRP.security.fscrypt=` written by TWRP libtar has the
 * wire format:
 *
 *     '0' + <binary fscrypt_policy_v1 OR _v2 struct> + '\n'
 *
 * (see android_bootable_recovery/libtar/block.c around line 630). The
 * leading '0' is a literal TWRP marker byte (0x30), not a version field.
 *
 * This tool emits ONLY the raw struct bytes as lowercase hex — without the
 * TWRP '0' prefix. The PC side strips that marker byte too: verify_backup.py
 * _get_fscrypt_from_pax removes the leading '0' (0x30) before returning its
 * hex, so the PC string also starts directly with the struct bytes. Both
 * sides are normalised at the source — the diff layer compares identical
 * struct hex and does no normalisation of its own.
 *
 * Output format (multi-arg, one line per path, matches /hash_files style):
 *
 *     <hex>  <path>\n
 *
 *   On "no policy set" / not a directory / no fscrypt on this fs:
 *     -  <path>\n
 *
 *   On hard error (ENOENT, EACCES, ...): line goes to stderr, "-  <path>"
 *   still emitted on stdout so the awk loader keeps alignment with input.
 *
 * Usage:  fscrypt_policy_reader [-v1|-v2|-auto] dir1 [dir2 ...]
 *   -auto  (default) try _EX (returns v1 or v2 depending on kernel/fs),
 *          fall back to legacy v1 ioctl on EINVAL/ENOTTY.
 *   -v1    force legacy FS_IOC_GET_ENCRYPTION_POLICY (32-byte v1 struct).
 *   -v2    force FS_IOC_GET_ENCRYPTION_POLICY_EX and require v2 result.
 *
 * Exit code: 0 if all paths processed (incl. "no policy" lines).
 *            1 if any path produced a hard error.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

/* --------------------------------------------------------------------------
 * fscrypt UAPI structs/ioctls.
 *
 * We define these locally rather than relying on <linux/fscrypt.h> so the
 * tool builds against older kernel-header sets in the recovery NDK sysroot.
 * Layout is taken from upstream Linux include/uapi/linux/fscrypt.h and the
 * fscrypt headers shipped with android_bootable_recovery (libtar uses the
 * same on-disk wire format).
 * -------------------------------------------------------------------------- */

#ifndef FS_KEY_DESCRIPTOR_SIZE
#define FS_KEY_DESCRIPTOR_SIZE 8
#endif

#ifndef FSCRYPT_KEY_IDENTIFIER_SIZE
#define FSCRYPT_KEY_IDENTIFIER_SIZE 16
#endif

struct fscrypt_policy_v1_local {
    uint8_t version;                                   /* 0 */
    uint8_t contents_encryption_mode;
    uint8_t filenames_encryption_mode;
    uint8_t flags;
    uint8_t master_key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
};

struct fscrypt_policy_v2_local {
    uint8_t version;                                   /* 2 */
    uint8_t contents_encryption_mode;
    uint8_t filenames_encryption_mode;
    uint8_t flags;
    uint8_t __reserved[4];
    uint8_t master_key_identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
};

struct fscrypt_get_policy_ex_arg_local {
    uint64_t policy_size;       /* in/out */
    union {
        uint8_t version;
        struct fscrypt_policy_v1_local v1;
        struct fscrypt_policy_v2_local v2;
    } policy;
};

#ifndef FS_IOC_GET_ENCRYPTION_POLICY
#define FS_IOC_GET_ENCRYPTION_POLICY    _IOW('f', 21, struct fscrypt_policy_v1_local)
#endif

#ifndef FS_IOC_GET_ENCRYPTION_POLICY_EX
#define FS_IOC_GET_ENCRYPTION_POLICY_EX _IOWR('f', 22, uint8_t[9])  /* opaque size */
#endif

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

static void bytes_to_hex(const uint8_t *bytes, size_t n, char *out) {
    static const char *hexdig = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i]     = hexdig[(bytes[i] >> 4) & 0xF];
        out[2*i + 1] = hexdig[bytes[i] & 0xF];
    }
    out[2*n] = '\0';
}

enum { MODE_AUTO, MODE_V1, MODE_V2 };

/*
 * Read the policy of `path` and write its hex form into `hex_out`
 * (must hold 2*max_struct + 1 bytes; v2 = 32 bytes -> 65 chars suffices).
 *
 * Returns:
 *   0  policy read OK, hex_out filled
 *   1  no policy set (or fs not fscrypt) — caller emits "-"
 *  -1  hard error  — caller emits "-" and sets any_err
 */
static int read_policy(const char *path, int mode, char *hex_out) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "fscrypt_policy_reader: %s: %s\n", path, strerror(errno));
        return -1;
    }
    /* fscrypt is a directory-level property. Plain files inherit from
     * their parent dir's policy; we don't traverse — only emit policies
     * for actual directories. Anything else: "-". */
    if (!S_ISDIR(st.st_mode)) return 1;

    int fd = open(path, O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT || errno == EACCES) {
            fprintf(stderr, "fscrypt_policy_reader: %s: %s\n", path, strerror(errno));
            return -1;
        }
        fprintf(stderr, "fscrypt_policy_reader: %s: open: %s\n", path, strerror(errno));
        return -1;
    }

    int rc = -1;
    if (mode == MODE_AUTO || mode == MODE_V2) {
        struct fscrypt_get_policy_ex_arg_local ex;
        memset(&ex, 0, sizeof(ex));
        ex.policy_size = sizeof(ex.policy);
        if (ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY_EX, &ex) == 0) {
            if (ex.policy.version == 0) {
                bytes_to_hex((uint8_t*)&ex.policy.v1, sizeof(ex.policy.v1), hex_out);
            } else {
                /* v2 (and any future versions copy through as-is up to the
                 * reported policy_size). For our use case it's always v2. */
                size_t n = sizeof(ex.policy.v2);
                if (ex.policy_size && ex.policy_size <= sizeof(ex.policy)) n = (size_t)ex.policy_size;
                bytes_to_hex((uint8_t*)&ex.policy, n, hex_out);
            }
            rc = 0;
        } else if (errno == ENODATA) {
            rc = 1;  /* no policy on this dir */
        } else if (mode == MODE_V2) {
            fprintf(stderr, "fscrypt_policy_reader: %s: ioctl_ex: %s\n", path, strerror(errno));
            rc = -1;
        } else {
            /* fall through to legacy */
        }
    }

    if (rc == -1 && (mode == MODE_AUTO || mode == MODE_V1)) {
        struct fscrypt_policy_v1_local v1;
        memset(&v1, 0, sizeof(v1));
        if (ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY, &v1) == 0) {
            bytes_to_hex((uint8_t*)&v1, sizeof(v1), hex_out);
            rc = 0;
        } else if (errno == ENODATA) {
            rc = 1;
        } else {
            fprintf(stderr, "fscrypt_policy_reader: %s: ioctl: %s\n", path, strerror(errno));
            rc = -1;
        }
    }

    close(fd);
    return rc;
}

static void usage(void) {
    fprintf(stderr,
        "Usage: fscrypt_policy_reader [-v1|-v2|-auto] dir1 [dir2 ...]\n"
        "  -auto  (default) try v2 then fall back to v1\n"
        "  -v1    force legacy FS_IOC_GET_ENCRYPTION_POLICY\n"
        "  -v2    force FS_IOC_GET_ENCRYPTION_POLICY_EX\n"
        "Output (one line per path):\n"
        "  <hex>  <path>     policy present\n"
        "  -      <path>     no policy / not a directory\n");
}

int main(int argc, char **argv) {
    int mode = MODE_AUTO;
    int argi = 1;

    if (argc >= 2) {
        if      (!strcmp(argv[1], "-auto")) { mode = MODE_AUTO; argi = 2; }
        else if (!strcmp(argv[1], "-v1"))   { mode = MODE_V1;   argi = 2; }
        else if (!strcmp(argv[1], "-v2"))   { mode = MODE_V2;   argi = 2; }
        else if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
            usage(); return 0;
        }
    }
    if (argi >= argc) { usage(); return 2; }

    /* hex buffer: v2 union holds the full ex.policy (24 bytes) which gives
     * 48 hex chars; size with the 8-byte policy_size we copy is bounded at
     * sizeof(ex.policy) = 24. 128 is plenty of headroom for future growth. */
    char hex[128];
    int any_err = 0;
    for (int i = argi; i < argc; i++) {
        int r = read_policy(argv[i], mode, hex);
        if (r == 0) {
            printf("%s  %s\n", hex, argv[i]);
        } else if (r == 1) {
            printf("-  %s\n", argv[i]);
        } else {
            printf("-  %s\n", argv[i]);
            any_err = 1;
        }
    }
    return any_err;
}

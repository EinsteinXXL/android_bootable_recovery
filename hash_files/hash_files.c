/*
 * hash_files — fast file hasher using BoringSSL libcrypto (HW-accelerated).
 *
 * Drop-in replacement for toybox sha256sum/sha1sum/md5sum when batching many
 * files. Multi-arg (one process, N files) eliminates per-file fork overhead,
 * and BoringSSL uses ARMv8 sha1/sha2 crypto extensions on capable cores
 * (Cortex-A55/A75/A76 on SDM855 etc.) — typically 5-10x faster than toybox
 * portable C implementations.
 *
 * Output format matches GNU coreutils / toybox: '<hex>  <path>\n'
 *
 * Usage: hash_files [-1|-256|-md5] file1 file2 ...
 *   -1     SHA-1   (default; fastest with HW ext)
 *   -256   SHA-256 (also HW-accelerated)
 *   -md5   MD5     (no HW path, fallback)
 *
 * Errors on individual files print to stderr and continue (don't kill batch).
 * Exit code: 0 on full success, 1 if any file failed.
 */
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

enum { ALGO_SHA1, ALGO_SHA256, ALGO_MD5 };

#define BUF_SIZE (1 << 20)  /* 1 MiB read buffer — good tradeoff for HW pipelining */

static int hash_one(const char *path, int algo, char *hex_out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "hash_files: %s: %s\n", path, strerror(errno));
        return -1;
    }

    static unsigned char buf[BUF_SIZE];
    SHA_CTX    ctx1;
    SHA256_CTX ctx256;
    MD5_CTX    ctxm;

    if      (algo == ALGO_SHA1)   SHA1_Init(&ctx1);
    else if (algo == ALGO_SHA256) SHA256_Init(&ctx256);
    else                          MD5_Init(&ctxm);

    ssize_t n;
    for (;;) {
        n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;  /* interrupted by signal — retry */
        if (n <= 0) break;                       /* EOF (0) or real read error (<0) */
        if      (algo == ALGO_SHA1)   SHA1_Update(&ctx1, buf, n);
        else if (algo == ALGO_SHA256) SHA256_Update(&ctx256, buf, n);
        else                          MD5_Update(&ctxm, buf, n);
    }
    int read_err = (n < 0) ? errno : 0;
    close(fd);

    if (read_err) {
        fprintf(stderr, "hash_files: %s: read: %s\n", path, strerror(read_err));
        return -1;
    }

    unsigned char raw[SHA256_DIGEST_LENGTH];
    int dlen;
    if      (algo == ALGO_SHA1)   { SHA1_Final(raw, &ctx1);   dlen = SHA_DIGEST_LENGTH; }
    else if (algo == ALGO_SHA256) { SHA256_Final(raw, &ctx256); dlen = SHA256_DIGEST_LENGTH; }
    else                          { MD5_Final(raw, &ctxm);   dlen = MD5_DIGEST_LENGTH; }

    for (int i = 0; i < dlen; i++)
        sprintf(hex_out + i*2, "%02x", raw[i]);
    hex_out[dlen*2] = 0;
    return 0;
}

static void usage(void) {
    fprintf(stderr,
        "Usage: hash_files [-1|-256|-md5] file1 [file2 ...]\n"
        "  -1     SHA-1   (default, HW-accelerated)\n"
        "  -256   SHA-256 (HW-accelerated)\n"
        "  -md5   MD5     (no HW path)\n"
        "Output: '<hex>  <path>\n' (sha256sum-compatible)\n");
}

int main(int argc, char **argv) {
    int algo = ALGO_SHA1;
    int argi = 1;

    if (argc >= 2) {
        if      (!strcmp(argv[1], "-1"))   { algo = ALGO_SHA1;   argi = 2; }
        else if (!strcmp(argv[1], "-256")) { algo = ALGO_SHA256; argi = 2; }
        else if (!strcmp(argv[1], "-md5")) { algo = ALGO_MD5;    argi = 2; }
        else if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
            usage(); return 0;
        }
    }

    if (argi >= argc) { usage(); return 2; }

    char hex[2 * SHA256_DIGEST_LENGTH + 1];
    int any_err = 0;
    for (int i = argi; i < argc; i++) {
        if (hash_one(argv[i], algo, hex) == 0) {
            /* Two-space separator matches GNU/toybox style.
             * NOTE: path is printed raw — caller MUST ensure paths
             * contain no newlines (filter in shell or post-process). */
            if (printf("%s  %s\n", hex, argv[i]) < 0) {
                fprintf(stderr, "hash_files: write: %s\n", strerror(errno));
                return 1;   /* stdout broken/full — don't fake a partial result */
            }
        } else {
            any_err = 1;
        }
    }
    /* Catch buffered write errors (e.g. ENOSPC on a redirected stdout) that
     * only surface at flush time — otherwise a truncated hash list would be
     * reported as success. */
    if (fflush(stdout) != 0) {
        fprintf(stderr, "hash_files: flush: %s\n", strerror(errno));
        return 1;
    }
    return any_err;
}

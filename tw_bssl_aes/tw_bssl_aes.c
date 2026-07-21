/*
 * tw_bssl_aes.c — streaming AEAD encrypt/decrypt via BoringSSL (chunked, cipher-agile):
 *                 AES-256-GCM (HW AES) / ChaCha20-Poly1305 (software)
 *
 * Interface:
 *   tw_bssl_aes enc <password>        — stdin=plaintext  → stdout=encrypted
 *   tw_bssl_aes dec <password>        — stdin=encrypted   → stdout=plaintext
 *   tw_bssl_aes enc|dec --pwfd <fd>   — password via pipe fd (not visible in /proc/cmdline)
 *
 * Format (32-byte header + chunk stream):
 *   Header (32 B):
 *     0..3    Magic:    "BAES"  (4 bytes)
 *     4..9    Reserved: 0       (6 bytes padding)
 *     10..11  Version:  uint16 LE (1)
 *     12..13  Flags:    uint16 LE — AEAD cipher id (0=AES-256-GCM, 1=ChaCha20-Poly1305)
 *     14..15  IterK:    uint16 LE (PBKDF2 iterations / 1000, default 100)
 *     16..31  Salt:     16 bytes (random)
 *   Followed by a sequence of chunks, each:
 *     [4 B]   ChunkHdr: uint32 LE — bit31 = LAST flag, bits 0..30 = plaintext length n (<= 65536)
 *     [n+16]  AEAD output: ciphertext (n B) + tag (16 B), as produced by EVP_AEAD_CTX_seal
 *   The stream ends with exactly ONE LAST chunk (n may be 0).
 *
 * The format constants (sizes, offsets, cipher ids) live centrally in
 * baes_format.h — shared SSoT with the reader (twrp-functions.cpp) and the
 * banner (twrpTar.cpp).
 *
 * AEAD construction (AES-256-GCM or ChaCha20-Poly1305 — both 32-B key/12-B nonce/16-B tag):
 *   Key:    PBKDF2-HMAC-SHA256(password, salt, iterations, 32) — key only, no IV
 *   Nonce:  12 B = chunk counter (uint64 LE, bytes 0..7) | 0 0 0 | LAST flag (byte 11)
 *   AAD:    chunk 0 = the 32-B header (binds version/flags/iter/salt); none afterwards
 *   Tag:    16 B per chunk. Authenticates content + nonce → tampering, corruption,
 *           reordering, truncation and a wrong password all fail deterministically.
 *
 * Nonce uniqueness: every segment (.win) gets a fresh random salt → its own key,
 * so the per-segment counter starting at 0 is globally unique (no nonce reuse).
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aead.h>
#include <sys/auxv.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>            /* strcasecmp — env cipher override */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "baes_format.h"        /* BAES wire-format constants (shared SSoT) */

/* ARMv8 Crypto Extensions detection via getauxval (no BoringSSL export needed) */
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif

static int has_hw_aes(void) {
	return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
}

/* ------------------------------------------------------------------ */

/* AEAD primitive for a cipher id (flags field). NULL = unknown -> caller die()s. */
static const EVP_AEAD *select_aead(uint16_t cipher_id) {
	switch (cipher_id) {
		case BAES_CIPHER_AES_256_GCM:        return EVP_aead_aes_256_gcm();
		case BAES_CIPHER_CHACHA20_POLY1305:  return EVP_aead_chacha20_poly1305();
		default:                             return NULL;
	}
}

static const char *cipher_name(uint16_t cipher_id) {
	return (cipher_id == BAES_CIPHER_CHACHA20_POLY1305) ? "ChaCha20-Poly1305"
	                                                    : "AES-256-GCM";
}

/* Cipher choice when encrypting: the env override TW_AEAD_CIPHER (gcm|chacha)
 * wins (test/benchmark — e.g. force ChaCha on a HW-AES device), otherwise HW
 * detection: ARMv8 AES -> GCM, else ChaCha20-Poly1305. */
static uint16_t resolve_cipher(void) {
	const char *e = getenv("TW_AEAD_CIPHER");
	if (e && *e) {
		if (strcasecmp(e, "chacha") == 0 || strcasecmp(e, "chacha20") == 0 ||
		    strcasecmp(e, "chacha20-poly1305") == 0)
			return BAES_CIPHER_CHACHA20_POLY1305;
		if (strcasecmp(e, "gcm") == 0 || strcasecmp(e, "aes") == 0 ||
		    strcasecmp(e, "aes-256-gcm") == 0)
			return BAES_CIPHER_AES_256_GCM;
		/* unknown value -> ignore, HW detection applies */
	}
	return has_hw_aes() ? BAES_CIPHER_AES_256_GCM : BAES_CIPHER_CHACHA20_POLY1305;
}

static char *pw_to_wipe = NULL;
/* Points at the local derived[] stack buffer (key) of the currently active
 * do_encrypt/do_decrypt so die() can wipe it on error paths too. Set after key
 * derivation; reset to NULL (and the buffer wiped) right after EVP_AEAD_CTX_new,
 * once the key lives inside the AEAD context. */
static unsigned char *der_to_wipe = NULL;

static int hw_logged = 0;

/* Securely zero a stack buffer — memory barriers against dead-store
 * elimination, same technique as the password wipe. NULL-safe. */
static void secure_wipe(unsigned char *p, size_t n) {
	if (!p) return;
	__asm__ __volatile__("" : : "r"(p) : "memory");
	memset(p, 0, n);
	__asm__ __volatile__("" : : "r"(p) : "memory");
}

static void die(const char *msg) {
	if (pw_to_wipe) {
		__asm__ __volatile__("" : : "r"(pw_to_wipe) : "memory");
		memset(pw_to_wipe, 0, strnlen(pw_to_wipe, 256));
		__asm__ __volatile__("" : : "r"(pw_to_wipe) : "memory");
	}
	secure_wipe(der_to_wipe, BAES_KEY_LEN);   /* wipe the key on error paths too */
	fprintf(stderr, "tw_bssl_aes: %s\n", msg);
	exit(1);
}

static void die_errno(const char *msg) {
	char buf[256];
	snprintf(buf, sizeof(buf), "%s: %s", msg, strerror(errno));
	die(buf);
}

static void log_cipher_once(uint16_t cipher_id) {
	if (hw_logged) return;
	hw_logged = 1;
	if (cipher_id == BAES_CIPHER_AES_256_GCM)
		fprintf(stderr, "Using BoringSSL AES-256-GCM%s\n",
		        has_hw_aes() ? " with ARMv8 hardware acceleration" : " (software)");
	else
		fprintf(stderr, "Using BoringSSL %s (software AEAD)\n", cipher_name(cipher_id));
}

/* ------------------------------------------------------------------ */

static int derive_key(const char *password, const unsigned char *salt,
                      unsigned char *out, int iterations) {
	int pwlen = (int)strlen(password);

	/* PKCS5_PBKDF2_HMAC returns 1 on success */
	if (PKCS5_PBKDF2_HMAC(password, pwlen,
	                      salt, BAES_SALT_LEN,
	                      iterations,
	                      EVP_sha256(),
	                      BAES_KEY_LEN, out) != 1) {
		return -1;
	}
	return 0;
}

/* Nonce from chunk counter + LAST flag. The LAST flag is part of the nonce, so
 * the tag binds it: a flipped LAST bit or reordered/truncated chunks cause a
 * nonce mismatch → open() fails. */
static void build_nonce(unsigned char nonce[BAES_AEAD_NONCE_LEN], uint64_t counter, int is_last) {
	int i;
	memset(nonce, 0, BAES_AEAD_NONCE_LEN);
	for (i = 0; i < 8; i++)
		nonce[i] = (unsigned char)((counter >> (8 * i)) & 0xFF);
	/* bytes 8..10 = 0; byte 11 = LAST flag */
	nonce[11] = is_last ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* robust read/write helpers — retry on EINTR, log errno on failure    */
/* ------------------------------------------------------------------ */

static ssize_t robust_read(int fd, void *buf, size_t count) {
	for (;;) {
		ssize_t n = read(fd, buf, count);
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		return n;
	}
}

/* Reads exactly 'want' bytes unless a real EOF (read()==0) occurs. On a pipe,
 * read() may return less than requested without EOF — hence the loop.
 * Returns 'want' (full), < want (only at EOF), or -1 on error. */
static ssize_t read_full(int fd, unsigned char *buf, size_t want) {
	size_t total = 0;
	while (total < want) {
		ssize_t r = robust_read(fd, buf + total, want - total);
		if (r < 0) return -1;
		if (r == 0) break;            /* EOF */
		total += (size_t)r;
	}
	return (ssize_t)total;
}

static int robust_write_all(int fd, const unsigned char *buf, int len) {
	int written = 0;
	while (written < len) {
		ssize_t w = write(fd, buf + written, (size_t)(len - written));
		if (w < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		written += (int)w;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* encrypt                                                             */
/* ------------------------------------------------------------------ */

static void do_encrypt(const char *password) {
	unsigned char header[BAES_HEADER_SIZE];
	unsigned char salt[BAES_SALT_LEN];
	unsigned char derived[BAES_KEY_LEN];
	unsigned char inbuf[BAES_CHUNK_PT];
	unsigned char outbuf[BAES_CHUNK_PT + BAES_AEAD_TAG_LEN];
	unsigned char nonce[BAES_AEAD_NONCE_LEN];
	EVP_AEAD_CTX *aead = NULL;
	uint64_t counter = 0;
	uint16_t cipher = resolve_cipher();   /* HW AES -> GCM, else ChaCha20-Poly1305 (env override) */

	if (RAND_bytes(salt, BAES_SALT_LEN) != 1)
		die("RAND_bytes failed");

	if (derive_key(password, salt, derived, BAES_ITER_DEFAULT) != 0)
		die("PBKDF2 failed");
	der_to_wipe = derived;   /* wipeable by die() from here on */

	log_cipher_once(cipher);

	/* build header (version 1) */
	memset(header, 0, BAES_HEADER_SIZE);
	memcpy(header, BAES_MAGIC, BAES_MAGIC_LEN);              /* magic         */
	header[BAES_OFF_VERSION]     = (BAES_VERSION >> 0) & 0xFF; /* version lo  */
	header[BAES_OFF_VERSION + 1] = (BAES_VERSION >> 8) & 0xFF; /* version hi  */
	header[BAES_OFF_CIPHER]      = (unsigned char)(cipher & 0xFF);        /* flags = AEAD cipher id */
	header[BAES_OFF_CIPHER + 1]  = (unsigned char)((cipher >> 8) & 0xFF);
	{   uint16_t ik = (uint16_t)(BAES_ITER_DEFAULT / BAES_ITER_DIVISOR);
		header[BAES_OFF_ITER]     = (ik >> 0) & 0xFF;       /* iter_k lo     */
		header[BAES_OFF_ITER + 1] = (ik >> 8) & 0xFF;       /* iter_k hi     */
	}
	memcpy(header + BAES_OFF_SALT, salt, BAES_SALT_LEN);     /* salt          */

	if (robust_write_all(STDOUT_FILENO, header, BAES_HEADER_SIZE) != 0)
		die_errno("write header failed");

	aead = EVP_AEAD_CTX_new(select_aead(cipher), derived, BAES_KEY_LEN,
	                        EVP_AEAD_DEFAULT_TAG_LENGTH);
	if (!aead) die("EVP_AEAD_CTX_new failed");

	/* The key now lives in the AEAD context — wipe the plaintext key in the
	 * derived[] stack buffer immediately (no lingering during streaming). */
	secure_wipe(derived, BAES_KEY_LEN);
	der_to_wipe = NULL;

	/* Streaming encrypt: read stdin → seal chunk → write stdout */
	for (;;) {
		ssize_t n = read_full(STDIN_FILENO, inbuf, BAES_CHUNK_PT);
		if (n < 0) die_errno("read stdin failed");
		int is_last = (n < (ssize_t)BAES_CHUNK_PT);  /* EOF reached */

		build_nonce(nonce, counter, is_last);
		const unsigned char *aad = (counter == 0) ? header : NULL;
		size_t aad_len = (counter == 0) ? BAES_HEADER_SIZE : 0;

		size_t out_len = 0;
		if (EVP_AEAD_CTX_seal(aead, outbuf, &out_len, sizeof(outbuf),
		                      nonce, BAES_AEAD_NONCE_LEN,
		                      inbuf, (size_t)n, aad, aad_len) != 1)
			die("EVP_AEAD_CTX_seal failed");

		/* 4-byte chunk header: bit31 = LAST, bits 0..30 = plaintext length */
		uint32_t fh = (uint32_t)n | (is_last ? BAES_CHUNK_LAST_BIT : 0u);
		unsigned char fhb[4];
		fhb[0] = fh & 0xFF;         fhb[1] = (fh >> 8) & 0xFF;
		fhb[2] = (fh >> 16) & 0xFF; fhb[3] = (fh >> 24) & 0xFF;
		if (robust_write_all(STDOUT_FILENO, fhb, 4) != 0)
			die_errno("write chunk header failed");
		if (robust_write_all(STDOUT_FILENO, outbuf, (int)out_len) != 0)
			die_errno("write chunk failed");

		counter++;
		if (is_last) break;
	}

	EVP_AEAD_CTX_free(aead);
}

/* ------------------------------------------------------------------ */
/* decrypt                                                             */
/* ------------------------------------------------------------------ */

static void do_decrypt(const char *password) {
	unsigned char header[BAES_HEADER_SIZE];
	unsigned char salt[BAES_SALT_LEN];
	unsigned char derived[BAES_KEY_LEN];
	unsigned char inbuf[BAES_CHUNK_PT + BAES_AEAD_TAG_LEN];
	unsigned char outbuf[BAES_CHUNK_PT];
	unsigned char nonce[BAES_AEAD_NONCE_LEN];
	EVP_AEAD_CTX *aead = NULL;
	int iterations;
	uint64_t counter = 0;

	ssize_t hn = read_full(STDIN_FILENO, header, BAES_HEADER_SIZE);
	if (hn < 0) die_errno("read header failed");
	if (hn < (ssize_t)BAES_HEADER_SIZE) die("unexpected EOF reading header");

	if (memcmp(header, BAES_MAGIC, BAES_MAGIC_LEN) != 0)
		die("invalid magic (not a BAES stream)");

	{   uint16_t ver = (uint16_t)header[BAES_OFF_VERSION] | ((uint16_t)header[BAES_OFF_VERSION + 1] << 8);
		if (ver != BAES_VERSION) die("unsupported version");
	}

	/* AEAD cipher from the flags field (self-describing; decrypt trusts the stream) */
	uint16_t cipher = (uint16_t)header[BAES_OFF_CIPHER] | ((uint16_t)header[BAES_OFF_CIPHER + 1] << 8);
	const EVP_AEAD *alg = select_aead(cipher);
	if (!alg) die("unsupported cipher");

	{   uint16_t ik = (uint16_t)header[BAES_OFF_ITER] | ((uint16_t)header[BAES_OFF_ITER + 1] << 8);
		iterations = (int)ik * BAES_ITER_DIVISOR;
		if (iterations < 1000 || iterations > 10000000)
			die("invalid iteration count");
	}

	memcpy(salt, header + BAES_OFF_SALT, BAES_SALT_LEN);

	if (derive_key(password, salt, derived, iterations) != 0)
		die("PBKDF2 failed — wrong password?");
	der_to_wipe = derived;   /* wipeable by die() from here on */

	log_cipher_once(cipher);

	aead = EVP_AEAD_CTX_new(alg, derived, BAES_KEY_LEN,
	                        EVP_AEAD_DEFAULT_TAG_LENGTH);
	if (!aead) die("EVP_AEAD_CTX_new failed");

	/* Key now in the AEAD context — wipe derived[] immediately (see do_encrypt). */
	secure_wipe(derived, BAES_KEY_LEN);
	der_to_wipe = NULL;

	/* Streaming decrypt: chunk header → sealed chunk → open → write stdout */
	for (;;) {
		unsigned char fhb[4];
		ssize_t fn = read_full(STDIN_FILENO, fhb, 4);
		if (fn < 0) die_errno("read chunk header failed");
		if (fn == 0) die("truncated stream (missing final chunk)");
		if (fn < 4)  die("truncated chunk header");

		uint32_t fh  = (uint32_t)fhb[0] | ((uint32_t)fhb[1] << 8)
		             | ((uint32_t)fhb[2] << 16) | ((uint32_t)fhb[3] << 24);
		uint32_t len = fh & BAES_CHUNK_LEN_MASK;
		int is_last  = (int)((fh >> 31) & 1u);
		if (len > BAES_CHUNK_PT) die("invalid chunk length");

		size_t sealed = (size_t)len + BAES_AEAD_TAG_LEN;
		ssize_t rn = read_full(STDIN_FILENO, inbuf, sealed);
		if (rn < 0) die_errno("read chunk failed");
		if ((size_t)rn < sealed) die("truncated chunk data");

		build_nonce(nonce, counter, is_last);
		const unsigned char *aad = (counter == 0) ? header : NULL;
		size_t aad_len = (counter == 0) ? BAES_HEADER_SIZE : 0;

		size_t out_len = 0;
		if (EVP_AEAD_CTX_open(aead, outbuf, &out_len, sizeof(outbuf),
		                      nonce, BAES_AEAD_NONCE_LEN,
		                      inbuf, sealed, aad, aad_len) != 1)
			die("authentication failed — wrong password or corrupt data");

		if (out_len > 0) {
			if (robust_write_all(STDOUT_FILENO, outbuf, (int)out_len) != 0)
				die_errno("write stdout failed");
		}

		counter++;
		if (is_last) {
			/* Nothing may follow the LAST chunk (trailing data = tampering) */
			unsigned char extra;
			ssize_t e = robust_read(STDIN_FILENO, &extra, 1);
			if (e > 0) die("trailing data after final chunk");
			break;
		}
	}

	EVP_AEAD_CTX_free(aead);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
	const char *password = NULL;
	char pw_buf[256];
	int pwfd;

	/* New mode: password via pipe fd (not visible in /proc/cmdline) */
	if (argc == 4 && strcmp(argv[2], "--pwfd") == 0) {
		pwfd = atoi(argv[3]);
		if (pwfd < 3) die("--pwfd: invalid fd");
		ssize_t n = robust_read(pwfd, pw_buf, sizeof(pw_buf) - 1);
		if (n < 0) die_errno("--pwfd: read failed");
		if (n == 0) die("--pwfd: no password (EOF)");
		pw_buf[n] = '\0';
		if (n == (ssize_t)(sizeof(pw_buf) - 1)) {
			char dummy;
			if (robust_read(pwfd, &dummy, 1) > 0)
				die("--pwfd: password too long (max 255 bytes)");
		}
		close(pwfd);
		password = pw_buf;
		pw_to_wipe = pw_buf;
	} else if (argc == 3) {
		password = argv[2];
		pw_to_wipe = argv[2];
	} else {
		die("usage: tw_bssl_aes enc|dec <password>\n"
		    "       tw_bssl_aes enc|dec --pwfd <fd>");
	}

	if (password[0] == '\0')
		die("empty password not allowed");

	if (strcmp(argv[1], "enc") == 0) {
		do_encrypt(password);
	} else if (strcmp(argv[1], "dec") == 0) {
		do_decrypt(password);
	} else {
		die("usage: tw_bssl_aes enc|dec <password>\n"
		    "       tw_bssl_aes enc|dec --pwfd <fd>");
	}

	if (pw_to_wipe) {
		__asm__ __volatile__("" : : "r"(pw_to_wipe) : "memory");
		memset(pw_to_wipe, 0, strnlen(pw_to_wipe, 256));
		__asm__ __volatile__("" : : "r"(pw_to_wipe) : "memory");
	}


	return 0;
}

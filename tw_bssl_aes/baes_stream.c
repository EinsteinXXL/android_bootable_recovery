/*
 * baes_stream.c -- streaming BAES AEAD core (chunked, cipher-agile):
 *                  AES-256-GCM (HW AES) / ChaCha20-Poly1305 (software).
 *
 * Process-independent by design:
 *   - I/O goes through a StageIO (stage_io.h), not through fixed fds.
 *   - errors RETURN -1 with a message; nothing here terminates the process.
 *   - the encrypt cipher is passed in by the caller; decrypt reads it
 *     self-describing from the stream header.
 *
 * Format (see baes_format.h): 32-byte header + chunk stream, each chunk
 *   [4 B LE: bit31=LAST, bits0..30=plaintext len n<=65536][n B ct + 16 B tag].
 * AEAD: PBKDF2-HMAC-SHA256 key (no IV); nonce = counter|000|LAST; AAD = header on
 * chunk 0. Tag binds content+nonce -> tamper/corruption/reorder/truncation/wrong
 * password all fail deterministically.
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aead.h>
#include <sys/auxv.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "baes_stream.h"
#include "baes_format.h"        /* BAES wire-format constants (shared SSoT) */

/* ARMv8 Crypto Extensions detection via getauxval (no BoringSSL export needed) */
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif

int baes_has_hw_aes(void) {
	return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
}

/* ------------------------------------------------------------------ */

/* AEAD primitive for a cipher id (flags field). NULL = unknown. */
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

/* Securely zero a stack buffer -- memory barriers against dead-store
 * elimination, same technique as the password wipe. NULL-safe. */
static void secure_wipe(unsigned char *p, size_t n) {
	if (!p) return;
	__asm__ __volatile__("" : : "r"(p) : "memory");
	memset(p, 0, n);
	__asm__ __volatile__("" : : "r"(p) : "memory");
}

static int hw_logged = 0;

static void log_cipher_once(uint16_t cipher_id) {
	if (hw_logged) return;
	hw_logged = 1;
	if (cipher_id == BAES_CIPHER_AES_256_GCM)
		fprintf(stderr, "Using BoringSSL AES-256-GCM%s\n",
		        baes_has_hw_aes() ? " with ARMv8 hardware acceleration" : " (software)");
	else
		fprintf(stderr, "Using BoringSSL %s (software AEAD)\n", cipher_name(cipher_id));
}

/* Error-message setters: fill errmsg with a human-readable reason instead of
 * terminating the process. */
static void set_err(char *buf, size_t len, const char *msg) {
	if (buf && len) snprintf(buf, len, "%s", msg);
}
/* The errno text is appended ONLY when errno is actually set: a StageIO backed by
 * a ring or a memory buffer reports failure without touching errno, and an
 * unconditional strerror() would render that as "Success" -- or as a stale errno
 * from an unrelated syscall. */
static void set_err_errno(char *buf, size_t len, const char *msg) {
	int e;
	if (!buf || !len) return;
	e = errno;
	if (e != 0)
		snprintf(buf, len, "%s: %s", msg, strerror(e));
	else
		snprintf(buf, len, "%s", msg);
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
 * nonce mismatch -> open() fails. */
static void build_nonce(unsigned char nonce[BAES_AEAD_NONCE_LEN], uint64_t counter, int is_last) {
	int i;
	memset(nonce, 0, BAES_AEAD_NONCE_LEN);
	for (i = 0; i < 8; i++)
		nonce[i] = (unsigned char)((counter >> (8 * i)) & 0xFF);
	/* bytes 8..10 = 0; byte 11 = LAST flag */
	nonce[11] = is_last ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* encrypt                                                             */
/* ------------------------------------------------------------------ */

int baes_stream_encrypt(const StageIO *in, const StageIO *out,
                        const char *password, uint16_t cipher_id,
                        char *errmsg, size_t errlen) {
	unsigned char header[BAES_HEADER_SIZE];
	unsigned char salt[BAES_SALT_LEN];
	unsigned char derived[BAES_KEY_LEN];
	unsigned char inbuf[BAES_CHUNK_PT];
	unsigned char outbuf[BAES_CHUNK_PT + BAES_AEAD_TAG_LEN];
	unsigned char nonce[BAES_AEAD_NONCE_LEN];
	EVP_AEAD_CTX *aead = NULL;
	uint64_t counter = 0;

	if (RAND_bytes(salt, BAES_SALT_LEN) != 1) {
		set_err(errmsg, errlen, "RAND_bytes failed");
		goto fail;
	}

	if (derive_key(password, salt, derived, BAES_ITER_DEFAULT) != 0) {
		set_err(errmsg, errlen, "PBKDF2 failed");
		goto fail;
	}

	log_cipher_once(cipher_id);

	/* build header (version 1) */
	memset(header, 0, BAES_HEADER_SIZE);
	memcpy(header, BAES_MAGIC, BAES_MAGIC_LEN);                /* magic         */
	header[BAES_OFF_VERSION]     = (BAES_VERSION >> 0) & 0xFF; /* version lo    */
	header[BAES_OFF_VERSION + 1] = (BAES_VERSION >> 8) & 0xFF; /* version hi    */
	header[BAES_OFF_CIPHER]      = (unsigned char)(cipher_id & 0xFF);        /* flags = AEAD cipher id */
	header[BAES_OFF_CIPHER + 1]  = (unsigned char)((cipher_id >> 8) & 0xFF);
	{	uint16_t ik = (uint16_t)(BAES_ITER_DEFAULT / BAES_ITER_DIVISOR);
		header[BAES_OFF_ITER]     = (ik >> 0) & 0xFF;         /* iter_k lo     */
		header[BAES_OFF_ITER + 1] = (ik >> 8) & 0xFF;         /* iter_k hi     */
	}
	memcpy(header + BAES_OFF_SALT, salt, BAES_SALT_LEN);       /* salt          */

	if (out->write_all(out->ctx, header, BAES_HEADER_SIZE) != 0) {
		set_err_errno(errmsg, errlen, "write header failed");
		goto fail;
	}

	aead = EVP_AEAD_CTX_new(select_aead(cipher_id), derived, BAES_KEY_LEN,
	                        EVP_AEAD_DEFAULT_TAG_LENGTH);
	if (!aead) {
		set_err(errmsg, errlen, "EVP_AEAD_CTX_new failed");
		goto fail;
	}

	/* The key now lives in the AEAD context -- wipe the plaintext key in the
	 * derived[] stack buffer immediately (no lingering during streaming). */
	secure_wipe(derived, BAES_KEY_LEN);

	/* Streaming encrypt: read plaintext -> seal chunk -> write out */
	for (;;) {
		ssize_t n = in->read_full(in->ctx, inbuf, BAES_CHUNK_PT);
		if (n < 0) {
			set_err_errno(errmsg, errlen, "read plaintext failed");
			goto fail;
		}
		int is_last = (n < (ssize_t)BAES_CHUNK_PT);  /* EOF reached */

		build_nonce(nonce, counter, is_last);
		const unsigned char *aad = (counter == 0) ? header : NULL;
		size_t aad_len = (counter == 0) ? BAES_HEADER_SIZE : 0;

		size_t out_len = 0;
		if (EVP_AEAD_CTX_seal(aead, outbuf, &out_len, sizeof(outbuf),
		                      nonce, BAES_AEAD_NONCE_LEN,
		                      inbuf, (size_t)n, aad, aad_len) != 1) {
			set_err(errmsg, errlen, "EVP_AEAD_CTX_seal failed");
			goto fail;
		}

		/* 4-byte chunk header: bit31 = LAST, bits 0..30 = plaintext length */
		uint32_t fh = (uint32_t)n | (is_last ? BAES_CHUNK_LAST_BIT : 0u);
		unsigned char fhb[4];
		fhb[0] = fh & 0xFF;         fhb[1] = (fh >> 8) & 0xFF;
		fhb[2] = (fh >> 16) & 0xFF; fhb[3] = (fh >> 24) & 0xFF;
		if (out->write_all(out->ctx, fhb, 4) != 0) {
			set_err_errno(errmsg, errlen, "write chunk header failed");
			goto fail;
		}
		if (out->write_all(out->ctx, outbuf, out_len) != 0) {
			set_err_errno(errmsg, errlen, "write chunk failed");
			goto fail;
		}

		counter++;
		if (is_last) break;
	}

	EVP_AEAD_CTX_free(aead);
	return 0;

fail:
	secure_wipe(derived, BAES_KEY_LEN);   /* wipe the key on error paths too */
	if (aead) EVP_AEAD_CTX_free(aead);
	return -1;
}

/* ------------------------------------------------------------------ */
/* decrypt                                                             */
/* ------------------------------------------------------------------ */

int baes_stream_decrypt(const StageIO *in, const StageIO *out,
                        const char *password,
                        char *errmsg, size_t errlen) {
	unsigned char header[BAES_HEADER_SIZE];
	unsigned char salt[BAES_SALT_LEN];
	unsigned char derived[BAES_KEY_LEN];
	unsigned char inbuf[BAES_CHUNK_PT + BAES_AEAD_TAG_LEN];
	unsigned char outbuf[BAES_CHUNK_PT];
	unsigned char nonce[BAES_AEAD_NONCE_LEN];
	EVP_AEAD_CTX *aead = NULL;
	int iterations;
	uint64_t counter = 0;

	ssize_t hn = in->read_full(in->ctx, header, BAES_HEADER_SIZE);
	if (hn < 0) {
		set_err_errno(errmsg, errlen, "read header failed");
		goto fail;
	}
	if (hn < (ssize_t)BAES_HEADER_SIZE) {
		set_err(errmsg, errlen, "unexpected EOF reading header");
		goto fail;
	}

	if (memcmp(header, BAES_MAGIC, BAES_MAGIC_LEN) != 0) {
		set_err(errmsg, errlen, "invalid magic (not a BAES stream)");
		goto fail;
	}

	{	uint16_t ver = (uint16_t)header[BAES_OFF_VERSION] | ((uint16_t)header[BAES_OFF_VERSION + 1] << 8);
		if (ver != BAES_VERSION) {
			set_err(errmsg, errlen, "unsupported version");
			goto fail;
		}
	}

	/* AEAD cipher from the flags field (self-describing; decrypt trusts the stream) */
	uint16_t cipher = (uint16_t)header[BAES_OFF_CIPHER] | ((uint16_t)header[BAES_OFF_CIPHER + 1] << 8);
	const EVP_AEAD *alg = select_aead(cipher);
	if (!alg) {
		set_err(errmsg, errlen, "unsupported cipher");
		goto fail;
	}

	{	uint16_t ik = (uint16_t)header[BAES_OFF_ITER] | ((uint16_t)header[BAES_OFF_ITER + 1] << 8);
		iterations = (int)ik * BAES_ITER_DIVISOR;
		if (iterations < 1000 || iterations > 10000000) {
			set_err(errmsg, errlen, "invalid iteration count");
			goto fail;
		}
	}

	memcpy(salt, header + BAES_OFF_SALT, BAES_SALT_LEN);

	if (derive_key(password, salt, derived, iterations) != 0) {
		set_err(errmsg, errlen, "PBKDF2 failed -- wrong password?");
		goto fail;
	}

	log_cipher_once(cipher);

	aead = EVP_AEAD_CTX_new(alg, derived, BAES_KEY_LEN,
	                        EVP_AEAD_DEFAULT_TAG_LENGTH);
	if (!aead) {
		set_err(errmsg, errlen, "EVP_AEAD_CTX_new failed");
		goto fail;
	}

	/* Key now in the AEAD context -- wipe derived[] immediately (see encrypt). */
	secure_wipe(derived, BAES_KEY_LEN);

	/* Streaming decrypt: chunk header -> sealed chunk -> open -> write out */
	for (;;) {
		unsigned char fhb[4];
		ssize_t fn = in->read_full(in->ctx, fhb, 4);
		if (fn < 0) {
			set_err_errno(errmsg, errlen, "read chunk header failed");
			goto fail;
		}
		if (fn == 0) {
			set_err(errmsg, errlen, "truncated stream (missing final chunk)");
			goto fail;
		}
		if (fn < 4) {
			set_err(errmsg, errlen, "truncated chunk header");
			goto fail;
		}

		uint32_t fh  = (uint32_t)fhb[0] | ((uint32_t)fhb[1] << 8)
		             | ((uint32_t)fhb[2] << 16) | ((uint32_t)fhb[3] << 24);
		uint32_t len = fh & BAES_CHUNK_LEN_MASK;
		int is_last  = (int)((fh >> 31) & 1u);
		if (len > BAES_CHUNK_PT) {
			set_err(errmsg, errlen, "invalid chunk length");
			goto fail;
		}

		size_t sealed = (size_t)len + BAES_AEAD_TAG_LEN;
		ssize_t rn = in->read_full(in->ctx, inbuf, sealed);
		if (rn < 0) {
			set_err_errno(errmsg, errlen, "read chunk failed");
			goto fail;
		}
		if ((size_t)rn < sealed) {
			set_err(errmsg, errlen, "truncated chunk data");
			goto fail;
		}

		build_nonce(nonce, counter, is_last);
		const unsigned char *aad = (counter == 0) ? header : NULL;
		size_t aad_len = (counter == 0) ? BAES_HEADER_SIZE : 0;

		size_t out_len = 0;
		if (EVP_AEAD_CTX_open(aead, outbuf, &out_len, sizeof(outbuf),
		                      nonce, BAES_AEAD_NONCE_LEN,
		                      inbuf, sealed, aad, aad_len) != 1) {
			set_err(errmsg, errlen, "authentication failed -- wrong password or corrupt data");
			goto fail;
		}

		if (out_len > 0) {
			if (out->write_all(out->ctx, outbuf, out_len) != 0) {
				set_err_errno(errmsg, errlen, "write plaintext failed");
				goto fail;
			}
		}

		counter++;
		if (is_last) {
			/* Nothing may follow the LAST chunk (trailing data = tampering) */
			unsigned char extra;
			ssize_t e = in->read_full(in->ctx, &extra, 1);
			if (e > 0) {
				set_err(errmsg, errlen, "trailing data after final chunk");
				goto fail;
			}
			break;
		}
	}

	EVP_AEAD_CTX_free(aead);
	return 0;

fail:
	secure_wipe(derived, BAES_KEY_LEN);
	if (aead) EVP_AEAD_CTX_free(aead);
	return -1;
}

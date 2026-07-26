/*
	Copyright 2026 TeamWin / TWRP-OFRP-CryptedBackup-Fix
	This file is part of TWRP/TeamWin Recovery Project.

	TWRP is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	TWRP is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
*/

/* ---------------------------------------------------------------------------
 * baes_stream.h -- streaming BAES AEAD core (chunked, cipher-agile) as a
 * reusable library, decoupled from process I/O.
 *
 * The crypto engine is driven by a StageIO (stage_io.h) rather than by hardcoded
 * fds, and it REPORTS errors (return -1 + message) rather than calling exit(), so
 * it can run in any context. Its caller is the in-process pipeline engine
 * (stage_engine.cpp -> run_baes_*), where the AES stage is a thread.
 *
 * The wire format is defined by baes_format.h (single source of truth); every
 * build that shares that header reads and writes the same stream.
 *
 * Sensitive-material discipline: the derived AEAD key (on the stack inside these
 * functions) is securely wiped on EVERY exit path (success and error). The
 * PASSWORD buffer is owned and wiped by the CALLER (it is borrowed here as a
 * const char*).
 * --------------------------------------------------------------------------- */

#ifndef TW_BAES_STREAM_H
#define TW_BAES_STREAM_H

#include <stdint.h>
#include <stddef.h>
#include "../stage_io.h"   /* repo root; dir-relative so it needs no -I setup */

#ifdef __cplusplus
extern "C" {
#endif

/* Encrypt: read plaintext from `in`, write a BAES stream to `out`.
 * cipher_id: BAES_CIPHER_AES_256_GCM (0) or BAES_CIPHER_CHACHA20_POLY1305 (1)
 * (baes_format.h). The caller resolves the cipher and passes it in (the backup
 * path hands over twrpTar's aead_cipher_id). Returns 0 on success, -1 on error
 * (errmsg, if non-NULL and errlen>0, receives a human-readable reason). */
int baes_stream_encrypt(const StageIO* in, const StageIO* out,
                        const char* password, uint16_t cipher_id,
                        char* errmsg, size_t errlen);

/* Decrypt: read a BAES stream from `in`, write plaintext to `out`. The AEAD
 * cipher is read self-describing from the stream header (flags field). Returns 0
 * on success, -1 on error (wrong password, corruption, truncation, trailing
 * data, unsupported version/cipher -- all deterministic AEAD failures). */
int baes_stream_decrypt(const StageIO* in, const StageIO* out,
                        const char* password,
                        char* errmsg, size_t errlen);

/* ARMv8 AES hardware presence (getauxval HWCAP_AES). Feeds the cipher banner
 * that baes_stream_encrypt/decrypt emit. */
int baes_has_hw_aes(void);

#ifdef __cplusplus
}
#endif

#endif /* TW_BAES_STREAM_H */

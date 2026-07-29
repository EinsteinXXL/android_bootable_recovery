/*
	Copyright 2026 TeamWin
	This file is part of TWRP/TeamWin Recovery Project.

	TWRP is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	TWRP is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with TWRP.  If not, see <http://www.gnu.org/licenses/>.
*/

// BackupHeaderManager — consolidates the TWRP.* PAX g-header peeks. Counterpart
// to InfoManager (.info FILE) — this reads the g-header INSIDE the archive.

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>     // FILE/fopen/fread/fclose (Try_Decrypting_File)
#include <stdint.h>    // uint8_t/uint16_t/uint32_t (BAES header fields)
#include <string.h>    // memcmp/memmem/strncmp/strlen/memset/strerror
#include <errno.h>     // errno (Try_Decrypting_File I/O errors)
#include <glob.h>
#include <zstd.h>   // in-process zstd decode (libzstd_twrp), types 6/7

#include <string>
#include <fstream>  // ifstream (Get_File_Type magic read)
#include <map>

#include "backupheadermanager.hpp"
#include "twrp-functions.hpp"   // Archive_Type / DetectResult / is_legacy_type / Path_Exists
#include "twcommon.h"           // LOGERR/LOGINFO (dual: recovery gui_print / standalone printf)

// BAES crypto for the inner decrypt sniff (Try_Decrypting_File) — only when
// encryption is compiled in; otherwise Try_Decrypting_File stubs via #else below.
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
#include <openssl/evp.h>
#include <openssl/aead.h>
#include "tw_bssl_aes/baes_format.h"
#endif

using namespace std;

BackupHeaderManager::BackupHeaderManager() : mLoaded(false), mType(LEGACY_UNCOMPRESSED), mStatus(DET_REJECT_UNKNOWN) {
}

// ============================================================================================
// Detection internals — three layered steps: Get_File_Type (outer magic sniff)
// -> Try_Decrypting_File (inner BAES decrypt sniff) -> detect_archive_type
// (orchestrates both + plain-tar g-marker verify).
// ============================================================================================

Archive_Type BackupHeaderManager::Get_File_Type(string fn) {
	/* Binary magic detection. Design points:
	 * (1) ifstream::read(), NOT ::get() — get() is the string API that stops at
	 *     '\n' and NUL-terminates, which is semantically wrong for raw binary
	 *     data. read() reads exactly count bytes, no delimiter, no NUL.
	 * (2) the zstd check covers the FULL 4-byte magic (RFC 8478: 0x28 0xB5 0x2F
	 *     0xFD). A 2-byte check would carry a ~1/65536 collision rate (vs
	 *     ~1/2^32) — worst case a false-positive zstd detection followed by a
	 *     decoder failure on non-zstd bytes.
	 * (3) is_open() guard: without it a failed open() would test uninitialized
	 *     header bytes for magic -> random detection.
	 * (4) header[] initialized to {0,0,0,0} — if the file yields < 4 bytes the
	 *     unwritten slots are defined zeros instead of UB. */
	unsigned char header[4] = {0, 0, 0, 0};
	ifstream f;
	f.open(fn.c_str(), ios::in | ios::binary);
	if (!f.is_open())
		return LEGACY_UNCOMPRESSED;
	f.read(reinterpret_cast<char*>(header), 4);
	std::streamsize n = f.gcount();
	f.close();

	if (n < 2)
		return LEGACY_UNCOMPRESSED;

	if (header[0] == 0x1f && header[1] == 0x8b)
		return LEGACY_COMPRESSED;                                // gzip/pigz (legacy, 2-byte magic)
	if (n >= 4 && header[0] == 0x28 && header[1] == 0xb5
	           && header[2] == 0x2f && header[3] == 0xfd)
		return COMPRESSED;                               // zstd RFC 8478 (4-byte magic)
	if (header[0] == 0x42 && header[1] == 0x41)                  // "BA" = BAES (tw_bssl_aes)
		return ENCRYPTED;
	if (header[0] == 0x4f && header[1] == 0x41)                  // "OA" = openaes (legacy)
		return LEGACY_ENCRYPTED;
	return LEGACY_UNCOMPRESSED; // default — ustar-based detection happens elsewhere
}

// Partition-scoped outer type: determines the archive type of ONE partition by
// walking its segments serially (glob `<base>[0-9][0-9][0-9]` derived from the
// first segment) and calling Get_File_Type per segment. Legacy OpenAES
// background: with `userdata_encryption=1` (a kitkat leftover) original TWRP
// forks an UNencrypted set (thread 0 -> win000..) and encrypted threads
// (-> win100..). The first segment is therefore ALWAYS unencrypted — gzip
// (compression on) OR plain tar (compression off); OpenAES ("OA") only
// starts in later segments, so gzip AND plain-tar leads can both be heterogeneous.
// Do NOT "optimize" this back to a first-segment-only probe: a plain-tar+OA backup
// would then pass as homogeneous legacy plain tar and fail mid-restore on the OA
// segments instead of being rejected before the wipe.
// Our homogeneous DFP backups (zstd/BSSL) are unambiguous from the first segment.
//   - zstd / BAES        -> done with the first segment
//   - gzip / plain tar   -> legacy possible; continue until "OA" appears or all segments are done
//   - "OA" anywhere      -> LEGACY_ENCRYPTED (OpenAES, unsupported -> reject)
// The source of truth is the archive itself (magic bytes), never a .info.
Archive_Type BackupHeaderManager::Get_Archive_Type_From_Segments(string fn) {
	// Derive the segment base from the first segment: "data.ext4.win000" -> "data.ext4.win".
	string base = fn;
	size_t len = base.size();
	if (len >= 3 && base[len-1] >= '0' && base[len-1] <= '9'
	             && base[len-2] >= '0' && base[len-2] <= '9'
	             && base[len-3] >= '0' && base[len-3] <= '9')
		base.resize(len - 3);

	glob_t gl;
	gl.gl_pathc = 0;
	gl.gl_pathv = NULL;
	string pat = base + "[0-9][0-9][0-9]";
	bool globbed = (glob(pat.c_str(), 0, NULL, &gl) == 0 && gl.gl_pathc > 0);  // sorted -> win000 first
	size_t count = globbed ? gl.gl_pathc : 1;   // no split (unsplit .win / twrpTarMain) -> fn only

	Archive_Type backup_type = LEGACY_UNCOMPRESSED;    // default (plain tar/unknown)
	for (size_t i = 0; i < count; i++) {
		Archive_Type t = Get_File_Type(globbed ? string(gl.gl_pathv[i]) : fn);   // magic of ONE segment

		// "OA" in ANY segment -> legacy OpenAES, done immediately.
		if (t == LEGACY_ENCRYPTED) { backup_type = LEGACY_ENCRYPTED; break; }

		// The first segment decides the homogeneous types (zstd/BAES = our DFP
		// backups); gzip AND plain tar keep iterating — both can carry an OpenAES tail
		// (original TWRP enc threads from win100.., see function comment).
		// Homogeneous plain tar (legacy and DFP alike) stays LEGACY_UNCOMPRESSED.
		if (i == 0) {
			if (t == COMPRESSED || t == ENCRYPTED) { backup_type = t; break; }
			if (t == LEGACY_COMPRESSED)
				backup_type = LEGACY_COMPRESSED;   // legacy gzip -> continue: OA may appear in a later segment
			// plain tar/unknown (LEGACY_UNCOMPRESSED): backup_type stays LEGACY_UNCOMPRESSED, keep scanning
		}
	}
	if (globbed)
		globfree(&gl);
	return backup_type;
}

int BackupHeaderManager::Try_Decrypting_File(string fn, const string& password, Archive_Type *out_archive_type, string *out_plaintext) {
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
	FILE *f = fopen(fn.c_str(), "rb");
	if (f == NULL) {
		LOGERR("Failed to open '%s': %s\n", fn.c_str(), strerror(errno));
		return -1;
	}

	// Only the BAES format (magic "BAES") is supported; legacy OpenAES ("OA")
	// backups are rejected.
	uint8_t magic[10];
	if (fread(magic, 1, 10, f) != 10) {
		LOGERR("Failed to read magic from '%s'\n", fn.c_str());
		fclose(f);
		return -1;
	}

	if (memcmp(magic, BAES_MAGIC, BAES_MAGIC_LEN) == 0) {
		// ---- tw_bssl_aes (BoringSSL AEAD, chunked) path ----
		// Header (32 B): 0..3 "BAES", 4..9 reserved, 10..11 version, 12..13 flags,
		// 14..15 IterK, 16..31 salt. Then chunks [4 B len|LAST][ciphertext+16 B tag].
		// We open the FIRST chunk: a passing AEAD tag verify == correct password
		// (cryptographically sound, no heuristic); the decrypted head reveals
		// the inner format (zstd magic / ustar).
		uint8_t header[BAES_HEADER_SIZE];
		memcpy(header, magic, 10);
		if (fread(header + 10, 1, 22, f) != 22) {
			LOGERR("Failed to read BAES header\n");
			fclose(f);
			return -1;
		}

		uint16_t ver = (uint16_t)header[BAES_OFF_VERSION] | ((uint16_t)header[BAES_OFF_VERSION + 1] << 8);
		if (ver != BAES_VERSION) {
			LOGERR("BAES: unsupported version %u\n", (unsigned)ver);
			fclose(f);
			return -1;
		}

		// Cipher agility: AEAD from the flags field (offset 12) — the stream
		// describes itself, identical to the filter and the PC tool.
		// 0 = AES-256-GCM, 1 = ChaCha20-Poly1305.
		uint16_t cipher_id = (uint16_t)header[BAES_OFF_CIPHER] | ((uint16_t)header[BAES_OFF_CIPHER + 1] << 8);
		const EVP_AEAD *aead_alg = (cipher_id == BAES_CIPHER_AES_256_GCM) ? EVP_aead_aes_256_gcm()
		                         : (cipher_id == BAES_CIPHER_CHACHA20_POLY1305) ? EVP_aead_chacha20_poly1305()
		                         : NULL;
		if (!aead_alg) {
			LOGERR("BAES: unsupported cipher id %u in '%s'\n", (unsigned)cipher_id, fn.c_str());
			fclose(f);
			return -1;
		}

		uint16_t ik = (uint16_t)header[BAES_OFF_ITER] | ((uint16_t)header[BAES_OFF_ITER + 1] << 8);
		int iterations = (int)ik * BAES_ITER_DIVISOR;
		if (iterations < 1000 || iterations > 10000000) {
			LOGERR("BAES: invalid iteration count\n");
			fclose(f);
			return -1;
		}

		// Read the first chunk header (4 B): bit31 = LAST, bits 0..30 = plaintext length.
		uint8_t fhb[4];
		if (fread(fhb, 1, 4, f) != 4) {
			LOGERR("BAES: cannot read first chunk header\n");
			fclose(f);
			return -1;
		}
		uint32_t fh = (uint32_t)fhb[0] | ((uint32_t)fhb[1] << 8)
		            | ((uint32_t)fhb[2] << 16) | ((uint32_t)fhb[3] << 24);
		uint32_t clen = fh & BAES_CHUNK_LEN_MASK;
		int is_last = (int)((fh >> 31) & 1u);
		if (clen > BAES_CHUNK_PT) {
			LOGERR("BAES: invalid first chunk length\n");
			fclose(f);
			return -1;
		}

		size_t sealed = (size_t)clen + BAES_AEAD_TAG_LEN;
		uint8_t *cbuf = (uint8_t*)malloc(sealed);
		uint8_t *plaintext = (uint8_t*)malloc(clen ? clen : 1);
		if (!cbuf || !plaintext) {
			free(cbuf); free(plaintext); fclose(f);
			return -1;
		}
		size_t got = fread(cbuf, 1, sealed, f);
		fclose(f);
		if (got != sealed) {
			LOGERR("BAES: truncated first chunk\n");
			free(cbuf); free(plaintext);
			return -1;
		}

		// An empty password on an encrypted backup is semantically broken
		// (PBKDF2(empty, salt) yields a key derivable from the salt alone).
		// Reject directly instead of burning CPU on PBKDF2 rounds.
		if (password.empty()) {
			LOGERR("BAES: empty password rejected for encrypted backup '%s'.\n", fn.c_str());
			free(cbuf); free(plaintext);
			return 0; // signal "wrong password" to caller
		}

		uint8_t key[BAES_KEY_LEN];
		if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
		                      header + BAES_OFF_SALT, BAES_SALT_LEN, iterations,
		                      EVP_sha256(), BAES_KEY_LEN, key) != 1) {
			LOGERR("BAES: PBKDF2 failed\n");
			free(cbuf); free(plaintext);
			return -1;
		}

		EVP_AEAD_CTX *aead = EVP_AEAD_CTX_new(aead_alg, key, BAES_KEY_LEN,
		                                      EVP_AEAD_DEFAULT_TAG_LENGTH);
		memset(key, 0, sizeof(key));
		if (!aead) {
			free(cbuf); free(plaintext);
			return -1;
		}

		// Nonce for chunk 0: counter=0 (bytes 0..7 = 0), byte 11 = LAST flag. AAD = header.
		uint8_t nonce[BAES_AEAD_NONCE_LEN];
		memset(nonce, 0, sizeof(nonce));
		nonce[11] = is_last ? 1 : 0;

		size_t out_len = 0;
		int ok = EVP_AEAD_CTX_open(aead, plaintext, &out_len, clen ? clen : 1,
		                           nonce, BAES_AEAD_NONCE_LEN, cbuf, sealed, header, BAES_HEADER_SIZE);
		EVP_AEAD_CTX_free(aead);
		free(cbuf);

		if (!ok) {
			// AEAD tag verify failed == wrong password OR corrupt backup. Deterministic.
			LOGINFO("'%s': BAES-AEAD authentication failed -- wrong password or corrupt data.\n", fn.c_str());
			free(plaintext);
			return 0; // wrong password / corrupt
		}

		// Optionally hand the decrypted first chunk back (for the g-header peek).
		if (out_plaintext) out_plaintext->assign((char*)plaintext, out_len);

		// Password cryptographically confirmed. Inner format at the plaintext head.
		if (out_len < 2) {
			LOGINFO("Successfully decrypted '%s' (BAES) but too small.\n", fn.c_str());
			free(plaintext);
			return 1;
		}
		// zstd magic (0x28 0xB5 0x2F 0xFD, RFC 8478) -> DFP zstd+BSSL-AES.
		if (out_len >= 4 && plaintext[0] == 0x28 && plaintext[1] == 0xb5
		                 && plaintext[2] == 0x2f && plaintext[3] == 0xfd) {
			LOGINFO("Successfully decrypted '%s' (BAES+zstd).\n", fn.c_str());
			if (out_archive_type) *out_archive_type = COMPRESSED_ENCRYPTED;
			free(plaintext);
			return 3;
		}
		if (out_len >= 262 && strncmp((char*)(plaintext + 257), "ustar", 5) == 0) {
			LOGINFO("Successfully decrypted '%s' (BAES+tar).\n", fn.c_str());
			if (out_archive_type) *out_archive_type = ENCRYPTED;
			free(plaintext);
			return 2;
		}

		LOGINFO("Successfully decrypted '%s' (BAES, unknown inner format).\n", fn.c_str());
		free(plaintext);
		return 1;
	}

	// Unknown magic (OpenAES "OA" or unknown format) — reject.
	LOGERR("Try_Decrypting_File: '%s' is not a BAES-encrypted backup (magic mismatch).\n",
	       fn.c_str());
	fclose(f);
	return -1;
#else
	LOGERR("Encrypted backup support not included.\n");
	return -1;
#endif
}

// Self-describing archive-type detector. The source of truth is exclusively
// the archive itself (magic bytes + decryption probe of the first chunk if
// needed) — never a .info. Mapping:
//   gzip magic (1f 8b)       -> LEGACY_COMPRESSED (1)          legacy TWRP, single-pipe
//   zstd magic (28 b5 2f fd) -> COMPRESSED (6)        multi-pipe
//   "OA" (OpenAES)           -> DET_REJECT_OPENAES             unsupported, always rejected
//   "BA" (BAES, encrypted)   -> inner sniff decrypts the 1st chunk:
//        ustar -> ENCRYPTED (5) | zstd -> COMPRESSED_ENCRYPTED (7)
//   else (magic==LEGACY_UNCOMPRESSED, plain tar): ustar @257 present?
//        no 'g' @156              -> LEGACY_UNCOMPRESSED (0)   legacy plain tar (original TWRP)
//        'g' + TWRP.tartype==4    -> UNCOMPRESSED (4)      this build's plain tar, POSITIVELY verified
//        'g' without valid tartype -> DET_REJECT_UNKNOWN       broken/foreign
//        no ustar                 -> DET_REJECT_UNKNOWN
// is_legacy_type(t) (t <= 3) separates legacy (single-pipe) from DFP
// (multi-pipe, staggered restore). A 'g' header ALONE is NOT enough (PAX global is
// standard tar; every pax archive has 'g'), so the self-describing value
// TWRP.tartype==4 (written by createTar/write_global_headers) is positively
// verified — otherwise reject (broken/foreign rather than blindly DFP).
// Private: the only caller is BackupHeaderManager::Load(), which the outside
// world reaches through Load()/GetType()/GetStatus().
DetectResult BackupHeaderManager::detect_archive_type(const std::string &probe, const std::string &password,
                                         Archive_Type *out, std::string *out_plaintext) {
	Archive_Type m = Get_Archive_Type_From_Segments(probe);   // partition type: all segments (detects heterogeneous OpenAES)
	*out = m;   // Carry the outer type out on ALL paths (reject too) -> Load needs no second scan.
	            // The DET_OK branches below refine *out (BSSL 5/7, UNCOMPRESSED); reject paths keep m.
	if (m == LEGACY_COMPRESSED)   { *out = LEGACY_COMPRESSED;   return DET_OK; }
	if (m == COMPRESSED)          { *out = COMPRESSED;          return DET_OK; }
	if (m == LEGACY_ENCRYPTED)    { return DET_REJECT_OPENAES; }
	if (m == ENCRYPTED) {
		// BAES outside -> decrypt the first chunk (tag verify == correct
		// password); the inner format at the plaintext head is the final type.
		// The magic on win000 only sees "BAES"->5; only this sniff separates 5
		// from 7, including multi-archive. out_plaintext (optional) passes the
		// decrypted first chunk through to the caller (BackupHeaderManager thus
		// avoids a second decrypt); extractTarFork passes nullptr.
		Archive_Type inner = ENCRYPTED;
		int r = Try_Decrypting_File(probe, password, &inner, out_plaintext);
		if (r < 1)  return DET_WRONG_PASSWORD;   // wrong password / corrupt
		if (r == 1) return DET_REJECT_UNKNOWN;   // decrypted, but not tar
		*out = inner;                            // 2 -> 5, 3 -> 7
		return DET_OK;
	}
	// m == LEGACY_UNCOMPRESSED: plain tar or open() failure. Check the header directly.
	// 4096 instead of 512: safely covers the leading PAX g-headers (tartype/
	// backup_size/ext_app_data_size/ead) with reserve for growing records.
	// The +1 byte stays 0-initialized = guaranteed terminator for atoi() below.
	unsigned char h[4096 + 1] = {0};
	int fd = open(probe.c_str(), O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		LOGINFO("detect_archive_type: open('%s') failed: %s\n",
		        probe.c_str(), strerror(errno));
		return DET_REJECT_UNKNOWN;
	}
	ssize_t n = read(fd, h, 4096);
	close(fd);
	if (n < 263 || memcmp(h + 257, "ustar", 5) != 0) {
		LOGINFO("detect_archive_type: no ustar magic in '%s' (%zd bytes)\n",
		        probe.c_str(), n);
		return DET_REJECT_UNKNOWN;
	}
	// No PAX global header @156 -> legacy plain tar (original TWRP, single-pipe).
	if (h[156] != 'g') {
		*out = LEGACY_UNCOMPRESSED;
		return DET_OK;
	}
	// 'g' present: that alone is standard tar (every pax archive has 'g') -> do
	// NOT wave it through as DFP. POSITIVELY verify that our self-describing
	// marker TWRP.tartype==UNCOMPRESSED is in the g-header payload
	// (createTar writes it as the FIRST g-record -> it precedes every file;
	// memmem hits the real one first).
	const char *tartype_tag = "TWRP.tartype=";   // == libtar.h TWRP_TARTYPE_TAG
	const void *p = memmem(h, (size_t)n, tartype_tag, strlen(tartype_tag));
	if (p != NULL && atoi((const char *)p + strlen(tartype_tag)) == UNCOMPRESSED) {
		*out = UNCOMPRESSED;
		return DET_OK;
	}
	// 'g' header without a valid TWRP.tartype -> broken/foreign. Standard reject
	// path (emit_detect_reject -> "restore_unknown_segment"); *out = outer type.
	LOGINFO("detect_archive_type: '%s' has PAX-g header but no valid TWRP.tartype -> reject\n",
	        probe.c_str());
	*out = LEGACY_UNCOMPRESSED;
	return DET_REJECT_UNKNOWN;
}

// Decompresses the first bytes of a zstd stream in-process (libzstd_twrp) up
// to out_cap bytes — enough for the PAX g-header at the tar head. true on >0
// output; partial output/incomplete status is fine (we only need the first KBs).
bool BackupHeaderManager::zstd_head(const char *src, size_t src_len, string &out, size_t out_cap) {
	ZSTD_DStream *ds = ZSTD_createDStream();
	if (!ds)
		return false;
	ZSTD_initDStream(ds);
	out.assign(out_cap, '\0');
	ZSTD_inBuffer  in = { src, src_len, 0 };
	ZSTD_outBuffer ob = { &out[0], out_cap, 0 };
	size_t rc = ZSTD_decompressStream(ds, &ob, &in);
	ZSTD_freeDStream(ds);
	(void)rc;
	out.resize(ob.pos);
	return ob.pos > 0;
}

// Peels the plaintext tar head for the (already detected) DFP type (enough for
// the PAX g-header at the start). plain = the first chunk decrypted by
// detect_archive_type via Try_Decrypting_File — only set for types 5/7 -> NO
// second decrypt. Type 6 reads+decompresses itself (libzstd_twrp), type 4 is
// plain tar. DFP (4-7) only; legacy/reject never reach this (Load).
bool BackupHeaderManager::decode_head(const string &segment, Archive_Type t, const string &plain, string &tarhead) {
	if (t == ENCRYPTED) {
		tarhead = plain;                                              // type 5: plaintext is tar
		return !tarhead.empty();
	}
	if (t == COMPRESSED_ENCRYPTED)
		return zstd_head(plain.data(), plain.size(), tarhead, 8192);  // type 7: plaintext is zstd

	if (t == COMPRESSED) {
		// Type 6: read the first ~128 KB compressed, then decompress.
		int fd = open(segment.c_str(), O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			return false;
		string comp(131072, '\0');
		ssize_t n = read(fd, &comp[0], comp.size());
		close(fd);
		if (n <= 0)
			return false;
		comp.resize((size_t)n);
		return zstd_head(comp.data(), comp.size(), tarhead, 8192);
	}
	if (t == UNCOMPRESSED) {
		// Type 4 (plain tar): the g-header sits in plaintext at the start — read the first 4 KB.
		int fd = open(segment.c_str(), O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			return false;
		tarhead.assign(4096, '\0');
		ssize_t n = read(fd, &tarhead[0], tarhead.size());
		close(fd);
		if (n <= 0)
			return false;
		tarhead.resize((size_t)n);
		return true;
	}
	return false;   // legacy (0/1) / OpenAES: no g-header
}

// Scans the peeled tar head for ALL "TWRP.<key>=<value>\n" records (PAX g) and
// stores them generically in mHeader. A value ends at newline (PAX record) or
// NUL (block padding/read limit). One scan -> all values; new keys need no code here.
void BackupHeaderManager::parse(const string &tarhead) {
	size_t pos = 0;
	while ((pos = tarhead.find("TWRP.", pos)) != string::npos) {
		size_t eq = tarhead.find('=', pos);
		if (eq == string::npos)
			break;
		size_t end = tarhead.find_first_of("\n\0", eq + 1, 2);  // \n OR NUL terminates the value
		if (end == string::npos)
			end = tarhead.size();
		string key = tarhead.substr(pos, eq - pos);             // "TWRP.backup_size"
		string val = tarhead.substr(eq + 1, end - (eq + 1));    // "24905311676"
		mHeader[key] = val;
		pos = end;
	}
}

// Detects type + status via detect_archive_type (ONE detection; extractTarFork
// consumes the result through GetType()/GetStatus()) and parses the TWRP.*
// g-records — only for this build's own types, which carry them.
// detect_archive_type sets mType ALWAYS (outer type even on reject).
// Returns true only if a g-header was parsed
// (DFP 4-7). Exactly ONE BAES decrypt: detect delivers the plaintext chunk in
// plain; decode_head reuses it.
bool BackupHeaderManager::Load(const string &segment, const string &password) {
	mHeader.clear();
	mLoaded = false;
	mType = LEGACY_UNCOMPRESSED;
	string plain;
	mStatus = detect_archive_type(segment, password, &mType, &plain);
	if (mStatus != DET_OK)
		return false;   // mType was already set by detect_archive_type (outer type, reject too)
	if (TWFunc::is_legacy_type(mType))            // legacy (0/1): no g-header -> nothing to parse
		return false;
	string tarhead;
	if (!decode_head(segment, mType, plain, tarhead))
		return false;
	parse(tarhead);
	mLoaded = true;
	return true;
}

int BackupHeaderManager::GetValue(const string &key, string &value) const {
	map<string, string>::const_iterator pos = mHeader.find(key);
	if (pos == mHeader.end())
		return -1;
	value = pos->second;
	return 0;
}

// 1 = ext app data present, 0 = explicitly none, -1 = no marker (caller: treat as "off").
int BackupHeaderManager::GetEad() const {
	string v;
	if (GetValue("TWRP.ead", v) != 0)
		return -1;
	return atoi(v.c_str());
}

// Restore progress denominator (= Total_Backup_Size). 0 = no marker (caller: get_size()).
unsigned long long BackupHeaderManager::GetBackupSize() const {
	string v;
	if (GetValue("TWRP.backup_size", v) != 0)
		return 0;
	return strtoull(v.c_str(), NULL, 10);
}

// Ext-app-data share of the backup (bytes, same accounting as backup_size).
// 0 = no marker (old backups without the field -> caller subtracts 0).
unsigned long long BackupHeaderManager::GetExtAppDataSize() const {
	string v;
	if (GetValue("TWRP.ext_app_data_size", v) != 0)
		return 0;
	return strtoull(v.c_str(), NULL, 10);
}

// --- Detection result (set in Load via detect_archive_type) ----------------
// mType is ALWAYS valid (outer type even on reject); mStatus carries DET_OK/reject reason.
Archive_Type BackupHeaderManager::GetType()   const { return mType; }
DetectResult BackupHeaderManager::GetStatus() const { return mStatus; }
bool         BackupHeaderManager::IsLegacy()  const { return TWFunc::is_legacy_type(mType); }

// Maps 1:1 to Get_File_Type (outer magic, NO decrypt). static = stateless.
Archive_Type BackupHeaderManager::GetFileType(const string& fn) { return Get_File_Type(fn); }

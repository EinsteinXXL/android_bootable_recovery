#ifndef BAES_FORMAT_H
#define BAES_FORMAT_H
/*
 * baes_format.h -- BAES v2 encrypted-backup wire format (single source of truth).
 *
 * Shared by:
 *   - writer/filter   : tw_bssl_aes/tw_bssl_aes.c  (enc/dec)
 *   - reader/pw probe : twrp-functions.cpp         (Try_Decrypting_File)
 *   - cipher banner   : twrpTar.cpp                (read_baes_cipher_id)
 * The PC tool Tools/twrp_extract.py cannot include a C header — on format
 * changes its constants must be kept in sync with this file manually.
 *
 * Header (32 B):
 *   0..3    Magic "BAES" (4 B)
 *   4..9    Reserved 0   (6 B)
 *   10..11  Version  uint16 LE (1)
 *   12..13  Flags    uint16 LE -- AEAD cipher id (0=AES-256-GCM, 1=ChaCha20-Poly1305)
 *   14..15  IterK    uint16 LE (PBKDF2 iterations / 1000)
 *   16..31  Salt     16 B random
 * Then chunks: [4 B uint32 LE: bit31=LAST, bits 0..30=plaintext length n (<=65536)]
 *              [n B ciphertext + 16 B AEAD tag]
 */

#define BAES_HEADER_SIZE              32
#define BAES_MAGIC                    "BAES"
#define BAES_MAGIC_LEN                4
#define BAES_VERSION                  1

/* Header offsets (little-endian uint16, except magic/salt): */
#define BAES_OFF_VERSION              10   /* [10..11] */
#define BAES_OFF_CIPHER               12   /* [12..13] AEAD cipher id (flags) */
#define BAES_OFF_ITER                 14   /* [14..15] PBKDF2 iter / 1000 */
#define BAES_OFF_SALT                 16   /* [16..31] */

#define BAES_SALT_LEN                 16
#define BAES_KEY_LEN                  32   /* PBKDF2 output = AEAD key (no IV) */
#define BAES_ITER_DIVISOR             1000 /* stored as uint16 = iter / 1000 */
#define BAES_ITER_DEFAULT             100000

/* AEAD cipher ids (header flags field). Both AEADs: 32-B key, 12-B nonce, 16-B tag. */
#define BAES_CIPHER_AES_256_GCM       0
#define BAES_CIPHER_CHACHA20_POLY1305 1

/* Chunk stream: */
#define BAES_CHUNK_PT                 65536        /* max plaintext per chunk (64 KB) */
#define BAES_AEAD_TAG_LEN             16
#define BAES_AEAD_NONCE_LEN           12
#define BAES_CHUNK_LAST_BIT           0x80000000u  /* bit31 of the 4-B chunk header */
#define BAES_CHUNK_LEN_MASK           0x7FFFFFFFu  /* bits 0..30 = plaintext length */

#endif /* BAES_FORMAT_H */

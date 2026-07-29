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
 * stage_io.h -- byte source/sink abstraction for the in-process pipeline engine.
 *
 * A StageIO is a pair of function pointers (+ context) that a stage loop (zstd /
 * BAES-AES / gzip) uses INSTEAD of raw read()/write() on hardcoded fds. This is
 * the single seam that lets the SAME stage-loop code run over:
 *   - fd backends     (the file end of a pipeline: a .win segment or an ADB FIFO),
 *   - ring backends   (every inter-stage and tar boundary, stage_ring.h), and
 *   - memory backends (buffer source / std::string sink, stage_engine.hpp).
 *
 * Pure C so the BAES stream core (tw_bssl_aes/baes_stream.c, C + BoringSSL) can
 * use the exact same primitive as the C++ engine (stage_engine.cpp). Self-guarded
 * with extern "C" for C++ callers.
 * --------------------------------------------------------------------------- */

#ifndef TW_STAGE_IO_H
#define TW_STAGE_IO_H

#include <stddef.h>
#include <sys/types.h>   /* ssize_t */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StageIO {
	/* Read up to `want` bytes into buf. Returns `want` (full), 0..want-1 ONLY
	 * on a real EOF (short read), or -1 on error. */
	ssize_t (*read_full)(void* ctx, void* buf, size_t want);
	/* Write ALL n bytes. Returns 0 on success, -1 on error. */
	int     (*write_all)(void* ctx, const void* buf, size_t n);
	void*   ctx;
} StageIO;

/* fd-backed StageIO callbacks. ctx points at an int holding the fd (the caller
 * keeps that int alive for the StageIO's lifetime). EINTR-retrying and
 * partial-read/write-safe. */
ssize_t stage_io_fd_read_full(void* ctx, void* buf, size_t want);
int     stage_io_fd_write_all(void* ctx, const void* buf, size_t n);

/* Convenience constructor for an fd-backed StageIO. fd_ptr must outlive the
 * returned StageIO (it is stored as ctx). Both directions are wired; a stage
 * uses only the relevant callback. */
static inline StageIO stage_io_from_fd(int* fd_ptr) {
	StageIO io;
	io.read_full = stage_io_fd_read_full;
	io.write_all = stage_io_fd_write_all;
	io.ctx       = (void*)fd_ptr;
	return io;
}

/* fd-backed source with a rolling POSIX_FADV_WILLNEED window (restore source
 * prefetch). Wraps stage_io_fd_read_full and keeps `window` bytes of async
 * readahead queued ahead of the sequential read position: every read advances
 * `pos`; once pos+window outruns the queued `frontier` by >= 8 MB, the gap is
 * re-armed in ONE fadvise call. Sequential reads only (the frontier assumes no
 * seeks); a window past EOF is clamped by the kernel; the advise only QUEUES
 * readahead -- correctness is untouched if it is ignored. window <= 0 behaves
 * exactly like stage_io_fd_read_full. */
typedef struct StageIoFdRa {
	int       fd;        /* segment fd (owned by the caller, like fd_ptr above) */
	long long window;    /* bytes to keep queued ahead of pos (<= 0 = plain read) */
	long long pos;       /* cumulative bytes handed to the reader */
	long long frontier;  /* absolute offset up to which WILLNEED is queued */
} StageIoFdRa;

ssize_t stage_io_fd_ra_read_full(void* ctx, void* buf, size_t want);

/* Convenience constructor. ra must outlive the returned StageIO (stored as
 * ctx). Source side only (write_all = NULL -- same pattern as the buffer
 * source in stage_engine.hpp). */
static inline StageIO stage_io_from_fd_ra(StageIoFdRa* ra) {
	StageIO io;
	io.read_full = stage_io_fd_ra_read_full;
	io.write_all = 0;   /* source only */
	io.ctx       = (void*)ra;
	return io;
}

#ifdef __cplusplus
}
#endif

#endif /* TW_STAGE_IO_H */

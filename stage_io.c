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

/* fd-backed StageIO callbacks: EINTR-retrying, partial-read/write-safe. */

#include "stage_io.h"

#include <errno.h>
#include <fcntl.h>    /* posix_fadvise64 (rolling readahead source) */
#include <unistd.h>

/* Reads exactly `want` bytes unless a real EOF (read()==0) occurs. On a pipe,
 * read() may return less than requested without EOF -- hence the loop.
 * Returns `want` (full), < want (only at EOF), or -1 on error. */
ssize_t stage_io_fd_read_full(void* ctx, void* buf, size_t want) {
	int fd = *(int*)ctx;
	unsigned char* p = (unsigned char*)buf;
	size_t total = 0;
	while (total < want) {
		ssize_t r = read(fd, p + total, want - total);
		if (r < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		if (r == 0) break;            /* EOF */
		total += (size_t)r;
	}
	return (ssize_t)total;
}

/* Rolling-readahead source (ctx = StageIoFdRa*, see stage_io.h): a plain full
 * read, then keep `window` bytes of async WILLNEED queued ahead of the read
 * position. Re-arm gate 8 MB -> one posix_fadvise64 per ~8 MB read, not per
 * read() call. The frontier starts wherever the caller pre-queued the initial
 * window (RestorePipeline::setup), so the first re-arm fires after ~8 MB. */
#define STAGE_IO_RA_REARM (8LL << 20)

ssize_t stage_io_fd_ra_read_full(void* ctx, void* buf, size_t want) {
	StageIoFdRa* ra = (StageIoFdRa*)ctx;
	ssize_t got = stage_io_fd_read_full(&ra->fd, buf, want);
	if (got > 0 && ra->window > 0) {
		ra->pos += got;
		if (ra->pos + ra->window >= ra->frontier + STAGE_IO_RA_REARM) {
			long long target = ra->pos + ra->window;
			posix_fadvise64(ra->fd, ra->frontier, target - ra->frontier,
			                POSIX_FADV_WILLNEED);
			ra->frontier = target;
		}
	}
	return got;
}

/* Writes ALL n bytes. Returns 0 on success, -1 on a real error. EINTR- and
 * partial-write-safe. */
int stage_io_fd_write_all(void* ctx, const void* buf, size_t n) {
	int fd = *(int*)ctx;
	const unsigned char* p = (const unsigned char*)buf;
	size_t written = 0;
	while (written < n) {
		ssize_t w = write(fd, p + written, n - written);
		if (w < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		written += (size_t)w;
	}
	return 0;
}

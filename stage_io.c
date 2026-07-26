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

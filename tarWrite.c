/*
	Copyright 2012 bigbiff/Dees_Troy TeamWin
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

#include <fcntl.h>
#include <unistd.h>
#include "libtar/libtar.h"
#include "twcommon.h"

/*
 * Delegates to tar_io_write (libtar/block.c), the shared block-I/O primitive
 * for backup and restore: it hardens EINTR/partial writes, while the common
 * case — one 512-byte block per call, and on the ADB FIFO an atomic write
 * because T_BLOCKSIZE < PIPE_BUF — never iterates the loop, staying a single
 * syscall. Returns -1 on a real error, which the caller detects as
 * != T_BLOCKSIZE in block.c.
 */
ssize_t write_libtar_no_buffer(int fd, const void *buffer, size_t size) {
	return tar_io_write(fd, buffer, size);
}

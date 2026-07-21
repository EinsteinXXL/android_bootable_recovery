/*
        Copyright 2013 bigbiff/Dees_Troy TeamWin
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

#ifndef _TARWRITE_HEADER
#define _TARWRITE_HEADER

/* Return type is ssize_t (not writefunc_t) — matches the definition in
 * tarWrite.c and the writefunc_t signature itself. Upstream TWRP wrongly
 * declares writefunc_t (a function pointer type) as the return type here;
 * calling through that prototype is UB that only works by AArch64 ABI
 * accident (pointer and ssize_t both live in x0). */
ssize_t write_libtar_no_buffer(int fd, const void *buffer, size_t size);

#endif  // _TARWRITE_HEADER

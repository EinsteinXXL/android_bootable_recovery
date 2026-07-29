/*
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

#ifndef __ORSCMD_H
#define __ORSCMD_H

#define ORS_INPUT_FILE "/system/bin/orsin"
#define ORS_OUTPUT_FILE "/system/bin/orsout"

// Status line the recovery writes into ORS_OUTPUT_FILE as the LAST line before
// closing it: "<prefix><decimal status>\n", 0 = success. The twrp binary
// consumes that line, keeps it out of its own output and exits with the value.
// Shared by both sides of the FIFO, so the wire format has one definition.
// A missing line means no status was reported -> the binary exits 0.
#define ORS_RESULT_PREFIX "TWRP_ORS_RESULT:"

#endif //__ORSCMD_H

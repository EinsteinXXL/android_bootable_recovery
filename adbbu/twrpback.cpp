/*
		Copyright 2013 to 2017 TeamWin
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/time.h>
#include <zlib.h>
#include <ctype.h>
#include <semaphore.h>
#include <string>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <utils/threads.h>
#include <pthread.h>

#include "twadbstream.h"
#include "twrpback.hpp"
#include "libtwadbbu.hpp"
#include "../twrpDigest/twrpDigest.hpp"
#include "../twrpDigest/twrpMD5.hpp"
#include "../twrpAdbBuFifo.hpp"

// F_SETPIPE_SZ (Linux >= 2.6.35): fallback define in case the libc header
// does not expose it (uapi: F_LINUX_SPECIFIC_BASE(1024) + 7).
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif

twrpback::twrpback(void) {
	adbd_fp = NULL;
	read_fd = 0;
	write_fd = 0;
	adb_control_twrp_fd = 0;
	adb_control_bu_fd = 0;
	adb_read_fd = 0;
	adb_write_fd = 0;
	ors_fd = 0;
	debug_adb_fd = 0;
	firstPart = true;
	stream_mode = false;
	createFifos();
	adbloginit();
}

twrpback::~twrpback(void) {
	adblogfile.close();
	closeFifos();
}

void twrpback::printErrMsg(std::string msg, int errNum) {
	std::stringstream str;
	str << strerror(errNum);
	adblogwrite(msg +  " " + str.str() + "\n");
}

void twrpback::createFifos(void) {
        if (mkfifo(TW_ADB_BU_CONTROL, 0666) < 0) {
                std::string msg = "Unable to create TW_ADB_BU_CONTROL fifo: ";
		printErrMsg(msg, errno);
        }
        if (mkfifo(TW_ADB_TWRP_CONTROL, 0666) < 0) {
                std::string msg = "Unable to create TW_ADB_TWRP_CONTROL fifo: ";
		printErrMsg(msg, errno);
                unlink(TW_ADB_BU_CONTROL);
        }
}

void twrpback::closeFifos(void) {
        if (unlink(TW_ADB_BU_CONTROL) < 0) {
                std::string msg = "Unable to remove TW_ADB_BU_CONTROL: ";
		printErrMsg(msg, errno);
        }
        if (unlink(TW_ADB_TWRP_CONTROL) < 0) {
                std::string msg = "Unable to remove TW_ADB_TWRP_CONTROL: ";
		printErrMsg(msg, errno);
	}
}

void twrpback::adbloginit(void) {
	adblogfile.open("/tmp/adb.log", std::fstream::app);
}

void twrpback::adblogwrite(std::string writemsg) {
	adblogfile << writemsg << std::flush;
}

void twrpback::close_backup_fds() {
	if (ors_fd > 0)
		close(ors_fd);
	if (write_fd > 0)
		close(write_fd);
	if (adb_read_fd > 0)
		close(adb_read_fd);
	if (adb_control_bu_fd > 0)
		close(adb_control_bu_fd);
	#ifdef _DEBUG_ADB_BACKUP
		if (debug_adb_fd > 0)
			close(debug_adb_fd);
	#endif
	if (adbd_fp != NULL)
		fclose(adbd_fp);
	if (access(TW_ADB_BACKUP, F_OK) == 0)
		unlink(TW_ADB_BACKUP);
}

void twrpback::close_restore_fds() {
	if (ors_fd > 0)
		close(ors_fd);
	if (write_fd > 0)
		close(write_fd);
	if (adb_control_bu_fd > 0)
		close(adb_control_bu_fd);
	if (adb_control_twrp_fd > 0)
		close(adb_control_twrp_fd);
	// Close the data-FIFO write end on the error/abort path too: Close-on-Trailer
	// and TWEOF only cover the regular path. Init is 0, so guard on > 0 like the others.
	if (adb_write_fd > 0) {
		close(adb_write_fd);
		adb_write_fd = -1;
	}
	if (adbd_fp != NULL)
		fclose(adbd_fp);
	if (access(TW_ADB_RESTORE, F_OK) == 0)
		unlink(TW_ADB_RESTORE);
	#ifdef _DEBUG_ADB_BACKUP
	if (debug_adb_fd > 0)
		close(debug_adb_fd);
	#endif
}

// ---------------------------------------------------------------------------
// pump_data: frame-aware bulk pump of the backup data FIFO -> adbd stream.
// Reads up to ADB_DATA_BUFFER_SIZE (the producer chunk: libtar bulk / zstd) at
// once and respects the 1-MB TWDATA stride (DATA_MAX_CHUNK_SIZE incl. the
// 512-B TWDATA header) -> byte-identical on the wire. digest + fwrite run
// straight from the read buffer; fflush only at frame boundaries. Flushing per
// 512-B block would force one socket write per block -> latency-bound mini USB
// transfers (~8 MB/s despite ~24 MB/s on the wire), so we coalesce instead.
//
// drain=false (main loop): nonblocking until EAGAIN -- preserves the caller's
//   control-FIFO interleaving (TWEOF/TWENDADB poll).
// drain=true (TWEOF): switch the FIFO to blocking and read until EOF. The
//   producer is guaranteed closed before TWEOF (twrpTar sends Write_TWEOF only
//   after closeTar/finish_pipeline). O_NONBLOCK is restored afterwards (the next
//   partition polls control + data alternately again).
//
// Returns false = write error toward adbd (caller finishes up); on the read
// side EAGAIN/EOF end the pump normally with true.
// ---------------------------------------------------------------------------
bool twrpback::pump_data(twrpMD5 &digest, uint64_t &totalbytes, uint64_t &fileBytes,
                         uint64_t &dataChunkBytes, bool &firstDataPacket, bool drain) {
	// bu is single-threaded (one backup per process) -- static buffer, same
	// idiom as data_buf in libtar/append.c.
	static char buf[ADB_DATA_BUFFER_SIZE];
	bool ok = true;
	int flags = -1;

	if (drain) {
		flags = fcntl(adb_read_fd, F_GETFL);
		if (flags >= 0)
			fcntl(adb_read_fd, F_SETFL, flags & ~O_NONBLOCK);
	}

	while (true) {
		// Frame remainder: the 512-B TWDATA header counts toward the 1-MB stride;
		// while it is still pending (firstDataPacket) subtract it from the remainder.
		size_t want = DATA_MAX_CHUNK_SIZE - dataChunkBytes;
		if (firstDataPacket)
			want -= sizeof(struct AdbBackupControlType);
		if (want > sizeof(buf))
			want = sizeof(buf);

		ssize_t bytes = read(adb_read_fd, buf, want);
		if (bytes < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				std::string msg = "Error reading TW_ADB_BACKUP: ";
				printErrMsg(msg, errno);
			}
			break;	// EAGAIN: FIFO empty for now -> back to the control poll
		}
		if (bytes == 0)
			break;	// EOF: all producer writers have closed

		// Write the TWDATA header only once real data is present
		// (no spurious frame on an empty stream).
		if (firstDataPacket) {
			if (!twadbbu::Write_TWDATA(adbd_fp)) {
				ok = false;
				break;
			}
			fileBytes += sizeof(struct AdbBackupControlType);
			dataChunkBytes += sizeof(struct AdbBackupControlType);
			firstDataPacket = false;
		}

		digest.update((unsigned char *) buf, bytes);
		totalbytes += bytes;
		fileBytes += bytes;
		dataChunkBytes += bytes;

		if (fwrite(buf, 1, bytes, adbd_fp) != (size_t) bytes) {
			std::string msg = "Cannot write to adbd stream: ";
			printErrMsg(msg, errno);
			ok = false;
			break;
		}
		#ifdef _DEBUG_ADB_BACKUP
		if (write_all(debug_adb_fd, buf, bytes) < 0) {
			std::string msg = "Cannot write to debug_adb_fd: ";
			printErrMsg(msg, errno);
			ok = false;
			break;
		}
		#endif

		if (dataChunkBytes == DATA_MAX_CHUNK_SIZE) {
			// Frame full: the next data starts with a fresh TWDATA header.
			// fflush only here (once per MB) instead of per 512-B block.
			dataChunkBytes = 0;
			firstDataPacket = true;
			fflush(adbd_fp);
		}
	}

	if (drain && flags >= 0)
		fcntl(adb_read_fd, F_SETFL, flags);
	return ok;
}

// EINTR-/partial-write-safe write() wrapper: batch writes > PIPE_BUF (4096)
// are not atomic on FIFOs. Same pattern as tar_io_write (libtar/block.c), kept
// local on purpose -- adbbu stays free of a libtar dependency.
ssize_t twrpback::write_all(int fd, const void *buf, size_t count) {
	size_t total = 0;
	while (total < count) {
		ssize_t n = write(fd, (const char *) buf + total, count - total);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		total += n;
	}
	return (ssize_t) count;
}

// Freeze-prone stock-adbd PTY detected (isatty, unpatched + no twadbd): ask the
// TWRP GUI to notify the user (wake screen + red log overlay). Uses the same
// TW_ADB_FIFO as the normal adbbackup/adbrestore op.
bool twrpback::send_adb_bu_notice(void) {
	int fd = open(TW_ADB_FIFO, O_WRONLY);
	int errctr = 0;
	while (fd < 0 && errctr < ADB_BU_MAX_ERROR) {
		usleep(10000);
		fd = open(TW_ADB_FIFO, O_WRONLY);
		errctr++;
	}
	if (fd < 0) {
		adblogwrite("Unable to open TW_ADB_FIFO to send GUI notice\n");
		return false;
	}
	char op[512];
	memset(op, 0, sizeof(op));
	snprintf(op, sizeof(op), "%s", ADB_BU_NOTICE_OP);
	bool ok = (write(fd, op, sizeof(op)) == (ssize_t)sizeof(op));
	if (!ok)
		adblogwrite("Unable to write GUI notice to TW_ADB_FIFO\n");
	close(fd);
	return ok;
}

bool twrpback::backup(std::string command) {
	twrpMD5 digest;
	int errctr = 0;
	uint64_t totalbytes = 0, dataChunkBytes = 0, fileBytes = 0;
	uint64_t md5fnsize = 0;
	struct AdbBackupControlType endadb;

	//ADBSTRUCT_STATIC_ASSERT(sizeof(endadb) == MAX_ADB_READ);

	bool writedata = true;
	bool compressed = false;
	bool firstDataPacket = true;

	// Freeze guard: an unpatched stock adbd hands bu a PTY (kRaw->kPty) whose n_tty
	// layer sporadically freezes completely under a bulk stream. Via twadbd
	// (adb shell adbbu start) or the system/core socketpair patch adbd_fd is a
	// socket -> isatty=false, so the guard never fires. On a PTY: refuse instead of
	// freezing + notify the user through the TWRP GUI.
	if (isatty(adbd_fd)) {
		adblogwrite("Refusing direct adb backup over stock-adbd PTY (freeze-prone). Run 'adb shell adbbu start' first.\n");
		send_adb_bu_notice();
		return false;
	}

	// If adbd/host dies mid-stream, fwrite should return EPIPE (-> the error path
	// logs and cleans up) instead of SIGPIPE killing the process silently.
	signal(SIGPIPE, SIG_IGN);

	adbd_fp = fdopen(adbd_fd, "w");
	if (adbd_fp == NULL) {
		adblogwrite("Unable to open adb_fp\n");
		return false;
	}
	// 128-KB stdio buffer: coalesces the 512-B command/TWDATA headers with the
	// following bulk fwrites into large socket writes (stdio passes chunks >= the
	// buffer size straight through). Set before the first I/O.
	if (setvbuf(adbd_fp, NULL, _IOFBF, ADB_DATA_BUFFER_SIZE) != 0)
		adblogwrite("setvbuf on adbd stream failed\n");

	if (mkfifo(TW_ADB_BACKUP, 0666) < 0) {
		adblogwrite("Unable to create TW_ADB_BACKUP fifo\n");
		return false;
	}

	adblogwrite("opening TW_ADB_FIFO\n");

	write_fd = open(TW_ADB_FIFO, O_WRONLY);
	while (write_fd < 0) {
		write_fd = open(TW_ADB_FIFO, O_WRONLY);
		usleep(10000);
		errctr++;
		if (errctr > ADB_BU_MAX_ERROR) {
			std::string msg = "Unable to open TW_ADB_FIFO";
			printErrMsg(msg, errno);
			close_backup_fds();
			return false;
		}
	}

	memset(operation, 0, sizeof(operation));
	if (snprintf(operation, sizeof(operation), "adbbackup %s", command.c_str()) >= (int)sizeof(operation)) {
		adblogwrite("Operation too big to write to ORS_INPUT_FILE\n");
		close_backup_fds();
		return false;
	}
	if (write(write_fd, operation, sizeof(operation)) != sizeof(operation)) {
		adblogwrite("Unable to write to ORS_INPUT_FILE\n");
		close_backup_fds();
		return false;
	}

	memset(&cmd, 0, sizeof(cmd));

	adblogwrite("opening TW_ADB_BU_CONTROL\n");
	adb_control_bu_fd = open(TW_ADB_BU_CONTROL, O_RDONLY | O_NONBLOCK);
	if (adb_control_bu_fd < 0) {
		adblogwrite("Unable to open TW_ADB_BU_CONTROL for reading.\n");
		close_backup_fds();
		return false;
	}

	adblogwrite("opening TW_ADB_BACKUP\n");
	adb_read_fd = open(TW_ADB_BACKUP, O_RDONLY | O_NONBLOCK);
	if (adb_read_fd < 0) {
		adblogwrite("Unable to open TW_ADB_BACKUP for reading.\n");
		close_backup_fds();
		return false;
	}
	// Raise the FIFO capacity to the producer chunk size (default 64 KB,
	// best-effort) so one read() can swallow a full 128-KB producer write
	// (libtar bulk / zstd) at once.
	if (fcntl(adb_read_fd, F_SETPIPE_SZ, ADB_DATA_BUFFER_SIZE) < 0)
		adblogwrite("Unable to set TW_ADB_BACKUP pipe size\n");

	//loop until TWENDADB sent
	while (true) {
		if (read(adb_control_bu_fd, &cmd, sizeof(cmd)) > 0) {
			struct AdbBackupControlType structcmd;

			memcpy(&structcmd, cmd, sizeof(cmd));
			std::string cmdtype = structcmd.get_type();

			//we received an error, exit and unlink
			if (cmdtype == TWERROR) {
				writedata = false;
				adblogwrite("Error received. Quitting...\n");
				close_backup_fds();
				return false;
			}
			//we received the end of adb backup stream so we should break the loop
			else if (cmdtype == TWENDADB) {
				writedata = false;
				adblogwrite("Recieved TWENDADB\n");
				memcpy(&endadb, cmd, sizeof(cmd));
				std::stringstream str;
				str << totalbytes;
				adblogwrite(str.str() + " total bytes written\n");
				break;
			}
			//we recieved the TWSTREAMHDR structure metadata to write to adb
			else if (cmdtype == TWSTREAMHDR) {
				writedata = false;
				adblogwrite("writing TWSTREAMHDR\n");
				if (fwrite(cmd, 1, sizeof(cmd), adbd_fp) != sizeof(cmd)) {
					std::string msg = "Error writing TWSTREAMHDR to adbd";
					printErrMsg(msg, errno);
					close_backup_fds();
					return false;
				}
				fflush(adbd_fp);
			}
			//we will be writing an image from TWRP
			else if (cmdtype == TWIMG) {
				struct twfilehdr twimghdr;

				adblogwrite("writing TWIMG\n");
				digest.init();
				memset(&twimghdr, 0, sizeof(twimghdr));
				memcpy(&twimghdr, cmd, sizeof(cmd));
				md5fnsize = twimghdr.size;
				compressed = false;

				#ifdef _DEBUG_ADB_BACKUP
				std::string debug_fname = "/data/media/";
				debug_fname.append(basename(twimghdr.name));
				debug_fname.append("-backup.img");
				debug_adb_fd = open(debug_fname.c_str(), O_WRONLY | O_CREAT, 0666);
				adblogwrite("Opening adb debug tar\n");
				#endif

				if (fwrite(cmd, 1, sizeof(cmd), adbd_fp) != sizeof(cmd)) {
					adblogwrite("Error writing TWIMG to adbd\n");
					close_backup_fds();
					return false;
				}
				fflush(adbd_fp);
				writedata = true;
			}
			//we will be writing a tar from TWRP
			else if (cmdtype == TWFN) {
				struct twfilehdr twfilehdr;

				adblogwrite("writing TWFN\n");
				digest.init();

				//ADBSTRUCT_STATIC_ASSERT(sizeof(twfilehdr) == MAX_ADB_READ);

				memset(&twfilehdr, 0, sizeof(twfilehdr));
				memcpy(&twfilehdr, cmd, sizeof(cmd));
				md5fnsize = twfilehdr.size;

				compressed = twfilehdr.compressed == 1 ? true: false;

				#ifdef _DEBUG_ADB_BACKUP
				std::string debug_fname = "/data/media/";
				debug_fname.append(basename(twfilehdr.name));
				debug_fname.append("-backup.tar");
				debug_adb_fd = open(debug_fname.c_str(), O_WRONLY | O_CREAT, 0666);
				adblogwrite("Opening adb debug tar\n");
				#endif

				if (fwrite(cmd, 1, sizeof(cmd), adbd_fp) != sizeof(cmd)) {
					adblogwrite("Error writing TWFN to adbd\n");
					close_backup_fds();
					return false;
				}
				fflush(adbd_fp);
				writedata = true;
			}
			/*
			We received the command that we are done with the file stream.
			We will flush the remaining data stream.
			Update md5 and write final results to adb stream.
			If we need padding because the total bytes are not a multiple
			of 512, we pad the end with 0s to we reach 512.
			We also write the final md5 to the adb stream.
			*/
			else if (cmdtype == TWEOF) {
				adblogwrite("received TWEOF\n");
				// Drain the remainder through the frame-aware 128-KB pump (drain=true:
				// blocking until EOF -- the tar writer is already closed at TWEOF). This
				// keeps TWDATA-header framing on the trailing data so the restore frame
				// parser stays in sync; write errors here are fatal.
				if (!pump_data(digest, totalbytes, fileBytes, dataChunkBytes, firstDataPacket, true)) {
					close_backup_fds();
					return false;
				}

				if (fileBytes % DATA_MAX_CHUNK_SIZE != 0) {
					int64_t count = fileBytes / DATA_MAX_CHUNK_SIZE + 1;
					uint64_t ceilingBytes = count * DATA_MAX_CHUNK_SIZE;
					size_t paddingBytes = (size_t)(ceilingBytes - fileBytes);
					// For a COMPRESSED stream, write the alignment padding as a zstd
					// skippable frame (magic 0x184D2A50) instead of raw zeros. `zstd -d`
					// skips skippable frames by design -> no "unsupported format"/ERROR on
					// ADB restore (the zeros would reach zstd AFTER the real frame).
					// Compressed only: raw tar zeros are harmless (= tar EOF padding), and
					// images/uncompressed never pass through zstd. The byte count is
					// unchanged -> the 512-B/1-MB alignment of the MD5TRAILER holds; only
					// the padding CONTENT changes. Restore forwards the bytes 1:1 (no
					// restore-side touch), so md5 stays consistent (both sides digest the
					// same bytes). The 8-B header needs paddingBytes>=8; on the (extremely
					// rare) natural padding of 1..7 add one more 1-MB frame (stays
					// 1-MB-aligned). paddingBytes==0 cannot occur here (guarded above).
					if (compressed && paddingBytes < 8) {
						ceilingBytes += DATA_MAX_CHUNK_SIZE;
						paddingBytes = (size_t)(ceilingBytes - fileBytes);
					}
					// Heap instead of a stack VLA: data-dependent up to ~1 MB (edge case ~2 MB).
					std::vector<char> padding(paddingBytes, 0);
					if (compressed) {
						// zstd Skippable Frame Header, little-endian on the wire:
						// [Magic 0x184D2A50][Frame_Size uint32 = paddingBytes-8][Nullen].
						unsigned char *p = (unsigned char *) padding.data();
						p[0] = 0x50; p[1] = 0x2A; p[2] = 0x4D; p[3] = 0x18;
						uint32_t fsz = (uint32_t)(paddingBytes - 8);
						p[4] = (unsigned char)(fsz & 0xFF);
						p[5] = (unsigned char)((fsz >> 8) & 0xFF);
						p[6] = (unsigned char)((fsz >> 16) & 0xFF);
						p[7] = (unsigned char)((fsz >> 24) & 0xFF);
					}
					std::stringstream paddingStr;
					paddingStr << paddingBytes;
					adblogwrite("writing padding to stream: " + paddingStr.str() + " bytes\n");
					if (fwrite(padding.data(), 1, paddingBytes, adbd_fp) != paddingBytes) {
						adblogwrite("Error writing padding to adbd\n");
						close_backup_fds();
						return false;
					}
					#if defined(_DEBUG_ADB_BACKUP)
					if (write(debug_adb_fd, padding.data(), paddingBytes) < 1) {
						std::string msg = "Cannot write to ADB_CONTROL_READ_FD: ";
						printErrMsg(msg, errno);
						close_restore_fds();
						return false;
					}
					#endif
					totalbytes += paddingBytes;
					digest.update((unsigned char *) padding.data(), paddingBytes);
					fflush(adbd_fp);
				}

				AdbBackupFileTrailer md5trailer;

				memset(&md5trailer, 0, sizeof(md5trailer));

				std::string md5string = digest.return_digest_string();

				strncpy(md5trailer.start_of_trailer, TWRP, sizeof(md5trailer.start_of_trailer));
				strncpy(md5trailer.type, MD5TRAILER, sizeof(md5trailer.type));
				strncpy(md5trailer.md5, md5string.c_str(), sizeof(md5trailer.md5));

				md5trailer.crc = crc32(0L, Z_NULL, 0);
				md5trailer.crc = crc32(md5trailer.crc, (const unsigned char*) &md5trailer, sizeof(md5trailer));

				md5trailer.ident = crc32(0L, Z_NULL, 0);
				md5trailer.ident = crc32(md5trailer.ident, (const unsigned char*) &md5trailer, sizeof(md5trailer));
				md5trailer.ident = crc32(md5trailer.ident, (const unsigned char*) &md5fnsize, sizeof(md5fnsize));

				if (fwrite(&md5trailer, 1, sizeof(md5trailer), adbd_fp) != sizeof(md5trailer))  {
					adblogwrite("Error writing md5trailer to adbd\n");
					close_backup_fds();
					return false;
				}
				fflush(adbd_fp);
				writedata = false;
				firstDataPacket = true;
				fileBytes = 0;
			}
			memset(&cmd, 0, sizeof(cmd));
			dataChunkBytes = 0;
		}
		//If we are to write data because of a new file stream, lets write all the data.
		//This will allow us to not write data after a command structure has been written
		//to the adb stream.
		//If the stream is compressed, we need to always write the data.
		// 128-KB frame-aware pump (pump_data): nonblocking until EAGAIN, then back
		// to the control poll above. Bulk pumping avoids the latency-bound mini USB
		// writes that per-block flushing would cause.
		if (writedata || compressed) {
			if (!pump_data(digest, totalbytes, fileBytes, dataChunkBytes, firstDataPacket, false)) {
				close_backup_fds();
				return false;
			}
		}
	}

	//Write the final end adb structure to the adb stream
	if (fwrite(&endadb, 1, sizeof(endadb), adbd_fp) != sizeof(endadb)) {
		adblogwrite("Error writing endadb to adbd\n");
		close_backup_fds();
		return false;
	}
	fflush(adbd_fp);
	close_backup_fds();
	return true;
}

bool twrpback::restore(void) {
	twrpMD5 digest;
	char cmd[MAX_ADB_READ];
	char readAdbStream[MAX_ADB_READ];
	struct AdbBackupControlType structcmd;
	int errctr = 0;
	uint64_t totalbytes = 0, dataChunkBytes = 0;
	uint64_t md5fnsize = 0, fileBytes = 0;
	bool read_from_adb;
	bool md5sumdata;
	// tweofrcvd MUST be initialized: if it were indeterminate and happened to be
	// true, the very FIRST MD5TRAILER would consume a never-received TWEOF and the
	// TWEOF synchronization would start shifted by one partition.
	bool compressed, tweofrcvd = false, extraData;

	read_from_adb = true;

	// Freeze guard (see backup()): PTY = unpatched stock adbd without twadbd ->
	// refuse instead of freezing + GUI notice. Socket (twadbd/patch) -> isatty=false.
	if (isatty(adbd_fd)) {
		adblogwrite("Refusing direct adb restore over stock-adbd PTY (freeze-prone). Run 'adb shell adbbu start' first.\n");
		send_adb_bu_notice();
		return false;
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	adbd_fp = fdopen(adbd_fd, "r");
	if (adbd_fp == NULL) {
		adblogwrite("Unable to open adb_fp\n");
		close_restore_fds();
		return false;
	}
	// 128-KB stdio buffer: the 512-B command freads stay, but the underlying
	// socket reads become large (fewer syscalls).
	if (setvbuf(adbd_fp, NULL, _IOFBF, ADB_DATA_BUFFER_SIZE) != 0)
		adblogwrite("setvbuf on adbd stream failed\n");

	if(mkfifo(TW_ADB_RESTORE, 0666)) {
		adblogwrite("Unable to create TW_ADB_RESTORE fifo\n");
		close_restore_fds();
		return false;
	}

	adblogwrite("opening TW_ADB_FIFO\n");
	write_fd = open(TW_ADB_FIFO, O_WRONLY);

	while (write_fd < 0) {
		write_fd = open(TW_ADB_FIFO, O_WRONLY);
		errctr++;
		if (errctr > ADB_BU_MAX_ERROR) {
			std::string msg = "Unable to open TW_ADB_FIFO.";
			printErrMsg(msg, errno);
			close_restore_fds();
			return false;
		}
	}

	memset(operation, 0, sizeof(operation));
	// GUI .ab restore (stream_mode) -> its own op so the FIFO thread knows a GUI
	// action thread owns the completion (just report status); PC adb restore ->
	// ADB_RESTORE_OP (the engine owns the completion).
	sprintf(operation, "%s", stream_mode ? ADB_RESTORE_STREAM_OP : ADB_RESTORE_OP);
	if (write(write_fd, operation, sizeof(operation)) != sizeof(operation)) {
		adblogwrite("Unable to write to TW_ADB_FIFO\n");
		close_restore_fds();
		return false;
	}

	memset(&readAdbStream, 0, sizeof(readAdbStream));
	memset(&cmd, 0, sizeof(cmd));

	adblogwrite("opening TW_ADB_BU_CONTROL\n");
	adb_control_bu_fd = open(TW_ADB_BU_CONTROL, O_RDONLY | O_NONBLOCK);
	if (adb_control_bu_fd < 0) {
		std::string msg = "Unable to open TW_ADB_BU_CONTROL for writing.";
		printErrMsg(msg, errno);
		close_restore_fds();
		return false;
	}

	adblogwrite("opening TW_ADB_TWRP_CONTROL\n");
	adb_control_twrp_fd = open(TW_ADB_TWRP_CONTROL, O_WRONLY | O_NONBLOCK);
	if (adb_control_twrp_fd < 0) {
		std::string msg = "Unable to open TW_ADB_TWRP_CONTROL for writing. Retrying...";
		printErrMsg(msg, errno);
		while (adb_control_twrp_fd < 0) {
			adb_control_twrp_fd = open(TW_ADB_TWRP_CONTROL, O_WRONLY | O_NONBLOCK);
			usleep(10000);
			errctr++;
			if (errctr > ADB_BU_MAX_ERROR) {
				adblogwrite("Unable to open TW_ADB_TWRP_CONTROL\n");
				close_backup_fds();
				return false;
			}
		}
	}

	//Loop until we receive TWENDADB from TWRP
	while (true) {
		memset(&cmd, 0, sizeof(cmd));
		if (read(adb_control_bu_fd, &cmd, sizeof(cmd)) > 0) {
			struct AdbBackupControlType structcmd;
			memcpy(&structcmd, cmd, sizeof(cmd));
			std::string cmdtype = structcmd.get_type();

			//If we receive TWEOF from TWRP close adb data fifo
			if (cmdtype == TWEOF) {
				adblogwrite("Received TWEOF\n");
				// TWEOF synchronization: TWRP sends exactly ONE TWEOF per partition, and
				// it must never survive a partition boundary. Unconditionally setting
				// tweofrcvd=true + close(fd) here would be wrong in the wait case (where
				// this TWEOF just ends the wait after the MD5TRAILER, i.e. is already
				// consumed): the stale flag would then be spent by the NEXT partition's
				// trailer (chain permanently off by one), and a late-read TWEOF would
				// close the freshly opened data fd of the WRONG partition ("Bad file
				// descriptor" series, TWRP hanging forever in open(TW_ADB_RESTORE) /
				// wchan=fifo_open).
				if (!read_from_adb) {
					// Wait case: this exact TWEOF was expected after the MD5TRAILER ->
					// consume it and keep reading, do NOT latch it. adb_write_fd is
					// always -1 here (Close-on-Trailer).
					read_from_adb = true;
				} else {
					// Ahead case: TWEOF arrived before we processed the trailer (TWRP has
					// its exact size bytes; we may still be pumping padding). Latch it for
					// the immediately following trailer of the SAME partition; the open fd
					// here still belongs to the current partition -> closing is fine
					// (padding leftovers run through the md5sumdata path, "end of stream
					// reached").
					tweofrcvd = true;
					if (adb_write_fd >= 0) {
						close(adb_write_fd);
						adb_write_fd = -1;
					}
				}
			}
			//Break when TWRP sends TWENDADB
			else if (cmdtype == TWENDADB) {
				adblogwrite("Received TWENDADB\n");
				break;
			}
			//we received an error, exit and unlink
			else if (cmdtype == TWERROR) {
				adblogwrite("Error received. Quitting...\n");
				close_restore_fds();
				return false;
			}
		}
		//If we should read from the adb stream, write commands and data to TWRP
		if (read_from_adb) {
			int readbytes;
			if ((readbytes = fread(readAdbStream, 1, sizeof(readAdbStream), adbd_fp)) == sizeof(readAdbStream)) {
				memcpy(&structcmd, readAdbStream, sizeof(readAdbStream));
				std::string cmdtype = structcmd.get_type();

				//Tell TWRP we have read the entire adb stream
				if (cmdtype == TWENDADB) {
					struct AdbBackupControlType endadb;
					uint32_t crc, endadbcrc;

					md5sumdata = false;
					memset(&endadb, 0, sizeof(endadb));
					memcpy(&endadb, readAdbStream, sizeof(readAdbStream));
					endadbcrc = endadb.crc;
					memset(&endadb.crc, 0, sizeof(endadb.crc));
					crc = crc32(0L, Z_NULL, 0);
					crc = crc32(crc, (const unsigned char*) &endadb, sizeof(endadb));

					if (crc == endadbcrc) {
						adblogwrite("sending TWENDADB\n");
						if (write(adb_control_twrp_fd, &endadb, sizeof(endadb)) < 1) {
							std::string msg = "Cannot write to ADB_CONTROL_READ_FD: ";
							printErrMsg(msg, errno);
							close_restore_fds();
							return false;
						}
						read_from_adb = false;
					}
					else {
						adblogwrite("ADB TWENDADB crc header doesn't match\n");
						close_restore_fds();
						return false;
					}
				}
				//Send TWRP partition metadata
				else if (cmdtype == TWSTREAMHDR) {
					struct AdbBackupStreamHeader cnthdr;
					uint32_t crc, cnthdrcrc;

					//ADBSTRUCT_STATIC_ASSERT(sizeof(cnthdr) == MAX_ADB_READ);

					md5sumdata = false;
					memset(&cnthdr, 0, sizeof(cnthdr));
					memcpy(&cnthdr, readAdbStream, sizeof(readAdbStream));
					cnthdrcrc = cnthdr.crc;
					memset(&cnthdr.crc, 0, sizeof(cnthdr.crc));
					crc = crc32(0L, Z_NULL, 0);
					crc = crc32(crc, (const unsigned char*) &cnthdr, sizeof(cnthdr));

					if (crc == cnthdrcrc) {
						adblogwrite("Restoring TWSTREAMHDR\n");
						if (write(adb_control_twrp_fd, readAdbStream, sizeof(readAdbStream)) < 0) {
							std::string msg = "Cannot write to adb_control_twrp_fd: ";
							printErrMsg(msg, errno);
							close_restore_fds();
							return false;
						}
					}
					else {
						adblogwrite("ADB TWSTREAMHDR crc header doesn't match\n");
						close_restore_fds();
						return false;
					}
				}
				//Tell TWRP we are sending a partition image
				else if (cmdtype == TWIMG) {
					struct twfilehdr twimghdr;
					uint32_t crc, twimghdrcrc;
					md5sumdata = false;
					fileBytes = 0;
					read_from_adb = true;
					dataChunkBytes = 0;
					extraData = false;

					digest.init();
					adblogwrite("Restoring TWIMG\n");
					memset(&twimghdr, 0, sizeof(twimghdr));
					memcpy(&twimghdr, readAdbStream, sizeof(readAdbStream));
					md5fnsize = twimghdr.size;
					twimghdrcrc = twimghdr.crc;
					memset(&twimghdr.crc, 0, sizeof(twimghdr.crc));

					crc = crc32(0L, Z_NULL, 0);
					crc = crc32(crc, (const unsigned char*) &twimghdr, sizeof(twimghdr));
					if (crc == twimghdrcrc) {
						if (write(adb_control_twrp_fd, readAdbStream, sizeof(readAdbStream)) < 1) {
							std::string msg = "Cannot write to adb_control_twrp_fd: ";
							printErrMsg(msg, errno);
							close_restore_fds();
							return false;
						}
					}
					else {
						adblogwrite("ADB TWIMG crc header doesn't match\n");
						close_restore_fds();
						return false;
					}

					#ifdef _DEBUG_ADB_BACKUP
					std::string debug_fname = "/data/media/";
					debug_fname.append(basename(twimghdr.name));
					debug_fname.append("-restore.img");
					adblogwrite("image: " + debug_fname + "\n");
					debug_adb_fd = open(debug_fname.c_str(), O_WRONLY | O_CREAT, 0666);
					adblogwrite("Opened restore image\n");
					#endif

					adblogwrite("opening TW_ADB_RESTORE\n");
					adb_write_fd = open(TW_ADB_RESTORE, O_WRONLY);
					// FIFO capacity for the 128-KB batches (best-effort).
					if (adb_write_fd >= 0 && fcntl(adb_write_fd, F_SETPIPE_SZ, ADB_DATA_BUFFER_SIZE) < 0)
						adblogwrite("Unable to set TW_ADB_RESTORE pipe size\n");
				}
				//Tell TWRP we are sending a tar stream
				else if (cmdtype == TWFN) {
					struct twfilehdr twfilehdr;
					uint32_t crc, twfilehdrcrc;
					fileBytes = 0;
					md5sumdata = false;
					read_from_adb = true;
					dataChunkBytes = 0;
					extraData = false;

					digest.init();
					adblogwrite("Restoring TWFN\n");
					memset(&twfilehdr, 0, sizeof(twfilehdr));
					memcpy(&twfilehdr, readAdbStream, sizeof(readAdbStream));
					md5fnsize = twfilehdr.size;
					twfilehdrcrc = twfilehdr.crc;
					memset(&twfilehdr.crc, 0, sizeof(twfilehdr.crc));

					crc = crc32(0L, Z_NULL, 0);
					crc = crc32(crc, (const unsigned char*) &twfilehdr, sizeof(twfilehdr));

					if (crc == twfilehdrcrc) {
						if (write(adb_control_twrp_fd, readAdbStream, sizeof(readAdbStream)) < 1) {
							std::string msg = "Cannot write to adb_control_twrp_fd: ";
							printErrMsg(msg, errno);
							close_restore_fds();
							return false;
						}
					}
					else {
						adblogwrite("ADB TWFN crc header doesn't match\n");
						close_restore_fds();
						return false;
					}

					#ifdef _DEBUG_ADB_BACKUP
					std::string debug_fname = "/data/media/";
					debug_fname.append(basename(twfilehdr.name));
					debug_fname.append("-restore.tar");
					adblogwrite("tar: " + debug_fname + "\n");
					debug_adb_fd = open(debug_fname.c_str(), O_WRONLY | O_CREAT, 0666);
					adblogwrite("Opened restore tar\n");
					#endif

					compressed = twfilehdr.compressed == 1 ? true: false;
					adblogwrite("opening TW_ADB_RESTORE\n");
					adb_write_fd = open(TW_ADB_RESTORE, O_WRONLY);
					// FIFO capacity for the 128-KB batches (best-effort).
					if (adb_write_fd >= 0 && fcntl(adb_write_fd, F_SETPIPE_SZ, ADB_DATA_BUFFER_SIZE) < 0)
						adblogwrite("Unable to set TW_ADB_RESTORE pipe size\n");
				}
				else if (cmdtype == MD5TRAILER) {
					// Close-on-Trailer: by protocol the MD5TRAILER is the end of this
					// partition's data stream -> close the data-FIFO write end
					// unconditionally so the extract pipeline gets its EOF. A
					// `fileBytes >= md5fnsize` condition is wrong for the compressed
					// case (fileBytes = COMPRESSED wire bytes, md5fnsize = UNcompressed
					// size), so zstd would never get EOF and would only "terminate" by
					// crashing on trailing padding. Buffered FIFO bytes are not lost by
					// close (POSIX: the reader drains the buffer, then sees EOF).
					if (adb_write_fd >= 0) {
						close(adb_write_fd);
						adb_write_fd = -1;
					}
					if (tweofrcvd) {
						read_from_adb = true;
						tweofrcvd = false;
					}
					else
						read_from_adb = false; //don't read from adb until TWRP sends TWEOF
					md5sumdata = false;
					if (!checkMD5Trailer(readAdbStream, md5fnsize, &digest)) {
						close_restore_fds();
						break;
					}
					continue;
				}
				//Send the tar or partition image md5 to TWRP
				else if (cmdtype == TWDATA) {
					// 128-KB batch pump: fread grabs min(128 KB, frame remainder) at once.
					// The MD5TRAILER detection still runs per 512-B block (same get_type()
					// semantics); non-trailer blocks go into the FIFO as ONE digest.update
					// + ONE write_all. Bookkeeping (dataChunkBytes/totalbytes/fileBytes
					// count the trailer block too). After a write error (TWRP side closed):
					// md5sumdata=true -- from then on we only digest, no longer forwarding
					// to the FIFO.
					static char databuf[ADB_DATA_BUFFER_SIZE];
					dataChunkBytes += sizeof(readAdbStream);
					bool leave_twdata = false;
					while (!leave_twdata) {
						size_t want = DATA_MAX_CHUNK_SIZE - dataChunkBytes;
						if (want > sizeof(databuf))
							want = sizeof(databuf);
						if ((readbytes = fread(databuf, 1, want, adbd_fp)) != (int) want) {
							// Surface a stream break mid data-frame instead of aborting
							// silently (which would leave "failed" with no diagnostic
							// in adb.log).
							std::stringstream spos;
							spos << totalbytes;
							adblogwrite("adbd input stream died mid-frame (fread short) after " + spos.str() + " payload bytes\n");
							close_restore_fds();
							return false;
						}

						// Per-block trailer scan within the batch (512-B steps).
						size_t pos = 0;
						bool trailer_hit = false;
						while (pos < (size_t) readbytes) {
							memcpy(&structcmd, databuf + pos, sizeof(structcmd));
							std::string blocktype = structcmd.get_type();

							dataChunkBytes += sizeof(readAdbStream);
							totalbytes += sizeof(readAdbStream);
							fileBytes += sizeof(readAdbStream);

							if (blocktype == MD5TRAILER) {
								trailer_hit = true;
								break;
							}
							pos += sizeof(readAdbStream);
						}

						// Digest + forward the data blocks before the (possible) trailer
						// in one go.
						if (pos > 0) {
							digest.update((unsigned char *) databuf, pos);
							read_from_adb = true;
							#ifdef _DEBUG_ADB_BACKUP
							if (write_all(debug_adb_fd, databuf, pos) < 0) {
								std::string msg = "Cannot write to debug_adb_fd: ";
								printErrMsg(msg, errno);
								close_restore_fds();
								return false;
							}
							#endif
							if (!md5sumdata && write_all(adb_write_fd, databuf, pos) < 0) {
								std::string msg = "Cannot write to TWRP ADB FIFO: ";
								md5sumdata = true;
								printErrMsg(msg, errno);
								adblogwrite("end of stream reached.\n");
							}
						}

						if (trailer_hit) {
							// Close-on-Trailer -- see the comment in the outer MD5TRAILER
							// branch: close unconditionally -> zstd/tar get their EOF.
							if (adb_write_fd >= 0) {
								close(adb_write_fd);
								adb_write_fd = -1;
							}
							if (tweofrcvd) {
								tweofrcvd = false;
								read_from_adb = true;
							}
							else
								read_from_adb = false; //don't read from adb until TWRP sends TWEOF
							if (!checkMD5Trailer(databuf + pos, md5fnsize, &digest)) {
								close_restore_fds();
							}
							leave_twdata = true;
						}
						else if (dataChunkBytes == DATA_MAX_CHUNK_SIZE) {
							dataChunkBytes = 0;
							md5sumdata = false;
							leave_twdata = true;
						}
					}
				}
				else if (md5sumdata) {
					digest.update((unsigned char*)readAdbStream, sizeof(readAdbStream));
					md5sumdata = true;
				}
			}
			else {
				// A short fread on the blocking adbd stream = EOF/error (host adb server
				// killed, USB break, adbd pump dead). Log the position and abort hard
				// instead of spinning forever without progress (a perceived "freeze");
				// the TWRP side then runs out via its regular error path (FIFO EOF ->
				// extract error -> restore failed).
				std::stringstream spos;
				spos << totalbytes;
				adblogwrite("adbd input stream ended prematurely (fread short, EOF/error) after " + spos.str() + " payload bytes -- host adb stream died?\n");
				close_restore_fds();
				return false;
			}
		}
	}
	std::stringstream str;
	str << totalbytes;
	close_restore_fds();
	adblogwrite(str.str() + " bytes restored from adbbackup\n");
	return true;
}

void twrpback::streamFileForTWRP(void) {
	adblogwrite("streamFileForTwrp" + streamFn + "\n");
}

void twrpback::setStreamFileName(std::string fn) {
	streamFn = fn;
	stream_mode = true;	// GUI .ab restore -> restore() writes ADB_RESTORE_STREAM_OP
	adbd_fd = open(fn.c_str(), O_RDONLY);
	if (adbd_fd < 0) {
		adblogwrite("Unable to open adb_fd\n");
		close(adbd_fd);
		return;
	}
	restore();
}

void twrpback::threadStream(void) {
	pthread_t thread;
	ThreadPtr streamPtr = &twrpback::streamFileForTWRP;
	PThreadPtr p = *(PThreadPtr*)&streamPtr;
	pthread_create(&thread, NULL, p, this);
	pthread_join(thread, NULL);
}

bool twrpback::checkMD5Trailer(char readAdbStream[], uint64_t md5fnsize, twrpMD5 *digest) {
	struct AdbBackupFileTrailer md5tr;
	uint32_t crc, md5trcrc, md5ident, md5identmatch;

	//ADBSTRUCT_STATIC_ASSERT(sizeof(md5tr) == MAX_ADB_READ);
	memcpy(&md5tr, readAdbStream, MAX_ADB_READ);
	md5ident = md5tr.ident;

	memset(&md5tr.ident, 0, sizeof(md5tr.ident));

	md5identmatch = crc32(0L, Z_NULL, 0);
	md5identmatch = crc32(md5identmatch, (const unsigned char*) &md5tr, sizeof(md5tr));
	md5identmatch = crc32(md5identmatch, (const unsigned char*) &md5fnsize, sizeof(md5fnsize));

	if (md5identmatch == md5ident) {
		adblogwrite("checking MD5TRAILER\n");
		md5trcrc = md5tr.crc;
		memset(&md5tr.crc, 0, sizeof(md5tr.crc));
		crc = crc32(0L, Z_NULL, 0);
		crc = crc32(crc, (const unsigned char*) &md5tr, sizeof(md5tr));
		if (crc == md5trcrc) {
			if (write(adb_control_twrp_fd, &md5tr, sizeof(md5tr)) < 1) {
				std::string msg = "Cannot write to adb_control_twrp_fd: ";
				printErrMsg(msg, errno);
				close_restore_fds();
				return false;
			}
		}
		else {
			adblogwrite("ADB MD5TRAILER crc header doesn't match\n");
			close_restore_fds();
			return false;
		}

		AdbBackupFileTrailer md5;

		memset(&md5, 0, sizeof(md5));
		strncpy(md5.start_of_trailer, TWRP, sizeof(md5.start_of_trailer));
		strncpy(md5.type, TWMD5, sizeof(md5.type));
		std::string md5string = digest->return_digest_string();
		strncpy(md5.md5, md5string.c_str(), sizeof(md5.md5));

		adblogwrite("sending MD5 verification: " + md5string + "\n");
		if (write(adb_control_twrp_fd, &md5, sizeof(md5)) < 1) {
			std::string msg = "Cannot write to adb_control_twrp_fd: ";
			printErrMsg(msg, errno);
			close_restore_fds();
			return false;
		}
		return true;
	}
	return false;
}

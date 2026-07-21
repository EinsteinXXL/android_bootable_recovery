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

#ifndef _TWRPBACK_HPP
#define _TWRPBACK_HPP

#include <sys/types.h>
#include <fstream>
#include "../twrpDigest/twrpMD5.hpp"

class twrpback {
public:
	int adbd_fd;                                                             // adbd data stream
	twrpback(void);
	virtual ~twrpback(void);
	bool backup(std::string command);                                        // adb backup stream
	bool restore(void);                                                      // adb restore stream
	void adblogwrite(std::string writemsg);                                  // adb debugging log function
	void createFifos(void);                                                  // create fifos needed for adb backup
	void closeFifos(void);                                                   // close created fifos
	void streamFileForTWRP(void);                                            // stream file to twrp via bu
	void setStreamFileName(std::string fn);                                  // tell adb backup what file to load on storage
	void threadStream(void);                                                 // thread bu for streaming

private:
	int read_fd;                                                             // ors input fd
	int write_fd;                                                            // ors operation fd
	int ors_fd;                                                              // ors output fd
	int adb_control_twrp_fd;                                                 // fd for bu to twrp communication
	int adb_control_bu_fd;                                                   // fd for twrp to bu communication
	int adb_read_fd;                                                         // adb read data stream
	int adb_write_fd;                                                        // adb write data stream
	int debug_adb_fd;                                                        // fd to write debug tars
	bool firstPart;                                                          // first partition in the stream
	bool stream_mode;                                                        // true = via `bu --twrp stream` (GUI .ab restore) -> restore() writes ADB_RESTORE_STREAM_OP instead of ADB_RESTORE_OP so the GUI action thread owns the completion
	FILE *adbd_fp;                                                           // file pointer for adb stream
	char cmd[512];                                                           // store result of commands
	char operation[512];                                                     // operation to send to ors
	std::ofstream adblogfile;                                                // adb stream log file
	std::string streamFn;
	typedef void (twrpback::*ThreadPtr)(void);
	typedef void* (*PThreadPtr)(void *);
	void adbloginit(void);                                                   // setup adb log stream file
	void close_backup_fds();                                                 // close backup resources
	void close_restore_fds();                                                // close restore resources
	bool checkMD5Trailer(char adbReadStream[], uint64_t md5fnsize, twrpMD5* digest); // Check MD5 Trailer
	bool pump_data(twrpMD5 &digest, uint64_t &totalbytes, uint64_t &fileBytes,
	               uint64_t &dataChunkBytes, bool &firstDataPacket, bool drain);     // 128-KB frame-aware data pump FIFO->adbd (backup); drain=true: blocking until EOF (TWEOF drain)
	static ssize_t write_all(int fd, const void *buf, size_t count);                 // EINTR-/partial-safe write (batch writes > PIPE_BUF are not atomic)
	void printErrMsg(std::string msg, int errNum);                          // print error msg to adb log
	bool send_adb_bu_notice(void);                                          // PTY detected (freeze-prone): TWRP GUI notice via TW_ADB_FIFO
};

#endif // _TWRPBACK_HPP

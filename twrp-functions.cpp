/*
	Copyright 2012-2020 TeamWin
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

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <vector>
#include "twrp_affinity.hpp"
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cctype>
#include <algorithm>
#include <selinux/label.h>
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#include <thread>

#include <android-base/strings.h>
#include <android-base/properties.h>
#include <android-base/chrono_utils.h>

#include "twrp-functions.hpp"
#include "twcommon.h"
#include "gui/gui.hpp"
#ifndef BUILD_TWRPTAR_MAIN
#include "data.hpp"
#include "partitions.hpp"
#include "variables.h"
#include "bootloader_message/include/bootloader_message/bootloader_message.h"
#include "cutils/properties.h"
#include "cutils/android_reboot.h"
#include <sys/reboot.h>
#endif // ndef BUILD_TWRPTAR_MAIN
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
#include <openssl/evp.h>
#include <openssl/aead.h>
#include "tw_bssl_aes/baes_format.h"
#endif
// Unconditional include — the class is needed in BOTH modules (recovery +
// twrpTarMain); the header is dual-clean (only <string>/<map>/twrp-functions.hpp).
// The recovery-only Try_Decrypting_Backup (gated by #ifndef BUILD_TWRPTAR_MAIN)
// additionally uses GetFileType + Load.
#include "backupheadermanager.hpp"   // detection/g-header consolidation
#include "set_metadata.h"

extern "C" {
	#include "libcrecovery/common.h"
}

#ifdef TW_INCLUDE_LIBRESETPROP
    #include <resetprop.hpp>
#endif

struct selabel_handle *selinux_handle;

/* Execute a command */
int TWFunc::Exec_Cmd(const string& cmd, string &result, bool combine_stderr) {
	FILE* exec;
	char buffer[130];
	int ret = 0;
	std::string popen_cmd = cmd;
	if (combine_stderr)
		popen_cmd = cmd + " 2>&1";
	exec = __popen(popen_cmd.c_str(), "r");

	while (!feof(exec)) {
		if (fgets(buffer, 128, exec) != NULL) {
			result += buffer;
		}
	}
	ret = __pclose(exec);
	return ret;
}

int TWFunc::Exec_Cmd(const string& cmd, bool Show_Errors) {
	pid_t pid;
	int status;
	switch(pid = fork())
	{
		case -1:
			LOGERR("Exec_Cmd(): vfork failed: %d!\n", errno);
			return -1;
		case 0: // child
			execl("/system/bin/sh", "sh", "-c", cmd.c_str(), NULL);
			_exit(127);
			break;
		default:
		{
			if (TWFunc::Wait_For_Child(pid, &status, cmd, Show_Errors) != 0)
				return -1;
			else
				return 0;
		}
	}
}

// Returns "file.name" from a full /path/to/file.name
string TWFunc::Get_Filename(const string& Path) {
	size_t pos = Path.find_last_of("/");
	if (pos != string::npos) {
		string Filename;
		Filename = Path.substr(pos + 1, Path.size() - pos - 1);
		return Filename;
	} else
		return Path;
}

// Returns "/path/to/" from a full /path/to/file.name
string TWFunc::Get_Path(const string& Path) {
	size_t pos = Path.find_last_of("/");
	if (pos != string::npos) {
		string Pathonly;
		Pathonly = Path.substr(0, pos + 1);
		return Pathonly;
	} else
		return Path;
}

int TWFunc::Wait_For_Child(pid_t pid, int *status, string Child_Name, bool Show_Errors) {
	pid_t rc_pid;

	rc_pid = waitpid(pid, status, 0);
	if (rc_pid > 0) {
		if (WIFSIGNALED(*status)) {
			if (Show_Errors)
				gui_msg(Msg(msg::kError, "pid_signal={1} process ended with signal: {2}")(Child_Name)(WTERMSIG(*status))); // Seg fault or some other non-graceful termination
			return -1;
		} else if (WEXITSTATUS(*status) == 0) {
			LOGINFO("%s process ended with RC=%d\n", Child_Name.c_str(), WEXITSTATUS(*status)); // Success
		} else {
			if (Show_Errors)
				gui_msg(Msg(msg::kError, "pid_error={1} process ended with ERROR: {2}")(Child_Name)(WEXITSTATUS(*status))); // Graceful exit, but there was an error
			return -1;
		}
	} else { // no PID returned
		if (errno == ECHILD)
			LOGERR("%s no child process exist\n", Child_Name.c_str());
		else {
			LOGERR("%s Unexpected error %d\n", Child_Name.c_str(), errno);
			return -1;
		}
	}
	return 0;
}

int TWFunc::Wait_For_Child_Timeout(pid_t pid, int *status, const string& Child_Name, int timeout) {
	pid_t retpid = waitpid(pid, status, WNOHANG);
	for (; retpid == 0 && timeout; --timeout) {
		sleep(1);
		retpid = waitpid(pid, status, WNOHANG);
	}
	if (retpid == 0 && timeout == 0) {
		LOGERR("%s took too long, killing process\n", Child_Name.c_str());
		kill(pid, SIGKILL);
		for (timeout = 5; retpid == 0 && timeout; --timeout) {
			sleep(1);
			retpid = waitpid(pid, status, WNOHANG);
		}
		if (retpid)
			LOGINFO("Child process killed successfully\n");
		else
			LOGINFO("Child process took too long to kill, may be a zombie process\n");
		return -1;
	} else if (retpid > 0) {
		if (WIFSIGNALED(*status)) {
			gui_msg(Msg(msg::kError, "pid_signal={1} process ended with signal: {2}")(Child_Name)(WTERMSIG(*status))); // Seg fault or some other non-graceful termination
			return -1;
		} else if (WEXITSTATUS(*status) != 0) {
			// A graceful exit with code != 0 is a real error (e.g. tw_bssl_aes
			// "truncated chunk data" / "authentication failed", zstd decompress
			// errors). Without this check the restore reap (closeTarRestore ->
			// finish_pipeline) would swallow sub-child errors on a clean tar EOF.
			// Symmetric to Wait_For_Child. (Normal path: filters exit 0 on stdin
			// EOF; an EPIPE exit only happens on cancel, classified as CANCELLED
			// via stop_restore.)
			gui_msg(Msg(msg::kError, "pid_error={1} process ended with ERROR: {2}")(Child_Name)(WEXITSTATUS(*status)));
			return -1;
		}
	} else if (retpid < 0) { // no PID returned
		if (errno == ECHILD)
			LOGERR("%s no child process exist\n", Child_Name.c_str());
		else {
			LOGERR("%s Unexpected error %d\n", Child_Name.c_str(), errno);
			return -1;
		}
	}
	return 0;
}

bool TWFunc::Path_Exists(string Path) {
	struct stat st;
	return stat(Path.c_str(), &st) == 0;
}

// Archive-byte detection lives encapsulated in BackupHeaderManager
// (GetFileType() / Load()+getters); is_legacy_type/emit_detect_reject stay here
// (type predicate and GUI glue, no archive byte readers).

// Legacy (original TWRP, single-pipe) vs this build (multi-pipe, self-describing).
bool TWFunc::is_legacy_type(Archive_Type t) { return t <= LEGACY_COMPRESSED_ENCRYPTED; }

// Unified GUI rejection message for a non-OK DetectResult.
void TWFunc::emit_detect_reject(DetectResult dr, const std::string &path) {
	if (dr == DET_REJECT_OPENAES)
		gui_err("restore_openaes_rejected=This backup is encrypted with OpenAES and is no longer supported. OpenAES was removed from TWRP v3.7+ by the core developers.");
	else if (dr == DET_WRONG_PASSWORD)
		gui_msg(Msg(msg::kError, "fail_decrypt_tar=Failed to decrypt tar file '{1}'")(path));
	else
		gui_err("restore_unknown_segment=Backup segment has an unknown format -- header not recognized.");
}

unsigned long TWFunc::Get_File_Size(const string& Path) {
	struct stat st;

	if (stat(Path.c_str(), &st) != 0)
		return 0;
	return st.st_size;
}

// Generic write-behind page-cache trim of a SEEKABLE output fd. Drops clean
// pages BEHIND the write head while the file is still being written — bounds
// the page-cache peak (otherwise written-back clean pages accumulate until
// close). lseek64(SEEK_CUR) reads the write progress (on an OFD SHARED via
// fork+dup2 = how far the writing sub-child has come; on direct self-write =
// our own position). From THRESHOLD on: first sync_file_range (range safely on
// disk), THEN posix_fadvise64 DONTNEED (drops ONLY clean pages), always
// TAIL_MARGIN behind the head. trim_offset = in/out (last dropped offset; the
// caller resets it per segment to 0). fd<0 or non-seekable (lseek64 ESPIPE) =>
// no-op. off64_t/lseek64/posix_fadvise64 are 64-bit independent of
// arch/_FILE_OFFSET_BITS (output may exceed 2 GB). The adbbackup gating and the
// output_fd/t->fd choice are done by the twrpTar caller; only the mechanics
// live here. Shared trim mechanics (output + input): flush=true (output,
// written) syncs the range to disk first, then drops; flush=false (input/.win,
// read) — pages are clean anyway -> FADV only, no flush wait.
static void trim_cache_impl(int fd, off64_t& trim_offset, bool flush) {
	static const off64_t THRESHOLD   = 128LL * 1024 * 1024;
	static const off64_t TAIL_MARGIN =  16LL * 1024 * 1024;
	if (fd < 0)
		return;
	off64_t cur = lseek64(fd, 0, SEEK_CUR);
	if (cur < 0)
		return;                                  // ESPIPE (FIFO) etc. -> not seekable, no trim
	if (cur - trim_offset < THRESHOLD)
		return;
	off64_t flush_to = cur - TAIL_MARGIN;
	if (flush_to <= trim_offset)
		return;
	off64_t len = flush_to - trim_offset;
	// Order is mandatory (output only): flush the range to disk first, THEN drop clean-only.
	if (flush)
		sync_file_range(fd, trim_offset, len,
			SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER);
	posix_fadvise64(fd, trim_offset, len, POSIX_FADV_DONTNEED);
	trim_offset = flush_to;
}

void TWFunc::Trim_Output_Cache(int fd, off64_t& trim_offset) {
	trim_cache_impl(fd, trim_offset, /*flush=*/true);
}

// C wrapper for libtar/append.c (tar_append_regfile, in-file output trim every
// 128 MB). extern "C" -> C linkage (libtar is C); calls the C++ mechanics
// above, no duplication. trim_offset points at the twrpTar member
// output_trim_offset (shared with the tarList hook). (The restore input trim
// needs no wrapper — extract.c calls FADV directly.)
extern "C" void twrp_trim_output_cache(int fd, off64_t *trim_offset) {
	if (trim_offset)
		TWFunc::Trim_Output_Cache(fd, *trim_offset);
}

std::string TWFunc::Remove_Beginning_Slash(const std::string& path) {
	std::string res;
	size_t pos = path.find_first_of("/");
	if (pos != std::string::npos) {
		res = path.substr(pos+1);
	}
	return res;
}

std::string TWFunc::Remove_Trailing_Slashes(const std::string& path, bool leaveLast)
{
	std::string res;
	size_t last_idx = 0, idx = 0;

	while (last_idx != std::string::npos)
	{
		if (last_idx != 0)
			res += '/';

		idx = path.find_first_of('/', last_idx);
		if (idx == std::string::npos) {
			res += path.substr(last_idx, idx);
			break;
		}

		res += path.substr(last_idx, idx-last_idx);
		last_idx = path.find_first_not_of('/', idx);
	}

	if (leaveLast)
		res += '/';
	return res;
}

void TWFunc::Strip_Quotes(char* &str) {
	if (strlen(str) > 0 && str[0] == '\"')
		str++;
	if (strlen(str) > 0 && str[strlen(str)-1] == '\"')
		str[strlen(str)-1] = 0;
}

vector<string> TWFunc::split_string(const string &in, char del, bool skip_empty) {
	vector<string> res;

	if (in.empty() || del == '\0')
		return res;

	string field;
	istringstream f(in);
	if (del == '\n') {
		while (getline(f, field)) {
			if (field.empty() && skip_empty)
				continue;
			res.push_back(field);
		}
	} else {
		while (getline(f, field, del)) {
			if (field.empty() && skip_empty)
				continue;
			res.push_back(field);
		}
	}
	return res;
}

timespec TWFunc::timespec_diff(timespec& start, timespec& end)
{
	timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

int32_t TWFunc::timespec_diff_ms(timespec& start, timespec& end)
{
	return ((end.tv_sec * 1000) + end.tv_nsec/1000000) -
			((start.tv_sec * 1000) + start.tv_nsec/1000000);
}

bool TWFunc::Wait_For_File(const string& path, std::chrono::nanoseconds timeout) {
    android::base::Timer t;
    while (t.duration() < timeout) {
        struct stat sb;
        if (stat(path.c_str(), &sb) != -1) {
            return true;
        }
        std::this_thread::sleep_for(10ms);
    }
	return false;
}

bool TWFunc::Wait_For_Battery(std::chrono::nanoseconds timeout) {
	std::string battery_path;
#ifdef TW_CUSTOM_BATTERY_PATH
	battery_path = EXPAND(TW_CUSTOM_BATTERY_PATH);
#else
	battery_path = "/sys/class/power_supply/battery";
#endif
	if (!battery_path.empty()) return TWFunc::Wait_For_File(battery_path, timeout);

	return false;
}

#ifndef BUILD_TWRPTAR_MAIN

// Returns "/path" from a full /path/to/file.name
string TWFunc::Get_Root_Path(const string& Path) {
	string Local_Path = Path;

	// Make sure that we have a leading slash
	if (Local_Path.substr(0, 1) != "/")
		Local_Path = "/" + Local_Path;

	// Trim the path to get the root path only
	size_t position = Local_Path.find("/", 2);
	if (position != string::npos) {
		Local_Path.resize(position);
	}
	return Local_Path;
}

int TWFunc::Recursive_Mkdir(string Path) {
	std::vector<std::string> parts = Split_String(Path, "/", true);
	std::string cur_path;
	for (size_t i = 0; i < parts.size(); ++i) {
		cur_path += "/" + parts[i];
		if (!TWFunc::Path_Exists(cur_path)) {
			if (mkdir(cur_path.c_str(), 0777)) {
				gui_msg(Msg(msg::kError, "create_folder_strerr=Can not create '{1}' folder ({2}).")(cur_path)(strerror(errno)));
				return false;
			} else {
				tw_set_default_metadata(cur_path.c_str());
			}
		}
	}
	return true;
}

void TWFunc::GUI_Operation_Text(string Read_Value, string Default_Text) {
	string Display_Text;

	DataManager::GetValue(Read_Value, Display_Text);
	if (Display_Text.empty())
		Display_Text = Default_Text;

	DataManager::SetValue("tw_operation", Display_Text);
	DataManager::SetValue("tw_partition", "");
}

void TWFunc::GUI_Operation_Text(string Read_Value, string Partition_Name, string Default_Text) {
	string Display_Text;

	DataManager::GetValue(Read_Value, Display_Text);
	if (Display_Text.empty())
		Display_Text = Default_Text;

	DataManager::SetValue("tw_operation", Display_Text);
	DataManager::SetValue("tw_partition", Partition_Name);
}

// Per-operation log slicing: writes the boot/decrypt context [0..ctx_end) +
// separator line + the current operation [op_start..EOF) from Source
// (/tmp/recovery.log) to Destination (O_TRUNC, 0644). ctx_end == op_start
// (first operation of the session) => no separator, result == full copy
// (byte-identical). Returns false on ANY error or inconsistent offsets — the
// caller (Save_Recovery_Log) then falls back to the full copy. If the log keeps
// growing during the copy (MTP/GUI threads), the fstat snapshot applies — the
// same tolerance as a plain full copy.
bool TWFunc::Copy_Log_Slices(const string& Source, const string& Destination, long long ctx_end, long long op_start) {
	if (ctx_end < 0 || op_start < ctx_end)
		return false;

	int src_fd = open(Source.c_str(), O_RDONLY | O_CLOEXEC);
	if (src_fd < 0)
		return false;
	struct stat st;
	if (fstat(src_fd, &st) != 0 || (long long)st.st_size < op_start) {
		close(src_fd);
		return false;
	}
	int dst_fd = open(Destination.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (dst_fd < 0) {
		close(src_fd);
		return false;
	}

	char buf[65536];
	bool ok = true;
	long long ranges[2][2] = { {0, ctx_end}, {op_start, (long long)st.st_size} };
	for (int r = 0; r < 2 && ok; r++) {
		if (r == 1 && op_start > ctx_end) {
			// Separator only when something was actually skipped (never for the
			// first operation of the session).
			char sep[256];
			// Points at the LIVE session log under /tmp (TMP_LOG_FILE): it carries
			// the complete current session. The persistent /data/recovery/log.zstd
			// is only written at reboot (Update_Log_File) and does not yet contain
			// the running session.
			int sep_len = snprintf(sep, sizeof(sep),
				"\n=== per-operation log: %lld KB skipped (earlier operations this session; full session log: " TMP_LOG_FILE ") ===\n\n",
				(op_start - ctx_end + 1023) / 1024);
			if (sep_len <= 0 || sep_len >= (int)sizeof(sep) || write(dst_fd, sep, sep_len) != sep_len) {
				ok = false;
				break;
			}
		}
		if (lseek64(src_fd, ranges[r][0], SEEK_SET) < 0) {
			ok = false;
			break;
		}
		long long remaining = ranges[r][1] - ranges[r][0];
		while (remaining > 0 && ok) {
			ssize_t rd = read(src_fd, buf, (remaining < (long long)sizeof(buf)) ? (size_t)remaining : sizeof(buf));
			if (rd < 0) {
				if (errno == EINTR) continue;
				ok = false;
				break;
			}
			if (rd == 0)
				break;   // EOF earlier than the snapshot (defensive; a tmpfs log never shrinks)
			ssize_t off = 0;
			while (off < rd) {
				ssize_t wr = write(dst_fd, buf + off, rd - off);
				if (wr < 0) {
					if (errno == EINTR) continue;
					ok = false;
					break;
				}
				off += wr;
			}
			remaining -= rd;
		}
	}
	close(src_fd);
	close(dst_fd);
	return ok;
}

void TWFunc::Copy_Log(string Source, string Destination) {
	int logPipe[2];
	int comp_pid;
	int destination_fd;
	std::string destLogBuffer;

	PartitionManager.Mount_By_Path(Destination, false);

	size_t extPos = Destination.find(".zstd");
	std::string uncompressedLog(Destination);
	uncompressedLog.replace(extPos, Destination.length(), "");

	if (Path_Exists(Destination)) {
		// The persistent recovery log is ALWAYS zstd (write side below: zstd -1
		// -T0; Update_Log_File always passes log.zstd/last_log.zstd) — no
		// Get_File_Type detour, decompress directly with zstd -c -d.
		std::string destFileBuffer;
		std::string getCompressedContents = "zstd -c -d " + Destination;
		if (Exec_Cmd(getCompressedContents, destFileBuffer, false) < 0) {
			LOGINFO("Unable to get destination logfile contents.\n");
			return;
		}
		destLogBuffer.append(destFileBuffer);
	} else if (Path_Exists(uncompressedLog)) {
		std::ifstream uncompressedIfs(uncompressedLog.c_str());
		std::stringstream uncompressedSS;
		uncompressedSS << uncompressedIfs.rdbuf();
		uncompressedIfs.close();
		std::string uncompressedLogBuffer(uncompressedSS.str());
		destLogBuffer.append(uncompressedLogBuffer);
		std::remove(uncompressedLog.c_str());
	}

	std::ifstream ifs(Source.c_str());
	std::stringstream ss;
	ss << ifs.rdbuf();
	std::string srcLogBuffer(ss.str());
	ifs.close();

	// Hard cap: do not let the persistent log grow without bound. If old history
	// (destLogBuffer) + current session (srcLogBuffer) would exceed the limit,
	// drop the old history and start fresh with ONLY the current session — the
	// newest log is never lost (TW_MAX_PERSISTENT_LOG_SIZE).
	if (destLogBuffer.size() + srcLogBuffer.size() > TW_MAX_PERSISTENT_LOG_SIZE) {
		LOGINFO("Persistent log would exceed %d MB -- resetting history, keeping current session only.\n",
		        (int)(TW_MAX_PERSISTENT_LOG_SIZE / (1024 * 1024)));
		destLogBuffer.clear();
	}

	if (pipe2(logPipe, O_CLOEXEC) < 0) {
		LOGINFO("Unable to open pipe to write to persistent log file: %s\n", Destination.c_str());
		return;
	}

	destination_fd = open(Destination.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (destination_fd < 0) {
		LOGINFO("Cannot open %s: %s\n", Destination.c_str(), strerror(errno));
		close(logPipe[0]);
		close(logPipe[1]);
		return;
	}

	comp_pid = fork();
	if (comp_pid < 0) {
		LOGINFO("fork() failed\n");
		close(destination_fd);
		close(logPipe[0]);
		close(logPipe[1]);
	} else if (comp_pid == 0) {
		close(logPipe[1]);
		dup2(logPipe[0], fileno(stdin));
		dup2(destination_fd, fileno(stdout));
		// The persistent log is a single compressor fork (no multi-pipe). Pinning
		// + dynamic -T<size> would be overkill for the tiny log file: fixed -T0
		// (zstd uses all cores), no sched_setaffinity.
		if (execlp("zstd", "zstd", "-1", "-T0", "-c", "-", NULL) < 0) {
			close(destination_fd);
			close(logPipe[0]);
			_exit(-1);
		}
	} else {
		close(logPipe[0]);
		if (write(logPipe[1], destLogBuffer.c_str(), destLogBuffer.size()) < 0) {
			LOGINFO("Unable to append to persistent log: %s\n", Destination.c_str());
			close(logPipe[1]);
			close(destination_fd);
			waitpid(comp_pid, nullptr, 0);
			return;
		}
		if (write(logPipe[1], srcLogBuffer.c_str(), srcLogBuffer.size()) < 0) {
			LOGINFO("Unable to append to persistent log: %s\n", Destination.c_str());
			close(logPipe[1]);
			close(destination_fd);
			waitpid(comp_pid, nullptr, 0);
			return;
		}
		close(logPipe[1]);
		waitpid(comp_pid, nullptr, 0);
	}
	close(destination_fd);
}

void TWFunc::Update_Log_File(void) {
	std::string recoveryDir = get_log_dir() + "recovery/";

	if (get_log_dir() == CACHE_LOGS_DIR) {
		if (!PartitionManager.Mount_By_Path(CACHE_LOGS_DIR, false)) {
			LOGINFO("Failed to mount %s for TWFunc::Update_Log_File\n", CACHE_LOGS_DIR);
		}
	}

	if (!TWFunc::Path_Exists(recoveryDir)) {
		LOGINFO("Recreating %s folder.\n", recoveryDir.c_str());
		if (!Create_Dir_Recursive(recoveryDir,  S_IRWXU | S_IRWXG | S_IWGRP | S_IXGRP, 0, 0)) {
			LOGINFO("Unable to create %s folder.\n", recoveryDir.c_str());
		}
	}

	std::string logCopy = recoveryDir + "log.zstd";
	std::string lastLogCopy = recoveryDir + "last_log.zstd";
	copy_file(logCopy, lastLogCopy, 0600);
	Copy_Log(TMP_LOG_FILE, logCopy);
	chown(logCopy.c_str(), 1000, 1000);
	chmod(logCopy.c_str(), 0600);
	chmod(lastLogCopy.c_str(), 0640);

	if (get_log_dir() == CACHE_LOGS_DIR) {
		if (PartitionManager.Mount_By_Path("/cache", false)) {
			if (unlink("/cache/recovery/command") && errno != ENOENT) {
				LOGINFO("Can't unlink %s\n", "/cache/recovery/command");
			}
		}
	}
	sync();
}

void TWFunc::Clear_Bootloader_Message() {
	std::string err;
	if (!clear_bootloader_message(&err)) {
		LOGINFO("%s\n", err.c_str());
	}
}

void TWFunc::Update_Intent_File(string Intent) {
	if (PartitionManager.Mount_By_Path("/cache", false) && !Intent.empty()) {
		TWFunc::write_to_file("/cache/recovery/intent", Intent);
	}
}

// reboot: Reboot the system. Return -1 on error, no return on success
int TWFunc::tw_reboot(RebootCommand command)
{
	DataManager::Flush();
	Update_Log_File();

	// Always force a sync before we reboot
	sync();

	switch (command) {
		case rb_current:
		case rb_system:
			Update_Intent_File("s");
			sync();
			check_and_run_script("/system/bin/rebootsystem.sh", "reboot system");
#ifdef ANDROID_RB_PROPERTY
			return property_set(ANDROID_RB_PROPERTY, "reboot,");
#elif defined(ANDROID_RB_RESTART)
			return android_reboot(ANDROID_RB_RESTART, 0, 0);
#else
			return reboot(RB_AUTOBOOT);
#endif
		case rb_recovery:
			check_and_run_script("/system/bin/rebootrecovery.sh", "reboot recovery");
			return property_set(ANDROID_RB_PROPERTY, "reboot,recovery");
		case rb_bootloader:
			check_and_run_script("/system/bin/rebootbootloader.sh", "reboot bootloader");
			return property_set(ANDROID_RB_PROPERTY, "reboot,bootloader");
		case rb_poweroff:
			check_and_run_script("/system/bin/poweroff.sh", "power off");
#ifdef ANDROID_RB_PROPERTY
			return property_set(ANDROID_RB_PROPERTY, "shutdown,");
#elif defined(ANDROID_RB_POWEROFF)
			return android_reboot(ANDROID_RB_POWEROFF, 0, 0);
#else
			return reboot(RB_POWER_OFF);
#endif
		case rb_download:
			check_and_run_script("/system/bin/rebootdownload.sh", "reboot download");
			return property_set(ANDROID_RB_PROPERTY, "reboot,download");
		case rb_edl:
			check_and_run_script("/system/bin/rebootedl.sh", "reboot edl");
			return property_set(ANDROID_RB_PROPERTY, "reboot,edl");
		case rb_fastboot:
			return property_set(ANDROID_RB_PROPERTY, "reboot,fastboot");
		default:
			return -1;
	}
	return -1;
}

void TWFunc::check_and_run_script(const char* script_file, const char* display_name)
{
	// Check for and run startup script if script exists
	struct stat st;
	if (stat(script_file, &st) == 0) {
		gui_msg(Msg("run_script=Running {1} script...")(display_name));
		chmod(script_file, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		TWFunc::Exec_Cmd(script_file);
		gui_msg("done=Done.");
	}
}

int TWFunc::removeDir(const string path, bool skipParent) {
	DIR *d = opendir(path.c_str());
	int r = 0;
	string new_path;

	if (d == NULL) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(path)(strerror(errno)));
		return -1;
	}

	if (d) {
		struct dirent *p;
		while (!r && (p = readdir(d))) {
			if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
				continue;
			new_path = path + "/";
			new_path.append(p->d_name);
			if (p->d_type == DT_DIR) {
				r = removeDir(new_path, true);
				if (!r) {
					if (p->d_type == DT_DIR)
						r = rmdir(new_path.c_str());
					else
						LOGINFO("Unable to removeDir '%s': %s\n", new_path.c_str(), strerror(errno));
				}
			} else if (p->d_type == DT_REG || p->d_type == DT_LNK || p->d_type == DT_FIFO || p->d_type == DT_SOCK) {
				r = unlink(new_path.c_str());
				if (r != 0) {
					LOGINFO("Unable to unlink '%s: %s'\n", new_path.c_str(), strerror(errno));
				}
			}
		}
		closedir(d);

		if (!r) {
			if (skipParent)
				return 0;
			else
				r = rmdir(path.c_str());
		}
	}
	return r;
}

int TWFunc::copy_file(string src, string dst, int mode, bool mount_paths) {
	if (mount_paths) {
		PartitionManager.Mount_By_Path(src, false);
		PartitionManager.Mount_By_Path(dst, false);
	}
	if (!Path_Exists(src)) {
		LOGINFO("Path %s does not exist. Unable to copy file to %s\n", src.c_str(), dst.c_str());
		return -1;
	}
	std::ifstream srcfile(src.c_str(), ios::binary);
	std::ofstream dstfile(dst.c_str(), ios::binary);
	/* Check source/destination stream state BEFORE rdbuf streams: checking only
	 * dstfile.bad() (as upstream does) silently produces a 0-byte copy when the
	 * source exists but is unreadable (permission denied, IO). Callers
	 * (especially the repacker) rely on the return code. */
	if (!srcfile.is_open()) {
		LOGINFO("Unable to open source %s for read: %s\n", src.c_str(), strerror(errno));
		return -1;
	}
	if (!dstfile.is_open()) {
		LOGINFO("Unable to open destination %s for write: %s\n", dst.c_str(), strerror(errno));
		return -1;
	}
	dstfile << srcfile.rdbuf();
	/* srcfile.bad() = badbit after an IO error during the rdbuf stream;
	 * dstfile.bad() = write error. Both must be clean. */
	if (srcfile.bad() || dstfile.bad()) {
		LOGINFO("Unable to copy file %s to %s (src.bad=%d dst.bad=%d)\n",
		        src.c_str(), dst.c_str(), (int)srcfile.bad(), (int)dstfile.bad());
		return -1;
	}

	srcfile.close();
	dstfile.close();
	if (!Path_Exists(dst)) {
		LOGINFO("Destination %s does not exist after copy. Skipping chmod.\n", dst.c_str());
		return -1;
	}
	if (chmod(dst.c_str(), mode) != 0) {
		if (errno != EOPNOTSUPP)
			LOGINFO("Unable to chmod file: %s. (Filesystem does not support it?)\n", dst.c_str());
	}
	return 0;
}

unsigned int TWFunc::Get_D_Type_From_Stat(string Path) {
	struct stat st;

	stat(Path.c_str(), &st);
	if (st.st_mode & S_IFDIR)
		return DT_DIR;
	else if (st.st_mode & S_IFBLK)
		return DT_BLK;
	else if (st.st_mode & S_IFCHR)
		return DT_CHR;
	else if (st.st_mode & S_IFIFO)
		return DT_FIFO;
	else if (st.st_mode & S_IFLNK)
		return DT_LNK;
	else if (st.st_mode & S_IFREG)
		return DT_REG;
	else if (st.st_mode & S_IFSOCK)
		return DT_SOCK;
	return DT_UNKNOWN;
}

int TWFunc::read_file(string fn, string& results) {
	ifstream file;
	file.open(fn.c_str(), ios::in);

	if (file.is_open()) {
		std::string line;
		while (std::getline(file, line)) {
			results += line;
		}
		file.close();
		return 0;
	}

	LOGINFO("Cannot find file %s\n", fn.c_str());
	return -1;
}

int TWFunc::read_file(string fn, vector<string>& results) {
	ifstream file;
	string line;
	file.open(fn.c_str(), ios::in);
	if (file.is_open()) {
		while (getline(file, line))
			results.push_back(line);
		file.close();
		return 0;
	}
	LOGINFO("Cannot find file %s\n", fn.c_str());
	return -1;
}

int TWFunc::read_file(string fn, uint64_t& results) {
	ifstream file;
	file.open(fn.c_str(), ios::in);

	if (file.is_open()) {
		file >> results;
		file.close();
		return 0;
	}

	LOGINFO("Cannot find file %s\n", fn.c_str());
	return -1;
}

bool TWFunc::write_to_file(const string& fn, const string& line) {
	FILE *file;
	file = fopen(fn.c_str(), "w");
	if (file != NULL) {
		fwrite(line.c_str(), line.size(), 1, file);
		fclose(file);
		return true;
	}
	LOGINFO("Cannot find file %s\n", fn.c_str());
	return false;
}

bool TWFunc::write_to_file(const string& fn, const std::vector<string> lines) {
	FILE *file;
	file = fopen(fn.c_str(), "a+");
	if (file != NULL) {
		for (auto&& line: lines) {
			fwrite(line.c_str(), line.size(), 1, file);
			fwrite("\n", sizeof(char), 1, file);
		}
		fclose(file);
		return true;
	}
	return false;
}


bool TWFunc::Try_Decrypting_Backup(string Restore_Path, const string& Password) {
	DIR* d;

	string Filename;
	Restore_Path += "/";
	d = opendir(Restore_Path.c_str());
	if (d == NULL) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(Restore_Path)(strerror(errno)));
		return false;
	}

	struct dirent* de;
	while ((de = readdir(d)) != NULL) {
		Filename = Restore_Path;
		Filename += de->d_name;
		if (BackupHeaderManager::GetFileType(Filename) == ENCRYPTED) {   // outer magic only
			BackupHeaderManager hdr;
			hdr.Load(Filename, Password);                       // decrypt probe
			if (hdr.GetStatus() != DET_OK) {
				DataManager::SetValue("tw_restore_password", ""); // Clear the bad password
				DataManager::SetValue("tw_restore_display", "");  // Also clear the display mask
				closedir(d);
				return false;
			}
			break;   // homogeneous: one successfully probed segment suffices (OpenAES is always rejected)
		}
	}
	closedir(d);
	return true;
}

string TWFunc::Get_Current_Date() {
	string Current_Date;
	time_t seconds = time(0);
	struct tm *t = localtime(&seconds);
	char timestamp[255];
	sprintf(timestamp,"%04d-%02d-%02d--%02d-%02d-%02d",t->tm_year+1900,t->tm_mon+1,t->tm_mday,t->tm_hour,t->tm_min,t->tm_sec);
	Current_Date = timestamp;
	return Current_Date;
}

string TWFunc::System_Property_Get(string Prop_Name) {
	return Partition_Property_Get(Prop_Name, PartitionManager, PartitionManager.Get_Android_Root_Path(), "build.prop");
}

string TWFunc::Partition_Property_Get(string Prop_Name, TWPartitionManager &PartitionManager, string Mount_Point, string prop_file_name) {
	bool mount_state = PartitionManager.Is_Mounted_By_Path(Mount_Point);
	std::vector<string> buildprop;
	string propvalue;
	string prop_file;
	if (!PartitionManager.Mount_By_Path(Mount_Point, true))
		return propvalue;
	if (Mount_Point == PartitionManager.Get_Android_Root_Path()) {
		prop_file = Mount_Point + "/system/" + prop_file_name;
	} else {
		prop_file = Mount_Point + "/" + prop_file_name;
	}
	if (!TWFunc::Path_Exists(prop_file)) {
		LOGINFO("Unable to locate file: %s\n", prop_file.c_str());
		return propvalue;
	}
	if (TWFunc::read_file(prop_file, buildprop) != 0) {
		LOGINFO("Unable to open %s for getting '%s'.\n", prop_file_name.c_str(), Prop_Name.c_str());
		DataManager::SetValue(TW_BACKUP_NAME, Get_Current_Date());
		if (!mount_state)
			PartitionManager.UnMount_By_Path(Mount_Point, false);
		return propvalue;
	}
	int line_count = buildprop.size();
	int index;
	size_t start_pos = 0, end_pos;
	string propname;
	for (index = 0; index < line_count; index++) {
		end_pos = buildprop.at(index).find("=", start_pos);
		propname = buildprop.at(index).substr(start_pos, end_pos);
		if (propname == Prop_Name) {
			propvalue = buildprop.at(index).substr(end_pos + 1, buildprop.at(index).size());
			if (!mount_state)
				PartitionManager.UnMount_By_Path(Mount_Point, false);
			return propvalue;
		}
	}
	if (!mount_state)
		PartitionManager.UnMount_By_Path(Mount_Point, false);
	return propvalue;
}

void TWFunc::Auto_Generate_Backup_Name() {
	string propvalue = System_Property_Get("ro.build.display.id");
	if (propvalue.empty()) {
		DataManager::SetValue(TW_BACKUP_NAME, Get_Current_Date());
		return;
	}
	else {
		//remove periods from build display so it doesn't confuse the extension code
		propvalue.erase(remove(propvalue.begin(), propvalue.end(), '.'), propvalue.end());
	}
	string Backup_Name = Get_Current_Date();
	Backup_Name += "_" + propvalue;
	if (Backup_Name.size() > MAX_BACKUP_NAME_LEN)
		Backup_Name.resize(MAX_BACKUP_NAME_LEN);
	// Trailing spaces cause problems on some file systems, so remove them
	string space_check, space = " ";
	space_check = Backup_Name.substr(Backup_Name.size() - 1, 1);
	while (space_check == space) {
		Backup_Name.resize(Backup_Name.size() - 1);
		space_check = Backup_Name.substr(Backup_Name.size() - 1, 1);
	}
	replace(Backup_Name.begin(), Backup_Name.end(), ' ', '_');
	if (PartitionManager.Check_Backup_Name(Backup_Name, false, true) != 0) {
		LOGINFO("Auto generated backup name '%s' is not valid, using date instead.\n", Backup_Name.c_str());
		DataManager::SetValue(TW_BACKUP_NAME, Get_Current_Date());
	} else {
		DataManager::SetValue(TW_BACKUP_NAME, Backup_Name);
	}
}

void TWFunc::Fixup_Time_On_Boot(const string& time_paths /* = "" */)
{
#ifdef QCOM_RTC_FIX
	static bool fixed = false;
	if (fixed)
		return;

	LOGINFO("TWFunc::Fixup_Time: Pre-fix date and time: %s\n", TWFunc::Get_Current_Date().c_str());

	struct timeval tv;
	uint64_t offset = 0;
	std::string sepoch = "/sys/class/rtc/rtc0/since_epoch";

	if (TWFunc::read_file(sepoch, offset) == 0) {

		LOGINFO("TWFunc::Fixup_Time: Setting time offset from file %s\n", sepoch.c_str());

		tv.tv_sec = offset;
		tv.tv_usec = 0;
		settimeofday(&tv, NULL);

		gettimeofday(&tv, NULL);

		if (tv.tv_sec > 1517600000) { // Anything older then 2 Feb 2018 19:33:20 GMT will do nicely thank you ;)

			LOGINFO("TWFunc::Fixup_Time: Date and time corrected: %s\n", TWFunc::Get_Current_Date().c_str());
			fixed = true;
			return;

		}

	} else {

		LOGINFO("TWFunc::Fixup_Time: opening %s failed\n", sepoch.c_str());

	}

	LOGINFO("TWFunc::Fixup_Time: will attempt to use the ats files now.\n");

	// Devices with Qualcomm Snapdragon 800 do some shenanigans with RTC.
	// They never set it, it just ticks forward from 1970-01-01 00:00,
	// and then they have files /data/system/time/ats_* with 64bit offset
	// in miliseconds which, when added to the RTC, gives the correct time.
	// So, the time is: (offset_from_ats + value_from_RTC)
	// There are multiple ats files, they are for different systems? Bases?
	// Like, ats_1 is for modem and ats_2 is for TOD (time of day?).
	// Look at file time_genoff.h in CodeAurora, qcom-opensource/time-services

	std::vector<std::string> paths; // space separated list of paths
	if (time_paths.empty()) {
		paths = Split_String("/data/system/time/ /data/time/ /data/vendor/time/", " ");
		if (!PartitionManager.Mount_By_Path("/data", false))
			return;
	} else {
		// When specific path(s) are used, Fixup_Time needs those
		// partitions to already be mounted!
		paths = Split_String(time_paths, " ");
	}

	FILE *f;
	offset = 0;
	struct dirent *dt;
	std::string ats_path;

	// Prefer ats_2, it seems to be the one we want according to logcat on hammerhead
	// - it is the one for ATS_TOD (time of day?).
	// However, I never saw a device where the offset differs between ats files.
	for (size_t i = 0; i < paths.size(); ++i)
	{
		DIR *d = opendir(paths[i].c_str());
		if (!d)
			continue;

		while ((dt = readdir(d)))
		{
			if (dt->d_type != DT_REG || strncmp(dt->d_name, "ats_", 4) != 0)
				continue;

			if (ats_path.empty() || strcmp(dt->d_name, "ats_2") == 0)
				ats_path = paths[i] + dt->d_name;
		}

		closedir(d);
	}

	if (ats_path.empty()) {
		LOGINFO("TWFunc::Fixup_Time: no ats files found, leaving untouched!\n");
	} else if ((f = fopen(ats_path.c_str(), "r")) == NULL) {
		LOGINFO("TWFunc::Fixup_Time: failed to open file %s\n", ats_path.c_str());
	} else if (fread(&offset, sizeof(offset), 1, f) != 1) {
		LOGINFO("TWFunc::Fixup_Time: failed load uint64 from file %s\n", ats_path.c_str());
		fclose(f);
	} else {
		fclose(f);

		LOGINFO("TWFunc::Fixup_Time: Setting time offset from file %s, offset %llu\n", ats_path.c_str(), (unsigned long long) offset);
		DataManager::SetValue("tw_qcom_ats_offset", (unsigned long long) offset, 1);
		fixed = true;
	}

	if (!fixed) {
#ifdef TW_QCOM_ATS_OFFSET
		// Offset is the difference between the current time and the time since_epoch
		// To calculate the offset in Android, the following expression (from a root shell) can be used:
		// echo "$(( ($(date +%s) - $(cat /sys/class/rtc/rtc0/since_epoch)) ))"
		// Add 3 zeros to the output and use that in the TW_QCOM_ATS_OFFSET flag in your BoardConfig.mk
		// For example, if the result of the calculation is 1642433544, use 1642433544000 as the offset
		offset = (uint64_t) TW_QCOM_ATS_OFFSET;
		DataManager::SetValue("tw_qcom_ats_offset", (unsigned long long) offset, 1);
		LOGINFO("TWFunc::Fixup_Time: Setting time offset from TW_QCOM_ATS_OFFSET, offset %llu\n", (unsigned long long) offset);
#else
		// Failed to get offset from ats file, check twrp settings
		unsigned long long value;
		if (DataManager::GetValue("tw_qcom_ats_offset", value) < 0) {
			return;
		} else {
			offset = (uint64_t) value;
			LOGINFO("TWFunc::Fixup_Time: Setting time offset from twrp setting file, offset %llu\n", (unsigned long long) offset);
			// Do not consider the settings file as a definitive answer, keep fixed=false so next run will try ats files again
		}
#endif
	}

	gettimeofday(&tv, NULL);

	tv.tv_sec += offset/1000;
#ifdef TW_CLOCK_OFFSET
// Some devices are even quirkier and have ats files that are offset from the actual time
	tv.tv_sec = tv.tv_sec + TW_CLOCK_OFFSET;
#endif
	tv.tv_usec += (offset%1000)*1000;

	while (tv.tv_usec >= 1000000)
	{
		++tv.tv_sec;
		tv.tv_usec -= 1000000;
	}

	settimeofday(&tv, NULL);

	LOGINFO("TWFunc::Fixup_Time: Date and time corrected: %s\n", TWFunc::Get_Current_Date().c_str());
#endif
}

std::vector<std::string> TWFunc::Split_String(const std::string& str, const std::string& delimiter, bool removeEmpty)
{
	std::vector<std::string> res;
	size_t idx = 0, idx_last = 0;

	while (idx < str.size())
	{
		idx = str.find_first_of(delimiter, idx_last);
		if (idx == std::string::npos)
			idx = str.size();

		if (idx-idx_last != 0 || !removeEmpty)
			res.push_back(str.substr(idx_last, idx-idx_last));

		idx_last = idx + delimiter.size();
	}

	return res;
}

bool TWFunc::Create_Dir_Recursive(const std::string& path, mode_t mode, uid_t uid, gid_t gid)
{
	std::vector<std::string> parts = Split_String(path, "/");
	std::string cur_path;
	struct stat info;
	for (size_t i = 0; i < parts.size(); ++i)
	{
		cur_path += "/" + parts[i];
		if (stat(cur_path.c_str(), &info) < 0 || !S_ISDIR(info.st_mode))
		{
			if (mkdir(cur_path.c_str(), mode) < 0)
				return false;
			chown(cur_path.c_str(), uid, gid);
		}
	}
	return true;
}

int TWFunc::Set_Brightness(std::string brightness_value)
{
	int result = -1;
	std::string secondary_brightness_file;

	if (DataManager::GetIntValue("tw_has_brightnesss_file")) {
		LOGINFO("TWFunc::Set_Brightness: Setting brightness control to %s\n", brightness_value.c_str());
		result = TWFunc::write_to_file(DataManager::GetStrValue("tw_brightness_file"), brightness_value);
		DataManager::GetValue("tw_secondary_brightness_file", secondary_brightness_file);
		if (!secondary_brightness_file.empty()) {
			LOGINFO("TWFunc::Set_Brightness: Setting secondary brightness control to %s\n", brightness_value.c_str());
			TWFunc::write_to_file(secondary_brightness_file, brightness_value);
		}
	}
	return result ? 0 : -1;
}

bool TWFunc::Toggle_MTP(bool enable) {
#ifdef TW_HAS_MTP
	static int was_enabled = false;

	if (enable && was_enabled) {
		if (!PartitionManager.Enable_MTP())
			PartitionManager.Disable_MTP();
	} else {
		was_enabled = DataManager::GetIntValue("tw_mtp_enabled");
		PartitionManager.Disable_MTP();
		usleep(500);
	}
	return was_enabled;
#else
	return false;
#endif
}

void TWFunc::SetPerformanceMode(bool mode) {
	if (mode) {
		property_set("recovery.perf.mode", "1");
	} else {
		property_set("recovery.perf.mode", "0");
	}
	// Some time for events to catch up to init handlers
	usleep(500000);
}

std::string TWFunc::to_string(unsigned long value) {
	std::ostringstream os;
	os << value;
	return os.str();
}

// Splits a byte count into a human-readable number + unit: < 1 MB is rendered in KB,
// everything else in MB (>= 1 MB stays byte-identical to the previous plain-MB output).
// Returns the numeric part as a string; sets unit to "KB" or "MB".
std::string TWFunc::Bytes_To_Readable_Size(unsigned long long bytes, std::string& unit) {
	std::ostringstream os;
	if (bytes < 1048576ULL) {
		unit = "KB";
		os << (bytes / 1024ULL);
	} else {
		unit = "MB";
		os << (bytes / 1048576ULL);
	}
	return os.str();
}

void TWFunc::Disable_Stock_Recovery_Replace(void) {
	if (PartitionManager.Mount_By_Path(PartitionManager.Get_Android_Root_Path(), false)) {
		// Disable flashing of stock recovery
		if (TWFunc::Path_Exists("/system/recovery-from-boot.p")) {
			rename("/system/recovery-from-boot.p", "/system/recovery-from-boot.bak");
			gui_msg("rename_stock=Renamed stock recovery file in /system to prevent the stock ROM from replacing TWRP.");
			sync();
		}
		PartitionManager.UnMount_By_Path(PartitionManager.Get_Android_Root_Path(), false);
	}
}

unsigned long long TWFunc::IOCTL_Get_Block_Size(const char* block_device) {
	unsigned long block_device_size;
	int ret = 0;

	int fd = open(block_device, O_RDONLY);
	if (fd < 0) {
		LOGINFO("Find_Partition_Size: Failed to open '%s', (%s)\n", block_device, strerror(errno));
	} else {
		ret = ioctl(fd, BLKGETSIZE, &block_device_size);
		close(fd);
		if (ret) {
			LOGINFO("Find_Partition_Size: ioctl error: (%s)\n", strerror(errno));
		} else {
			return (unsigned long long)(block_device_size) * 512LLU;
		}
	}
	return 0;
}

void TWFunc::copy_kernel_log(string curr_storage) {
	std::string dmesgDst = curr_storage + "/dmesg.log";
	std::string dmesgCmd = "/system/bin/dmesg";

	std::string result;
	Exec_Cmd(dmesgCmd, result, false);
	write_to_file(dmesgDst, result);
	gui_msg(Msg("copy_kernel_log=Copied kernel log to {1}")(dmesgDst));
	tw_set_default_metadata(dmesgDst.c_str());
}

void TWFunc::copy_logcat(string curr_storage) {
	std::string logcatDst = curr_storage + "/logcat.txt";
	std::string logcatCmd = "logcat -d";

	std::string result;
	Exec_Cmd(logcatCmd, result, false);
	write_to_file(logcatDst, result);
	gui_msg(Msg("copy_logcat=Copied logcat to {1}")(logcatDst));
	tw_set_default_metadata(logcatDst.c_str());
}

bool TWFunc::isNumber(string strtocheck) {
	int num = 0;
	std::istringstream iss(strtocheck);

	if (!(iss >> num).fail())
		return true;
	else
		return false;
}

int TWFunc::stream_adb_backup(string &Restore_Name) {
	string cmd = "/system/bin/bu --twrp stream " + Restore_Name;
	LOGINFO("stream_adb_backup: %s\n", cmd.c_str());
	int ret = TWFunc::Exec_Cmd(cmd);
	if (ret != 0)
		return -1;
	return ret;
}

std::string TWFunc::get_log_dir() {
	if (PartitionManager.Find_Partition_By_Path(CACHE_LOGS_DIR) == NULL) {
		if (PartitionManager.Find_Partition_By_Path(DATA_LOGS_DIR) == NULL) {
			LOGINFO("Unable to find a directory to store TWRP logs.");
			return "";
		} else {
			return DATA_LOGS_DIR;
		}
	}
	else {
		return CACHE_LOGS_DIR;
	}
}

void TWFunc::check_selinux_support() {
	if (TWFunc::Path_Exists("/prebuilt_file_contexts")) {
		if (TWFunc::Path_Exists("/file_contexts")) {
			printf("Renaming regular /file_contexts -> /file_contexts.bak\n");
			rename("/file_contexts", "/file_contexts.bak");
		}
		printf("Moving /prebuilt_file_contexts -> /file_contexts\n");
		rename("/prebuilt_file_contexts", "/file_contexts");
	}
	struct selinux_opt selinux_options[] = {
		{ SELABEL_OPT_PATH, "/file_contexts" }
	};
	selinux_handle = selabel_open(SELABEL_CTX_FILE, selinux_options, 1);
	if (!selinux_handle)
		printf("No file contexts for SELinux\n");
	else
		printf("SELinux contexts loaded from /file_contexts\n");
	{ // Check to ensure SELinux can be supported by the kernel
		char *contexts = NULL;
		std::string cacheDir = TWFunc::get_log_dir();
		std::string se_context_check = cacheDir + "recovery/";
		int ret = 0;

		if (cacheDir == CACHE_LOGS_DIR) {
			PartitionManager.Mount_By_Path(CACHE_LOGS_DIR, false);
		}
		if (TWFunc::Path_Exists(se_context_check)) {
			ret = lgetfilecon(se_context_check.c_str(), &contexts);
			if (ret < 0) {
				LOGINFO("Could not check %s SELinux contexts, using /system/bin/teamwin instead which may be inaccurate.\n", se_context_check.c_str());
				lgetfilecon("/system/bin/teamwin", &contexts);
			}
		}
		if (ret < 0) {
			gui_warn("no_kernel_selinux=Kernel does not have support for reading SELinux contexts.");
		} else {
			free(contexts);
			gui_msg("full_selinux=Full SELinux support is present.");
		}
	}
}

bool TWFunc::Is_TWRP_App_In_System() {
	LOGINFO("checking for twrp app\n");
	TWPartition* sys = PartitionManager.Find_Partition_By_Path(PartitionManager.Get_Android_Root_Path());
	if (!sys->Get_Super_Status()) {
		bool is_system_mounted = true;
		if(!PartitionManager.Is_Mounted_By_Path(PartitionManager.Get_Android_Root_Path())) {
			is_system_mounted = false;
			PartitionManager.Mount_By_Path(PartitionManager.Get_Android_Root_Path(), false);
		}
		string base_path = PartitionManager.Get_Android_Root_Path();
		if (TWFunc::Path_Exists(PartitionManager.Get_Android_Root_Path() + "/system"))
			base_path += "/system"; // For devices with system as a root file system (e.g. Pixel)
		string install_path = base_path + "/priv-app";
		if (!TWFunc::Path_Exists(install_path))
			install_path = base_path + "/app";
		install_path += "/twrpapp";
		if (TWFunc::Path_Exists(install_path)) {
			LOGINFO("App found at '%s'\n", install_path.c_str());
			DataManager::SetValue("tw_app_installed_in_system", 1);
			return true;
		}
		if (!is_system_mounted)
			PartitionManager.UnMount_By_Path(PartitionManager.Get_Android_Root_Path(), false);
		DataManager::SetValue("tw_app_installed_in_system", 0);
	}
	DataManager::SetValue("tw_app_installed_in_system", 0);
	return false;
}

void TWFunc::checkforapp(){

	string sdkverstr = System_Property_Get("ro.build.version.sdk");
	int sdkver = 0;
	if (!sdkverstr.empty()) {
		sdkver = atoi(sdkverstr.c_str());
	}
	if (sdkver <= 13) {
		if (sdkver == 0)
			LOGINFO("Unable to read sdk version from build prop\n");
		else
			LOGINFO("SDK version too low for TWRP app (%i < 14)\n", sdkver);
		DataManager::SetValue("tw_app_install_status", 1); // 0 = no status, 1 = not installed, 2 = already installed or do not install
		goto exit;
	}
	if (Is_TWRP_App_In_System()) {
		DataManager::SetValue("tw_app_install_status", 2); // 0 = no status, 1 = not installed, 2 = already installed or do not install
		goto exit;
	}
	if (PartitionManager.Mount_By_Path("/data", false)) {
		const char parent_path[] = "/data/app";
		const char app_prefix[] = "me.twrp.twrpapp-";
		DIR *d = opendir(parent_path);
		if (d) {
			struct dirent *p;
			while ((p = readdir(d))) {
				if (p->d_type != DT_DIR || strlen(p->d_name) < strlen(app_prefix) || strncmp(p->d_name, app_prefix, strlen(app_prefix)))
					continue;
				closedir(d);
				LOGINFO("App found at '%s/%s'\n", parent_path, p->d_name);
				DataManager::SetValue("tw_app_install_status", 2); // 0 = no status, 1 = not installed, 2 = already installed or do not install
				goto exit;
			}
			closedir(d);
		}
	} else {
		LOGINFO("Data partition cannot be mounted during app check\n");
		DataManager::SetValue("tw_app_install_status", 2); // 0 = no status, 1 = not installed, 2 = already installed or do not install
	}

	LOGINFO("App not installed\n");
	DataManager::SetValue("tw_app_install_status", 1); // 0 = no status, 1 = not installed, 2 = already installed
exit:
	return;

}

int TWFunc::Property_Override(string Prop_Name, string Prop_Value) {
#ifdef TW_INCLUDE_LIBRESETPROP
    return setprop(Prop_Name.c_str(), Prop_Value.c_str(), false);
#else
    return -2;
#endif
}

void TWFunc::List_Mounts() {
	std::vector<std::string> mounts;
	read_file("/proc/mounts", mounts);
	LOGINFO("Mounts:\n");
	for (auto&& mount: mounts) {
		LOGINFO("%s\n", mount.c_str());
	}
}

#ifdef TW_INCLUDE_CRYPTO
#ifdef USE_FSCRYPT_POLICY_V1
bool TWFunc::Get_Encryption_Policy(struct fscrypt_policy_v1 &policy, std::string path) {
#else
bool TWFunc::Get_Encryption_Policy(struct fscrypt_policy_v2 &policy, std::string path) {
#endif
	if (!TWFunc::Path_Exists(path)) {
		LOGERR("Unable to find %s to get policy\n", path.c_str());
		return false;
	}
	if (!fscrypt_policy_get_struct(path.c_str(), &policy)) {
		LOGERR("No policy set for path %s\n", path.c_str());
		return false;
	}
	return true;
}

#ifdef USE_FSCRYPT_POLICY_V1
bool TWFunc::Set_Encryption_Policy(std::string path, struct fscrypt_policy_v1 &policy) {
#else
bool TWFunc::Set_Encryption_Policy(std::string path, struct fscrypt_policy_v2 &policy) {
#endif
	if (!TWFunc::Path_Exists(path)) {
		LOGERR("unable to find %s to set policy\n", path.c_str());
		return false;
	}
	uint8_t binary_policy[FS_KEY_DESCRIPTOR_SIZE];
	char policy_hex[FSCRYPT_KEY_IDENTIFIER_HEX_SIZE];
	bytes_to_hex(binary_policy, FS_KEY_DESCRIPTOR_SIZE, policy_hex);
	if (!fscrypt_policy_set_struct(path.c_str(), &policy)) {
		LOGERR("unable to set policy for path: %s\n", path.c_str());
		return false;
	}
	return true;
}
#endif

string TWFunc::Check_For_TwrpFolder() {
	string oldFolder = "";
	vector<string> customTWRPFolders;
	string mainPath = DataManager::GetCurrentStoragePath();
	DIR* d;
	struct dirent* de;

	if (DataManager::GetIntValue(TW_IS_ENCRYPTED) && DataManager::GetIntValue(TW_CRYPTO_PWTYPE)) {
		goto exit;
	}


	d = opendir(mainPath.c_str());
	if (d == NULL) {
		goto exit;
	}

	while ((de = readdir(d)) != NULL) {
		string name = de->d_name;
		string fullPath = mainPath + '/' + name;
		unsigned char type = de->d_type;

		if (name == "." || name == "..") continue;

		if (type == DT_UNKNOWN) {
			type = Get_D_Type_From_Stat(fullPath);
		}

		if (type == DT_DIR && Path_Exists(fullPath + "/.twrpcf")) {
			if ('/' + name == TW_DEFAULT_RECOVERY_FOLDER) {
				oldFolder = name;
			} else {
				customTWRPFolders.push_back(name);
			}
		}
	}

	closedir(d);

	if (oldFolder == "" && customTWRPFolders.empty()) {
		LOGINFO("No recovery folder found. Using default folder.\n");
		// Do not mount/mkdir in fastboot mode (it would break fastbootd startup).
		if (android::base::GetProperty(TW_FASTBOOT_MODE_PROP, "0") != "1") {
			TWPartition* SDCard = PartitionManager.Find_Partition_By_Path(DataManager::GetCurrentStoragePath());
			if (SDCard->Mount(true)) {
				mainPath += TW_DEFAULT_RECOVERY_FOLDER;
				mkdir(mainPath.c_str(), 0777);
			}
		}
		goto exit;
	} else if (customTWRPFolders.empty()) {
		LOGINFO("No custom recovery folder found. Using TWRP as default.\n");
		goto exit;
	} else {
		if (customTWRPFolders.size() > 1) {
			LOGINFO("More than one custom recovery folder found. Using first one from the list.\n");
		} else {
			LOGINFO("One custom recovery folder found.\n");
		}
		string customPath =  '/' + customTWRPFolders.at(0);

		if (Path_Exists(mainPath + TW_DEFAULT_RECOVERY_FOLDER)) {
			string oldBackupFolder = mainPath + TW_DEFAULT_RECOVERY_FOLDER + "/BACKUPS/" + DataManager::GetStrValue("device_id");
			string newBackupFolder = mainPath + customPath + "/BACKUPS/" + DataManager::GetStrValue("device_id");

			if (Path_Exists(oldBackupFolder)) {
				vector<string> backups;
				d = opendir(oldBackupFolder.c_str());

				if (d != NULL) {
					while ((de = readdir(d)) != NULL) {
						string name = de->d_name;
						unsigned char type = de->d_type;

						if (name == "." || name == "..") continue;

						if (type == DT_UNKNOWN) {
							type = Get_D_Type_From_Stat(mainPath + '/' + name);
						}

						if (type == DT_DIR) {
							backups.push_back(name);
						}
					}
					closedir(d);
				}

				for (auto it = backups.begin(); it != backups.end(); it++) {
					Exec_Cmd("mv -f \"" + oldBackupFolder + '/' + *it + "\" \"" + newBackupFolder + '/' + *it + (Path_Exists(newBackupFolder + '/' + *it) ? "_new\"" : "\""));
				}
			}
			Exec_Cmd("rm -rf \"" + mainPath + TW_DEFAULT_RECOVERY_FOLDER + '\"');
		}

		return customPath;
	}

exit:
	return TW_DEFAULT_RECOVERY_FOLDER;
}

bool TWFunc::Check_Xml_Format(const std::string filename) {
	std::string buffer(' ', 4);
	std::string abx_hdr("ABX\x00", 4);
	std::ifstream File;
	File.open(filename);
	if (File.is_open()) {
		File.get(&buffer[0], buffer.size());
		File.close();
		// Android Binary Xml start from these bytes
		if(!buffer.compare(0, abx_hdr.size(), abx_hdr))
			return false; // ABX format - requires conversion
	}
	return true; // good format, possible to parse
}

#endif // ndef BUILD_TWRPTAR_MAIN

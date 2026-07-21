/*
	Copyright 2026 TeamWin / TWRP CryptedBackup Fix
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

// twadbd service dispatch -- replaces libadbd_services (which we do NOT link).
// Serves ONLY backup:/restore: by fork+exec of /system/bin/bu with a socketpair
// as stdio (NO PTY -> none of the n_tty freeze class). All other adb services are
// deliberately disabled in backup mode (twadbd lives only for the minutes of a
// backup; shell/push/pull run normally over stock adbd).
//
// bu attaches over /tmp/twadbfifo to the permanent twrpAdbBuFifo thread in
// recovery -- the actual backup/restore engine is COMPLETELY unchanged; twadbd
// only swaps the transport (adbd PTY -> twadbd socketpair). argv semantics are
// bit-identical to the stock path (system/core/adb/daemon/services.cpp:283-289).
//
// SELinux: TWRP recovery runs permissive (androidboot: avc ... permissive=1), so
// bu needs no explicit domain switch; execution is allowed from twadbd's context.
// (In an enforcing recovery a setcon to u:r:shell:s0 would have to be added here,
// like shell_service.cpp.)

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include <android-base/logging.h>
#include <android-base/strings.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "sysdeps.h"

// Fork+exec of bu with socketpair(sv[0]=parent/service fd, sv[1]=child/stdio).
// Returns the parent fd (the adb runtime attaches it as a local socket and pumps
// it <-> the host transport). A detached waiter ends twadbd as soon as bu is
// done (one-shot).
static unique_fd StartBu(const std::string& shell_cmd) {
	int sv[2];
	if (adb_socketpair(sv) < 0) {
		PLOG(ERROR) << "twadbd: socketpair for bu failed";
		return unique_fd{};
	}

	pid_t pid = fork();
	if (pid < 0) {
		PLOG(ERROR) << "twadbd: fork for bu failed";
		adb_close(sv[0]);
		adb_close(sv[1]);
		return unique_fd{};
	}

	if (pid == 0) {
		// Child: socketpair end onto stdin/out/err. bu uses fd 0 (restore read) /
		// fd 1 (backup write); stderr mixes into the same channel as in the stock
		// kRaw path (shell_service.cpp ForkAndExec).
		adb_close(sv[0]);
		dup2(sv[1], STDIN_FILENO);
		dup2(sv[1], STDOUT_FILENO);
		dup2(sv[1], STDERR_FILENO);
		if (sv[1] > STDERR_FILENO) adb_close(sv[1]);
		// adbd/twadbd set SIGPIPE=SIG_IGN; put the bu child back to default
		// (bionic would otherwise inherit SIG_IGN -- http://b/35209888).
		signal(SIGPIPE, SIG_DFL);
		execl("/system/bin/sh", "sh", "-c", shell_cmd.c_str(), (char*)nullptr);
		_exit(127);
	}

	// Parent (twadbd):
	adb_close(sv[1]);

	// One-shot waiter: wait for bu to end, give the fdevent loop a moment to drain
	// the last socket buffer to the host, then end twadbd. (The flush grace is
	// pragmatic.)
	std::thread([pid]() {
		int status = 0;
		while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
		}
		sleep(2);
		_exit(0);
	}).detach();

	return unique_fd{sv[0]};
}

// A rejected service (not backup:/restore:) -> return an explanatory message to
// the host instead of a bare "error: closed". ONLY for shell* services (that is
// what the user types: `adb shell ...`): twadbd advertises shell_v2 (libadbd
// supported_features) -> frame the message in the shell-v2 protocol
// ([id:1][len:u32 native][data]; kIdStdout=1 then kIdExit=3 with status 1); an
// old raw-shell host (no "v2" in the service string) gets raw text. Other
// services (sync: = push/pull etc.) keep the clean unique_fd{} ("closed") -- a
// text fd would corrupt their binary protocol (adb push would hang instead of
// failing cleanly). No alarm(0) here -> a shell probe does NOT extend the idle
// timer.
static const char kRejectNotice[] =
	"TWRP ADB backup mode active. Only 'adb backup' and 'adb restore' are accepted here.\n";

static unique_fd RejectWithNotice(std::string_view name) {
	if (!name.starts_with("shell")) {
		return unique_fd{};
	}
	int sv[2];
	if (adb_socketpair(sv) < 0) {
		return unique_fd{};
	}
	bool v2 = name.find("v2") != std::string_view::npos;
	// Detached writer: write the message, then close sv[1] -> the host sees the
	// output + (for v2) the exit status, then EOF. sv[0] is pumped by the adb
	// runtime to the host (same idiom as StartBu).
	std::thread([v2, wfd = sv[1]]() {
		if (v2) {
			const uint32_t len = sizeof(kRejectNotice) - 1;
			char hdr[5];
			hdr[0] = 1;  // ShellProtocol::kIdStdout
			memcpy(&hdr[1], &len, sizeof(len));
			WriteFdExactly(wfd, hdr, sizeof(hdr));
			WriteFdExactly(wfd, kRejectNotice, len);
			char ex[6];
			ex[0] = 3;  // ShellProtocol::kIdExit
			const uint32_t one = 1;
			memcpy(&ex[1], &one, sizeof(one));
			ex[5] = 1;  // exit status
			WriteFdExactly(wfd, ex, sizeof(ex));
		} else {
			WriteFdExactly(wfd, kRejectNotice, sizeof(kRejectNotice) - 1);
		}
		adb_close(wfd);
	}).detach();
	return unique_fd{sv[0]};
}

unique_fd daemon_service_to_fd(std::string_view name, atransport* /* transport */) {
	// Disarm the idle timeout ONLY on an ACCEPTED backup:/restore:. An
	// unconditional alarm(0) here would let the first rejected foreign service
	// (e.g. a host `adb shell`) permanently disable the timer -- twadbd would then
	// never end despite being idle.
	if (android::base::ConsumePrefix(&name, "backup:")) {
		alarm(0);
		std::string cmd = "/system/bin/bu backup ";
		cmd += std::string(name);
		return StartBu(cmd);
	} else if (name.starts_with("restore:")) {
		alarm(0);
		return StartBu("/system/bin/bu restore");
	}

	LOG(ERROR) << "twadbd: unsupported service in backup mode: " << std::string(name);
	return RejectWithNotice(name);
}

asocket* daemon_service_to_socket(std::string_view /* name */) {
	return nullptr;
}

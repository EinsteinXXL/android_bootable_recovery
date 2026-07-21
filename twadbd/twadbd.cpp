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

// twadbd -- short-lived TWRP mode daemon for PTY-free adb backup/restore.
//
// Why: adbd forces a PTY for backup:/restore: (shell_service.cpp kRaw+kNone ->
// kPty). The n_tty line discipline behind it sporadically freezes completely
// under a binary bulk stream. Fix without touching system/core/adb (manifest
// purity): a small dedicated daemon in the minadbd style that serves
// backup:/restore: ITSELF -- over a socketpair instead of a PTY (see
// twadbd_services.cpp).
//
// Lifecycle: the recovery process (twrpAdbBuFifo) stops stock adbd, starts twadbd
// for the duration of ONE backup/restore and then starts stock adbd again
// (one-shot). twadbd links the UNCHANGED libadbd (transport/USB/fdevent) and
// provides only the service dispatch (daemon_service_to_fd) itself --
// libadbd_services is deliberately NOT linked, so there is no symbol collision
// with the stock daemon_service_to_fd (exactly like minadbd).

#include <signal.h>
#include <unistd.h>

#include <android-base/logging.h>

#include "adb.h"
#include "adb_auth.h"
#include "transport.h"
#include "fdevent/fdevent.h"

// Shared constants (TWADBD_IDLE_SECS, TWADBD_EXIT_IDLE_TIMEOUT) -- the recovery
// lifecycle (twrpAdbBuFifo) uses the same values for the GUI text
// ("... after {1} minutes") and for detecting the timeout from the waitpid status.
#include "../adbbu/twadbstream.h"

// If no backup:/restore: arrives after mode start, twadbd ends after the
// TWADBD_IDLE_SECS window via SIGALRM (the handler exits with
// TWADBD_EXIT_IDLE_TIMEOUT) -> the recovery waiter reaps twadbd, detects the
// timeout from the exit code and starts stock adbd again. twadbd_services.cpp
// calls alarm(0) as soon as a backup:/restore: service is ACCEPTED (rejected
// foreign services leave the timer armed).

int main(int argc, char** argv) {
	(void)argc;
	android::base::InitLogging(argv, &android::base::StderrLogger);

	// A host/bu that vanishes mid-stream must not silently SIGPIPE-kill twadbd --
	// we want to see EPIPE on the write path.
	signal(SIGPIPE, SIG_IGN);

	// Recovery mode daemon: no auth (like minadbd) -- the device is physically in
	// TWRP, and auth keys do not exist in the recovery context anyway.
	auth_required = false;
	adb_device_banner = "recovery";

	// twadbd is started via fork+execve from the recovery process -- the signal
	// MASK and a SIG_IGN disposition survive execve (only handlers fall back to
	// SIG_DFL). An inherited SIGALRM state like that makes alarm() silently no-op
	// (the timeout would never fire; libadbd itself never touches SIGALRM). So
	// BEFORE alarm(): install our own terminating handler (overrides an inherited
	// SIG_IGN) and unblock SIGALRM (overrides an inherited mask). _exit is
	// async-signal-safe; the recovery waiter (waitpid) does the cleanup as for the
	// one-shot and detects the timeout from the exit code (!= the one-shot end's 0,
	// != SIGTERM).
	signal(SIGALRM, [](int) { _exit(TWADBD_EXIT_IDLE_TIMEOUT); });
	sigset_t alrm_unblock;
	sigemptyset(&alrm_unblock);
	sigaddset(&alrm_unblock, SIGALRM);
	sigprocmask(SIG_UNBLOCK, &alrm_unblock, nullptr);

	alarm(TWADBD_IDLE_SECS);

	init_transport_registration();
	usb_init();
	fdevent_loop();
	return 0;
}

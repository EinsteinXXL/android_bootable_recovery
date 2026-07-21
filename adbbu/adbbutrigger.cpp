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

// adbbu -- dedicated trigger binary for the PTY-free ADB backup mode.
// Deliberately separate from the twrp/orscmd CLI (which stays untouched).
//
//   adb shell adbbu start    -> TWRP switches into backup mode (stock adbd is
//                               replaced by the short-lived twadbd).
//   adb shell adbbu cancel   -> leave/abort the mode (stock adbd restored).
//
// Only writes an opcode into TW_ADB_FIFO; the USB-switch lifecycle is driven by
// the permanent twrpAdbBuFifo thread in the recovery process. The actual backup
// command stays UNCHANGED afterwards: adb backup --twrp [--compress] <parts>
// (this call's adb connection drops on the USB switch -- normal, like sideload;
// just run it again).

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "twadbstream.h"       // ADB_BU_MODE_START_OP/_CANCEL_OP, ADB_BU_MAX_ERROR
#include "../twrpAdbBuFifo.hpp" // TW_ADB_FIFO (as in twrpback.cpp)

int main(int argc, char** argv) {
	const char* op = nullptr;

	if (argc == 2 && strcmp(argv[1], "start") == 0) {
		op = ADB_BU_MODE_START_OP;
		printf("ADB backup mode starting -- the adb connection will drop momentarily.\n");
		printf("When the device reconnects (still shows as 'recovery'), run your backup\n");
		printf("or restore as usual, for example:\n");
		printf("    adb backup --twrp --compress data\n");
	} else if (argc == 2 && strcmp(argv[1], "cancel") == 0) {
		op = ADB_BU_MODE_CANCEL_OP;
		printf("Cancelling ADB backup mode -- normal adb will be restored.\n");
	} else {
		fprintf(stderr, "Usage: adbbu start|cancel\n");
		return 2;
	}
	fflush(stdout);

	// 512-byte block like bu/orscmd (the reader reads a fixed 512).
	char cmd[512];
	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "%s", op);

	int fd = open(TW_ADB_FIFO, O_WRONLY);
	int tries = 0;
	while (fd < 0 && tries < ADB_BU_MAX_ERROR) {
		usleep(50000);
		fd = open(TW_ADB_FIFO, O_WRONLY);
		tries++;
	}
	if (fd < 0) {
		fprintf(stderr, "adbbu: TWRP ADB FIFO not available -- is TWRP running?\n");
		return 1;
	}

	if (write(fd, cmd, sizeof(cmd)) != (ssize_t)sizeof(cmd)) {
		fprintf(stderr, "adbbu: failed to send command to TWRP\n");
		close(fd);
		return 1;
	}
	close(fd);
	return 0;
}

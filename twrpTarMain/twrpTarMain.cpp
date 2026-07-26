
/*
	Copyright 2014 TeamWin
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

#include "../twrp-functions.hpp"
#include "../twrpTar.hpp"
#include "../exclude.hpp"
#include "../progresstracking.hpp"
#include "../gui/gui.hpp"
#include "../gui/twmsg.h"
#include <string.h>

void gui_msg(const char* text)
{
	if (text) {
		Message msg = Msg(text);
		gui_msg(msg);
	}
}

void gui_warn(const char* text)
{
	if (text) {
		Message msg = Msg(msg::kWarning, text);
		gui_msg(msg);
	}
}

void gui_err(const char* text)
{
	if (text) {
		Message msg = Msg(msg::kError, text);
		gui_msg(msg);
	}
}

void gui_highlight(const char* text)
{
	if (text) {
		Message msg = Msg(msg::kHighlight, text);
		gui_msg(msg);
	}
}

void gui_msg(Message msg)
{
	std::string output = msg;
	output += "\n";
	fputs(output.c_str(), stdout);
}

// gui_activate/deactivate_msg_pipe: in recovery these manage the worker->parent
// GUI message pipe (gui/console.cpp); standalone twrpTar has no GUI -> no-op.
void gui_activate_msg_pipe(int) {}
void gui_deactivate_msg_pipe(void) {}

// fscrypt policy stubs: libtar (append.c/extract.c) and twrpTar.cpp
// (fscrypt_set_mode) call these TWRP helpers to save/restore /data encryption
// policies. Their real implementation
// (crypto/fscrypt/fscrypt_policy.cpp) pulls in libbase/libcutils/liblogwrap/
// libfscrypt/KeyUtil — half the key-management tree — which the lean twrpTar CLI
// deliberately does not link. As no-ops (extern "C", matched by name at link
// time) fscrypt policies are simply not preserved in the standalone build;
// tarring and BAES/zstd are unaffected.
extern "C" {
	struct fscrypt_policy_v2;
	bool fscrypt_set_mode(void) { return false; }
	bool lookup_ref_key(struct fscrypt_policy_v2 *, unsigned char *) { return false; }
	bool lookup_ref_tar(const unsigned char *, unsigned char *) { return false; }
	bool fscrypt_policy_get_struct(const char *, struct fscrypt_policy_v2 *) { return false; }
	bool fscrypt_policy_set_struct(const char *, const struct fscrypt_policy_v2 *) { return false; }
	void bytes_to_hex(const unsigned char *, size_t, char *) {}
}

void usage() {
	printf("twrpTar <action> [options]\n\n");
	printf("actions: -c create\n");
	printf("         -x extract\n\n");
	printf(" -d    target directory\n");
	printf(" -t    output file\n");
	printf(" -z    compress backup (zstd, in-process -- no external binary needed)\n");
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
	printf(" -e    encrypt/decrypt backup followed by password (BoringSSL AEAD, in-process)\n");
	printf(" -u    encrypt using userdata encryption (must be used with -e)\n");
#endif
	printf("\n\n");
	printf("Example: twrpTar -c -d /cache -t /sdcard/test.tar\n");
	printf("         twrpTar -x -d /cache -t /sdcard/test.tar\n");
}

int main(int argc, char **argv) {
	twrpTar tar;
	int use_encryption = 0, userdata_encryption = 0, use_compression = 0, include_root = 0;
	int i, action = 0;
	string Directory, Tar_Filename;
	ProgressTracking progress(1);
	std::atomic<pid_t> tar_fork_pid{0};
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
	string Password;
#endif

	if (argc < 2) {
		usage();
		return 0;
	}

	if (strcmp(argv[1], "-c") == 0)
		action = 1; // create tar
	else if (strcmp(argv[1], "-x") == 0)
		action = 2; // extract tar
	else {
		printf("Invalid action '%s' specified.\n", argv[1]);
		usage();
		return -1;
	}

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "-d") == 0) {
			i++;
			if (argc <= i) {
				printf("No argument specified for %s\n", argv[i - 1]);
				usage();
				return -1;
			} else {
				Directory = argv[i];
			}
		} else if (strcmp(argv[i], "-t") == 0) {
			i++;
			if (argc <= i) {
				printf("No argument specified for %s\n", argv[i - 1]);
				usage();
				return -1;
			} else {
				Tar_Filename = argv[i];
			}
		} else if (strcmp(argv[i], "-e") == 0) {
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
			i++;
			if (argc <= i) {
				printf("No argument specified for %s\n", argv[i - 1]);
				usage();
				return -1;
			} else {
				use_encryption = 1;
				Password = argv[i];
			}
#else
			printf("Encrypted tar file support not present\n");
			usage();
			return -1;
#endif
		} else if (strcmp(argv[i], "-z") == 0) {
			if (action == 2)
				printf("NOTE: %s option not needed when extracting.\n", argv[i]);
			use_compression = 1;
		} else if (strcmp(argv[i], "-u") == 0) {
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
			if (action == 2)
				printf("NOTE: %s option not needed when extracting.\n", argv[i]);
			userdata_encryption = 1;
#else
			printf("Encrypted tar file support not present\n");
			usage();
			return -1;
#endif
		}
	}

	TWExclude exclude;
	exclude.add_absolute_dir("/data/media");
	tar.setdir(Directory);
	tar.setfn(Tar_Filename);
	tar.setsize(exclude.Get_Folder_Size(Directory));
	tar.use_compression = use_compression;
	tar.backup_exclusions = &exclude;
	// Minimal PartitionSettings for the standalone CLI: createTarFork()/
	// extractTarFork() dereference part_settings->progress and ->adbbackup
	// (false = file path instead of ADB stream). No multi-partition context;
	// progress points at the local object.
	PartitionSettings part_settings;
	part_settings.progress = &progress;
	tar.part_settings = &part_settings;
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
	if (userdata_encryption && !use_encryption) {
		printf("userdata encryption set without encryption option\n");
		usage();
		return -1;
	}
	if (use_encryption) {
		tar.use_encryption = use_encryption;
		tar.userdata_encryption = userdata_encryption;
		tar.setpassword(Password);
	} else {
		use_encryption = false;
	}
#endif
	if (action == 1) {
		if (tar.createTarFork(&tar_fork_pid) != 0) {
			sync();
			return -1;
		}
		sync();
		printf("\n\ntar created successfully.\n");
	} else if (action == 2) {
		if (tar.extractTarFork() != 0) {
			sync();
			return -1;
		}
		sync();
		printf("\n\ntar extracted successfully.\n");
	}
	return 0;
}

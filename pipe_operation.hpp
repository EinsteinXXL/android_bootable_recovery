/*
	Copyright 2026 TeamWin / TWRP-OFRP-CryptedBackup-Fix
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

// ---------------------------------------------------------------------------
// Tier-2 per-archive pipeline (comp/crypt). PipeOperation encapsulates the
// declarative stage chain; BackupPipeline wires it forward (tar -> ... -> file),
// RestorePipeline backward (file -> ... -> tar). The forked PIDs are stored via
// write-through into twrpTar::comp_pid/crypt_pid so the proven
// reap_subchildren/cleanup path in twrpTar stays untouched. Definitions live in
// pipe_operation.cpp; access to twrpTar members/statics goes through the friend
// grants in twrpTar.hpp (friendship spans translation units -> no member
// becomes public).
// ---------------------------------------------------------------------------

#ifndef __PIPE_OPERATION_HPP
#define __PIPE_OPERATION_HPP

#include <string>
#include <cstdint>
#include <vector>   // core_for() returns a core slice (std::vector<int>)

extern "C" {
	#include "libtar/libtar.h"   // TAR_* flags for TWTAR_FLAGS
}

// Tar flags live here because both twrpTar.cpp and pipe_operation.cpp pass them
// to tar_open/tar_fdopen.
#ifdef USE_FSCRYPT
#define TWTAR_FLAGS TAR_GNU | TAR_STORE_SELINUX | TAR_STORE_POSIX_CAP | TAR_STORE_ANDROID_USER_XATTR | TAR_STORE_FSCRYPT_POL
#else
#define TWTAR_FLAGS TAR_GNU | TAR_STORE_SELINUX | TAR_STORE_POSIX_CAP | TAR_STORE_ANDROID_USER_XATTR
#endif

// Shared low-level helpers: defined in twrpTar.cpp (they use file-local
// constants/logging there), declared here for use in pipe_operation.cpp.
int  make_data_pipe(int p[2]);
bool write_password_or_log(int fd, const std::string& password);

class twrpTar;   // back reference; friend of twrpTar (see twrpTar.hpp)

// Declarative pipeline description (backup data direction tar -> ... -> file).
enum class PipeStage : uint8_t { ZSTD, AES };

class PipeOperation {
protected:
	twrpTar&    tw_;
	int         pipes_[4] = {-1, -1, -1, -1};   // max 2 stages -> max 2 pipes (4 fds)
	PipeStage   stages_[2];
	int         n_stages_ = 0;
	const char* err_key_;                       // gui_err key for abort() (backup_/restore_error)

	PipeOperation(twrpTar& tw, const char* err_key) : tw_(tw), err_key_(err_key) {}

	void build_stages();                                  // stage list from the mode
	std::vector<int> core_for(PipeStage s) const;         // core slice per stage (mode-dependent)
	int  make_all_pipes(int k);                           // make_data_pipe loop
	int  fork_zstd(int in, int out, bool decompress, const char* child_err);
	int  fork_aes (int in, int out, bool decrypt,    const char* child_err);

	// Unified setup-error cleanup. The object owns pipes_; via friend it uses
	// the private tw_.reap_subchildren + tw_.output_fd/input_fd/tarfn.
	// gui_err(err_key_), closes open pipes_, kill+reap comp/crypt, closes+
	// unlinks the output (backup) and closes the input (restore). Always
	// returns -1 (return idiom). log_msg may be NULL.
	int  abort(const char* log_msg);

public:
	virtual ~PipeOperation() {}
	virtual int setup() = 0;
};

// Backup: stage list wired FORWARD (tar -> S0 -> ... -> S_{k-1} -> file).
class BackupPipeline : public PipeOperation {
	int open_output();
public:
	explicit BackupPipeline(twrpTar& tw) : PipeOperation(tw, "backup_error=Error creating backup.") {}
	int setup() override;
};

// Restore: the same stage list wired BACKWARD (file -> ... -> tar).
class RestorePipeline : public PipeOperation {
	int open_input();   // O_RDONLY; adbbackup -> TW_ADB_RESTORE FIFO, else tarfn
public:
	explicit RestorePipeline(twrpTar& tw) : PipeOperation(tw, "restore_error=Error during restore process.") {}
	int setup() override;
};

#endif // __PIPE_OPERATION_HPP

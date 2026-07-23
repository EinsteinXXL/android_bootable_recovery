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
// Tier-2 per-archive pipeline (comp/crypt) — definitions. See pipe_operation.hpp.
//
// FD topology, close/fork order and core sources are deliberately preserved.
// exec_comp_child/exec_crypt_child remain twrpTar statics (reachable via
// friend); the internal reap_subchildren primitive is a twrpTar member (friend
// as well). Setup-error cleanup is PipeOperation::abort() below.
// ---------------------------------------------------------------------------

#include "pipe_operation.hpp"

extern "C" {
	#include "libtar/libtar.h"
	#include "twrpTar.h"        // write_tar_no_buffer
}
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <string>

#include "twrpTar.hpp"          // class twrpTar (full def + friend), Archive_Type constants
#include "twrp_affinity.hpp"    // tw_affinity::core_slice, *_cores
#include "twcommon.h"           // LOGINFO / LOGERR
#include "variables.h"
#include "adbbu/twadbstream.h"  // TW_ADB_BACKUP (FIFO path)
#include "gui/gui.hpp"          // gui_msg / gui_err / Msg / msg::kError
#include "data.hpp"             // DataManager::GetIntValue (read tw_zstd_level in the parent, fork-safe)
#include <stdio.h>              // snprintf (build -T/-N args + argv in the parent before the fork)

using namespace std;

// --- PipeOperation (base) --------------------------------------------------

// Stage list from the mode, ALWAYS in backup data direction (tar -> ... -> file).
void PipeOperation::build_stages() {
	n_stages_ = 0;
	switch (tw_.current_archive_type) {
		case COMPRESSED_ENCRYPTED:
			stages_[n_stages_++] = PipeStage::ZSTD;
			stages_[n_stages_++] = PipeStage::AES;
			break;
		case LEGACY_COMPRESSED:    // legacy gzip (pigz) — one decompress stage like compress-only zstd
		case COMPRESSED:
			stages_[n_stages_++] = PipeStage::ZSTD;
			break;
		case ENCRYPTED:
			stages_[n_stages_++] = PipeStage::AES;
			break;
		default:
			break;   // plain tar: 0 stages (the engine is not invoked for plain tar)
	}
}

// Core SLICE per stage. AES is mode-dependent (invariant): COMPRESSED_ENCRYPTED ->
// enc_and_comp_aes_cores, ENCRYPTED -> enc_only_aes_cores; zstd always zstd_cores. core_slice uses
// active_pipes + the list's is_cluster flag; at active==MAX one-core slices,
// with fewer pipes wider slices/cluster.
std::vector<int> PipeOperation::core_for(PipeStage s) const {
#ifdef BUILD_TWRPTAR_MAIN
	(void)s;
	return {};   // standalone twrpTar: no CPU pinning (single-pipe core)
#else
	if (s == PipeStage::ZSTD)
		return tw_affinity::core_slice(tw_affinity::zstd_cores, tw_affinity::zstd_is_cluster,
		                               tw_affinity::active_pipes, tw_.thread_id);
	if (tw_.current_archive_type == COMPRESSED_ENCRYPTED)
		return tw_affinity::core_slice(tw_affinity::enc_and_comp_aes_cores, tw_affinity::enc_and_comp_aes_is_cluster,
		                               tw_affinity::active_pipes, tw_.thread_id);
	return tw_affinity::core_slice(tw_affinity::enc_only_aes_cores, tw_affinity::enc_only_aes_is_cluster,
	                               tw_affinity::active_pipes, tw_.thread_id);
#endif
}

// Create k data pipes (pipes_[0..2k-1]). On failure: close and reset the ones
// already created.
int PipeOperation::make_all_pipes(int k) {
	for (int p = 0; p < k; ++p) {
		if (make_data_pipe(&pipes_[2 * p]) < 0) {
			for (int j = 0; j < 2 * p; ++j) { close(pipes_[j]); pipes_[j] = -1; }
			return -1;
		}
	}
	return 0;
}

// Derive the DecompSpec from the Archive_Type (single source for the fork_zstd
// decompress choice). Legacy gzip (LEGACY_COMPRESSED) -> pigz + -p; all zstd modes
// (COMPRESSED + the COMPRESSED_ENCRYPTED zstd stage) -> zstd + -T. Pinning strategy is
// handled uniformly by core_slice().
static DecompSpec decomp_spec_for(Archive_Type t) {
	if (t == LEGACY_COMPRESSED)
		return DecompSpec{ "pigz", /*flag_is_p=*/true  };
	return     DecompSpec{ "zstd", /*flag_is_p=*/false };
}

// Fork the zstd stage; write-through tw_.comp_pid. child_err = backup/restore
// key. Returns 0/-1. FORK SAFETY (multi-pipe): EVERYTHING the child needs
// (core_slice slice, -T/-N args, DataManager level, binary/path, complete argv)
// is built HERE in the PARENT before the fork() and lives on this stack — the
// child inherits it and does ONLY setup + execv (exec_comp_child), without any
// allocation or lock. Otherwise a deadlock occurs when a sibling pipe thread
// holds the malloc/DataManager lock at fork() time. exec_comp_child covers
// compress AND decompress (zstd/pigz) — the difference is in path/argv.
int PipeOperation::fork_zstd(int in, int out, bool decompress, const char* child_err) {
	std::vector<int> slice = core_for(PipeStage::ZSTD);
	int pipe_id = (int)tw_.thread_id;
	DecompSpec spec = decomp_spec_for(tw_.current_archive_type);   // POD; binary/flag only for decompress
	// zstd ignores -T when decompressing (decompress is always single-threaded)
	// -> pass NO thread arg for restore zstd. Compress (zstd -T) and pigz
	// decompress (-p) keep it.
	bool pass_thread_arg = !decompress || spec.flag_is_p;
	char targ[16] = "";
	if (pass_thread_arg)
#ifdef BUILD_TWRPTAR_MAIN
		// Standalone twrpTar single-pipe: zstd -T0 = use all cores.
		snprintf(targ, sizeof(targ), (decompress && spec.flag_is_p) ? "-p%d" : "-T%d", 0);
#else
		snprintf(targ, sizeof(targ), (decompress && spec.flag_is_p) ? "-p%d" : "-T%d",
		         tw_affinity::compute_compressor_threads(tw_affinity::active_pipes, pipe_id));
#endif
	char larg[8] = "";
	if (!decompress) {
#ifdef BUILD_TWRPTAR_MAIN
		int lev = 1;   // standalone twrpTar: zstd level fixed at 1 (flag -1), no DataManager
#else
		int lev = DataManager::GetIntValue("tw_zstd_level");
		if (lev < 1 || lev > 19) lev = 1;
#endif
		snprintf(larg, sizeof(larg), "-%d", lev);
	}
	const char* bin  = decompress ? spec.binary : "zstd";
	const char* path = (decompress && spec.flag_is_p) ? "/system/bin/pigz" : "/system/bin/zstd";
	const char* argv[6];
	int n = 0;
	argv[n++] = bin;
	argv[n++] = decompress ? "-d" : larg;   // compress: "-N" (level); decompress: "-d"
	if (pass_thread_arg)
		argv[n++] = targ;                    // "-T<n>" (compress) / "-p<n>" (pigz decompress); zstd decompress: no arg
	argv[n++] = "-c";
	argv[n++] = NULL;

	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0)
		twrpTar::exec_comp_child(in, out, slice, path, argv, child_err);
	tw_.comp_pid = pid;
	return 0;
}

// Fork the tw_bssl_aes stage: create pw_pipe, fork, write-through
// tw_.crypt_pid, send the password IMMEDIATELY after the fork (invariant).
// Returns 0/-1; on -1 the local pw_pipe is closed and crypt_pid may be set
// (the caller reaps). FORK SAFETY: core_for slice + pwfd arg + argv are built
// in the PARENT before the fork() (see fork_zstd); the child (exec_crypt_child)
// does ONLY setup + execv. Order: pipe2 -> fork -> [child: exec_crypt_child] /
// [parent: crypt_pid, close[0], password -> [1], close[1]].
int PipeOperation::fork_aes(int in, int out, bool decrypt, const char* child_err) {
	int pw_pipe[2];
	if (pipe2(pw_pipe, O_CLOEXEC) < 0)
		return -1;
	std::vector<int> slice = core_for(PipeStage::AES);
	char pwfd[16];
	snprintf(pwfd, sizeof(pwfd), "%d", pw_pipe[0]);
	const char* argv[5];
	argv[0] = "tw_bssl_aes";
	argv[1] = decrypt ? "dec" : "enc";
	argv[2] = "--pwfd";
	argv[3] = pwfd;
	argv[4] = NULL;
	pid_t pid = fork();
	if (pid < 0) {
		close(pw_pipe[0]); close(pw_pipe[1]);
		return -1;
	}
	if (pid == 0)
		twrpTar::exec_crypt_child(in, out, pw_pipe, slice, argv, child_err);
	tw_.crypt_pid = pid;
	close(pw_pipe[0]);
	if (!write_password_or_log(pw_pipe[1], tw_.password)) {
		close(pw_pipe[1]);
		return -1;
	}
	close(pw_pipe[1]);
	return 0;
}

// Unified setup-error cleanup. The object owns pipes_; comp/crypt PIDs and the
// file fds live on tw_ (friend access). Order matters: gui_err -> close pipes
// -> reap (SIGTERM) -> close+unlink output (backup) -> close input (restore).
// reap_subchildren is a no-op if nothing was forked (comp_pid/crypt_pid == 0);
// pipes_ entries may already be -1 (e.g. a tar_fdopen failure after all pipe
// ends are closed).
int PipeOperation::abort(const char* log_msg) {
	if (log_msg) LOGERR("%s\n", log_msg);
	gui_err(err_key_);
	for (int j = 0; j < 4; ++j)
		if (pipes_[j] >= 0) { close(pipes_[j]); pipes_[j] = -1; }
	tw_.reap_subchildren(/*kill_first=*/true, /*timeout_secs=*/0, /*report_failures=*/false);
	if (tw_.output_fd >= 0) {
		close(tw_.output_fd);
		tw_.output_fd = -1;
		if (!tw_.tarfn.empty()) unlink(tw_.tarfn.c_str());
	}
	if (tw_.input_fd >= 0) { close(tw_.input_fd); tw_.input_fd = -1; }
	return -1;
}

// --- BackupPipeline --------------------------------------------------------

// Open the output. Only the plain zstd path (COMPRESSED) honors
// adbbackup; the encrypted modes always open the tarfn file.
int BackupPipeline::open_output() {
	if (tw_.current_archive_type == COMPRESSED && tw_.part_settings->adbbackup) {
		LOGINFO("opening TW_ADB_BACKUP compressed stream\n");
		tw_.output_fd = open(TW_ADB_BACKUP, O_WRONLY);
	} else {
		tw_.output_fd = open(tw_.tarfn.c_str(),
			O_CLOEXEC | O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	}
	if (tw_.output_fd < 0) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(tw_.tarfn)(strerror(errno)));
		return -1;
	}
	return 0;
}

int BackupPipeline::setup() {
	char* charRootDir = (char*) tw_.tardir.c_str();
	const char* CHILD_ERR = "backup_error=Error creating backup.";
	build_stages();
	int k = n_stages_;

	if (open_output() < 0)
		return -1;
	if (make_all_pipes(k) < 0)
		return abort("Error creating pipe");

	// Fork the stages forward. Stage i: stdin = pipes_[2i] (read end of its
	// input pipe), stdout = next pipe's write end (pipes_[2i+3]) or output_fd.
	for (int i = 0; i < k; ++i) {
		int in  = pipes_[2 * i];
		int out = (i < k - 1) ? pipes_[2 * i + 3] : tw_.output_fd;
		int rc = (stages_[i] == PipeStage::ZSTD)
			? fork_zstd(in, out, /*decompress=*/false, CHILD_ERR)
			: fork_aes (in, out, /*decrypt=*/false,  CHILD_ERR);
		if (rc < 0)
			return abort("pipeline stage setup failed");
	}

	// Parent: close all pipe ends except tar_fd (= pipes_[1], write end of the
	// pipe closest to tar).
	for (int j = 0; j < 2 * k; ++j)
		if (j != 1 && pipes_[j] >= 0) { close(pipes_[j]); pipes_[j] = -1; }
	tw_.fd = pipes_[1];
	tw_.tar_type.writefunc = write_tar_no_buffer;
	if (tar_fdopen(&tw_.t, tw_.fd, charRootDir, &tw_.tar_type,
			O_CLOEXEC | O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
			TWTAR_FLAGS | (tw_.verbose_log ? TAR_TW_VERBOSE_LOG : 0)) != 0) {   // verbose log: found-fscrypt-policy (append.c)
		// tw_.fd == pipes_[1] (still open, tar_fdopen does not close on failure);
		// abort() closes that slot -> NO separate close(tw_.fd) (double close).
		return abort("tar_fdopen failed");
	}
	// Self-describing PAX g-headers (TWRP.backup_size/ext_app_data_size/ead)
	// BEFORE the first file — consolidated in twrpTar::write_global_headers
	// (friend access). is_plain_tar=false: no TWRP.tartype. The records pass through
	// zstd/AES; the restore reads them via in-process peek (BackupHeaderManager).
	if (tw_.write_global_headers(false) != 0) {
		// Tear down t/fd, then the established setup-error path: tar_close
		// closes pipes_[1] (== t->fd) and frees t; set the slot to -1 so abort()
		// does not close it again. abort() reaps comp/crypt (SIGTERM) and
		// closes+unlinks the output.
		tar_close(tw_.t);
		tw_.t = NULL;
		pipes_[1] = -1;
		return abort("write_global_headers failed");
	}
	return 0;
}

// --- RestorePipeline -------------------------------------------------------

// Open the input: adbbackup -> TW_ADB_RESTORE FIFO, else the segment file.
// O_RDONLY (restore reads).
int RestorePipeline::open_input() {
	if (tw_.part_settings->adbbackup) {
		LOGINFO("opening TW_ADB_RESTORE compressed stream\n");
		tw_.input_fd = open(TW_ADB_RESTORE, O_CLOEXEC | O_RDONLY | O_LARGEFILE);
	} else {
		tw_.input_fd = open(tw_.tarfn.c_str(), O_CLOEXEC | O_RDONLY | O_LARGEFILE);
	}
	if (tw_.input_fd < 0) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(tw_.tarfn)(strerror(errno)));
		return -1;
	}
	return 0;
}

int RestorePipeline::setup() {
	char* charRootDir = (char*) tw_.tardir.c_str();
	const char* CHILD_ERR = "restore_error=Error during restore process.";
	build_stages();
	int k = n_stages_;

	if (open_input() < 0)
		return -1;
	if (make_all_pipes(k) < 0)
		return abort("Error creating pipe");

	// Fork the stages backward (file-closest first -> crypt before comp for COMPRESSED_ENCRYPTED).
	// j = data position from the file; kind = stages_[k-1-j].
	// stdin = file (j==0) or previous pipe's read end (pipes_[2(j-1)]);
	// stdout = current pipe's write end (pipes_[2j+1]).
	for (int j = 0; j < k; ++j) {
		PipeStage kind = stages_[k - 1 - j];
		int in  = (j == 0) ? tw_.input_fd : pipes_[2 * (j - 1)];
		int out = pipes_[2 * j + 1];
		int rc = (kind == PipeStage::ZSTD)
			? fork_zstd(in, out, /*decompress=*/true, CHILD_ERR)
			: fork_aes (in, out, /*decrypt=*/true,  CHILD_ERR);
		if (rc < 0)
			return abort("pipeline stage setup failed");
	}

	// Parent: close all pipe ends except tar_fd (= read end of the last pipe,
	// pipes_[2(k-1)]).
	int tar_idx = 2 * (k - 1);
	for (int p = 0; p < 2 * k; ++p)
		if (p != tar_idx && pipes_[p] >= 0) { close(pipes_[p]); pipes_[p] = -1; }
	tw_.fd = pipes_[tar_idx];
	// Verbose log: TAR_TW_VERBOSE_LOG on the backup AND restore handle — gates
	// the libtar printf output (extract.c here; append.c found-fscrypt-policy on
	// backup). A dedicated bit, not TAR_VERBOSE.
	if (tar_fdopen(&tw_.t, tw_.fd, charRootDir, NULL,
			O_CLOEXEC | O_RDONLY | O_LARGEFILE,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
			TWTAR_FLAGS | (tw_.verbose_log ? TAR_TW_VERBOSE_LOG : 0)) != 0) {
		// tw_.fd == pipes_[tar_idx] (still open); abort() closes that slot +
		// reaps + closes input_fd + gui_err -> NO separate close/gui_err here.
		return abort("tar_fdopen failed");
	}
	return 0;
}

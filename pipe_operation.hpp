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
// Per-archive stage pipeline. PipeOperation encapsulates the declarative stage
// chain AND owns its lifecycle: the StageThread + StageRing handles live as
// members here, join_stages() is the private teardown primitive, finish()/abort()
// are the named public teardown intents. BackupPipeline wires the stages forward
// (tar -> ... -> file), RestorePipeline backward (file -> ... -> tar); each stage
// runs as an in-process THREAD.
//
// The object is held by twrpTar as a unique_ptr member (pipeline_) spanning the
// whole createTar()->closeTar() / openTar()->closeTarRestore() segment cycle —
// created per segment, consumed (finish/abort + reset) by twrpTar::
// finish_pipeline()/abort_pipeline(). Ownership boundary (same rule as
// ZstdStream): the pipeline owns the STAGES (threads + rings + tar-ring
// registry slot); the FILE ends (input_fd/output_fd) and the tar handle stay on
// twrpTar — those exist on paths without any pipeline (plain tar). Definitions
// live in pipe_operation.cpp; access to twrpTar members goes through the friend
// grants in twrpTar.hpp (friendship spans translation units -> no member
// becomes public).
// ---------------------------------------------------------------------------

#ifndef __PIPE_OPERATION_HPP
#define __PIPE_OPERATION_HPP

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

class twrpTar;      // back reference; friend of twrpTar (see twrpTar.hpp)
struct StageThread; // in-process stage (stage_engine.hpp) -- pointer-only here
class StageRing;    // SPSC stage-transport ring (stage_ring.h) -- pointer-only here

// Declarative pipeline description (backup data direction tar -> ... -> file).
enum class PipeStage : uint8_t { ZSTD, AES };

class PipeOperation {
protected:
	twrpTar&    tw_;
	PipeStage   stages_[2];
	int         n_stages_ = 0;
	const char* err_key_;                       // gui_err key for abort_setup() (backup_/restore_error)

	// The pipeline stages run IN-PROCESS as threads. Heap-owned HERE:
	// spawn_*_stage() creates them, join_stages() joins + frees them in comp->aes
	// order (delete only after a successful join -- never while a wedged thread
	// still references it). nullptr = no active thread of that kind.
	StageThread* comp_stage_ = nullptr;   // zstd (compress + decompress) / gzip (legacy decompress) thread
	StageThread* aes_stage_  = nullptr;   // BAES AES thread
	// Inter-stage SPSC ring for COMPRESSED_ENCRYPTED (S0<->S1); 1-stage modes leave
	// it null. Created in *Pipeline::setup(), freed in join_stages() ONLY after both
	// stage joins finished (a wedged/timed-out thread may still reference it ->
	// deliberate leak + the worker _exit()s, same discipline as the StageThreads).
	StageRing* inter_ring_ = nullptr;
	// tar-boundary ring (backup: tar -> S0; restore: S_last -> tar) + its registered
	// pseudo-fd (stage_engine.cpp registry; 0 = none). libtar reaches the ring via
	// the ring tartype's callbacks (pseudo-fd lookup). Freed in the join_stages()
	// funnel (registry slot released there FIRST).
	StageRing* tar_ring_ = nullptr;
	long tar_ring_pseudo_fd_ = 0;

	PipeOperation(twrpTar& tw, const char* err_key) : tw_(tw), err_key_(err_key) {}

	void build_stages();                                  // stage list from the mode
	std::vector<int> core_for(PipeStage s) const;         // core slice per stage (mode-dependent)
	// Start the zstd (or legacy-gzip) stage as an in-process THREAD. Creates
	// comp_stage_ (heap), wires its StageIO over the file end (in/out as an fd,
	// = input_fd/output_fd) or a ring side (in_ring/out_ring, fd arg -1), picks the
	// leaf loop from the archive type (LEGACY_COMPRESSED decompress -> zlib; else
	// zstd) + reads level/nbWorkers for compress from DataManager, and starts it.
	// in_ra_window > 0 on a file-backed IN side wires the rolling-readahead reader
	// (restore source prefetch, stage_io_fd_ra) instead of the plain fd reader;
	// ring-backed sides ignore it. Returns 0/-1 (on -1 nothing runs and
	// comp_stage_ is cleared).
	int  spawn_zstd_stage(int in, int out, bool decompress,
	                      StageRing* in_ring = nullptr, StageRing* out_ring = nullptr,
	                      long long in_ra_window = 0);
	// Start the AES stage as an in-process THREAD. Creates aes_stage_ (heap),
	// wires its StageIO over the file end (in/out) or a ring side, copies password +
	// aead_cipher_id + the AES core slice, and starts it. Ring/fd/in_ra_window
	// conventions as in spawn_zstd_stage. Returns 0/-1 (on -1 nothing runs and
	// aes_stage_ is cleared).
	int  spawn_aes_stage(int in, int out, bool decrypt,
	                     StageRing* in_ring = nullptr, StageRing* out_ring = nullptr,
	                     long long in_ra_window = 0);

	// Unified setup-error cleanup (only reachable while setup() runs): gui_err
	// (err_key_), poison + join the stage threads/rings, then via friend close+
	// unlink the output (backup) and close the input (restore) on tw_. Always
	// returns -1 (return idiom). log_msg may be NULL.
	int  abort_setup(const char* log_msg);

private:
	// Private stage-teardown primitive (single source of truth, comp->aes order) —
	// the flags live only here, behind the named intents finish()/abort()/
	// abort_setup(). poison_first = fail() the rings before the join (abort
	// paths); timeout_secs>0 = timed join (restore hardening), else blocking;
	// report_failures -> -1 on a stage rc != 0. Closes NO fds; frees the
	// pipeline-owned rings.
	int  join_stages(bool poison_first, int timeout_secs, bool report_failures);

public:
	// Safety net only (frees stages that are not running and rings no thread can
	// touch; NEVER joins). Every regular path consumes the pipeline via
	// finish()/abort() first, so this is a no-op there; _exit() paths skip
	// destructors entirely.
	virtual ~PipeOperation();
	PipeOperation(const PipeOperation&) = delete;
	PipeOperation& operator=(const PipeOperation&) = delete;

	virtual int setup() = 0;

	// Success close: let the stage threads end naturally via EOF (NO poison),
	// a stage rc cascades onto the return code. timeout_secs > 0 bounds each join
	// (backup close 120 s, restore close 10 s), <= 0 blocks. Named analogue of
	// ZstdStream::finish().
	int  finish(int timeout_secs);
	// Error/cancel close: poison the rings + join (stage status irrelevant).
	// Named analogue of ZstdStream::abort().
	void abort(int timeout_secs);
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

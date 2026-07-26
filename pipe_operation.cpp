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
// Per-archive stage pipeline — definitions. See pipe_operation.hpp.
//
// The stages run as in-process THREADS (spawn_*_stage). The pipeline OWNS its
// lifecycle: the stage/ring handles are members, join_stages() (below) is the
// single teardown funnel behind the named intents finish()/abort()/abort_setup();
// the destructor is a pure safety net.
// ---------------------------------------------------------------------------

#include "pipe_operation.hpp"

extern "C" {
	#include "libtar/libtar.h"
}
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <string>

#include "twrpTar.hpp"          // class twrpTar (full def + friend), Archive_Type constants
#include "stage_engine.hpp"     // StageThread, EngineStage, stage_thread_start (in-process stages)
#include "stage_ring.h"         // StageRing (SPSC stage transport) + stage_io_from_ring
#include "tw_bssl_aes/baes_format.h"   // BAES_CIPHER_AES_256_GCM (aead_cipher_id default)
#include "twrp_affinity.hpp"    // tw_affinity::core_slice, *_cores
#include "twcommon.h"           // LOGINFO / LOGERR
#include <new>                  // std::nothrow (StageThread heap alloc)
#include "adbbu/twadbstream.h"  // TW_ADB_BACKUP / TW_ADB_RESTORE (FIFO paths)
#include "gui/gui.hpp"          // gui_msg / gui_err / Msg / msg::kError
#include "data.hpp"             // DataManager::GetIntValue (reads tw_zstd_level on the worker main thread)

using namespace std;

// --- In-process stage transport: SPSC rings (stage_ring.h) -------------------

// Ring capacity (1 MiB, power of two; create() rounds up anyway). One ring per
// stage boundary (tar<->stage, stage<->stage); the file ends (input_fd/output_fd)
// stay real fds.
static constexpr size_t STAGE_RING_CAP = 1u << 20;

// tartype_t for ring-backed tar boundaries. The handle is a pseudo-fd from
// the stage_engine registry (stage_ring_fd_register); the callbacks map it back
// to the StageRing. openfunc is a fail stub -- ring handles attach exclusively
// via tar_fdopen, never tar_open.
static tartype_t ring_tar_type = { stage_ring_tar_open_stub, stage_ring_tar_close,
                                   stage_ring_tar_read, stage_ring_tar_write };

// --- PipeOperation (base) --------------------------------------------------

// Stage list from the mode, ALWAYS in backup data direction (tar -> ... -> file).
void PipeOperation::build_stages() {
	n_stages_ = 0;
	switch (tw_.current_archive_type) {
		case COMPRESSED_ENCRYPTED:
			stages_[n_stages_++] = PipeStage::ZSTD;
			stages_[n_stages_++] = PipeStage::AES;
			break;
		case LEGACY_COMPRESSED:    // legacy gzip archives — one decompress stage, same slot as zstd
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

// Core SLICE per stage. AES is mode-dependent: COMPRESSED_ENCRYPTED ->
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

// Start the AES stage as an in-process THREAD. The password is copied into the
// StageThread and handed to the stage loop directly. The StageThread is
// heap-owned by aes_stage_ and lives until join_stages() joins + frees it — the
// pipeline object itself spans the whole segment cycle (twrpTar::pipeline_). See
// pipe_operation.hpp.
int PipeOperation::spawn_aes_stage(int in, int out, bool decrypt,
                                   StageRing* in_ring, StageRing* out_ring) {
	StageThread* st = new (std::nothrow) StageThread();
	if (!st) {
		LOGERR("spawn_aes_stage: out of memory\n");
		return -1;
	}
	st->kind     = EngineStage::AES;
	st->is_decode   = decrypt;
	st->password = tw_.password;
	// Encrypt: cipher from the resolved backup cipher (copied into the worker via
	// the pipe_tar list in createTarFork). Decrypt reads the cipher self-describing
	// from the stream header, so it is unused there. -1 (unresolved) -> GCM
	// default (defensive; the backup path always resolves it >= 0).
	st->aead_cipher_id = (uint16_t)(tw_.aead_cipher_id >= 0 ? tw_.aead_cipher_id : BAES_CIPHER_AES_256_GCM);
	st->pin_slice = core_for(PipeStage::AES);   // mode-dependent AES slice; self-guards BUILD_TWRPTAR_MAIN (returns {})
	st->in_fd  = in;                            // file end (input_fd/output_fd) or -1 when this side is a ring
	st->out_fd = out;
	st->in_ring  = in_ring;                     // ring backing per side (fd arg is -1 then)
	st->out_ring = out_ring;
	st->in  = in_ring  ? stage_io_from_ring(in_ring)  : stage_io_from_fd(&st->in_fd);
	st->out = out_ring ? stage_io_from_ring(out_ring) : stage_io_from_fd(&st->out_fd);
	aes_stage_ = st;
	if (stage_thread_start(st) != 0) {
		LOGERR("spawn_aes_stage: %s\n", st->errmsg);
		aes_stage_ = nullptr;
		delete st;
		return -1;
	}
	return 0;
}

// Start the zstd (or legacy-gzip) stage as an in-process THREAD. See
// pipe_operation.hpp. The StageThread is heap-owned by comp_stage_ until
// join_stages() joins + frees it.
int PipeOperation::spawn_zstd_stage(int in, int out, bool decompress,
                                    StageRing* in_ring, StageRing* out_ring) {
	StageThread* st = new (std::nothrow) StageThread();
	if (!st) {
		LOGERR("spawn_zstd_stage: out of memory\n");
		return -1;
	}
	// Legacy gzip (LEGACY_COMPRESSED restore) -> zlib inflate stage; every other
	// compress/decompress -> zstd. build_stages() maps both legacy and zstd to
	// PipeStage::ZSTD; the archive type discriminates the leaf loop here.
	bool is_gzip = (decompress && tw_.current_archive_type == LEGACY_COMPRESSED);
	st->kind   = is_gzip ? EngineStage::GZIP : EngineStage::ZSTD;
	st->is_decode = decompress;
	if (!decompress) {
		// Compress: level + nbWorkers from the compressor-thread budget. Read
		// DataManager HERE, on the worker main thread where setup() runs
		// single-threaded -- never from the stage thread.
#ifdef BUILD_TWRPTAR_MAIN
		st->level = 1;          // standalone twrpTar: fixed zstd level 1
		st->zstd_worker_count = 0;     // synchronous (single core)
#else
		int lev = DataManager::GetIntValue("tw_zstd_level");
		if (lev < 1 || lev > 19) lev = 1;
		st->level = lev;
		int t = tw_affinity::compute_compressor_threads(tw_affinity::active_pipes, (int)tw_.thread_id);
		st->zstd_worker_count = (t <= 1) ? 0 : t;   // ==1 -> compress synchronously in the stage thread (one thread fewer)
#endif
	}
	st->pin_slice = core_for(PipeStage::ZSTD);   // zstd core slice; self-guards BUILD_TWRPTAR_MAIN (returns {})
	st->in_fd  = in;                             // file end (input_fd/output_fd) or -1 when this side is a ring
	st->out_fd = out;
	st->in_ring  = in_ring;                      // ring backing per side (fd arg is -1 then)
	st->out_ring = out_ring;
	st->in  = in_ring  ? stage_io_from_ring(in_ring)  : stage_io_from_fd(&st->in_fd);
	st->out = out_ring ? stage_io_from_ring(out_ring) : stage_io_from_fd(&st->out_fd);
	comp_stage_ = st;
	if (stage_thread_start(st) != 0) {
		LOGERR("spawn_zstd_stage: %s\n", st->errmsg);
		comp_stage_ = nullptr;
		delete st;
		return -1;
	}
	return 0;
}

// Unified setup-error cleanup. The stage threads + rings are members; only the
// file fds live on tw_ (friend access). Order matters: gui_err -> join/poison the
// stages (the teardown funnel wakes any ring-blocked thread via fail(), joins + frees
// the rings and releases the tar-ring registry slot) -> close+unlink output
// (backup) -> close input (restore). join_stages is a no-op if no stage started.
int PipeOperation::abort_setup(const char* log_msg) {
	if (log_msg) LOGERR("%s\n", log_msg);
	gui_err(err_key_);
	join_stages(/*poison_first=*/true, /*timeout_secs=*/0, /*report_failures=*/false);
	if (tw_.output_fd >= 0) {
		close(tw_.output_fd);
		tw_.output_fd = -1;
		if (!tw_.tarfn.empty()) unlink(tw_.tarfn.c_str());
	}
	if (tw_.input_fd >= 0) { close(tw_.input_fd); tw_.input_fd = -1; }
	return -1;
}

// Single source of truth for the stage teardown. The two stages run as in-process
// THREADS (comp_stage_ = zstd/gzip, aes_stage_ = BAES) and are joined in fixed
// comp->aes order — the compression stage first in BOTH directions (on restore
// that is the tar-adjacent stage, not the file-adjacent one). poison_first=true (error/abort paths)
// fail() the rings FIRST so any ring-blocked thread wakes with -1 and the joins
// below return promptly instead of hitting their 10s timeout; normal finish
// (poison_first=false) relies on the EOF cascade that already ran. timeout_secs>0
// bounds each join (restore deadlock hardening), else it blocks. Returns -1 if
// report_failures && a stage rc != 0. Deliberately closes NO fds — the file ends
// belong to twrpTar (closed in finish_pipeline/abort_pipeline/abort_setup).
// Frees the pipeline-owned rings LAST, once no thread can touch them.
int PipeOperation::join_stages(bool poison_first, int timeout_secs, bool report_failures) {
	int rc = 0;
	bool comp_wedged = false, aes_wedged = false;   // ring-lifetime gates (join timeout)
	if (poison_first) {
		if (inter_ring_ != nullptr) inter_ring_->fail();
		if (tar_ring_ != nullptr)   tar_ring_->fail();   // also wake/poison the tar boundary
	}
	// zstd/gzip stage = comp_stage_, joined FIRST (comp->aes order). Its rc carries
	// truncation (run_zstd_decompress -1 on an incomplete frame) and any zlib/zstd
	// error. delete only after a successful join (never while a wedged thread still
	// references it).
	if (comp_stage_ != nullptr) {
		int jt = timeout_secs;
		if (poison_first && jt <= 0) jt = 10;
		int jrc = stage_thread_join(comp_stage_, jt);
		if (report_failures && jrc != 0) {
			// Report the leaf loop's reason ("truncated stream", a zlib/zstd error,
			// ...). Only on the success close: on an abort path the stage fails
			// because the rings were poisoned, so its message says nothing about the
			// original cause.
			// Best effort on the worker error paths: the worker writes its failure
			// sentinel BEFORE tearing the pipeline down, so the parent may answer
			// with SIGUSR2 (Signal_Kill -> _exit) while this teardown is still
			// running. The line then never gets printed. That ordering is
			// deliberate -- fast failure reporting outranks the diagnostic.
			LOGERR("join_stages: %s stage failed: %s\n",
			       (comp_stage_->kind == EngineStage::GZIP) ? "gzip" : "zstd",
			       comp_stage_->errmsg[0] ? comp_stage_->errmsg : "unknown error");
			rc = -1;
		}
		comp_wedged = comp_stage_->started;   // still true only on a join timeout
		if (!comp_stage_->started)
			delete comp_stage_;
		comp_stage_ = nullptr;
	}
	// AES stage = aes_stage_, joined in the same comp->aes order. Its rc carries the
	// decrypt failure signal: a truncated encrypted stream fails in
	// baes_stream_decrypt (-> jrc != 0 -> [RESTORE FAILED]) even when tar saw a
	// clean block-aligned EOF.
	if (aes_stage_ != nullptr) {
		// Normal close (poison_first=false): the thread already finished -- tar_close
		// (backup) / tar_extract_all (restore) drove the EOF cascade -- so the join
		// returns at once. timeout_secs: 120 s from closeTar, 10 s from
		// closeTarRestore. Abort (poison_first=true): the ring fail() above unblocks
		// a ring-waiting thread; a still-wedged thread is bounded by the timeout (the
		// worker _exit()s right after, killing it).
		int jt = timeout_secs;
		if (poison_first && jt <= 0) jt = 10;
		int jrc = stage_thread_join(aes_stage_, jt);
		if (report_failures && jrc != 0) {
			// Same rule as the comp stage above. This is where a truncated or
			// tampered encrypted stream reports WHY it failed.
			LOGERR("join_stages: AES stage failed: %s\n",
			       aes_stage_->errmsg[0] ? aes_stage_->errmsg : "unknown error");
			rc = -1;
		}
		// Free ONLY after a successful join: stage_thread_join clears started on join
		// and leaves it set on timeout. Deleting a still-running (wedged) thread would
		// be a use-after-free -- leak it instead (the imminent _exit reclaims it).
		aes_wedged = aes_stage_->started;
		if (!aes_stage_->started)
			delete aes_stage_;
		aes_stage_ = nullptr;
	}
	// The inter-stage ring is pipeline-owned; free it here (single teardown funnel:
	// finish / abort / abort_setup all route through this method) but ONLY when no
	// stage thread can still touch it. A wedged thread -> poison (wake anything
	// still blocked) + deliberate leak; every wedge path _exit()s the worker right
	// after (isolation boundary).
	if (inter_ring_ != nullptr) {
		if (!comp_wedged && !aes_wedged)
			delete inter_ring_;
		else
			inter_ring_->fail();   // wedged thread: wake anything still blocked
		inter_ring_ = nullptr;
	}
	// Same rule for the tar-boundary ring. The registry slot is released FIRST --
	// the tar side (worker MAIN thread) is past tar_close whenever the teardown funnel
	// runs, so libtar never touches the registry again (wedge included: the worker
	// _exit()s right after).
	if (tar_ring_ != nullptr) {
		if (tar_ring_pseudo_fd_ != 0) {
			stage_ring_fd_unregister(tar_ring_pseudo_fd_);
			tar_ring_pseudo_fd_ = 0;
		}
		if (!comp_wedged && !aes_wedged)
			delete tar_ring_;
		else
			tar_ring_->fail();     // wedged thread: wake anything still blocked
		tar_ring_ = nullptr;
	}
	return rc;
}

// Success close: let the stage threads end naturally via EOF (NO poison),
// report=true (a stage rc cascades onto the return code). timeout_secs bounds
// each join: 120 s from the backup close, 10 s from the restore close.
int PipeOperation::finish(int timeout_secs) {
	return join_stages(/*poison_first=*/false, timeout_secs, /*report_failures=*/true);
}

// Error/cancel close: poison the rings + join the stage threads (stage status
// irrelevant here -> report=false).
void PipeOperation::abort(int timeout_secs) {
	join_stages(/*poison_first=*/true, timeout_secs, /*report_failures=*/false);
}

// Safety net: join_stages normally joins + frees the stages/rings and every
// regular path consumes the pipeline via finish()/abort() before the unique_ptr
// resets. This runs with handles still set only on an unexpected path; free them
// ONLY if the thread already finished (started cleared by a prior join) -- never
// delete a still-running thread here (use-after-free). A leaked running thread
// dies with the process anyway. The rings follow the same rule -- free only if NO
// stage thread can still be running (computed BEFORE the stage deletes below
// clear the pointers).
PipeOperation::~PipeOperation() {
	bool comp_gone = (comp_stage_ == nullptr || !comp_stage_->started);
	bool aes_gone  = (aes_stage_  == nullptr || !aes_stage_->started);
	if (inter_ring_ != nullptr && comp_gone && aes_gone) {
		delete inter_ring_;
		inter_ring_ = nullptr;
	}
	// tar-boundary ring -- same rule; release the registry slot first.
	if (tar_ring_ != nullptr && comp_gone && aes_gone) {
		if (tar_ring_pseudo_fd_ != 0) {
			stage_ring_fd_unregister(tar_ring_pseudo_fd_);
			tar_ring_pseudo_fd_ = 0;
		}
		delete tar_ring_;
		tar_ring_ = nullptr;
	}
	if (comp_stage_ != nullptr && !comp_stage_->started) {
		delete comp_stage_;
		comp_stage_ = nullptr;
	}
	if (aes_stage_ != nullptr && !aes_stage_->started) {
		delete aes_stage_;
		aes_stage_ = nullptr;
	}
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
	build_stages();
	int stage_count = n_stages_;

	// Transport: tar<->S0 is a ring (tar_ring_), the S0<->S1 boundary
	// (stage_count==2 <=> COMPRESSED_ENCRYPTED) a second ring (inter_ring_); only
	// the file end (output_fd) is a real fd. stage_count is always >= 1 here (the
	// engine runs only for the compressed/encrypted modes; plain tar takes the
	// direct path in createTar()).
	if (open_output() < 0)
		return -1;
	tar_ring_ = StageRing::create(STAGE_RING_CAP);
	if (tar_ring_ == nullptr)
		return abort_setup("Error creating stage ring");
	if (stage_count == 2) {
		inter_ring_ = StageRing::create(STAGE_RING_CAP);
		if (inter_ring_ == nullptr)
			return abort_setup("Error creating stage ring");
	}
	LOGINFO("Pipeline transport: SPSC ring(s) -- tar boundary%s (%zu KB)\n",
	        (stage_count == 2) ? " + inter-stage" : "", STAGE_RING_CAP >> 10);

	// All stages run as in-process THREADS. Wiring FORWARD (tar -> S0 -> ... -> file):
	// stage 0 reads the tar ring (tar writes into it via the ring tartype), the
	// S0->S1 boundary (stage_count==2) is inter_ring_, and only the last stage's
	// out stays output_fd (a real fd). Every inter-stage/tar boundary is a
	// pipeline-owned ring; the stage thread only closes its side on finish, which
	// signals EOF to the neighbour.
	for (int i = 0; i < stage_count; ++i) {
		bool out_is_ring = (i < stage_count - 1);
		int out = out_is_ring ? -1 : tw_.output_fd;
		StageRing* in_ring  = (i == 0) ? tar_ring_ : inter_ring_;
		StageRing* out_ring = out_is_ring ? inter_ring_ : nullptr;
		int rc = (stages_[i] == PipeStage::ZSTD)
			? spawn_zstd_stage(-1, out, /*decompress=*/false, in_ring, out_ring)
			: spawn_aes_stage (-1, out, /*decrypt=*/false,    in_ring, out_ring);
		if (rc < 0)
			return abort_setup("pipeline stage setup failed");
	}

	// Hand libtar a NEGATIVE pseudo-fd + the ring tartype (write side -> tar_close
	// triggers close_write = the EOF cascade). On any failure below, abort_setup()
	// -> the teardown funnel poisons/frees the rings and releases the registry slot.
	long pseudo_fd = stage_ring_fd_register(tar_ring_, /*write_side=*/true);
	if (pseudo_fd == 0)
		return abort_setup("ring fd registry full");
	tar_ring_pseudo_fd_ = pseudo_fd;
	if (tar_fdopen(&tw_.t, (int)pseudo_fd, charRootDir, &ring_tar_type,
			O_CLOEXEC | O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
			TWTAR_FLAGS | (tw_.verbose_log ? TAR_TW_VERBOSE_LOG : 0)) != 0) {   // verbose log: found-fscrypt-policy (append.c)
		return abort_setup("tar_fdopen failed");
	}
	// Self-describing PAX g-headers (TWRP.backup_size/ext_app_data_size/ead)
	// BEFORE the first file — consolidated in twrpTar::write_global_headers
	// (friend access). is_plain_tar=false: no TWRP.tartype. The records pass through
	// zstd/AES; the restore reads them via in-process peek (BackupHeaderManager).
	if (tw_.write_global_headers(false) != 0) {
		// Tear down t/fd (tar_close drives close_write on the tar ring), then
		// abort_setup(): the teardown funnel poisons/frees the rings, releases the
		// registry slot, and closes+unlinks the output.
		tar_close(tw_.t);
		tw_.t = NULL;
		return abort_setup("write_global_headers failed");
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
	build_stages();
	int stage_count = n_stages_;

	// Transport mirrors BackupPipeline::setup. The tar-adjacent boundary
	// (S_last -> tar) is a ring (tar_ring_), the inter-stage boundary
	// (stage_count==2) a second ring (inter_ring_); only the file end (input_fd:
	// .win segment or ADB FIFO) is a real fd. stage_count is always >= 1 here.
	if (open_input() < 0)
		return -1;
	tar_ring_ = StageRing::create(STAGE_RING_CAP);
	if (tar_ring_ == nullptr)
		return abort_setup("Error creating stage ring");
	if (stage_count == 2) {
		inter_ring_ = StageRing::create(STAGE_RING_CAP);
		if (inter_ring_ == nullptr)
			return abort_setup("Error creating stage ring");
	}
	LOGINFO("Pipeline transport: SPSC ring(s) -- tar boundary%s (%zu KB)\n",
	        (stage_count == 2) ? " + inter-stage" : "", STAGE_RING_CAP >> 10);

	// All stages are in-process THREADS. Wiring BACKWARD (file -> ... -> tar): data
	// position j (0 = file-closest) maps to stages_[stage_count-1-j]. in = input_fd
	// (j==0, a file) else the inter-stage ring; out is always a ring: j<stage_count-1
	// -> inter-stage ring, the tar-adjacent last stage (j==stage_count-1) -> tar ring
	// (tar reads it via the ring tartype). Closing the output ring on finish signals
	// EOF downstream, which lets tar_extract_all in the worker main thread complete.
	for (int j = 0; j < stage_count; ++j) {
		PipeStage kind = stages_[stage_count - 1 - j];
		bool in_is_ring = (j != 0);
		int in = in_is_ring ? -1 : tw_.input_fd;
		StageRing* in_ring  = in_is_ring ? inter_ring_ : nullptr;
		StageRing* out_ring = (j == stage_count - 1) ? tar_ring_ : inter_ring_;
		int rc = (kind == PipeStage::ZSTD)
			? spawn_zstd_stage(in, -1, /*decompress=*/true, in_ring, out_ring)
			: spawn_aes_stage (in, -1, /*decrypt=*/true,    in_ring, out_ring);
		if (rc < 0)
			return abort_setup("pipeline stage setup failed");
	}

	// NEGATIVE pseudo-fd + ring tartype (read side -> readfunc pulls from the tar
	// ring; tar_close triggers close_read = EPIPE analogue upstream). Failure ->
	// abort_setup() -> teardown funnel poisons/frees rings + registry slot.
	long pseudo_fd = stage_ring_fd_register(tar_ring_, /*write_side=*/false);
	if (pseudo_fd == 0)
		return abort_setup("ring fd registry full");
	tar_ring_pseudo_fd_ = pseudo_fd;
	// Verbose log: TAR_TW_VERBOSE_LOG on the backup AND restore handle — gates the
	// libtar printf output (extract.c here; append.c found-fscrypt-policy on backup).
	// A dedicated bit, not TAR_VERBOSE.
	if (tar_fdopen(&tw_.t, (int)pseudo_fd, charRootDir, &ring_tar_type,
			O_CLOEXEC | O_RDONLY | O_LARGEFILE,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
			TWTAR_FLAGS | (tw_.verbose_log ? TAR_TW_VERBOSE_LOG : 0)) != 0) {
		return abort_setup("tar_fdopen failed");
	}
	return 0;
}

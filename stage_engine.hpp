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

/* ---------------------------------------------------------------------------
 * stage_engine.hpp -- in-process pipeline stage engine.
 *
 * Every pipeline stage runs as a THREAD (libzstd_twrp / BoringSSL / zlib) inside
 * one of the N worker PROCESSES. The worker processes carry the crash isolation:
 * a libzstd/BoringSSL crash kills only that worker, which the recovery main
 * process detects via SIGCHLD like any other worker death; cancel reaches the
 * workers via SIGUSR2.
 *
 * Layering (matches the PipeOperation design in pipe_operation.hpp):
 *   - leaf STAGE LOOPS run_zstd_* / run_baes_* / run_gzip_* -- pure compute over
 *     a StageIO in/out, NO gui/DataManager/LOGERR (thread context). Return 0/-1.
 *   - StageThread wraps one stage loop on its own pthread (self-pins to a core
 *     slice).
 *   - PipeOperation::join_stages() joins the stage threads in fixed comp->aes
 *     order via stage_thread_join. Every pipeline path uses a timed join (abort
 *     paths and the restore close 10 s, the backup close a 120 s anti-wedge net);
 *     only ZstdStream::finish joins blocking, on a plain file fd.
 * --------------------------------------------------------------------------- */

#ifndef __STAGE_ENGINE_HPP
#define __STAGE_ENGINE_HPP

#include <pthread.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "stage_io.h"                 // StageIO (self-guarded extern "C")
#include "tw_bssl_aes/baes_stream.h"  // baes_stream_* (self-guarded extern "C")

class StageRing;   // SPSC stage-transport ring (stage_ring.h) -- pointer-only here

// Stage kind (parallels PipeStage in pipe_operation.hpp; GZIP = legacy restore).
enum class EngineStage : uint8_t { ZSTD, AES, GZIP };

// "Do not announce a size" for run_zstd_compress(). The zstd frame header field
// Frame_Content_Size is OPTIONAL: writing it makes a stream self-describing (the
// decoder knows the payload size up front), omitting it is the normal streaming
// case. NOTE: 0 is a VALID announcement ("this stream holds exactly 0 bytes") and
// zstd ENFORCES whatever is announced -- so the "unknown" sentinel must be the
// dedicated -1 value, never 0. Mirrored from <zstd.h> ZSTD_CONTENTSIZE_UNKNOWN so
// includers of this header do not need the zstd headers (static_assert in
// stage_engine.cpp keeps both in lockstep).
//   image backup (/super dd) -> size known up front  -> pass Backup_Size
//   tar pipeline stage       -> size unknowable       -> leave at the default
static constexpr unsigned long long FRAME_CONTENT_SIZE_UNKNOWN = (unsigned long long)-1;

// ---------------------------------------------------------------------------
// Pseudo-fd registry for ring-backed TAR handles.
// libtar's tartype_t callbacks carry no context pointer -- their only handle is
// the int fd. Ring-backed tar boundaries therefore register their StageRing
// here and hand libtar a NEGATIVE pseudo-fd (TW_RING_FD_BASE - slot); the
// callbacks map it back. Single-threaded BY DESIGN: register/lookup/unregister
// all run on the worker MAIN thread (the libtar tar loop); stage threads hold
// their ring pointers directly and never touch the registry. Each worker
// PROCESS (fork) starts with an empty registry (COW) -- 4 slots cover the one
// active pipeline per worker, CLI included.
// ---------------------------------------------------------------------------
long stage_ring_fd_register(StageRing* r, bool write_side);   // pseudo-fd < 0, or 0 = registry full
void stage_ring_fd_unregister(long pseudo_fd);                // no-op for 0/unknown

extern "C" {
// tartype_t-compatible callbacks (libtar.h openfunc_t/closefunc_t/readfunc_t/
// writefunc_t). open is a fail stub (ring handles attach via tar_fdopen only).
// close: write side -> close_write (EOF cascade downstream); read side ->
// close_read (EPIPE analogue upstream). read/
// write map ring errors to errno=EIO -- a poisoned ring surfaces as an I/O
// error in libtar, never as a clean EOF.
int     stage_ring_tar_open_stub(const char* pathname, int oflags, ...);
int     stage_ring_tar_close(int fd);
ssize_t stage_ring_tar_read (int fd, void* buf, size_t n);
ssize_t stage_ring_tar_write(int fd, const void* buf, size_t n);
}

// ---------------------------------------------------------------------------
// Leaf stage loops. Each runs on a StageThread, reads from `in`, writes to
// `out`, returns 0 on success or -1 on error (errmsg, if non-NULL, gets a
// reason). NO gui/DataManager/LOGERR here -- the worker main thread collects the
// return code and reports it.
// ---------------------------------------------------------------------------
// zstd compress: level = zstd level; zstd_worker_count = ZSTD_c_nbWorkers (0 = the
// calling thread compresses synchronously; >0 = async workers, sized by the
// compute_compressor_threads budget). checksumFlag=1 (frame checksum on every
// stream). frame_content_size: announce the payload size in the frame header; the
// default omits the field, which is what every tar-pipeline stage needs (segment
// size is decided while writing).
int run_zstd_compress  (const StageIO* in, const StageIO* out, int level, int zstd_worker_count,
                        char* errmsg, size_t errlen,
                        unsigned long long frame_content_size = FRAME_CONTENT_SIZE_UNKNOWN);
int run_zstd_decompress(const StageIO* in, const StageIO* out, char* errmsg, size_t errlen);
// Legacy gzip restore via zlib inflate (windowBits 15+32 auto, multi-member).
// Used for the LEGACY_COMPRESSED restore path.
int run_gzip_decompress(const StageIO* in, const StageIO* out, char* errmsg, size_t errlen);
// BAES AES stage -- thin adapters over the shared baes_stream core.
int run_baes_encrypt   (const StageIO* in, const StageIO* out, const std::string& password,
                        uint16_t aead_cipher_id, char* errmsg, size_t errlen);
int run_baes_decrypt   (const StageIO* in, const StageIO* out, const std::string& password,
                        char* errmsg, size_t errlen);

// ---------------------------------------------------------------------------
// StageIO adapters for IN-MEMORY buffers.
//
// They let the very same leaf loops above run over memory instead of an fd or a
// ring -- so the small whole-buffer users (the persistent recovery log) need no
// second zstd implementation next to run_zstd_*. No thread and no ring involved:
// the caller drives the loop synchronously.
// ---------------------------------------------------------------------------
struct BufferSource {
	const char* data;        // remaining bytes to hand out
	size_t      remaining;
};
// ctx = BufferSource*: hands out up to `want` bytes; a short return means EOF
// (the StageIO read_full contract).
ssize_t stage_io_buffer_read_full(void* ctx, void* buf, size_t want);
// ctx = std::string*: appends everything written. Always succeeds (0) unless the
// allocation throws.
int     stage_io_string_write_all(void* ctx, const void* buf, size_t n);

static inline StageIO stage_io_from_buffer(BufferSource* src) {
	StageIO io;
	io.read_full = stage_io_buffer_read_full;
	io.write_all = nullptr;                 // source only
	io.ctx       = (void*)src;
	return io;
}
static inline StageIO stage_io_to_string(std::string* dst) {
	StageIO io;
	io.read_full = nullptr;                 // sink only
	io.write_all = stage_io_string_write_all;
	io.ctx       = (void*)dst;
	return io;
}

// ---------------------------------------------------------------------------
// One running stage as a thread. Fill the params, stage_thread_start(), later
// stage_thread_join().
// ---------------------------------------------------------------------------
struct StageThread {
	// --- params (set before start) ---
	EngineStage kind   = EngineStage::ZSTD;
	bool        is_decode = false;   // false = compress/encrypt, true = decompress/decrypt
	StageIO     in{};
	StageIO     out{};
	// fd backing for the in/out StageIO. The StageIO ctx points at THESE ints, so
	// they must live as long as the thread -> members, not spawner locals.
	int         in_fd  = -1;
	int         out_fd = -1;
	// Rolling-readahead context for a file-backed IN side (restore source
	// prefetch, stage_io.h). Wired by spawn_*_stage when it gets an in_ra_window
	// budget: `in` then points at THIS member (stage_io_from_fd_ra) instead of
	// &in_fd -- same lifetime rule as in_fd. window 0 = unused.
	StageIoFdRa in_ra{};
	// Ring backing per side (alternative to in_fd/out_fd; fd stays -1 then).
	// NON-owning: the ring belongs to whoever owns this StageThread --
	// PipeOperation::tar_ring_/inter_ring_ (freed by join_stages once BOTH stage
	// joins are through) or ZstdStream::ring_ (freed in its finish()/abort()). The
	// trampoline closes the ring side (close_write for out / close_read for in, OUT
	// first) and poisons the ring via fail() when the leaf rc < 0 -- so a failed
	// stage surfaces as -1 at its neighbour, never as a clean EOF. The file ends
	// (in_fd/out_fd) are NEVER closed by the thread; the owner closes them after
	// the join.
	StageRing*  in_ring  = nullptr;
	StageRing*  out_ring = nullptr;
	int         level      = 1;   // zstd compress level
	int         zstd_worker_count = 0;   // zstd ZSTD_c_nbWorkers
	// zstd compress only: announce the payload size in the frame header. Default =
	// omit (every tar-pipeline stage); the /super image stream passes its known size.
	unsigned long long frame_content_size = FRAME_CONTENT_SIZE_UNKNOWN;
	std::string password;         // AES
	uint16_t    aead_cipher_id = 0;   // AES encrypt cipher (BAES_CIPHER_*); mirrors twrpTar::aead_cipher_id
	std::vector<int> pin_slice;   // core slice; the thread self-pins (empty = no pin)

	// --- result (valid after join) ---
	int  rc = 0;                  // 0 ok, -1 error
	char errmsg[128] = {0};

	// --- internals ---
	pthread_t       tid = 0;
	bool            started = false;
	pthread_mutex_t done_mutex;
	pthread_cond_t  done_cond;    // CLOCK_MONOTONIC, initialized in start
	bool            done = false; // for the timed join
};

// Start the stage on its own pthread (self-pins to pin_slice). 0/-1.
int stage_thread_start(StageThread* st);

// Join one stage thread. timeout_secs<=0 = blocking pthread_join. timeout_secs>0
// = wait up to that long; on timeout log + return -1 WITHOUT joining. Do NOT
// pthread_cancel zstd/BSSL -- the wedged thread and its sync objects are leaked
// deliberately: on the pipeline paths the worker PROCESS is the isolation boundary
// and _exit()s right after, on the ZstdStream paths (long-lived recovery process)
// the leak is permanent but bounded. Returns the stage rc (0/-1). No-op if not
// started.
int stage_thread_join(StageThread* st, int timeout_secs);

// ---------------------------------------------------------------------------
// ZstdStream -- a single in-process zstd stream for the IMAGE (dd) paths.
//
// The caller keeps its own read/write loop (progress, cancel, hashing) and pushes
// the bytes through a StageRing that a StageThread compresses/decompresses.
// Deliberately NOT named *Pipe: in this codebase "pipe" means one of the 1-4
// parallel backup/restore workers.
//
//   compress:   caller --write_all()--> [ring] --> thread --> sink_fd (.win file)
//   decompress: source_fd --> thread --> [ring] --read_full()--> caller
//
// The fd is NOT owned (the caller opened it and closes it AFTER finish()/abort()
// -- the thread writes/reads it until then, so closing early would pull the fd out
// from under a live thread).
// ---------------------------------------------------------------------------
class ZstdStream {
public:
	ZstdStream() {}
	~ZstdStream();                    // safety net: abort() (idempotent)
	ZstdStream(const ZstdStream&) = delete;
	ZstdStream& operator=(const ZstdStream&) = delete;

	// Compress the bytes handed to write_all() into sink_fd. level/worker_count
	// come from the caller (GUI slider / thread budget -- kept out of here so this
	// class stays free of recovery-only APIs and compiles for the CLI too).
	// frame_content_size: see FRAME_CONTENT_SIZE_UNKNOWN.
	int start_compress(int sink_fd, int level, int worker_count,
	                   unsigned long long frame_content_size, const char* tag);
	// Decompress source_fd; the caller pulls plaintext via read_full().
	int start_decompress(int source_fd, const char* tag);

	int     write_all(const void* buf, size_t n);    // 0 = all written, -1 = stage gone/failed
	ssize_t read_full(void* buf, size_t want);       // want / short = EOF / -1 = error

	// Clean end: signal EOF (compress) and join the thread. Returns the stage rc
	// (0/-1), so a zstd error still fails the operation even when the caller's own
	// loop succeeded.
	int  finish(const char* tag);
	// Error/cancel end: poison the ring (wakes a thread blocked on it) + timed join.
	// Idempotent, safe after finish().
	void abort();

private:
	StageRing*   ring_  = nullptr;
	StageThread* stage_ = nullptr;
	bool         compressing_ = false;
};

#endif // __STAGE_ENGINE_HPP

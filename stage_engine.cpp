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
// stage_engine.cpp -- see stage_engine.hpp. Leaf stage loops (zstd via
// libzstd_twrp, BAES via baes_stream, gzip via zlib) + StageThread management.
//
// The leaf loops run the full libzstd_twrp compress/decompress path, zlib inflate
// (legacy gzip) and the BAES AEAD core in-process -- linked into both the recovery
// binary and twrpTar. The StageIO seam lets the same loop run over an fd (the file
// ends) or an SPSC ring (the stage boundaries).
// ---------------------------------------------------------------------------

#include "stage_engine.hpp"

#include <zstd.h>
#include <zlib.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <new>        // std::nothrow (ZstdStream heap allocs)

#include "twcommon.h"          // LOGINFO / LOGERR (LOGERR only from ZstdStream; a stage loop uses neither it nor gui_err)

#ifndef BUILD_TWRPTAR_MAIN
#include "twrp_affinity.hpp"   // tw_affinity::apply_core_list_pin (self-pin the stage thread)
#endif
#include "stage_ring.h"        // StageRing (create/read_full/write_all/close_*/fail) + stage_io_from_ring

// ---------------------------------------------------------------------------
// Pseudo-fd registry for ring-backed TAR handles (contract in
// stage_engine.hpp). Single-threaded per worker process (worker MAIN thread
// only -- libtar tar loop) -> plain statics, no atomics needed. Stage threads
// never touch this; they hold their StageRing pointers directly.
// ---------------------------------------------------------------------------
namespace {

constexpr long TW_RING_FD_BASE  = -4000;   // pseudo-fds: -4000, -4001, ...
constexpr int  TW_RING_FD_SLOTS = 4;

struct RingFdSlot { StageRing* ring; bool write_side; };
RingFdSlot g_ring_fd[TW_RING_FD_SLOTS] = {};

inline RingFdSlot* ring_fd_lookup(long fd) {
	long idx = TW_RING_FD_BASE - fd;       // -4000 -> 0, -4001 -> 1, ...
	if (idx < 0 || idx >= TW_RING_FD_SLOTS)
		return nullptr;
	return g_ring_fd[idx].ring != nullptr ? &g_ring_fd[idx] : nullptr;
}

}   // namespace

long stage_ring_fd_register(StageRing* r, bool write_side) {
	for (int i = 0; i < TW_RING_FD_SLOTS; ++i) {
		if (g_ring_fd[i].ring == nullptr) {
			g_ring_fd[i].ring = r;
			g_ring_fd[i].write_side = write_side;
			return TW_RING_FD_BASE - i;
		}
	}
	return 0;   // full -- caller aborts the setup
}

void stage_ring_fd_unregister(long pseudo_fd) {
	long idx = TW_RING_FD_BASE - pseudo_fd;
	if (idx >= 0 && idx < TW_RING_FD_SLOTS)
		g_ring_fd[idx] = RingFdSlot{};
}

extern "C" int stage_ring_tar_open_stub(const char* pathname __unused,
                                        int oflags __unused, ...) {
	errno = EINVAL;   // never called: ring handles attach via tar_fdopen only
	return -1;
}

extern "C" int stage_ring_tar_close(int fd) {
	RingFdSlot* s = ring_fd_lookup(fd);
	if (s == nullptr)
		return 0;   // already unregistered -- nothing left to signal
	if (s->write_side)
		s->ring->close_write();   // EOF cascade downstream
	else
		s->ring->close_read();    // EPIPE analogue upstream
	return 0;
}

extern "C" ssize_t stage_ring_tar_read(int fd, void* buf, size_t n) {
	RingFdSlot* s = ring_fd_lookup(fd);
	if (s == nullptr) { errno = EBADF; return -1; }
	ssize_t got = s->ring->read_full(buf, n);
	if (got < 0)
		errno = EIO;   // ring poisoned (stage failed) -- never a clean EOF
	return got;        // want = full read; short ONLY on real EOF (contract)
}

extern "C" ssize_t stage_ring_tar_write(int fd, const void* buf, size_t n) {
	RingFdSlot* s = ring_fd_lookup(fd);
	if (s == nullptr) { errno = EBADF; return -1; }
	if (s->ring->write_all(buf, n) != 0) {
		errno = EIO;   // reader gone (EPIPE analogue) or poisoned
		return -1;
	}
	return (ssize_t)n;
}

// --- error-message helpers (leaf loops report via return + string, never exit) ---
static void set_err(char* buf, size_t len, const char* msg) {
	if (buf && len) snprintf(buf, len, "%s", msg);
}
// The errno text is appended ONLY when errno is actually set. An I/O failure on a
// StageRing returns -1 without touching errno, so an unconditional strerror()
// would render as "Success" -- or, worse, as a stale errno from an unrelated
// syscall.
static void set_err_errno(char* buf, size_t len, const char* msg) {
	if (!buf || !len) return;
	int e = errno;
	if (e != 0)
		snprintf(buf, len, "%s: %s", msg, strerror(e));
	else
		snprintf(buf, len, "%s", msg);
}

// The sentinel in stage_engine.hpp is mirrored from <zstd.h> so that includers do
// not need the zstd headers -- keep both identical.
static_assert(FRAME_CONTENT_SIZE_UNKNOWN == (unsigned long long)ZSTD_CONTENTSIZE_UNKNOWN,
              "FRAME_CONTENT_SIZE_UNKNOWN must match ZSTD_CONTENTSIZE_UNKNOWN");

// ---------------------------------------------------------------------------
// zstd compress -- ZSTD_compressStream2, ZSTD_c_nbWorkers from the budget,
// checksumFlag=1. Produces standard zstd frames.
// frame_content_size announces the payload size in the frame header; zstd then
// ENFORCES it and errors out if the stream turns out shorter/longer -- an extra
// integrity net for the image paths that know their size. The default omits the
// field (streaming case, every tar stage).
// ---------------------------------------------------------------------------
int run_zstd_compress(const StageIO* in, const StageIO* out, int level, int zstd_worker_count,
                      char* errmsg, size_t errlen, unsigned long long frame_content_size) {
	size_t inCap  = ZSTD_CStreamInSize();
	size_t outCap = ZSTD_CStreamOutSize();
	unsigned char* inbuf  = (unsigned char*)malloc(inCap);
	unsigned char* outbuf = (unsigned char*)malloc(outCap);
	ZSTD_CCtx* c = ZSTD_createCCtx();
	int rc = -1;

	if (!inbuf || !outbuf || !c) { set_err(errmsg, errlen, "zstd compress: out of memory"); goto done; }
	ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, level);
	ZSTD_CCtx_setParameter(c, ZSTD_c_checksumFlag, 1);
	if (zstd_worker_count > 0)
		ZSTD_CCtx_setParameter(c, ZSTD_c_nbWorkers, zstd_worker_count);
	if (frame_content_size != FRAME_CONTENT_SIZE_UNKNOWN) {
		// Must be set BEFORE the first compress call (it lands in the frame header).
		size_t pr = ZSTD_CCtx_setPledgedSrcSize(c, (unsigned long long)frame_content_size);
		if (ZSTD_isError(pr)) { set_err(errmsg, errlen, ZSTD_getErrorName(pr)); goto done; }
	}

	for (;;) {
		ssize_t n = in->read_full(in->ctx, inbuf, inCap);
		if (n < 0) { set_err_errno(errmsg, errlen, "zstd compress: read failed"); goto done; }
		bool last = ((size_t)n < inCap);   // short read == EOF
		ZSTD_inBuffer input = { inbuf, (size_t)n, 0 };
		ZSTD_EndDirective mode = last ? ZSTD_e_end : ZSTD_e_continue;
		bool finished;
		do {
			ZSTD_outBuffer output = { outbuf, outCap, 0 };
			size_t rem = ZSTD_compressStream2(c, &output, &input, mode);
			if (ZSTD_isError(rem)) { set_err(errmsg, errlen, ZSTD_getErrorName(rem)); goto done; }
			if (output.pos > 0 && out->write_all(out->ctx, outbuf, output.pos) != 0) {
				set_err_errno(errmsg, errlen, "zstd compress: write failed"); goto done;
			}
			finished = last ? (rem == 0) : (input.pos == input.size);
		} while (!finished);
		if (last) break;
	}
	rc = 0;
done:
	if (c) ZSTD_freeCCtx(c);
	free(inbuf);
	free(outbuf);
	return rc;
}

// ---------------------------------------------------------------------------
// zstd decompress -- ZSTD_decompressStream, continues across concatenated frames
// until EOF.
// ---------------------------------------------------------------------------
int run_zstd_decompress(const StageIO* in, const StageIO* out, char* errmsg, size_t errlen) {
	size_t inCap  = ZSTD_DStreamInSize();
	size_t outCap = ZSTD_DStreamOutSize();
	unsigned char* inbuf  = (unsigned char*)malloc(inCap);
	unsigned char* outbuf = (unsigned char*)malloc(outCap);
	ZSTD_DCtx* d = ZSTD_createDCtx();
	int rc = -1;
	bool   frame_done = false;   // at least one full frame decoded
	size_t last_ret   = 1;       // last ZSTD_decompressStream return (0 = at a frame boundary)

	if (!inbuf || !outbuf || !d) { set_err(errmsg, errlen, "zstd decompress: out of memory"); goto done; }

	for (;;) {
		ssize_t n = in->read_full(in->ctx, inbuf, inCap);
		if (n < 0) { set_err_errno(errmsg, errlen, "zstd decompress: read failed"); goto done; }
		if (n == 0) break;   // EOF
		ZSTD_inBuffer input = { inbuf, (size_t)n, 0 };
		while (input.pos < input.size) {
			ZSTD_outBuffer output = { outbuf, outCap, 0 };
			size_t r = ZSTD_decompressStream(d, &output, &input);
			if (ZSTD_isError(r)) {
				// Bytes AFTER a complete frame (e.g. the ADB stream's 1 MB block
				// padding) are benign end-of-stream -- tar + the post-restore digest
				// are the real integrity guards. An error BEFORE any complete frame
				// is real corruption.
				if (frame_done) { rc = 0; goto done; }
				set_err(errmsg, errlen, ZSTD_getErrorName(r));
				goto done;
			}
			if (output.pos > 0 && out->write_all(out->ctx, outbuf, output.pos) != 0) {
				set_err_errno(errmsg, errlen, "zstd decompress: write failed"); goto done;
			}
			last_ret = r;
			if (r == 0) frame_done = true;   // frame boundary reached
		}
	}
	// Clean end only if the last frame completed. last_ret != 0 at EOF = the stream
	// ended mid-frame (truncated) -> fail (COMPRESSED_ENCRYPTED truncation is
	// already caught earlier by the AES layer).
	if (last_ret != 0) {
		set_err(errmsg, errlen, "zstd decompress: truncated stream (incomplete frame)");
		goto done;   // rc stays -1
	}
	rc = 0;
done:
	if (d) ZSTD_freeDCtx(d);
	free(inbuf);
	free(outbuf);
	return rc;
}

// ---------------------------------------------------------------------------
// legacy gzip decompress via zlib inflate (windowBits 15+32 = auto gzip/zlib
// header; multi-member via inflateReset). Used for the LEGACY_COMPRESSED restore
// path.
// ---------------------------------------------------------------------------
int run_gzip_decompress(const StageIO* in, const StageIO* out, char* errmsg, size_t errlen) {
	const size_t IN_CAP  = 128 * 1024;
	const size_t OUT_CAP = 128 * 1024;
	unsigned char* inbuf  = (unsigned char*)malloc(IN_CAP);
	unsigned char* outbuf = (unsigned char*)malloc(OUT_CAP);
	z_stream zs;
	memset(&zs, 0, sizeof(zs));
	int rc = -1;
	bool inited = false;
	// Truncation detector: true only between members (after init and after every
	// completed member). See the EOF check below.
	bool at_member_boundary = true;

	if (!inbuf || !outbuf) { set_err(errmsg, errlen, "gzip: out of memory"); goto done; }
	if (inflateInit2(&zs, 15 + 32) != Z_OK) { set_err(errmsg, errlen, "gzip: inflateInit2 failed"); goto done; }
	inited = true;

	for (;;) {
		ssize_t n = in->read_full(in->ctx, inbuf, IN_CAP);
		if (n < 0) { set_err_errno(errmsg, errlen, "gzip: read failed"); goto done; }
		if (n == 0) break;   // EOF
		zs.next_in  = inbuf;
		zs.avail_in = (uInt)n;
		while (zs.avail_in > 0) {
			zs.next_out  = outbuf;
			zs.avail_out = (uInt)OUT_CAP;
			int zr = inflate(&zs, Z_NO_FLUSH);
			if (zr != Z_OK && zr != Z_STREAM_END && zr != Z_BUF_ERROR) {
				set_err(errmsg, errlen, zs.msg ? zs.msg : "gzip: inflate error");
				goto done;
			}
			// Inside a member from here on: inflate has taken in bytes of a member
			// (Z_BUF_ERROR with no output = an incomplete header/member waiting for
			// more input, which is equally "not at a boundary").
			at_member_boundary = false;
			size_t have = OUT_CAP - zs.avail_out;
			if (have > 0 && out->write_all(out->ctx, outbuf, have) != 0) {
				set_err_errno(errmsg, errlen, "gzip: write failed"); goto done;
			}
			if (zr == Z_STREAM_END) {
				if (inflateReset(&zs) != Z_OK) { set_err(errmsg, errlen, "gzip: inflateReset failed"); goto done; }
				at_member_boundary = true;   // member complete -> a clean end is possible here
				continue;   // possible next concatenated member
			}
			if (zr == Z_BUF_ERROR && have == 0)
				break;   // needs more input -> read the next block
		}
	}
	// EOF is a clean end ONLY at a member boundary. A stream cut mid-member (or in
	// a partial gzip header) is truncated, and the tar layer cannot see it: a cut on
	// a 512-byte boundary looks like a regular archive end to th_read
	// (libtar/block.c), so this return code is the only carrier of the failure.
	if (!at_member_boundary) {
		set_err(errmsg, errlen, "gzip: truncated stream (incomplete member)");
		goto done;   // rc stays -1
	}
	rc = 0;
done:
	if (inited) inflateEnd(&zs);
	free(inbuf);
	free(outbuf);
	return rc;
}

// --- StageIO adapters for in-memory buffers (contract in stage_engine.hpp) ---
ssize_t stage_io_buffer_read_full(void* ctx, void* buf, size_t want) {
	BufferSource* src = (BufferSource*)ctx;
	size_t n = (want < src->remaining) ? want : src->remaining;
	if (n > 0) {
		memcpy(buf, src->data, n);
		src->data      += n;
		src->remaining -= n;
	}
	return (ssize_t)n;   // short/0 == EOF
}

int stage_io_string_write_all(void* ctx, const void* buf, size_t n) {
	((std::string*)ctx)->append((const char*)buf, n);
	return 0;
}

// --- BAES AES stage -- thin adapters over the shared baes_stream core ---
int run_baes_encrypt(const StageIO* in, const StageIO* out, const std::string& password,
                     uint16_t aead_cipher_id, char* errmsg, size_t errlen) {
	// baes_stream_* is the C format core (tw_bssl_aes/); its parameter is named
	// cipher_id -- unambiguous inside the BAES layer.
	return baes_stream_encrypt(in, out, password.c_str(), aead_cipher_id, errmsg, errlen);
}
int run_baes_decrypt(const StageIO* in, const StageIO* out, const std::string& password,
                     char* errmsg, size_t errlen) {
	return baes_stream_decrypt(in, out, password.c_str(), errmsg, errlen);
}

// ---------------------------------------------------------------------------
// StageThread management
// ---------------------------------------------------------------------------
static void* stage_thread_trampoline(void* arg) {
	StageThread* st = (StageThread*)arg;
#ifndef BUILD_TWRPTAR_MAIN
	// Called UNCONDITIONALLY, an empty slice included: an empty slice means "run
	// free on all cores", which apply_core_list_pin implements via
	// reset_to_default(). Skipping the call for an empty slice would leave the
	// stage thread with the CPU mask it inherited from the pinned worker process,
	// confining zstd/AES to the worker's cores.
	tw_affinity::apply_core_list_pin(st->pin_slice);   // tid=0 = self (this thread)
#endif
	int rc = 0;
	switch (st->kind) {
		case EngineStage::ZSTD:
			rc = st->is_decode
			   ? run_zstd_decompress(&st->in, &st->out, st->errmsg, sizeof(st->errmsg))
			   : run_zstd_compress(&st->in, &st->out, st->level, st->zstd_worker_count,
			                       st->errmsg, sizeof(st->errmsg), st->frame_content_size);
			break;
		case EngineStage::AES:
			rc = st->is_decode
			   ? run_baes_decrypt(&st->in, &st->out, st->password, st->errmsg, sizeof(st->errmsg))
			   : run_baes_encrypt(&st->in, &st->out, st->password, st->aead_cipher_id, st->errmsg, sizeof(st->errmsg));
			break;
		case EngineStage::GZIP:
			rc = run_gzip_decompress(&st->in, &st->out, st->errmsg, sizeof(st->errmsg));
			break;
	}
	st->rc = rc;
	// A FAILED stage poisons its ring sides BEFORE the EOF-closes below -- the
	// neighbour then reads/writes -1 (EPIPE analogue) instead of a clean EOF, so a
	// failure can never surface as a silent success.
	if (rc != 0) {
		if (st->out_ring) st->out_ring->fail();
		if (st->in_ring)  st->in_ring->fail();
	}
	// Close the RING ends this stage holds so the neighbours see EOF. OUT first --
	// for restore this signals the downstream decompressor/tar that decryption is
	// done, letting tar_extract_all in the worker main thread complete; that in turn
	// calls finish_pipeline -> PipeOperation::join_stages -> stage_thread_join. Must
	// happen BEFORE signalling done. The file ends (in_fd/out_fd) are closed by the
	// owner after the join, never here.
	if (st->out_ring) st->out_ring->close_write();
	if (st->in_ring) st->in_ring->close_read();
	pthread_mutex_lock(&st->done_mutex);
	st->done = true;
	pthread_cond_signal(&st->done_cond);
	pthread_mutex_unlock(&st->done_mutex);
	return nullptr;
}

int stage_thread_start(StageThread* st) {
	st->rc = 0;
	st->errmsg[0] = '\0';
	st->done = false;
	st->started = false;
	pthread_mutex_init(&st->done_mutex, nullptr);
	pthread_condattr_t ca;
	pthread_condattr_init(&ca);
	pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
	pthread_cond_init(&st->done_cond, &ca);
	pthread_condattr_destroy(&ca);
	// pthread_create RETURNS its error number and does NOT set errno (POSIX), so
	// the code has to come from the return value.
	int prc = pthread_create(&st->tid, nullptr, stage_thread_trampoline, st);
	if (prc != 0) {
		snprintf(st->errmsg, sizeof(st->errmsg), "pthread_create failed: %s", strerror(prc));
		pthread_cond_destroy(&st->done_cond);
		pthread_mutex_destroy(&st->done_mutex);
		return -1;
	}
	st->started = true;
	return 0;
}

int stage_thread_join(StageThread* st, int timeout_secs) {
	if (!st->started)
		return st->rc;
	if (timeout_secs <= 0) {
		pthread_join(st->tid, nullptr);
		st->started = false;
		pthread_cond_destroy(&st->done_cond);
		pthread_mutex_destroy(&st->done_mutex);
		return st->rc;
	}
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += timeout_secs;
	pthread_mutex_lock(&st->done_mutex);
	int wr = 0;
	while (!st->done && wr == 0)
		wr = pthread_cond_timedwait(&st->done_cond, &st->done_mutex, &ts);
	bool done = st->done;
	pthread_mutex_unlock(&st->done_mutex);
	if (done) {
		pthread_join(st->tid, nullptr);
		st->started = false;
		pthread_cond_destroy(&st->done_cond);
		pthread_mutex_destroy(&st->done_mutex);
		return st->rc;
	}
	// Timeout: wedged stage. Do NOT pthread_join (would block forever) or
	// pthread_cancel (unsafe inside zstd/BSSL) -- leak the thread + sync objects
	// deliberately. On the pipeline paths the worker PROCESS is the isolation
	// boundary and _exit()s right after; on the ZstdStream paths this runs in the
	// long-lived recovery process, where the leak is permanent but bounded.
	// LOGINFO, not LOGERR: this function is reached from the success close AND from
	// the abort/cancel paths and cannot tell them apart. The caller that can
	// (PipeOperation::join_stages, via report_failures) raises the error.
	LOGINFO("stage_thread_join: %s stage timed out after %ds -- thread abandoned\n",
	        st->kind == EngineStage::AES ? "AES" : (st->kind == EngineStage::GZIP ? "gzip" : "zstd"),
	        timeout_secs);
	return -1;
}

// ---------------------------------------------------------------------------
// ZstdStream (contract in stage_engine.hpp)
// ---------------------------------------------------------------------------

// Same capacity as a pipeline stage boundary; 1 MB is noise against the 4 MB
// image read block.
static constexpr size_t ZSTD_STREAM_RING_CAP = 1u << 20;

// Allocate ring + StageThread and wire them: the ring is this class's end, the fd
// argument (sink_fd here, source_fd in start_decompress) the stage's file end.
int ZstdStream::start_compress(int sink_fd, int level, int worker_count,
                               unsigned long long frame_content_size, const char* tag) {
	ring_ = StageRing::create(ZSTD_STREAM_RING_CAP);
	stage_ = ring_ ? new (std::nothrow) StageThread() : nullptr;
	if (!ring_ || !stage_) {
		LOGERR("%s: zstd stream setup failed (out of memory)\n", tag);
		abort();
		return -1;
	}
	stage_->kind      = EngineStage::ZSTD;
	stage_->is_decode = false;
	stage_->level     = level;
	stage_->zstd_worker_count  = worker_count;
	stage_->frame_content_size = frame_content_size;
	stage_->out_fd    = sink_fd;                       // NOT owned -- caller closes after finish/abort
	stage_->in_ring   = ring_;                         // thread pulls what write_all() pushes
	stage_->in        = stage_io_from_ring(ring_);
	stage_->out       = stage_io_from_fd(&stage_->out_fd);
	if (stage_thread_start(stage_) != 0) {
		LOGERR("%s: %s\n", tag, stage_->errmsg);
		abort();
		return -1;
	}
	compressing_ = true;
	return 0;
}

int ZstdStream::start_decompress(int source_fd, const char* tag) {
	ring_ = StageRing::create(ZSTD_STREAM_RING_CAP);
	stage_ = ring_ ? new (std::nothrow) StageThread() : nullptr;
	if (!ring_ || !stage_) {
		LOGERR("%s: zstd stream setup failed (out of memory)\n", tag);
		abort();
		return -1;
	}
	stage_->kind      = EngineStage::ZSTD;
	stage_->is_decode = true;
	stage_->in_fd     = source_fd;                     // NOT owned -- caller closes after finish/abort
	stage_->out_ring  = ring_;                         // thread pushes what read_full() pulls
	stage_->in        = stage_io_from_fd(&stage_->in_fd);
	stage_->out       = stage_io_from_ring(ring_);
	if (stage_thread_start(stage_) != 0) {
		LOGERR("%s: %s\n", tag, stage_->errmsg);
		abort();
		return -1;
	}
	compressing_ = false;
	return 0;
}

int ZstdStream::write_all(const void* buf, size_t n) {
	return ring_ ? ring_->write_all(buf, n) : -1;
}

ssize_t ZstdStream::read_full(void* buf, size_t want) {
	return ring_ ? ring_->read_full(buf, want) : -1;
}

int ZstdStream::finish(const char* tag) {
	// Compress: closing the write side is the EOF that makes the stage flush its
	// final frame. Decompress: the stage hit EOF on the source fd already; the
	// caller drained the ring, so just join.
	if (ring_ && compressing_)
		ring_->close_write();
	int rc = 0;
	if (stage_) {
		rc = stage_thread_join(stage_, /*timeout_secs=*/0);   // blocking join
		if (rc != 0)
			LOGERR("%s: zstd stage failed (%s)\n", tag, stage_->errmsg[0] ? stage_->errmsg : "unknown error");
		if (!stage_->started)          // join succeeded -> safe to free
			delete stage_;
		stage_ = nullptr;
	}
	delete ring_;                      // no thread left that could touch it
	ring_ = nullptr;
	return rc;
}

void ZstdStream::abort() {
	// Poison FIRST: fail() is the only thing that wakes a stage blocked on an empty
	// or full ring.
	if (ring_)
		ring_->fail();
	bool wedged = false;
	if (stage_) {
		stage_thread_join(stage_, /*timeout_secs=*/10);
		wedged = stage_->started;      // still set only on a join timeout
		if (!wedged)
			delete stage_;
		stage_ = nullptr;
	}
	if (ring_) {
		// Free only when no thread can still reference the ring. A wedged stage is
		// leaked deliberately (use-after-free would be worse); this runs in the
		// long-lived recovery process, so the leak is permanent -- acceptable
		// because the ring is poisoned and bounded (1 MB),
		// and the timed futex (100 ms) makes a real wedge practically unreachable.
		if (!wedged)
			delete ring_;
		ring_ = nullptr;
	}
	compressing_ = false;
}

ZstdStream::~ZstdStream() {
	abort();   // idempotent no-op after finish()
}

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
 * stage_ring.h -- in-process SPSC byte ring for one stage boundary.
 *
 * A lock-free single-producer/single-consumer ring in the worker's heap, used
 * for every boundary of the stage engine (tar<->stage and stage<->stage). The
 * two sides are threads of one process and share the address space, so the
 * buffer is plain heap memory -- no shm_open/mmap:
 *
 *   - head (producer-owned) / tail (consumer-owned) as monotonically increasing
 *     u64 counters on SEPARATE cache lines (no false sharing); index = ctr & mask.
 *   - spin-then-futex blocking: short bounded spin (SPIN_ITERS, yield), then a
 *     TIMED futex wait on a per-direction eventcount word. Wake-only-if-waiter:
 *     the hot path pays zero syscalls unless the peer actually sleeps.
 *   - The futex wait ALWAYS uses a 100 ms timeout + re-check loop. That degrades
 *     the classic lost-wakeup bug class from "hang" to "<=100 ms blip" -- a
 *     deliberate robustness-over-elegance decision for a recovery tool.
 *   - All ring atomics use the default seq_cst ordering. At 128 KB chunk
 *     granularity (~2k handoffs/s) the fence cost is noise; the win of this
 *     ring is syscall avoidance + no kernel copy, not relaxed-ordering tricks.
 *     seq_cst closes the store->load rendezvous window between "publish data /
 *     read eventcount" and "arm waiter / re-check data" cleanly.
 *
 * SEMANTIC CONTRACT (modelled on POSIX pipe semantics, never weaker -- see
 * stage_io.h for the read_full/write_all shape):
 *   write_all()  : 0 = all bytes written; -1 once the reader closed its end
 *                  (EPIPE analogue) or fail() was called.
 *   read_full()  : `want` = full read; 0..want-1 ONLY on real EOF (writer
 *                  closed AND ring drained); -1 after fail().
 *   close_write(): EOF signal to the consumer (analogue of closing a pipe's
 *                  write end).
 *   close_read() : consumer gone -> producer gets -1 (EPIPE analogue), wakes it.
 *   fail()       : poison both directions, wake both sides. Used by the stage
 *                  trampoline on rc<0 and by the pipeline teardown. A failed
 *                  stage thus surfaces as -1 at the neighbour, NEVER as a clean
 *                  EOF. The REASON is not kept here — the stage's own errmsg is
 *                  the authoritative text and is logged by
 *                  PipeOperation::join_stages / ZstdStream::finish.
 *
 * Threading: exactly ONE producer thread and ONE consumer thread on the data
 * path (SPSC). close_write/close_read/fail() may additionally be called from the
 * worker MAIN thread (pipeline teardown) -- those control paths use a CAS kick +
 * unconditional wake and are multi-writer-safe. NO logging in here (stage-thread
 * context: no gui/DataManager/LOGERR by design); errors travel via return codes
 * ONLY -- never via errno. The ring clears errno on its failure returns and
 * preserves it across its internal futex calls, so a caller that renders
 * strerror(errno) next to a ring error cannot pick up unrelated noise.
 *
 * Dual-compiled: used by recovery AND twrpTar/twrpTar_static (CLI) -- keep this
 * header free of recovery-only includes (plain libc/pthread/atomics only).
 * --------------------------------------------------------------------------- */

#ifndef TW_STAGE_RING_H
#define TW_STAGE_RING_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>   /* ssize_t */

#ifdef __cplusplus

#include <atomic>

class StageRing {
public:
	/* Factory (nothrow). cap is rounded UP to a power of two (mask indexing).
	 * Returns nullptr on allocation failure -- caller aborts the setup. */
	static StageRing* create(size_t cap_bytes);
	~StageRing();

	/* --- producer side (exactly one thread) --- */
	int  write_all(const void* p, size_t n);   /* 0 | -1 (rclosed/failed) */
	void close_write();                        /* EOF to the consumer */

	/* --- consumer side (exactly one thread) --- */
	ssize_t read_full(void* p, size_t want);   /* want | 0..want-1 EOF | -1 */
	void close_read();                         /* EPIPE analogue to the producer */

	/* --- control (any thread; pipeline teardown paths) --- */
	void fail();

private:
	StageRing() {}
	StageRing(const StageRing&) = delete;
	StageRing& operator=(const StageRing&) = delete;

	void wait_for_data(uint64_t tail_now);
	void wait_for_space(uint64_t head_now);

	/* Line 0: read-mostly after create(). */
	uint8_t* buf_ = nullptr;
	size_t   cap_ = 0;               /* power of two */

	/* Line 1: producer-owned hot state. tail_cache_ avoids touching the
	 * consumer's line until the ring LOOKS full. */
	alignas(64) std::atomic<uint64_t> head_{0};
	uint64_t tail_cache_ = 0;

	/* Line 2: consumer-owned hot state (mirror). */
	alignas(64) std::atomic<uint64_t> tail_{0};
	uint64_t head_cache_ = 0;

	/* Line 3: eventcounts + flags (cold-ish control words).
	 * data_eventcount_  : producer signals "data available"  -> consumer waits here.
	 * space_eventcount_ : consumer signals "space available" -> producer waits here.
	 * Bit31 = WAITER flag, bits 0..30 = sequence (see stage_ring.cpp). */
	alignas(64) std::atomic<uint32_t> data_eventcount_{0};
	std::atomic<uint32_t> space_eventcount_{0};
	std::atomic<uint32_t> wclosed_{0};
	std::atomic<uint32_t> rclosed_{0};
	std::atomic<uint32_t> failed_{0};
};

extern "C" {
#endif /* __cplusplus */

/* StageIO-compatible callbacks (see stage_io.h): ctx = StageRing*. Wired by
 * stage_io_from_ring() below; the C stage cores (baes_stream.c) only ever see
 * the StageIO function pointers -- they never include this header. */
ssize_t stage_ring_io_read_full(void* ctx, void* buf, size_t want);
int     stage_ring_io_write_all(void* ctx, const void* buf, size_t n);

#ifdef __cplusplus
}   /* extern "C" */

#include "stage_io.h"

/* Ring-backed StageIO. The ring is NON-owned (the pipeline owns it via
 * PipeOperation::inter_ring_/tar_ring_); both directions are wired, a stage only
 * uses its relevant side (input stages read_full, output stages write_all). */
static inline StageIO stage_io_from_ring(StageRing* r) {
	StageIO io;
	io.read_full = stage_ring_io_read_full;
	io.write_all = stage_ring_io_write_all;
	io.ctx       = (void*)r;
	return io;
}

#endif /* __cplusplus */

#endif /* TW_STAGE_RING_H */

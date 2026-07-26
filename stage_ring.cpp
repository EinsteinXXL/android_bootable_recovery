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
 * stage_ring.cpp -- SPSC ring implementation (design notes in stage_ring.h).
 *
 * Eventcount protocol (per direction, word layout: bit31 WAITER, 30..0 seq):
 *
 *   waiter (blocking side)                signaller (hot path, single writer)
 *   ----------------------                -----------------------------------
 *   spin SPIN_ITERS on cond               publish (head/tail store, seq_cst)
 *   e = ec.fetch_or(WAITER) | WAITER      e = ec.load()
 *   re-check cond -> return if satisfied  if (e & WAITER):
 *   futex_wait(ec, e, 100 ms)                 ec.store((e+1) & ~WAITER)
 *   loop (caller re-checks)                   futex_wake(ec, ALL)
 *
 * Why this cannot hang:
 *   - The waiter re-checks the condition AFTER arming WAITER. seq_cst on both
 *     the publish store and the fetch_or/re-check loads forbids the classic
 *     store->load reordering miss on both sides.
 *   - If the signaller's clear+wake races the waiter's futex_wait, the word no
 *     longer equals `e` -> futex_wait returns EAGAIN immediately.
 *   - Control paths (close_write/close_read/fail from a THIRD thread, pipeline
 *     teardown) use a CAS kick + UNCONDITIONAL wake (multi-writer-safe, no
 *     reliance on WAITER).
 *   - Belt and braces: every futex_wait carries a 100 ms timeout + re-check
 *     loop -- any residual missed wake costs at most one timeout tick, never a
 *     wedge. (The stage-thread join timeout + worker _exit is the outer
 *     isolation boundary.)
 *
 * NO logging in this file (stage-thread context; by design stage code never
 * touches gui/DataManager/LOGERR). Errors travel via return codes.
 * --------------------------------------------------------------------------- */

#include "stage_ring.h"

#include <errno.h>        /* errno save/restore around the futex syscalls */
#include <limits.h>       /* INT_MAX (futex wake-all) */
#include <linux/futex.h>  /* FUTEX_WAIT_PRIVATE / FUTEX_WAKE_PRIVATE */
#include <new>            /* std::nothrow */
#include <stdlib.h>       /* malloc/free */
#include <string.h>       /* memcpy */
#include <sys/syscall.h>  /* SYS_futex (bionic has no libc wrapper) */
#include <time.h>         /* struct timespec (relative futex timeout) */
#include <unistd.h>       /* syscall */

namespace {

constexpr uint32_t EVENTCOUNT_WAITER = 0x80000000u;

/* Spin budget before sleeping. Bounded iteration count (no clock syscall in
 * the hot path); on the A55/A76 this is on the order of a few microseconds.
 * Kept SMALL on purpose: the pipeline stages idle a lot (storage-bound), and
 * burned spin cycles are heat, not throughput. */
constexpr int SPIN_ITERS = 2048;

/* Futex wait timeout. Self-healing ceiling for any missed wake. */
constexpr int FUTEX_TIMEOUT_MS = 100;

static_assert(sizeof(std::atomic<uint32_t>) == sizeof(uint32_t),
              "futex word must be exactly 4 bytes");

inline void cpu_relax() {
#if defined(__aarch64__) || defined(__arm__)
	__asm__ __volatile__("yield" ::: "memory");
#else
	__asm__ __volatile__("" ::: "memory");
#endif
}

/* std::atomic<uint32_t> is layout-compatible with uint32_t (static_assert
 * above + is_always_lock_free on arm/arm64) -- standard practice for futex
 * words in C++ without C++20 atomic_wait. */
/* EAGAIN (word changed), ETIMEDOUT (the timeout tick below), EINTR and a genuine
 * wake are all identical for us -- the caller loops and re-checks its condition.
 * errno is therefore saved and restored around both syscalls: the ring reports
 * failure EXCLUSIVELY through return values, so an errno left behind here is not
 * a cause but noise. Without this it leaks into the stage's error text and gets
 * reported as the reason for an unrelated I/O failure ("read failed: Try again"
 * from a futex EAGAIN). */
inline void futex_wait_ms(std::atomic<uint32_t>* a, uint32_t expect, int ms) {
	int saved = errno;
	struct timespec ts;
	ts.tv_sec  = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	syscall(SYS_futex, reinterpret_cast<uint32_t*>(a),
	        FUTEX_WAIT_PRIVATE, expect, &ts, nullptr, 0);
	errno = saved;
}

inline void futex_wake_all(std::atomic<uint32_t>* a) {
	int saved = errno;
	syscall(SYS_futex, reinterpret_cast<uint32_t*>(a),
	        FUTEX_WAKE_PRIVATE, INT_MAX, nullptr, nullptr, 0);
	errno = saved;
}

/* Hot-path signal: single writer per direction (producer->data_eventcount_,
 * consumer->space_eventcount_). Zero cost (one relaxed-ish load) when nobody waits. */
inline void eventcount_signal(std::atomic<uint32_t>& eventcount) {
	uint32_t e = eventcount.load();
	if (e & EVENTCOUNT_WAITER) {
		eventcount.store((e + 1) & ~EVENTCOUNT_WAITER);
		futex_wake_all(&eventcount);
	}
}

/* Control-path signal (close_write/close_read/fail; may run on the worker MAIN thread while
 * the data threads live): CAS (multi-writer-safe against the hot-path store)
 * + UNCONDITIONAL wake. The flag the caller set right before is seq_cst, so a
 * woken (or EAGAIN-bounced, or timing-out) waiter re-checks and sees it. */
inline void eventcount_wake(std::atomic<uint32_t>& eventcount) {
	uint32_t e = eventcount.load();
	while (!eventcount.compare_exchange_weak(e, (e + 1) & ~EVENTCOUNT_WAITER)) {
	}
	futex_wake_all(&eventcount);
}

}   // namespace

// --- lifecycle --------------------------------------------------------------

/* Upper bound for the power-of-two round-up below: without it a cap_bytes above
 * SIZE_MAX/2 would shift the counter to 0 (endless loop / malloc(0)). Every call
 * site passes a 1 MiB constant, so this is a closed door, not a live limit. */
static constexpr size_t MAX_RING_CAP = (size_t)64 << 20;

StageRing* StageRing::create(size_t cap_bytes) {
	if (cap_bytes == 0 || cap_bytes > MAX_RING_CAP)
		return nullptr;               /* caller aborts the setup */
	size_t c = 1;
	while (c < cap_bytes)
		c <<= 1;                      /* round up to power of two (mask indexing) */
	StageRing* r = new (std::nothrow) StageRing();
	if (r == nullptr)
		return nullptr;
	r->buf_ = (uint8_t*)malloc(c);
	if (r->buf_ == nullptr) {
		delete r;
		return nullptr;
	}
	r->cap_ = c;
	return r;
}

StageRing::~StageRing() {
	free(buf_);
	buf_ = nullptr;
}

// --- blocking helpers (spin -> timed futex) ----------------------------------

void StageRing::wait_for_data(uint64_t tail_now) {
	for (int i = 0; i < SPIN_ITERS; ++i) {
		if (head_.load() != tail_now)
			return;
		if (wclosed_.load() || failed_.load())
			return;
		cpu_relax();
	}
	uint32_t e = data_eventcount_.fetch_or(EVENTCOUNT_WAITER) | EVENTCOUNT_WAITER;
	/* Decisive re-check AFTER arming the waiter bit (see file header). */
	if (head_.load() != tail_now || wclosed_.load() || failed_.load())
		return;
	futex_wait_ms(&data_eventcount_, e, FUTEX_TIMEOUT_MS);
}

void StageRing::wait_for_space(uint64_t head_now) {
	for (int i = 0; i < SPIN_ITERS; ++i) {
		if (tail_.load() + cap_ != head_now)   /* some space appeared */
			return;
		if (rclosed_.load() || failed_.load())
			return;
		cpu_relax();
	}
	uint32_t e = space_eventcount_.fetch_or(EVENTCOUNT_WAITER) | EVENTCOUNT_WAITER;
	if (tail_.load() + cap_ != head_now || rclosed_.load() || failed_.load())
		return;
	futex_wait_ms(&space_eventcount_, e, FUTEX_TIMEOUT_MS);
}

// --- producer ----------------------------------------------------------------

int StageRing::write_all(const void* p, size_t n) {
	const uint8_t* src = (const uint8_t*)p;
	while (n > 0) {
		/* errno is cleared on the failure returns: the contract is "failure via
		 * the return value only", and a stale errno from any earlier syscall
		 * would otherwise be appended to the stage's error text as if it were
		 * the cause. */
		if (failed_.load()) {
			errno = 0;
			return -1;
		}
		if (rclosed_.load()) {
			errno = 0;
			return -1;               /* EPIPE analogue: reader is gone */
		}
		uint64_t h = head_.load();
		size_t free_b = cap_ - (size_t)(h - tail_cache_);
		if (free_b == 0) {
			tail_cache_ = tail_.load();
			free_b = cap_ - (size_t)(h - tail_cache_);
			if (free_b == 0) {
				wait_for_space(h);
				continue;            /* re-check flags + space */
			}
		}
		size_t chunk = (n < free_b) ? n : free_b;
		size_t idx   = (size_t)(h & (cap_ - 1));
		size_t first = cap_ - idx;
		if (first > chunk)
			first = chunk;
		memcpy(buf_ + idx, src, first);
		if (chunk > first)
			memcpy(buf_, src + first, chunk - first);   /* wrap: second part */
		head_.store(h + chunk);      /* seq_cst publish (data memcpy'd above) */
		eventcount_signal(data_eventcount_);
		src += chunk;
		n   -= chunk;
	}
	return 0;
}

void StageRing::close_write() {
	wclosed_.store(1);
	eventcount_wake(data_eventcount_);               /* wake a drained-and-waiting consumer -> EOF */
}

// --- consumer ----------------------------------------------------------------

ssize_t StageRing::read_full(void* p, size_t want) {
	uint8_t* dst = (uint8_t*)p;
	size_t   got = 0;
	while (got < want) {
		if (failed_.load()) {
			errno = 0;               /* see write_all(): failure via return value only */
			return -1;
		}
		uint64_t t = tail_.load();
		size_t avail = (size_t)(head_cache_ - t);
		if (avail == 0) {
			head_cache_ = head_.load();
			avail = (size_t)(head_cache_ - t);
			if (avail == 0) {
				if (wclosed_.load()) {
					/* Writer closed AND ring drained = real EOF. Contract from
					 * stage_io.h: a short count ONLY here. */
					return (ssize_t)got;
				}
				wait_for_data(t);
				continue;
			}
		}
		size_t chunk = ((want - got) < avail) ? (want - got) : avail;
		size_t idx   = (size_t)(t & (cap_ - 1));
		size_t first = cap_ - idx;
		if (first > chunk)
			first = chunk;
		memcpy(dst + got, buf_ + idx, first);
		if (chunk > first)
			memcpy(dst + got + first, buf_, chunk - first);
		tail_.store(t + chunk);
		eventcount_signal(space_eventcount_);
		got += chunk;
	}
	return (ssize_t)got;
}

void StageRing::close_read() {
	rclosed_.store(1);
	eventcount_wake(space_eventcount_);              /* wake a full-and-waiting producer -> -1 */
}

// --- control -----------------------------------------------------------------

void StageRing::fail() {
	failed_.store(1);
	eventcount_wake(data_eventcount_);
	eventcount_wake(space_eventcount_);
}

// --- StageIO glue (C linkage; ctx = StageRing*) -------------------------------

extern "C" ssize_t stage_ring_io_read_full(void* ctx, void* buf, size_t want) {
	return ((StageRing*)ctx)->read_full(buf, want);
}

extern "C" int stage_ring_io_write_all(void* ctx, const void* buf, size_t n) {
	return ((StageRing*)ctx)->write_all(buf, n);
}

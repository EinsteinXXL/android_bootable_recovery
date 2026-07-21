
/*
	Copyright 2013 to 2020 TeamWin
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

extern "C" {
	#include "libtar/libtar.h"
	#include "twrpTar.h"
	#include "tarWrite.h"
}
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <glob.h>
#include <fcntl.h>
#include <stdlib.h>             /* setenv/getenv — Cipher-Force-Knob -> Filter-Env */
#include <strings.h>            /* strcasecmp — force-knob values */
#include <cutils/properties.h>  /* property_get — twrp.force_aead Force-Knob */
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <csignal>
#include <dirent.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <sys/prctl.h>
#include <zlib.h>
#include <semaphore.h>
#include <time.h>
#include "twrpTar.hpp"
#include "pipe_operation.hpp"
#include "twrp_affinity.hpp"
#include "twcommon.h"
#include "variables.h"
#include "tw_bssl_aes/baes_format.h"   // BAES-Wire-Format-Konstanten (gemeinsame SSoT)
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES	(1 << 3)
#endif
#include <sys/resource.h>
#include <sys/syscall.h>
#include "adbbu/libtwadbbu.hpp"
#include "twrp-functions.hpp"
#include "backupheadermanager.hpp"   // GetFileType()/Load()/getters instead of free TWFunc detection
#include "gui/gui.hpp"
#include <chrono>
#include <random>
#include <new>              // placement-new for SegmentClaim (restore work queue)
#include <algorithm>
#include <unordered_map>
#include "progresstracking.hpp"

#ifndef BUILD_TWRPTAR_MAIN
#include "data.hpp"
#include "infomanager.hpp"
#include "set_metadata.h"
#endif //ndef BUILD_TWRPTAR_MAIN

#ifdef TW_INCLUDE_FBE
#ifdef USE_FSCRYPT
#include "fscrypt_policy.h"
#endif
#endif

// TWTAR_FLAGS moved to pipe_operation.hpp (shared by twrpTar.cpp and
// pipe_operation.cpp; pipe_operation.hpp is included above).

using namespace std;

// ---------------------------------------------------------------------------
// File-local constants. CPU affinity constants live in tw_affinity (via
// BoardConfig flags). Only topology-independent values remain here.
// ---------------------------------------------------------------------------
namespace {
	constexpr int PIPE_SIZE_BYTES = 262144;   // 256 KB per pipe (F_SETPIPE_SZ)
	// Array dimension for pipe-related data structures. The real pipe count per
	// backup/restore run comes from tw_affinity::compute_pipe_count().
	constexpr int MAX_PIPELINES = tw_affinity::MAX_PIPELINES_HARDCAP;
}

// ---------------------------------------------------------------------------
// File-local helper: bundled data-pipe setup. pipe2(O_CLOEXEC) + F_SETPIPE_SZ
// on both ends. Returns 0=ok, -1=error. F_SETPIPE_SZ is best-effort; failures
// are logged but not escalated, because the default pipe buffer (64 KB) is
// suboptimal but functional.
// ---------------------------------------------------------------------------
int make_data_pipe(int p[2]) {
	if (pipe2(p, O_CLOEXEC) < 0)
		return -1;
	if (fcntl(p[0], F_SETPIPE_SZ, PIPE_SIZE_BYTES) < 0)
		LOGINFO("Warning: F_SETPIPE_SZ %d failed on read end: %s\n", PIPE_SIZE_BYTES, strerror(errno));
	if (fcntl(p[1], F_SETPIPE_SZ, PIPE_SIZE_BYTES) < 0)
		LOGINFO("Warning: F_SETPIPE_SZ %d failed on write end: %s\n", PIPE_SIZE_BYTES, strerror(errno));
	return 0;
}

// ---------------------------------------------------------------------------
// Tier-2 cleanup consolidation. The createTar() setup-error cleanup moved to
// PipeOperation::abort() (pipe_operation.cpp) — the pipeline owns its pipes_,
// and the reap/fd/unlink part uses the private reap_subchildren + the tw_ fds
// via friend. The close-stage cleanups (finish_pipeline/abort_pipeline) are
// further down next to reap_subchildren.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PipeChildRegistry — single source of truth for the SIGUSR2 broadcast
// mechanics (cancel path). Cross-thread visibility via std::atomic.
//
// Two separate file-static instances keep backup and restore pipe children
// STRICTLY separated — a shared slot vector would let a cancel during a backup
// accidentally hit restore children (or vice versa after a phase change
// without reset()). kill_tag_ flows into the LOGINFO output so recovery.log
// distinguishes the two paths ("Killing child" vs "Killing restore child").
//
// Publish order in add(): pid first, then count — the cancel path must never
// see a set count_ without the corresponding pids_ entry (J2 race fix).
// ---------------------------------------------------------------------------
namespace {
class PipeChildRegistry {
	std::atomic<pid_t> pids_[MAX_PIPELINES];
	std::atomic<int>   count_{0};
	// Cancel-vs-crash disambiguation for the SIGCHLD crash-detect loop.
	// kill_all_usr2() sets the flag — the parent SIGCHLD branch then suppresses
	// the "abnormal exit" abort, because a cancel terminates all workers anyway.
	// Without it the cancel path would detect itself as a crash (a worker
	// exit(0) is normal, but sub-child signals from kill_all_usr2 can pass a
	// NON-zero status through).
	std::atomic<bool>  cancel_in_flight_{false};
	const char*        kill_tag_;
public:
	explicit PipeChildRegistry(const char* kill_tag) noexcept
		: kill_tag_(kill_tag) { reset(); }

	void reset() noexcept {
		count_.store(0);
		cancel_in_flight_.store(false);
		for (int i = 0; i < MAX_PIPELINES; ++i) pids_[i].store(0);
	}

	// idx must be < MAX_PIPELINES. PID first, then count -- see the class header
	// comment (J2 race fix).
	void add(int idx, pid_t pid) noexcept {
		pids_[idx].store(pid);
		count_.store(idx + 1);
	}

	void clear(int idx) noexcept { pids_[idx].store(0); }

	bool cancel_in_flight() const noexcept { return cancel_in_flight_.load(); }

	void kill_all_usr2() noexcept {
		cancel_in_flight_.store(true);
		int n = count_.load();
		for (int i = 0; i < n; ++i) {
			pid_t p = pids_[i].load();
			if (p > 0) {
				LOGINFO("Killing %s %d (pid %d)\n", kill_tag_, i, (int)p);
				kill(p, SIGUSR2);
			}
		}
	}

	// Pause/resume via SIGSTOP/SIGCONT — same iteration pattern as
	// kill_all_usr2(). POSIX-idempotent: a double SIGSTOP on an already-stopped
	// process = no-op, SIGCONT on a non-stopped process = no-op.
	void pause_all() noexcept {
		int n = count_.load();
		for (int i = 0; i < n; ++i) {
			pid_t p = pids_[i].load();
			if (p > 0) {
				LOGINFO("Pausing %s %d (pid %d)\n", kill_tag_, i, (int)p);
				kill(p, SIGSTOP);
			}
		}
	}
	void resume_all() noexcept {
		int n = count_.load();
		for (int i = 0; i < n; ++i) {
			pid_t p = pids_[i].load();
			if (p > 0) {
				LOGINFO("Resuming %s %d (pid %d)\n", kill_tag_, i, (int)p);
				kill(p, SIGCONT);
			}
		}
	}
};

PipeChildRegistry g_backup_children("child");
PipeChildRegistry g_restore_children("restore child");

// Pin the calling pipe-worker process to its assigned big core. Called by the
// pipe child right after fork() in createTarFork()/extractTarFork() so the
// worker + the later-forked zstd sub-child land on the same core (shared L2 ->
// better cache locality between tar_block_read/write and zstd
// compress/decompress). p is the pipe slot index. Pinning comes from
// TW_AFFINITY_TAR_WORKER_CORES (mod-wrap, -1 = no pinning for that slot). Complete
// no-op if TW_USE_CPU_AFFINITY=false or the list is unset.
void pin_pipe_worker_to_big_core(int p) {
	// Core slice instead of a single core. At active < MAX the worker gets a
	// wider slice (or the whole cluster with range notation); at active==MAX
	// exactly 1 core. active_pipes is set here.
#ifndef BUILD_TWRPTAR_MAIN
	tw_affinity::apply_core_list_pin(
		tw_affinity::core_slice(tw_affinity::tar_worker_cores, tw_affinity::tar_worker_is_cluster,
		                        tw_affinity::active_pipes, p));
#endif
}

// ---------------------------------------------------------------------------
// DFP backup naming "%s%i%02i": pipe i writes win[i*100..i*100+99] for ALL
// modes (RAW, RAW+AES, compressed, compressed+AES). The pipe prefix keeps the
// concurrently writing backup pipes collision-free. On RESTORE the pipe id in
// the name is meaningless: after the DFP directory lead (win000) all segments
// are position- and pipe-independent (the libtar hardlink inode cache hangs off
// the TAR* handle -> no cross-segment references). extractTarFork() therefore
// distributes the segments via a work queue (SegmentClaim) instead of a fixed
// block p -> pipe p.
//
// Discovery via glob() instead of a 9999 Path_Exists loop: one readdir() pass,
// tolerant of sequence gaps, much faster for large backups.
// ---------------------------------------------------------------------------

// Cross-process work-queue counter for the multi-pipe restore. A single
// std::atomic<int> in a MAP_SHARED|MAP_ANONYMOUS region: the parent creates it
// BEFORE the fork loop, the pipe children inherit the region via fork() and
// pull their segment indices via next() (fetch_add). RAII in the GuiAffinityGuard
// style: ctor maps, dtor unmaps. fork semantics: the object lives in the parent
// scope of extractTarFork(); the children always call _exit() (NO destructor in
// the child -> no double munmap; consistent with the child loop's _exit
// invariant). ATOMIC_INT_LOCK_FREE==2 guarantees cross-process lock-freedom
// (always true on aarch64).
static_assert(ATOMIC_INT_LOCK_FREE == 2,
              "SegmentClaim needs an always-lock-free atomic<int> for cross-process MAP_SHARED");
struct SegmentClaim {
	std::atomic<int>* ctr_ = nullptr;
	SegmentClaim() {
		void* m = mmap(nullptr, sizeof(std::atomic<int>), PROT_READ | PROT_WRITE,
		               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (m != MAP_FAILED)
			ctr_ = new (m) std::atomic<int>(0);
	}
	~SegmentClaim() {
		if (ctr_) {
			using AtomicInt = std::atomic<int>;
			ctr_->~AtomicInt();
			munmap((void*)ctr_, sizeof(std::atomic<int>));
		}
	}
	bool valid() const { return ctr_ != nullptr; }
	int  next()        { return ctr_->fetch_add(1, std::memory_order_relaxed); }
	SegmentClaim(const SegmentClaim&)            = delete;   // owns the mmap region
	SegmentClaim& operator=(const SegmentClaim&) = delete;
};

// ===========================================================================
// Cipher agility (BAES): AEAD choice per backup. 0 = AES-256-GCM (HW AES),
// 1 = ChaCha20-Poly1305 (software). The cipher id lives self-describing in the
// stream header (flags field, offset 12) — filter/pw-probe/PC-tool read it from
// there (== the cipher SSoT). These helpers serve ONLY the GUI/log banner and
// the test/benchmark force knob; the real crypto choice is made by tw_bssl_aes
// itself.
// ===========================================================================

// Backup: determine the effective AEAD cipher. The force knob 'twrp.force_aead'
// (chacha|gcm; test/benchmark, e.g. force ChaCha on a HW-AES device) wins over
// HW detection. The result is passed to the filter via env (tw_bssl_aes reads
// TW_AEAD_CIPHER) and used by the banner. Returns: 0 = AES-256-GCM,
// 1 = ChaCha20-Poly1305.
static int resolve_backup_cipher() {
	char prop[PROPERTY_VALUE_MAX] = {0};
#ifndef BUILD_TWRPTAR_MAIN
	property_get("twrp.force_aead", prop, "");   // force knob; absent in standalone -> HW detection
#endif
	int cid;
	if (strcasecmp(prop, "chacha") == 0 || strcasecmp(prop, "chacha20") == 0 ||
	    strcasecmp(prop, "chacha20-poly1305") == 0)
		cid = BAES_CIPHER_CHACHA20_POLY1305;
	else if (strcasecmp(prop, "gcm") == 0 || strcasecmp(prop, "aes") == 0 ||
	         strcasecmp(prop, "aes-256-gcm") == 0)
		cid = BAES_CIPHER_AES_256_GCM;
	else
		cid = (getauxval(AT_HWCAP) & HWCAP_AES) ? BAES_CIPHER_AES_256_GCM : BAES_CIPHER_CHACHA20_POLY1305;
	setenv("TW_AEAD_CIPHER", cid == BAES_CIPHER_CHACHA20_POLY1305 ? "chacha" : "gcm", 1);
	return cid;
}

// Restore: read the AEAD cipher id from a segment's BAES header
// (self-describing). -1 if unreadable / not BAES — the banner then falls back
// to the HWCAP heuristic (purely cosmetic; the filter decrypts correctly from
// the header flags field regardless).
static int read_baes_cipher_id(const std::string& path) {
	int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	unsigned char hdr[BAES_OFF_CIPHER + 2];   // up to and including the cipher field (offset 12..13)
	ssize_t n = read(fd, hdr, sizeof(hdr));
	close(fd);
	if (n < (ssize_t)sizeof(hdr))
		return -1;
	if (memcmp(hdr, BAES_MAGIC, BAES_MAGIC_LEN) != 0)
		return -1;
	return (int)((uint16_t)hdr[BAES_OFF_CIPHER] | ((uint16_t)hdr[BAES_OFF_CIPHER + 1] << 8));
}

// Banner/log label for an AEAD cipher id (-1/unknown -> default name).
static const char* aead_cipher_label(int cipher_id) {
	return (cipher_id == BAES_CIPHER_CHACHA20_POLY1305) ? "ChaCha20-Poly1305" : "AES-256-GCM";
}

// Banner HW suffix: " HW" only for AES-256-GCM WITH hardware AES (HWCAP_AES), else "".
static const char* hw_suffix(int cipher_id) {
	return (cipher_id == BAES_CIPHER_AES_256_GCM && (getauxval(AT_HWCAP) & HWCAP_AES)) ? " HW" : "";
}

// detect_archive_type / DetectResult / is_legacy_type / emit_detect_reject moved to
// TWFunc (twrp-functions.cpp/.hpp): one detection, linkable in both build
// modules. Callers here use TWFunc::detect_archive_type / TWFunc::is_legacy_type /
// TWFunc::emit_detect_reject; BackupHeaderManager::Load likewise.

// Segment discovery for the restore: all archives `basefn[0-9][0-9][0-9]`
// (matches both the DFP scheme `%s%i%02i` AND legacy `%s%03i`) as a sorted path
// list. Lexical sorting is identical to numeric here (fixed 3-digit suffix,
// same length) -> win000 is guaranteed to be element 0 (DFP directory lead
// first). The pipe assignment happens at runtime via a work queue
// (SegmentClaim), no longer statically via the block prefix. Empty list ->
// nothing to restore (the caller handles that).
//
// Caller: extractTarFork() once per restore (legacy and DFP multi-pipe branch).
static std::vector<std::string> discover_segments(const std::string& basefn) {
	std::vector<std::string> segs;
	glob_t gl;
	std::string pattern = basefn + "[0-9][0-9][0-9]";
	if (glob(pattern.c_str(), GLOB_NOSORT, NULL, &gl) == 0) {
		segs.reserve(gl.gl_pathc);
		for (size_t k = 0; k < gl.gl_pathc; k++)
			segs.push_back(gl.gl_pathv[k]);
	}
	globfree(&gl);
	std::sort(segs.begin(), segs.end());
	return segs;
}

// Per-file LPT distribution of the file entries across the pipes.
//
// After directory-first processing, file entries have no ordering or locality
// constraints left: all directories + fscrypt policies are set by the directory
// lead in pipe 0, BEFORE any file pipe starts. This removes fscrypt-group bin
// packing; what remains is pure byte load balancing.
//
// Algorithm:
//   1. Buckets = individual REG files with size > 0
//   2. Sort descending by size
//   3. Greedy LPT: each file to the currently least-loaded pipe
//   4. Forward pass: size==0 non-DIRs (symlinks, empty REGs) inherit the
//      thread_id of their walk predecessor (locality + determinism)
//
// DIR entries need no thread_id: the fill loop in createTarFork() sends all
// is_dir entries to pipe 0 (the lead). thread_id stays the struct default 0 for
// DIRs.
//
// Caller: createTarFork() after Generate_TarList().
static void apply_lpt_distribution(std::vector<TarListStruct>& list,
                                   int num_pipes) {
	if (num_pipes <= 0 || list.empty())
		return;

	// 1. Buckets = individual REG files with size > 0.
	struct Bucket { uint64_t sz; size_t idx; };
	std::vector<Bucket> buckets;
	buckets.reserve(list.size());
	for (size_t i = 0; i < list.size(); i++) {
		if (!list[i].is_dir && !list[i].is_hardlink_member && list[i].size > 0)
			buckets.push_back({list[i].size, i});
	}

	// 2. Sort descending.
	std::sort(buckets.begin(), buckets.end(),
	          [](const Bucket& a, const Bucket& b) { return a.sz > b.sz; });

	// 3. Greedy LPT.
	std::vector<uint64_t> pipe_load((size_t)num_pipes, 0);
	for (auto& b : buckets) {
		auto it = std::min_element(pipe_load.begin(), pipe_load.end());
		unsigned p = (unsigned)(it - pipe_load.begin());
		pipe_load[p] += b.sz;
		list[b.idx].thread_id = p;
	}

	// 4. Forward pass: size==0 non-DIRs (symlinks, empty REGs) inherit the
	//    thread_id of their walk predecessor. DIRs stay untouched (default 0).
	unsigned current_tid = 0;
	for (auto& it : list) {
		if (it.is_dir || it.is_hardlink_member)   // hardlinks go to pipe 0 anyway
			continue;
		if (it.size > 0)
			current_tid = it.thread_id;   // just set by LPT
		else
			it.thread_id = current_tid;   // 0-byte REG / symlink inherits
	}
}

}  // namespace

void twrpTar::Kill_Backup_Children(void) {
	g_backup_children.kill_all_usr2();
}

void twrpTar::Kill_Restore_Children(void) {
	g_restore_children.kill_all_usr2();
}

void twrpTar::Pause_Restore_Children(void) {
	g_restore_children.pause_all();
}

void twrpTar::Resume_Restore_Children(void) {
	g_restore_children.resume_all();
}

void twrpTar::Set_GUI_Efficiency(bool efficiency) {
#ifndef BUILD_TWRPTAR_MAIN
	// Delegates to the GUI pin state machine in tw_affinity — it pins the GUI
	// main thread to the efficiency/performance core and additionally maintains
	// the phase flag for the touch performance boost
	// (tw_affinity::gui_touch_boost_tick, called by the GUI loop in gui.cpp).
	tw_affinity::gui_set_efficiency_pin(efficiency);
#else
	(void)efficiency;  // CLI: no GUI thread, no pinning
#endif
}

// ---- Child-to-parent message pipe helpers ----

static void parse_msg_pipe_frame(const char* buf, ssize_t buflen)
{
	// 8192 not 4095. The reader (run_pipe_poll) reads msgbuf[4096] -> buflen <=
	// 4096; after frame processing at most one incomplete frame remains (< 4095
	// B, since pkt_len <= 4091 -> frame <= 4095). Worst case partial_len+buflen =
	// 4094+4096 = 8190 < 8192 -> the overflow discard below never fires in normal
	// operation. The discard branch remains as a safety net.
	static char partial[8192];
	static size_t partial_len = 0;

	if (buf == nullptr) {
		partial_len = 0;
		return;
	}

	if (partial_len + buflen > sizeof(partial)) {
		LOGERR("msg_pipe: frame buffer overflow, discarding %zu bytes\n", partial_len + buflen);
		partial_len = 0;
		return;
	}
	memcpy(partial + partial_len, buf, buflen);
	partial_len += buflen;

	size_t offset = 0;
	while (offset + 4 <= partial_len) {
		uint8_t magic = (uint8_t)partial[offset];
		if (magic != 0xAA) {
			offset++;
			continue;
		}
		uint16_t pkt_len = ((uint8_t)partial[offset + 2]) |
		                   ((uint16_t)((uint8_t)partial[offset + 3]) << 8);
		if (pkt_len > 4091) {
			offset++;
			continue;
		}
		if (offset + 4 + pkt_len > partial_len)
			break;

		uint8_t msg_type = (uint8_t)partial[offset + 1];
		std::string text(partial + offset + 4, pkt_len);

		if (msg_type == (uint8_t)msg::kError) {
			gui_print_color("error", "%s\n", text.c_str());
		} else if (msg_type == (uint8_t)msg::kWarning) {
			gui_print_color("warning", "%s\n", text.c_str());
		} else if (msg_type == (uint8_t)msg::kHighlight) {
			gui_print_color("highlight", "%s\n", text.c_str());
		} else {
			gui_print("%s\n", text.c_str());
		}

		offset += 4 + pkt_len;
	}

	if (offset > 0 && offset < partial_len) {
		memmove(partial, partial + offset, partial_len - offset);
		partial_len -= offset;
	} else if (offset >= partial_len) {
		partial_len = 0;
	}
}

static void reset_msg_pipe_parser(void) {
	parse_msg_pipe_frame(nullptr, 0);
}

/* Failure sentinel on progress_pipe[0->1] from the pipe worker to the parent.
 * The parent then triggers Kill_*_Children() + pipeline_failed=true and returns
 * -1 from extractTarFork()/createTarFork().
 *
 * Wire format (8B, atomic < PIPE_BUF):
 *   bits [63..32]  MAGIC = 0xFFFFFFFF   (discriminator against real fs values)
 *   bits [31.. 0]  pipe_idx of the source pipe
 *
 * Reach as a byte delta: >= 18.45 EiB above the MAGIC prefix — unreachable as a
 * real file delta (even theoretical sequential throughput would take billions of
 * years to reach this value in one tick). Thus collision-free against the normal
 * progress path, which only writes real fs values (0 or file bytes).
 *
 * Legacy compatibility: the old sentinel 0xFFFFFFFFFFFFFFFFULL also matches the
 * MAGIC prefix. Its lower 32 = 0xFFFFFFFF (= 2^32-1) fails the bounds check
 * (>= pipe_count) and is shown by the reader as "source pipe unknown". So any
 * forgotten migration site can never become a crash/UB risk, only log less
 * informatively.
 */
static constexpr unsigned long long SENTINEL_MAGIC      = 0xFFFFFFFF00000000ULL;
static constexpr unsigned long long SENTINEL_MAGIC_MASK = 0xFFFFFFFF00000000ULL;
static constexpr unsigned long long SENTINEL_PIPE_MASK  = 0x00000000FFFFFFFFULL;

static inline unsigned long long make_failure_sentinel(int pipe_idx) {
	return SENTINEL_MAGIC
	     | ((unsigned long long)(unsigned int)pipe_idx & SENTINEL_PIPE_MASK);
}

// Returns true if fs is a failure sentinel. *out_pipe is set to the encoded
// pipe index if it is in the valid range [0, pipe_count), else -1 (=
// legacy/unknown). pipe_count is the worker count of the current job — without
// that context the range cannot be validated.
static inline bool is_failure_sentinel(unsigned long long fs, int pipe_count, int* out_pipe) {
	if ((fs & SENTINEL_MAGIC_MASK) != SENTINEL_MAGIC) return false;
	int p = (int)(fs & SENTINEL_PIPE_MASK);
	*out_pipe = (p >= 0 && p < pipe_count) ? p : -1;
	return true;
}

/*
 * Best-effort writer for progress_pipe in the backup hot loop. Writes 8B
 * (atomic < PIPE_BUF). On EPIPE (parent read end closed) it logs LOGINFO once,
 * then skips all further writes for the current thread/process — this avoids
 * thousands of pointless EPIPE syscalls in the hot loop. __thread scope is
 * per-worker in the fork() model.
 *
 * Use ONLY where a lost progress value is acceptable. NOT for sentinel writes
 * right before _exit() — there the suppression would be pointless since the
 * worker ends immediately anyway (see (void)write + waitpid fallback at the 3
 * sentinel sites).
 */
static void progress_write_best_effort(int fd, unsigned long long v) {
	static __thread bool pipe_broken = false;
	if (pipe_broken)
		return;
	ssize_t n = write(fd, &v, sizeof(v));
	if (n == (ssize_t)sizeof(v))
		return;
	// n == -1 or partial (impossible for 8B in a pipe, but defensive).
	if (n < 0 && (errno == EPIPE || errno == EBADF)) {
		LOGINFO("[L3] progress_pipe broken (errno=%d) -- suppressing further writes from this worker\n", errno);
		pipe_broken = true;
	}
	// Ignore other errno values (e.g. EINTR) — best effort.
}

/*
 * Strict password-pipe writer. A truncated write would give tw_bssl_aes an
 * empty/cut password -> wrong key -> unusable backup or restore corruption.
 * Atomic guarantee: PW+\0 < 100 bytes << PIPE_BUF (4096), so either complete or
 * error.
 *
 * Returns true on a complete write, else false (the caller must escalate). The
 * strict check n == expected (rather than only n < 0) is defensive against
 * partial writes.
 */
bool write_password_or_log(int fd, const std::string& password) {
	size_t expected = password.size() + 1;
	ssize_t n = write(fd, password.c_str(), expected);
	if (n == (ssize_t)expected)
		return true;
	LOGERR("[H1] write password to tw_bssl_aes pipe failed: n=%zd errno=%d (%s)\n",
	       n, errno, strerror(errno));
	return false;
}

twrpTar::twrpTar(void) {
	use_encryption = 0;
	userdata_encryption = 0;
	use_compression = 0;
	split_archives = 0;
	comp_pid = 0;
	crypt_pid = 0;
	Total_Backup_Size = 0;
	exact_backup_size = 0;   // exact content sum (also reset per backup in createTarFork)
	exact_ext_app_data_size = 0;   // ext-app-data portion (g-header TWRP.ext_app_data_size)
	Archive_Current_Size = 0;
	include_root_dir = true;
	tar_type.openfunc = open;
	tar_type.closefunc = close;
	// tar_io_* (libtar/block.c): robust block I/O, short-read-safe on
	// pipes (same primitive as default_type in handle.c). writefunc
	// defensively co-initialized -- was uninitialized until createTar() (write_tar_no_buffer,
	// which internally also delegates to tar_io_write).
	tar_type.readfunc = tar_io_read;
	tar_type.writefunc = tar_io_write;
	input_fd = -1;
	output_fd = -1;
	output_trim_offset = 0;   // output cache trimmer: write-behind offset (also reset per segment in createTar())
	progress_pipe_fd = -1;   // defensive (-1 idiom like input/output_fd); the backup child sets it in child_pipe_preamble
	backup_exclusions = NULL;
	current_archive_type = LEGACY_UNCOMPRESSED;   // default (0 = pre-detection sentinel) — overwritten by Set_Archive_Type or magic detection

#ifdef USE_FSCRYPT
	fscrypt_set_mode();
#endif
}

twrpTar::~twrpTar(void) {
	// Do nothing
}

void twrpTar::setfn(string fn) {
	tarfn = fn;
}

void twrpTar::setdir(string dir) {
	tardir = dir;
}

void twrpTar::setsize(unsigned long long backup_size) {
	Total_Backup_Size = backup_size;
}

void twrpTar::setpassword(string pass) {
	password = pass;
}

void twrpTar::Signal_Kill(int signum) {
	_exit(0);
}

// Setup routine for each pipeline child right after fork(). Idempotent.
// SIGPIPE-IGN is doubly ensured (the parent also sets SIG_IGN via
// sigaction+restore — see createTarFork). SIG_IGN survives exec.
//
// Uses sigaction() instead of signal(): signal() is marked "obsolescent" since
// POSIX.1-2001 and varies in reset/restart semantics between BSD and SysV.
// sigaction with sa_mask=empty + SA_RESTART gives deterministic behavior across
// platforms (persistent handler, EINTR restart on blocking syscalls).
// Signal_Kill calls _exit(0) — the handler never returns, so SA_RESTART is
// practically irrelevant but semantically correct. _exit is async-signal-safe
// (POSIX § 2.4.3).
void twrpTar::child_init_pipeline(void) {
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, nullptr);
	sa.sa_handler = Signal_Kill;
	sigaction(SIGUSR2, &sa, nullptr);
}

// Shared pipeline-child setup after fork() for zstd.
// slice = core slice (from tw_affinity::core_slice); empty = un-pin to all cores
// (apply_core_list_pin resets to the default mask so the sub-child does NOT keep
// the mask inherited from the worker), 1 element = single core, several =
// cluster/soft pin.
void twrpTar::setup_pipeline_child_zstd(int fd_in, int fd_out, const std::vector<int>& slice) {
	child_init_pipeline();
	// Tier2Guard: kernel guarantee "worker dead => sub-child dead" — structurally
	// covers EVERY worker exit (_exit on error, Signal_Kill/cancel, SIGSEGV,
	// OOM kill) without any exit path having to cooperate. SIGKILL not SIGTERM:
	// PDEATHSIG only fires on paths where the archive is lost anyway (the normal
	// path reaps BEFORE the worker exit — so it never fires). Survives execve
	// (zstd/tw_bssl_aes without setuid/file-caps); hangs off the death of the
	// forking THREAD — workers are single-threaded. The getppid check closes the
	// fork->prctl window: if the worker already died, the child is reparented to
	// init (PID 1) (no subreaper in recovery).
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (getppid() == 1) _exit(1);
#ifndef BUILD_TWRPTAR_MAIN
	tw_affinity::apply_core_list_pin(slice);   // core slice (1 core = single pin, several = cluster)
#endif
	dup2(fd_in, STDIN_FILENO);
	dup2(fd_out, STDOUT_FILENO);
}

// Pipeline-child setup for tw_bssl_aes.
// pw_fd_keep: read end of the password pipe (strip CLOEXEC so execv sees it).
// slice = core slice (from core_slice); empty = un-pin to all cores (reset to
// the default mask, no worker inheritance).
void twrpTar::setup_pipeline_child_crypt(int fd_in, int fd_out, int pw_fd_keep, const std::vector<int>& slice) {
	child_init_pipeline();
	// Tier2Guard: see setup_pipeline_child_zstd().
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (getppid() == 1) _exit(1);
	fcntl(pw_fd_keep, F_SETFD, 0);   // strip CLOEXEC so tw_bssl_aes sees the FD
#ifndef BUILD_TWRPTAR_MAIN
	tw_affinity::apply_core_list_pin(slice);   // core slice instead of a single core
#endif
	dup2(fd_in, STDIN_FILENO);
	dup2(fd_out, STDOUT_FILENO);
}

// The zstd/pigz thread argument ("-T<n>" / "-p<n>") is built by the PARENT
// (PipeOperation::fork_zstd) BEFORE the fork() — directly via
// tw_affinity::compute_compressor_threads(active_pipes, pipe_id) + snprintf into
// a stack buffer, NOT as a std::string in the forked child (allocation ->
// malloc-lock deadlock risk). The thread COUNT always comes from the
// remainder-free budget law compute_compressor_threads (Σ over all pipes ==
// budget); it is INDEPENDENT of pinning (slice = WHICH cores, not HOW MANY).

void twrpTar::Set_Archive_Type(Archive_Type archive_type) {
	current_archive_type = archive_type;
}

// ---------------------------------------------------------------------------
// Shared parent-side pipeline mechanics extracted from createTarFork() (backup)
// and extractTarFork() (restore). Parametrized are only the real differences:
// registry, reap_label/tag, count_files (backup file tick), pipe_count, progress
// target. FD-close/reap order, J2 (PID before count), C2 (clear before waitpid),
// signalfd crash detect and the sentinel format stay identical. The fork loop +
// child body remain inline in the respective methods.
// ---------------------------------------------------------------------------
struct PipeParentState {
	bool reaped[MAX_PIPELINES] = {false};
	int  reap_status[MAX_PIPELINES] = {0};
	int  crash_pipe = -1, crash_status = 0, sentinel_pipe = -1;
	bool pipeline_failed = false;
};

// Parent poll loop over progress/msg/signalfd(SIGCHLD). Accumulates *size (and
// with count_files additionally *files via the 0-sentinel tick) and fills
// st.reaped/crash_pipe/sentinel_pipe. Closes the three read fds at the end.
// progress may be NULL (no GUI updates — BUILD_TWRPTAR_MAIN-capable).
// dfp_fd/go_fd/go_count: staggered-restore gate. If dfp_fd >= 0, the poll loop
// additionally waits for the DFP signal from pipe 0 and then releases the file
// pipes (wave B) by writing go_count bytes to go_fd. Backup and legacy restore
// call with the defaults (-1/-1/0) -> no-op.
static void run_pipe_poll(PipeParentState& st, int prog_fd, int msg_fd, int sigchld_fd,
                          int pipe_count, pid_t* child_pids, PipeChildRegistry& reg,
                          bool count_files, ProgressTracking* progress,
                          unsigned long long* size, unsigned long long* files,
                          int dfp_fd = -1, int go_fd = -1, int go_count = 0) {
	unsigned long long fs;
	struct pollfd pollfds[4];
	pollfds[0].fd = prog_fd;    pollfds[0].events = POLLIN;
	pollfds[1].fd = msg_fd;     pollfds[1].events = POLLIN;
	pollfds[2].fd = sigchld_fd; pollfds[2].events = POLLIN;   // -1 if signalfd setup failed
	pollfds[3].fd = dfp_fd; pollfds[3].events = POLLIN;  // DFP signal (-1 = inactive)
	int pipes_open = 2;
	char msgbuf[4096];

	// Poll start ~= restore start (the parent comes here right after the fork
	// loop). Measures the DFP phase duration + the bytes already restored at
	// wave-B release for the release log line (DFP branch below).
	struct timespec _t_poll_start;
	clock_gettime(CLOCK_MONOTONIC, &_t_poll_start);

	reset_msg_pipe_parser();

	while (pipes_open > 0) {
		int pret = poll(pollfds, 4, -1);
		if (pret < 0) {
			if (errno == EINTR) continue;
			break;
		}

		if (pollfds[0].fd >= 0) {
			if (pollfds[0].revents & POLLIN) {
				ssize_t n = read(pollfds[0].fd, &fs, sizeof(fs));
				if (n <= 0) {
					pollfds[0].fd = -1;
					pipes_open--;
				} else if (is_failure_sentinel(fs, pipe_count, &st.sentinel_pipe)) {
					if (st.sentinel_pipe >= 0)
						LOGINFO("Pipe %d reported fatal error -- aborting all pipes\n", st.sentinel_pipe);
					else
						LOGINFO("Child reported failure (source pipe unknown) -- aborting all pipes\n");
					st.pipeline_failed = true;
					reg.kill_all_usr2();
				} else {
					if (count_files) {
						if (fs > 0) {
							*size += fs;
							if (progress) progress->UpdateSize(*size);
						} else {
							(*files)++;
							if (progress) progress->UpdateSizeCount(*size, *files);
						}
					} else {
						*size += fs;
						if (progress) progress->UpdateSize(*size);
					}
				}
			} else if (pollfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				pollfds[0].fd = -1;
				pipes_open--;
			}
		}

		if (pollfds[1].fd >= 0) {
			if (pollfds[1].revents & POLLIN) {
				ssize_t n = read(pollfds[1].fd, msgbuf, sizeof(msgbuf));
				if (n <= 0) {
					pollfds[1].fd = -1;
					pipes_open--;
				} else {
					parse_msg_pipe_frame(msgbuf, n);
				}
			} else if (pollfds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				pollfds[1].fd = -1;
				pipes_open--;
			}
		}

		// SIGCHLD branch: out-of-band crash detection. Per-PID waitpid(WNOHANG),
		// never waitpid(-1) — other threads keep reaping their own sub-children.
		// clear(p) hides the slot from kill_all_usr2() (C2 reasoning).
		if (pollfds[2].fd >= 0 && (pollfds[2].revents & POLLIN)) {
			struct signalfd_siginfo si;
			while (read(pollfds[2].fd, &si, sizeof(si)) == sizeof(si)) {
				// drain
			}
			for (int p = 0; p < pipe_count; p++) {
				if (child_pids[p] <= 0 || st.reaped[p]) continue;
				int status = 0;
				pid_t r = waitpid(child_pids[p], &status, WNOHANG);
				if (r != child_pids[p]) continue;
				st.reaped[p] = true;
				st.reap_status[p] = status;
				reg.clear(p);
				bool abnormal = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
				if (abnormal && !st.pipeline_failed && !reg.cancel_in_flight()) {
					LOGERR("Pipe %d died unexpectedly (status=0x%x) -- aborting all pipes\n", p, status);
					st.crash_pipe   = p;
					st.crash_status = status;
					reg.kill_all_usr2();
					st.pipeline_failed = true;
				}
			}
		} else if (pollfds[2].fd >= 0 && (pollfds[2].revents & (POLLERR | POLLHUP | POLLNVAL))) {
			pollfds[2].fd = -1;
		}

		// DFP signal branch: pipe 0 reports "all directories extracted" ->
		// release wave B (file pipes) (go_count bytes on go_fd). A one-time event
		// -> stop polling dfp_fd afterwards. POLLHUP without a signal = pipe 0
		// died before the lead ended; the sentinel/SIGCHLD branch cleans up the
		// failure path via kill_all_usr2 (which also unblocks the wave-B children
		// waiting on go). The DFP fd does NOT count toward pipes_open — loop
		// termination depends only on prog_fd/msg_fd.
		if (pollfds[3].fd >= 0) {
			if (pollfds[3].revents & POLLIN) {
				char skb;
				ssize_t skn = read(pollfds[3].fd, &skb, 1);
				(void)skn;
				if (go_fd >= 0 && go_count > 0) {
					int gn = go_count < MAX_PIPELINES ? go_count : MAX_PIPELINES;
					char go[MAX_PIPELINES];
					for (int g = 0; g < gn; g++) go[g] = 1;
					ssize_t gw = write(go_fd, go, (size_t)gn);
					(void)gw;
					// Seconds since poll start + MB already restored at release.
					// Directories = 0 bytes -> ~0 MB = wave B released right after
					// the dirs (the early DFP signal takes effect).
					struct timespec _t_rel;
					clock_gettime(CLOCK_MONOTONIC, &_t_rel);
					double _el = (double)(_t_rel.tv_sec - _t_poll_start.tv_sec)
					           + (double)(_t_rel.tv_nsec - _t_poll_start.tv_nsec) / 1e9;
					LOGINFO("Directory-First-Processing: directories done -- releasing %d file pipe(s) after %.1fs (%llu MB)\n",
					        gn, _el, (size ? *size : 0ULL) / 1048576ULL);
				}
				pollfds[3].fd = -1;
			} else if (pollfds[3].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				pollfds[3].fd = -1;
			}
		}
	}
	close(prog_fd);
	close(msg_fd);
	if (sigchld_fd >= 0) close(sigchld_fd);
	if (dfp_fd >= 0) close(dfp_fd);
	if (go_fd >= 0) close(go_fd);
}

// Reap loop for all pipe children. Slots already reaped in the poll loop
// (SIGCHLD branch, st.reaped[p]) are skipped; the rest via Wait_For_Child with
// C2 clear-before-waitpid. Returns the number of abnormally terminated children.
static int run_pipe_reap(PipeParentState& st, int pipe_count, pid_t* child_pids,
                         PipeChildRegistry& reg, const char* reap_label) {
	int child_status = 0;
	int failed_children = 0;
	for (int p = 0; p < pipe_count; p++) {
		if (st.reaped[p]) {
			int s = st.reap_status[p];
			if (!WIFEXITED(s) || WEXITSTATUS(s) != 0) {
				LOGINFO("Pipe %d failed (status=0x%x)\n", p, s);
				failed_children++;
			}
			continue;
		}
		if (child_pids[p] > 0) {
			// C2: clear(p) BEFORE Wait_For_Child — closes the PID-recycling
			// window against a concurrent cancel.
			pid_t local_pid = child_pids[p];
			reg.clear(p);
			if (TWFunc::Wait_For_Child(local_pid, &child_status, reap_label) != 0) {
				LOGINFO("Pipe %d failed\n", p);
				failed_children++;
			}
		}
	}
	return failed_children;
}

// Final logging with trigger disambiguation. Returns true if the pipeline
// failed (the caller then sets gui_err/returns -1).
static bool finalize_pipe_log(const PipeParentState& st, int failed_children, const char* tag) {
	if (st.pipeline_failed || failed_children > 0) {
		if (st.pipeline_failed) {
			if (st.crash_pipe >= 0)
				LOGERR("Multi-pipe %s aborted: Pipe %d crashed (status=0x%x); %d worker(s) reaped abnormally\n",
				       tag, st.crash_pipe, st.crash_status, failed_children);
			else if (st.sentinel_pipe >= 0)
				LOGERR("Multi-pipe %s aborted: Pipe %d reported fatal error; %d worker(s) reaped abnormally\n",
				       tag, st.sentinel_pipe, failed_children);
			else
				LOGERR("Multi-pipe %s aborted: a worker reported fatal error (source pipe unknown); %d worker(s) reaped abnormally\n",
				       tag, failed_children);
		} else {
			LOGERR("Multi-pipe %s failed (%d children failed)\n", tag, failed_children);
		}
		return true;
	}
	return false;
}

// ---------------------------------------------------------------------------
// Four fork-adjacent blocks extracted from createTarFork() (backup) and
// extractTarFork() (restore). The order of the race/signal-critical steps is
// preserved. The fork-loop skeleton, the J2 registration (add()=PID before
// count), *tar_fork_pid (backup) and the differing child bodies stay inline in
// the respective methods.
// ---------------------------------------------------------------------------

// Set SIGPIPE to SIG_IGN in the parent, save the old handler in `old`. This is
// for the parent poll loop (it might write to closed pipes after the fork); the
// worker sets SIGPIPE separately via child_init_pipeline().
static void save_and_ignore_sigpipe(struct sigaction& old) {
	struct sigaction ign;
	memset(&ign, 0, sizeof(ign));
	ign.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &ign, &old);
}

// Block SIGCHLD before the fork loop and arm a signalfd for it (crash detect
// for abnormal worker death). The block mask is saved in old_chld_mask. Returns
// the signalfd (>=0) or -1 if signalfd() failed — then the mask is already
// restored and the parent poll runs gracefully in the old semantics (in-band
// sentinel only, no crash detect).
static int arm_sigchld_signalfd(sigset_t& old_chld_mask) {
	sigset_t chld_mask;
	sigemptyset(&chld_mask);
	sigaddset(&chld_mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &chld_mask, &old_chld_mask);
	int fd = signalfd(-1, &chld_mask, SFD_CLOEXEC | SFD_NONBLOCK);
	if (fd < 0) {
		LOGINFO("signalfd(SIGCHLD) failed: %s -- fallback to in-band sentinel only\n", strerror(errno));
		sigprocmask(SIG_SETMASK, &old_chld_mask, nullptr);
	}
	return fd;
}

// Fork-failure cleanup in the parent when fork() fails in the loop. Identical
// core in both methods: reap already-started workers (index < started) via
// SIGKILL+waitpid, close both pipes completely, reset the registry, restore the
// SIGPIPE handler, close the signalfd, restore the SIGCHLD mask.
// Method-specific parts (LOGINFO text, *tar_fork_pid=0 for backup, the final
// `return -1`) stay with the caller.
static void pipe_fork_failure_cleanup(int started, pid_t* child_pids, PipeChildRegistry& reg,
                                      int progress_pipe[2], int msg_pipe[2], int sigchld_fd,
                                      const struct sigaction& sigpipe_old, const sigset_t& old_chld_mask) {
	for (int k = 0; k < started; k++) {
		if (child_pids[k] > 0) {
			kill(child_pids[k], SIGKILL);
			waitpid(child_pids[k], nullptr, 0);
		}
	}
	close(progress_pipe[0]);
	close(progress_pipe[1]);
	close(msg_pipe[0]);
	close(msg_pipe[1]);
	reg.reset();
	sigaction(SIGPIPE, &sigpipe_old, nullptr);
	if (sigchld_fd >= 0) close(sigchld_fd);
	sigprocmask(SIG_SETMASK, &old_chld_mask, nullptr);
}

// Child preamble right after fork() in the pipe worker. Identical in both fork
// methods: restore the inherited SIGCHLD mask, close the inherited signalfd,
// install SIGPIPE-IGN+SIGUSR2 (child_init_pipeline), pin the worker to its core,
// close the read ends of both pipes, activate the msg-pipe channel for
// gui_msg(). Sets progress_pipe_fd (member) to the write end. progress_pipe/
// msg_pipe are method locals -> passed as parameters.
void twrpTar::child_pipe_preamble(int p, int progress_pipe[2], int msg_pipe[2],
                                  int sigchld_fd, const sigset_t& old_chld_mask) {
	if (sigchld_fd >= 0) close(sigchld_fd);
	sigprocmask(SIG_SETMASK, &old_chld_mask, nullptr);
	child_init_pipeline();  // SIGPIPE-IGN + SIGUSR2 handler, before any write/gui_msg
	pin_pipe_worker_to_big_core(p);
	close(progress_pipe[0]);
	progress_pipe_fd = progress_pipe[1];
	close(msg_pipe[0]);
	gui_activate_msg_pipe(msg_pipe[1]);
}

int twrpTar::createTarFork(std::atomic<pid_t> *tar_fork_pid) {
		int progress_pipe[2];

	// Reset partial-frame parser state from any previous (possibly failed) call
	reset_msg_pipe_parser();

	file_count = 0;
	if (backup_exclusions == NULL) {
		LOGINFO("backup_exclusions is NULL\n");
		return -1;
	}

#ifndef BUILD_TWRPTAR_MAIN
	// Privacy log: read tw_verbose_log in the PARENT (never touch DataManager in
	// the forked child — a sibling thread may hold the lock); the tarList
	// children inherit the member for the addFile LOGINFO gate.
	verbose_log = (DataManager::GetIntValue("tw_verbose_log") != 0);
	if (part_settings->adbbackup) {
		// Only the filename in the stream header: tarfn carries the fictional
		// LOCAL backup path (/data/media/0/TWRP/BACKUPS/...), which never exists
		// for an adb stream — it appeared misleadingly in the .ab, logs and
		// verify output. All restore consumers (twrpAdbBuFifo parse,
		// Get_ADB_Backup_Files, Python reader) use only the basename anyway.
		std::string Backup_FileName = TWFunc::Get_Filename(tarfn);
		if (!twadbbu::Write_TWFN(Backup_FileName, Total_Backup_Size, use_compression))
			return -1;
	}
#endif

	// Increase kernel pipe max for larger data pipes
	{
		int pmax_fd = open("/proc/sys/fs/pipe-max-size", O_WRONLY);
		if (pmax_fd >= 0) {
			if (write(pmax_fd, "1048576", 7) != 7)
				LOGINFO("Warning: could not set /proc/sys/fs/pipe-max-size\n");
			close(pmax_fd);
		}
	}

	if (pipe2(progress_pipe, O_CLOEXEC) < 0) {
		LOGERR("Error creating progress tracking pipe\n");
		gui_err("backup_error=Error creating backup.");
		return -1;
	}

	int msg_pipe[2] = {-1, -1};
	if (pipe2(msg_pipe, O_CLOEXEC) < 0) {
		LOGERR("Error creating message pipe\n");
		gui_err("backup_error=Error creating backup.");
		close(progress_pipe[0]);
		close(progress_pipe[1]);
		return -1;
	}

	// Pipeline count: size-dependent via compute_pipe_count(used_bytes) =
	// min( ceil(Total_Backup_Size / LADDER_UNIT), MAX budget ). Fixes the
	// size-blind bug (a small partition always got MAX_PIPES -> mini segments).
	// The MAX budget resolves TW_SET_MAX_PIPES > fallback (nproc/2), incl. the
	// nproc-2 safety net (central in compute_pipe_count(), the same budget as
	// compute_compressor_threads()).
#ifdef BUILD_TWRPTAR_MAIN
	int num_pipes = 1;   // standalone twrpTar: hard single-pipe core (no affinity/size scaling)
#else
	// adbbackup: HARD single-pipe (like the original TWRP reference, which never
	// splits/parallelizes adb). The adb stream is ONE stream over the wire under
	// ONE Write_TWFN header — multiple pipes would write into it interleaved ->
	// corrupt, non-restorable backup. With num_pipes==1 -> active_pipes==1 ->
	// compute_compressor_threads(1,0)==max_comp_threads (=8) -> the single zstd
	// gets -T8 (full CPU use, like upstream pigz all-cores; total budget unchanged).
	int num_pipes = part_settings->adbbackup ? 1 : tw_affinity::compute_pipe_count(Total_Backup_Size);
#endif
	LOGINFO("Parallel pipelines: %d\n", num_pipes);

	// ---- Build file list (in parent, before fork) ----
	unsigned long long file_count_local = 0;
	unsigned last_thread_id = 0;
	std::vector<TarListStruct> FileList;

	// === Walk + per-file LPT distribution (directory-first processing) ===
	// Encrypted and non-encrypted share the same Generate_TarList() call (a pure
	// directory walk, no fscrypt detection). The pipe assignment of the files is
	// done post-hoc by apply_lpt_distribution(); all directories go to pipe 0 as
	// the lead (fill loop below). Only the HWCAP_AES banner is AES-specific.
	if (use_encryption || userdata_encryption) {
		// Cipher agility: determine the effective AEAD (force knob/HWCAP), pass
		// it to the filter via env and choose the banner from it (not raw HWCAP).
		aead_cipher_id = resolve_backup_cipher();
		bool gcm = (aead_cipher_id == BAES_CIPHER_AES_256_GCM);
		LOGINFO("Using encryption (parallel, %s)\n", aead_cipher_label(aead_cipher_id));
		if (use_compression)
			gui_msg(gcm ? "aes_hw_comp" : "aes_sw_comp");
		else
			gui_msg(gcm ? "aes_hw_enc" : "aes_sw_enc");
	}
#ifndef BUILD_TWRPTAR_MAIN
	DataManager::SetValue("tw_file_progress", "Scanning files...");
	{
		char init_progress[64];
		snprintf(init_progress, sizeof(init_progress), "0MB of %lluMB",
		         Total_Backup_Size / 1048576);
		DataManager::SetValue("tw_size_progress", init_progress);
	}
#endif
	// Build the exact content sum (== size_backup) in the SAME walk — reset before the run.
	exact_backup_size = 0;
	exact_ext_app_data_size = 0;
	seen_hardlink_inodes.clear();
	{
		int ret = Generate_TarList(tardir, &FileList);
		if (ret < 0) {
			LOGERR("Error in Generate_TarList!\n");
			gui_err("backup_error=Error creating backup.");
			close(msg_pipe[0]);
			close(msg_pipe[1]);
			close(progress_pipe[0]);
			close(progress_pipe[1]);
			return -1;
		}
		file_count = (unsigned long long)ret;
		file_count_local = file_count;
	}

	// per-file LPT: assigns each file its thread_id (pipe), byte-balanced. DIRs
	// stay thread_id 0 (go to pipe 0 as the lead, fill loop below).
	apply_lpt_distribution(FileList, num_pipes);

	// last_thread_id = max(thread_id) over FileList. Empty list -> 0.
	last_thread_id = 0;
	for (auto& it : FileList) {
		if (it.thread_id > last_thread_id) last_thread_id = it.thread_id;
	}

	LOGINFO("File list built: %llu files, %u buckets\n", file_count, last_thread_id + 1);

	// Split FileList into per-pipe vectors — each child gets only its own entries.
	//
	// Directory-first processing: pipe 0 writes the complete DIR lead FIRST (all
	// directory entries of the whole FileList in walk order, parents before
	// children), then seamlessly its regular files. Pipes >0 receive only
	// REG/LNK. On restore all directories, including their fscrypt policy/
	// SELinux/xattrs, are in place BEFORE any file pipe starts — this eliminates
	// the mkdirhier() policy race (the kernel only allows
	// FS_IOC_SET_ENCRYPTION_POLICY on empty dirs). Two passes rather than one so
	// the directory lead does not interleave with pipe-0 files.
	std::vector<TarListStruct> PipeFileLists[MAX_PIPELINES];
	for (auto& item : FileList) {
		if (item.is_dir)
			PipeFileLists[0].push_back(item);
	}
	for (auto& item : FileList) {
		if (!item.is_dir && item.is_hardlink_member)
			PipeFileLists[0].push_back(item);   // hardlink set (nlink>1) into the lead: 1 inode hash, no cross-pipe/segment split
	}
	for (auto& item : FileList) {
		if (!item.is_dir && !item.is_hardlink_member)
			PipeFileLists[item.thread_id].push_back(item);
	}
	FileList.clear();

	// Set progress bar before fork
	part_settings->progress->SetSizeCount(exact_backup_size, file_count);   // partition_size=exact (multi-partition counter) + file_count
	// The DISPLAYED overall denominator (total_size, seeded in the
	// ProgressTracking ctor from the Backup_Size estimate) is NOT
	// exact_backup_size -> correct it by this partition's exact difference here,
	// otherwise the data bar only reaches 99% instead of 100% (hardlink/symlink delta).
	part_settings->progress->CorrectTotalSize((long long)exact_backup_size - (long long)Total_Backup_Size);

	// ---- Fork children (one per bucket) ----
	int actual_pipes = (int)last_thread_id + 1;
	if (actual_pipes > num_pipes) actual_pipes = num_pipes;
	if (actual_pipes < 1) actual_pipes = 1;

	// Single-segment detection: Total_Backup_Size <= MAX_ARCHIVE_SIZE => exactly
	// 1 pipe and (since Archive_Current_Size <= Total_Backup_Size) no
	// per-segment split possible => exactly one archive => no number suffix
	// needed (plain ".win", the original unsplit scheme; mode-independent — the
	// split depends only on the raw data size). actual_pipes==1 additionally
	// guards against a future LADDER_UNIT < MAX_ARCHIVE_SIZE divergence.
	// adbbackup is exempt (streams, no file on disk).
	bool single_segment = (!part_settings->adbbackup && actual_pipes == 1 &&
	                       Total_Backup_Size <= MAX_ARCHIVE_SIZE);

	// Active pipe count for the zstd thread budget (compute_compressor_threads()
	// in fork_zstd) — set BEFORE the fork loop, the comp sub-children inherit it
	// via fork().
#ifndef BUILD_TWRPTAR_MAIN
	tw_affinity::active_pipes = actual_pipes;
#endif
	// Diagnostics: the effective pipeline configuration to the log (pipe count +
	// zstd thread budget). Threads are remainder-distributed -> first vs last
	// pipe may differ; the budget-law distribution is shown (hard pin uses the
	// slice width instead, identical on hotdog). MAX_PIPES = budget counter
	// (unless max_comp_threads is set).
#ifdef BUILD_TWRPTAR_MAIN
	LOGINFO("Pipeline: %d active pipe(s) (twrpTar single-pipe core)\n", actual_pipes);
#else
	if (use_compression)
		LOGINFO("Pipeline: %d active pipe(s); zstd -T per pipe first=%d last=%d (MAX_PIPES=%d)\n",
		        actual_pipes, tw_affinity::compute_compressor_threads(actual_pipes, 0),
		        tw_affinity::compute_compressor_threads(actual_pipes, actual_pipes - 1),
		        tw_affinity::compute_pipe_count());
	else
		LOGINFO("Pipeline: %d active pipe(s) (uncompressed -- no zstd -T)\n", actual_pipes);
#endif

	// Reset static cancel-state to avoid Cancel_Backup() seeing stale PIDs from a previous backup
	g_backup_children.reset();

	// Set SIGPIPE to SIG_IGN, save the old handler. Children inherit SIG_IGN via
	// fork; exec preserves SIG_IGN. The parent handler is restored on every exit
	// path from here so the rest of TWRP keeps its previous behavior.
	struct sigaction sigpipe_old;
	save_and_ignore_sigpipe(sigpipe_old);

	// SIGCHLD crash detect: mirror of extractTarFork(). Block SIGCHLD before the
	// fork loop, integrate a signalfd into the parent poll so abnormal worker
	// death (OOM-SIGKILL, libtar/zstd SIGSEGV/SIGABRT) is detected — without this
	// out-of-band detection the parent would hang in poll(-1), because the other
	// workers keep progress_pipe[1]/msg_pipe[1] jointly open and the dead worker
	// could no longer write the in-band sentinel.
	sigset_t old_chld_mask;
	int sigchld_fd = arm_sigchld_signalfd(old_chld_mask);

	pid_t child_pids[MAX_PIPELINES] = {0};

	for (int p = 0; p < actual_pipes; p++) {
		child_pids[p] = fork();
		if (child_pids[p] < 0) {
			LOGINFO("Fork %d failed\n", p);
			pipe_fork_failure_cleanup(p, child_pids, g_backup_children, progress_pipe, msg_pipe,
			                          sigchld_fd, sigpipe_old, old_chld_mask);
			*tar_fork_pid = 0;
			return -1;
		}
		if (child_pids[p] > 0) {
			// Parent: register PID immediately so concurrent Cancel_Backup() sees fresh data
			g_backup_children.add(p, child_pids[p]);
			// Signal Cancel_Backup() the first child is live so Kill_Backup_Children() is reached
			if (p == 0) *tar_fork_pid = child_pids[0];
		}
		if (child_pids[p] == 0) {
			// === Child process for pipe p ===
			// Child preamble (restore SIGCHLD mask + close signalfd, SIGPIPE/
			// SIGUSR2 handler, core pin, close pipe read ends, activate the msg
			// pipe). See child_pipe_preamble().
			child_pipe_preamble(p, progress_pipe, msg_pipe, sigchld_fd, old_chld_mask);

			// Free COW pages: child only needs PipeFileLists[p]
			FileList.clear();
			for (int c = 0; c < MAX_PIPELINES; c++) {
				if (c != p) PipeFileLists[c].clear();
			}

			twrpTar pipe_tar;
			pipe_tar.setdir(tardir);
			pipe_tar.setfn(tarfn);
			pipe_tar.exact_backup_size = exact_backup_size;   // exact value (== size_backup) for g-header TWRP.backup_size in createTar (worker)
			pipe_tar.exact_ext_app_data_size = exact_ext_app_data_size;   // ext-app-data share to the worker (g-header TWRP.ext_app_data_size)
			pipe_tar.ItemList = &PipeFileLists[p];
			pipe_tar.thread_id = p;
			pipe_tar.use_compression = use_compression;
			if (use_encryption || userdata_encryption) {
				pipe_tar.use_encryption = use_encryption;
				pipe_tar.userdata_encryption = userdata_encryption;
				pipe_tar.setpassword(password);
			} else {
				pipe_tar.use_encryption = 0;
			}
			pipe_tar.split_archives = 1;
			pipe_tar.single_segment = single_segment;   // <=MAX + 1 pipe => plain ".win" (no win000)
			pipe_tar.verbose_log = verbose_log;   // verbose log: forward the parent read to the fresh worker object
			pipe_tar.progress_pipe_fd = progress_pipe_fd;
			pipe_tar.part_settings = part_settings;
			pipe_tar.backup_folder = backup_folder;
			pipe_tar.partition_name = partition_name;

			LOGINFO("Pipe %d: starting backup (thread_id=%d)\n", p, p);
			if (createList((void*)&pipe_tar) != 0) {
				LOGINFO("Error creating backup for pipe %d\n", p);
				// Failure sentinel FIRST over the progress pipe (mirror of
				// extractTarFork). Reports the internally detected error
				// (zstd/aes death -> EPIPE -> tarList) reliably over the fd the
				// parent ALWAYS reads in poll -> "Pipe X reported fatal error",
				// rather than only over the racy signalfd(SIGCHLD).
				// is_failure_sentinel is checked in run_pipe_poll BEFORE the
				// count_files logic -> no collision with the 0-file tick. Covers
				// only the INTERNAL error; an external kill/crash cannot send a
				// sentinel -> relies on signalfd. The write return code is
				// deliberately ignored (_exit follows; waitpid fallback).
				unsigned long long sentinel = make_failure_sentinel(p);
				(void)write(progress_pipe_fd, &sentinel, sizeof(sentinel));
				// Tier2Guard (mirror of the restore side): terminate the
				// comp/crypt sub-children in order (SIGTERM) + reap them BEFORE
				// the worker dies — otherwise they orphan and AES flushes a
				// well-formed-looking truncated tail into the partial archive.
				// Idempotent for all tarList error codes (already-reaped PIDs are
				// 0). Timeout-protected (10s SIGKILL fallback); PDEATHSIG remains
				// the net.
				pipe_tar.abort_pipeline(/*timeout_secs=*/10);
				gui_deactivate_msg_pipe();
				close(progress_pipe[1]);
				_exit(-1);
			}

			LOGINFO("Finished backup for pipe %d.\n", p);
			gui_deactivate_msg_pipe();
			close(progress_pipe[1]);
			_exit(0);
		}
	}

	// ---- Parent process ----
	// g_backup_children was populated inside the fork loop (J2 race fix).
	// *tar_fork_pid was already set in the loop at p==0 — no redundancy here.
	close(progress_pipe[1]);
	close(msg_pipe[1]);

	unsigned long long size_backup = 0, files_backup = 0;
	PipeParentState pp;
	run_pipe_poll(pp, progress_pipe[0], msg_pipe[0], sigchld_fd, actual_pipes, child_pids,
	              g_backup_children, /*count_files=*/true, part_settings->progress,
	              &size_backup, &files_backup);
#ifndef BUILD_TWRPTAR_MAIN
	DataManager::SetValue("tw_file_progress", "");
	DataManager::SetValue("tw_size_progress", "");
	// Keep the file counter ON deliberately: UpdateDisplayDetails then shows it,
	// like the size counter, at 100% (X of X) until the operation ends, instead
	// of letting it vanish 2-3 s before the backup end (during "Updating
	// partition details"). operation_start clears it symmetrically on the next
	// operation.
	part_settings->progress->DisplayFileCount(true);
	part_settings->progress->UpdateDisplayDetails(true);
#endif //ndef BUILD_TWRPTAR_MAIN
	// Wait for all children (extracted into run_pipe_reap()).
	int failed_children = run_pipe_reap(pp, actual_pipes, child_pids, g_backup_children, "createTarFork()");
	// Restore the caller's SIGPIPE handler (set before the fork loop).
	sigaction(SIGPIPE, &sigpipe_old, nullptr);
	// Restore the SIGCHLD mask (idempotent if signalfd setup failed).
	sigprocmask(SIG_SETMASK, &old_chld_mask, nullptr);
	*tar_fork_pid = 0;
	if (finalize_pipe_log(pp, failed_children, "backup")) {
		gui_err("backup_error=Error creating backup.");
		return -1;
	}
	return 0;
}

// Multi-pipe extractTarFork() — mirror of createTarFork().
//
// Flow:
//  1. Pipe setup (progress + msg)
//  2. Save SIGPIPE to SIG_IGN; g_restore_children.reset()
//  3. Single archive / adbbackup -> 1 fork with a direct extract()
//  4. Multi archive:
//     a. Magic-detection fallback when current_archive_type==LEGACY_UNCOMPRESSED
//     b. discover_segments() via glob() -> sorted segment list;
//        pipe_count = min(segment count, compute_pipe_count()+nprocs-2 clamp)
//     c. Staggered gate: pipe 0 does the win000 directory lead, wave B starts
//        only after it ends (dfp_pipe/go_pipe)
//     d. Fork loop for pipe_count pipes; each child claims segments via the
//        SegmentClaim work queue (no longer a fixed block p -> pipe p)
//        - In the child: child_init_pipeline, CPU pin via
//          tw_affinity::core_slice(tar_worker_cores, ...), thread_id=p,
//          stop_restore check between archives, openTar/extractTar/closeTar per
//          archive, on error SENTINEL + _exit(-1).
//     e. Parent: GUI efficiency core, poll loop with sentinel handling
//     f. waitpid all children + g_restore_children.clear(p)
//     g. return -1 if sentinel or failed_children
int twrpTar::extractTarFork() {
	int progress_pipe[2];
	int msg_pipe[2] = {-1, -1};
	// Staggered restore: dfp_pipe = pipe 0 -> parent (lead end), go_pipe =
	// parent -> wave B (release). Created only in the DFP multi-pipe path with
	// pipe_count > 1; otherwise they stay -1 (no-op in the poll loop).
	int dfp_pipe[2] = {-1, -1};
	int go_pipe[2] = {-1, -1};

#ifndef BUILD_TWRPTAR_MAIN
	// Privacy log: read tw_verbose_log in the PARENT (see createTarFork);
	// openTar/RestorePipeline in the children pass it as TAR_TW_VERBOSE_LOG to libtar.
	verbose_log = (DataManager::GetIntValue("tw_verbose_log") != 0);
#endif

	if (pipe2(progress_pipe, O_CLOEXEC) < 0) {
		LOGERR("Error creating progress tracking pipe\n");
		gui_err("restore_error=Error during restore process.");
		return -1;
	}
	if (pipe2(msg_pipe, O_CLOEXEC) < 0) {
		LOGERR("Error creating message pipe\n");
		gui_err("restore_error=Error during restore process.");
		close(progress_pipe[0]); close(progress_pipe[1]);
		return -1;
	}

	g_restore_children.reset();

	struct sigaction sigpipe_old;
	save_and_ignore_sigpipe(sigpipe_old);

	// ---- Branch 1: Single archive / ADB-Backup ----
	bool single_or_adb = TWFunc::Path_Exists(tarfn) || part_settings->adbbackup;

	// ---- Branch 2: Multi archive -- Segmente entdecken ----
	string basefn_local;
	std::vector<std::string> segments;
	int pipe_count = 1;

	if (!single_or_adb) {
		basefn_local = tarfn;
		string probe = basefn_local + "000";
		if (!TWFunc::Path_Exists(probe)) {
			LOGERR("Unable to locate '%s' or '%s'\n", basefn_local.c_str(), probe.c_str());
			gui_err("restore_error=Error during restore process.");
			close(progress_pipe[0]); close(progress_pipe[1]);
			close(msg_pipe[0]); close(msg_pipe[1]);
			sigaction(SIGPIPE, &sigpipe_old, nullptr);
			return -1;
		}

		// Self-describing type detection: one detector reads the magic + (for
		// BAES) the first chunk and sets current_archive_type for the whole multi
		// archive (all segments typed the same). is_legacy_type() then separates
		// legacy (single-pipe) from DFP (multi-pipe). The inner sniff separates type
		// 5 from 7 for multi on win000 too. The password is ready via
		// setpassword() from Restore_Tar.
		{
			Archive_Type at = LEGACY_UNCOMPRESSED;
			BackupHeaderManager hdr;
			hdr.Load(probe, password);          // detection via the class
			DetectResult dr = hdr.GetStatus();
			at = hdr.GetType();
			if (dr != DET_OK) {
				LOGINFO("extractTarFork: backup rejected (DetectResult=%d)\n", (int)dr);
				TWFunc::emit_detect_reject(dr, probe);
				close(progress_pipe[0]); close(progress_pipe[1]);
				close(msg_pipe[0]); close(msg_pipe[1]);
				sigaction(SIGPIPE, &sigpipe_old, nullptr);
				return -1;
			}
			Set_Archive_Type(at);
		}

		if (TWFunc::is_legacy_type(current_archive_type)) {
			// Legacy path: single-pipe (sequential = race-free like original
			// TWRP). Same segment list as the DFP path (discover_segments), only
			// the pipe count is fixed at 1 — original TWRP uses continuous
			// `%s%03i`, which the pattern also matches.
			segments = discover_segments(basefn_local);
			int legacy_count = (int)segments.size();
			if (legacy_count == 0) {
				LOGERR("extractTarFork: legacy backup has 0 archives\n");
				gui_err("restore_error=Error during restore process.");
				close(progress_pipe[0]); close(progress_pipe[1]);
				close(msg_pipe[0]); close(msg_pipe[1]);
				sigaction(SIGPIPE, &sigpipe_old, nullptr);
				return -1;
			}

			// OpenAES is already rejected at the win000 hdr.Load() above (because
			// Get_Archive_Type_From_Segments scans all segments). Corrupt
			// non-win000 segments are covered by the digest check +
			// validate_multi_archive_sequence.

			pipe_count = 1;
			LOGINFO("extractTarFork: legacy backup (%s), %d archive(s) -> single-pipe restore\n",
			        current_archive_type == LEGACY_COMPRESSED ? "gzip" : "plain tar", legacy_count);
			gui_msg(Msg(msg::kHighlight, "restore_legacy_detected=Legacy backup detected! Restoring in single pipe mode."));
		} else {
			segments = discover_segments(basefn_local);
			int n_seg = (int)segments.size();
			if (n_seg == 0) {
				LOGERR("discover_segments() returned 0 -- nothing to restore\n");
				gui_err("restore_error=Error during restore process.");
				close(progress_pipe[0]); close(progress_pipe[1]);
				close(msg_pipe[0]); close(msg_pipe[1]);
				sigaction(SIGPIPE, &sigpipe_old, nullptr);
				return -1;
			}

			// Pipe count = min(segment count, backup pipe cap). The cap
			// (compute_pipe_count(), incl. the nproc-2 safety net) EXACTLY mirrors
			// the createTarFork() choice, so the restore never starts more pipes
			// than the backup used / the device tolerates. Segments are
			// distributed at runtime via SegmentClaim (no longer a fixed block p
			// -> pipe p).
#ifdef BUILD_TWRPTAR_MAIN
			pipe_count = 1;
#else
			pipe_count = tw_affinity::compute_pipe_count();
#endif
			if (pipe_count > n_seg) pipe_count = n_seg;

			LOGINFO("extractTarFork: %d parallel pipe(s) for %d segment(s)\n", pipe_count, n_seg);

			// Staggered restore: pipe 0 extracts the complete DIR lead from
			// win000 first (all directories + fscrypt policies, set on empty
			// dirs). Only once it is in place (signalled at the first non-DIR via
			// dfp_pipe) does the parent release the file pipes (wave B) over
			// go_pipe. Every file is thus written into an already correctly
			// policed directory — the old mkdirhier() cross-pipe policy race is
			// structurally excluded. At pipe_count == 1 the gate is dropped (no
			// wave B); pipe 0 then extracts everything sequentially.
			if (pipe_count > 1) {
				if (pipe2(dfp_pipe, O_CLOEXEC) < 0 ||
				    pipe2(go_pipe, O_CLOEXEC) < 0) {
					LOGERR("Error creating dfp/go pipe: %s\n", strerror(errno));
					gui_err("restore_error=Error during restore process.");
					if (dfp_pipe[0] >= 0) { close(dfp_pipe[0]); close(dfp_pipe[1]); }
					close(progress_pipe[0]); close(progress_pipe[1]);
					close(msg_pipe[0]); close(msg_pipe[1]);
					sigaction(SIGPIPE, &sigpipe_old, nullptr);
					return -1;
				}
			}

			LOGINFO("Restoring with %d parallel pipeline(s)\n", pipe_count);
		}
	} else if (!part_settings->adbbackup) {
		// Single-file restore (unsplit `.win` / twrpTarMain): run the same
		// detector in the parent so current_archive_type + the AES banner below
		// are correct (extract() in the child no longer detects itself). ADB is
		// exempt — there the type comes from adb_compression in extract().
		Archive_Type at = LEGACY_UNCOMPRESSED;
		BackupHeaderManager hdr;
		hdr.Load(tarfn, password);          // detection via the class
		DetectResult dr = hdr.GetStatus();
		at = hdr.GetType();
		if (dr != DET_OK) {
			LOGINFO("extractTarFork: single-archive rejected (DetectResult=%d)\n", (int)dr);
			TWFunc::emit_detect_reject(dr, tarfn);
			close(progress_pipe[0]); close(progress_pipe[1]);
			close(msg_pipe[0]); close(msg_pipe[1]);
			sigaction(SIGPIPE, &sigpipe_old, nullptr);
			return -1;
		}
		Set_Archive_Type(at);
	}

	// AES banner ONCE in the parent before the fork loop (like the backup
	// createTarFork). In the child each of the N pipe children would fire it ->
	// N-fold GUI output. NOTE: restore does NOT set use_encryption/
	// use_compression (only the backup path does); here the current_archive_type
	// fixed after magic detection applies. OpenAES types (2/3) are already
	// rejected above.
	bool aes_enc  = (current_archive_type == ENCRYPTED ||
	                 current_archive_type == COMPRESSED_ENCRYPTED);
	bool aes_comp = (current_archive_type == COMPRESSED_ENCRYPTED);
	if (aes_enc) {
		// Read the real cipher self-describing from the .win000 header so the
		// banner is correct even on a cross-device restore. Fallback HWCAP if the
		// header is not (yet) readable — the filter decrypts from the header
		// flags field regardless of the banner.
		int cid = read_baes_cipher_id(single_or_adb ? tarfn : (basefn_local + "000"));
		if (cid >= 0)
			aead_cipher_id = cid;
		bool gcm = (cid >= 0) ? (cid == 0)
		                      : ((getauxval(AT_HWCAP) & HWCAP_AES) != 0);
		LOGINFO("Using encryption (parallel, %s)\n", aead_cipher_label(gcm ? BAES_CIPHER_AES_256_GCM : BAES_CIPHER_CHACHA20_POLY1305));
		gui_msg(gcm ? (aes_comp ? "aes_hw_decomp" : "aes_hw_dec")
		            : (aes_comp ? "aes_sw_decomp" : "aes_sw_dec"));
	}

	// Create the work-queue counter BEFORE the fork loop so all pipe children
	// inherit the same MAP_SHARED region (RAII: munmap automatically on every
	// return). Only the multi-archive restore uses it; the single/ADB path
	// (pipe_count==1, own branch in the child) leaves it unused. Catch mmap
	// errors here, BEFORE the SIGCHLD mask is blocked (simple cleanup, like the
	// dfp/go pipe errors).
	SegmentClaim claim;
	if (!single_or_adb && !claim.valid()) {
		LOGERR("Error creating restore work-queue counter (mmap): %s\n", strerror(errno));
		gui_err("restore_error=Error during restore process.");
		if (dfp_pipe[0] >= 0) { close(dfp_pipe[0]); close(dfp_pipe[1]); }
		if (go_pipe[0]  >= 0) { close(go_pipe[0]);  close(go_pipe[1]);  }
		close(progress_pipe[0]); close(progress_pipe[1]);
		close(msg_pipe[0]); close(msg_pipe[1]);
		sigaction(SIGPIPE, &sigpipe_old, nullptr);
		return -1;
	}

	// SIGCHLD crash detect: block SIGCHLD BEFORE the fork loop so (a) no signal
	// is lost between fork() and the signalfd setup and (b) workers inherit the
	// block mask — the worker restores it in its branch right after fork().
	// signalfd delivers SIGCHLD synchronously into the poll loop so abnormal
	// worker death (SIGKILL via OOM, SIGSEGV in libtar on a corrupt archive,
	// SIGABRT) is detected — the in-band failure sentinel does not fire there
	// (the worker no longer reaches the write site, see the make_failure_sentinel
	// calls below).
	sigset_t old_chld_mask;
	int sigchld_fd = arm_sigchld_signalfd(old_chld_mask);

	// Set the active pipe count (for worker pinning; restore zstd -d ignores -T,
	// so it has no effect on the thread budget, but this stays consistent with
	// the backup path).
#ifndef BUILD_TWRPTAR_MAIN
	tw_affinity::active_pipes = pipe_count;
#endif

	// ---- Fork-Loop ----
	pid_t child_pids[MAX_PIPELINES] = {0};
	for (int p = 0; p < pipe_count; p++) {
		child_pids[p] = fork();
		if (child_pids[p] < 0) {
			LOGINFO("Fork %d failed: %s\n", p, strerror(errno));
			pipe_fork_failure_cleanup(p, child_pids, g_restore_children, progress_pipe, msg_pipe,
			                          sigchld_fd, sigpipe_old, old_chld_mask);
			// dfp/go are restore-only and not part of pipe_fork_failure_cleanup
			// (the backup twin has none) — close them here, else up to 4 fds leak
			// on the fork error path.
			if (dfp_pipe[0] >= 0) { close(dfp_pipe[0]); close(dfp_pipe[1]); }
			if (go_pipe[0]  >= 0) { close(go_pipe[0]);  close(go_pipe[1]);  }
			return -1;
		}
		if (child_pids[p] > 0) {
			// Parent: register the PID immediately — Cancel_Restore() must not
			// see a set count_ without the corresponding PID.
			g_restore_children.add(p, child_pids[p]);
			continue;
		}

		// ====================================================================
		// === CHILD PROCESS - Pipe p =========================================
		// ====================================================================
		// Child preamble (restore SIGCHLD mask + close signalfd, SIGPIPE/SIGUSR2
		// handler, core pin, close pipe read ends, activate the msg pipe). See
		// child_pipe_preamble().
		child_pipe_preamble(p, progress_pipe, msg_pipe, sigchld_fd, old_chld_mask);

		this->thread_id = p;   // important for openTar() sub-child pinning

		// ---- Staggered-restore gate (DFP multi-pipe path only) ----
		if (dfp_pipe[0] >= 0) {
			if (p == 0) {
				// Pipe 0 carries the directory lead and signals its end. Needs no
				// go; keeps dfp_pipe[1] for writing.
				close(dfp_pipe[0]);
				close(go_pipe[0]); close(go_pipe[1]);
				this->dfp_done_fd = dfp_pipe[1];
			} else {
				// Wave B: extracts only once the lead is in place. A blocking read
				// — cancel/death delivers SIGUSR2 -> Signal_Kill -> _exit(0), so no
				// deadlock. EOF (gr <= 0, parent closed go without releasing) -> a
				// clean cancel exit.
				close(dfp_pipe[0]); close(dfp_pipe[1]);
				close(go_pipe[1]);
				char gob;
				ssize_t gr = read(go_pipe[0], &gob, 1);
				close(go_pipe[0]);
#ifdef BUILD_TWRPTAR_MAIN
				if (gr <= 0) {
#else
				if (gr <= 0 || PartitionManager.stop_restore.get_value() != 0) {
#endif
					LOGINFO("Pipe %d: released without go / stop_restore -- exiting\n", p);
					gui_deactivate_msg_pipe();
					close(progress_pipe[1]);
					_exit(-3);
				}
			}
		}

		// ---- Single-archive/ADB branch: direct extract() without multi-loop ----
		if (single_or_adb) {
			if (extract() != 0) {
				LOGINFO("Pipe %d: extract() failed\n", p);
				gui_print_color("error", "Restore pipe %d failed during single-archive extract()\n", p);
				unsigned long long sentinel = make_failure_sentinel(p);
				// Return code deliberately ignored — _exit(-1) follows right
				// below, the parent detects the failure via waitpid() as fallback.
				(void)write(progress_pipe_fd, &sentinel, sizeof(sentinel));
				// Reap the sub-children (comp_pid/crypt_pid), else zombies. The
				// multi branch below also calls this after each extractTar().
				// Timeout-protected (10s SIGKILL fallback).
				closeTarRestore();
				gui_deactivate_msg_pipe();
				close(progress_pipe[1]);
				_exit(-1);
			}
			// Same cleanup on the success path.
			closeTarRestore();
#ifndef BUILD_TWRPTAR_MAIN
			// Send TWEOF only AFTER closeTarRestore(): finish_pipeline reaped
			// comp/crypt and closed input_fd -> from here nobody holds a read end
			// of the data FIFO. Previously the TWEOF went out while input_fd +
			// zstd-stdin were still open -> bu's next open(TW_ADB_RESTORE,
			// O_WRONLY) hit the dying old reader and pumped the next partition
			// into the void via EPIPE ("Broken pipe" cascade in adb.log,
			// "unexpected EOF" in TWRP). The protocol invariant is now the same
			// everywhere: all read fds closed, THEN TWEOF (mirror of
			// Restore_Image_Test close->Write_TWEOF and closeTar
			// finish_pipeline->TWEOF).
			if (part_settings->adbbackup && !twadbbu::Write_TWEOF()) {
				LOGINFO("Pipe %d: Write_TWEOF after pipeline teardown failed\n", p);
				unsigned long long sentinel = make_failure_sentinel(p);
				// Return code deliberately ignored — _exit(-1) follows, waitpid fallback.
				(void)write(progress_pipe_fd, &sentinel, sizeof(sentinel));
				gui_deactivate_msg_pipe();
				close(progress_pipe[1]);
				_exit(-1);
			}
#endif
			gui_deactivate_msg_pipe();
			close(progress_pipe[1]);
			_exit(0);
		}

		// ---- Multi-archive branch: claim segments via the work queue ----
		// Instead of reading a fixed "block p", each pipe pulls its segment
		// indices dynamically from the shared SegmentClaim counter
		// (self-balancing, pipe-independent after the DFP lead). Pipe 0 runs alone
		// in wave A and thus necessarily claims index 0 (win000) as its first
		// segment.
		int n_segments = (int)segments.size();
		int claimed = 0;

		while (true) {
#ifndef BUILD_TWRPTAR_MAIN
			if (PartitionManager.stop_restore.get_value() != 0) {
				LOGINFO("Pipe %d: stop_restore signaled, exiting\n", p);
				// No gui_err — cancel is not an error; action.cpp already calls
				// gui_msg("restore_cancel=...") from the parent thread.
				gui_deactivate_msg_pipe();
				close(progress_pipe[1]);
				_exit(-3);
			}
#endif

			int idx = claim.next();
			if (idx >= n_segments)
				break;   // queue empty — all segments assigned
			tarfn = segments[idx];
			claimed++;

			// extractTar() internally calls openTar() (with a sub-child fork) and
			// tar_close(). closeTar() must NOT be called here (tar_append_eof()
			// fails on RDONLY). closeTarRestore() only reaps the sub-children and
			// closes input_fd.
			if (extractTar() != 0) {
				LOGINFO("Pipe %d: extractTar() failed for '%s'\n", p, tarfn.c_str());
				char errbuf[256];
				snprintf(errbuf, sizeof(errbuf),
				         "Restore pipe %d failed extracting %s", p, tarfn.c_str());
				gui_print_color("error", "%s\n", errbuf);
				unsigned long long sentinel = make_failure_sentinel(p);
				// Return code deliberately ignored — _exit(-1) follows, waitpid fallback.
				(void)write(progress_pipe_fd, &sentinel, sizeof(sentinel));
				// Reap the sub-children (comp_pid/crypt_pid), else zombies.
				// Symmetric to the single/ADB error path (above) and the
				// multi-success pattern (closeTarRestore() per iteration below).
				closeTarRestore();
				gui_deactivate_msg_pipe();
				close(progress_pipe[1]);
				_exit(-1);
			}
			if (closeTarRestore() != 0) {
				LOGINFO("Pipe %d: closeTarRestore() failed for '%s'\n", p, tarfn.c_str());
				char errbuf[256];
				snprintf(errbuf, sizeof(errbuf),
				         "Restore pipe %d failed reaping subprocesses for %s",
				         p, tarfn.c_str());
				gui_print_color("error", "%s\n", errbuf);
				unsigned long long sentinel = make_failure_sentinel(p);
				// Return code deliberately ignored — _exit(-1) follows, waitpid fallback.
				(void)write(progress_pipe_fd, &sentinel, sizeof(sentinel));
				gui_deactivate_msg_pipe();
				close(progress_pipe[1]);
				_exit(-1);
			}

			// DFP fallback: after the lead segment win000 (index 0, always
			// claimed by pipe 0 in wave A) fire the DFP signal reliably in case
			// win000 exceptionally contained ONLY directories (libtar then never
			// fired at the first non-DIR). A double signal is harmless — the
			// parent reacts only to the first. Invalidate dfp_done_fd afterwards
			// so later segments do not signal again.
			if (dfp_done_fd >= 0 && idx == 0) {
				char one = 1;
				(void)write(dfp_done_fd, &one, 1);
				dfp_done_fd = -1;
			}
		}

		LOGINFO("Pipe %d: finished (%d segment(s))\n", p, claimed);
		gui_deactivate_msg_pipe();
		close(progress_pipe[1]);
		_exit(0);
	}

	// ====================================================================
	// === PARENT PROCESS ================================================
	// ====================================================================
	// Move GUI affinity to the efficiency core: the parent poll loop +
	// UpdateSize() + msg-pipe parsing should not touch the big cores.
	Set_GUI_Efficiency(true);

	close(progress_pipe[1]);
	close(msg_pipe[1]);
	// Parent keeps dfp_pipe[0] (read end, signal from pipe 0) and go_pipe[1]
	// (write end, release to wave B); the other ends belong to the children.
	// run_pipe_poll closes dfp_pipe[0]/go_pipe[1] at the end (like
	// prog/msg/sigchld).
	if (dfp_pipe[1] >= 0) close(dfp_pipe[1]);
	if (go_pipe[0] >= 0) close(go_pipe[0]);

	unsigned long long size_restored = 0;
	PipeParentState pp;
	// go_count = pipe_count - 1 (all file pipes except pipe 0). With
	// dfp_pipe[0] == -1 (single/legacy/pipe_count==1) the DFP args are inactive.
	run_pipe_poll(pp, progress_pipe[0], msg_pipe[0], sigchld_fd, pipe_count, child_pids,
	              g_restore_children, /*count_files=*/false, part_settings->progress,
	              &size_restored, nullptr,
	              dfp_pipe[0], go_pipe[1], pipe_count - 1);

	// Wait for all children (extracted into run_pipe_reap()).
	int failed_children = run_pipe_reap(pp, pipe_count, child_pids, g_restore_children, "extractTarFork()");

	sigaction(SIGPIPE, &sigpipe_old, nullptr);
	// Restore the SIGCHLD mask — symmetric to the sigprocmask(SIG_BLOCK) before
	// the fork loop. Even if signalfd setup failed the mask was already reset
	// there — a double SETMASK on old_chld_mask is idempotent.
	sigprocmask(SIG_SETMASK, &old_chld_mask, nullptr);

	// GUI affinity back to the performance core (default) — the efficiency-core
	// pin before the fork loop only applied for the duration of the parallel
	// restore phase, so the parent poll loop left the big cores to the pipe
	// children and their sub-children (zstd/tw_bssl_aes) undisturbed. Mirror of
	// the backup path, which implements the same logic via the GuiAffinityGuard
	// RAII in partitionmanager.cpp.
	Set_GUI_Efficiency(false);

#ifndef BUILD_TWRPTAR_MAIN
	DataManager::SetValue("tw_file_progress", "");
	DataManager::SetValue("tw_size_progress", "");
#endif
	part_settings->progress->DisplayFileCount(false);
	part_settings->progress->UpdateDisplayDetails(true);

	if (finalize_pipe_log(pp, failed_children, "restore")) {
		// No plaintext error — concrete causes were already reported per pipe via
		// gui_err in the children.
		return -1;
	}
	LOGINFO("Finished multi-pipe restore.\n");
	return 0;
}

int twrpTar::Generate_TarList(string Path, std::vector<TarListStruct> *TarList) {
	DIR* d;
	struct dirent* de;
	struct stat st;
	string FileName;
	struct TarListStruct TarItem;
	int ret, file_count;
	file_count = 0;

	// Local helper lambda for DIR entries: mark as is_dir (lead), descend
	// recursively. thread_id is NOT set here — DIRs go to pipe 0 via the fill
	// loop, files are distributed post-hoc by apply_lpt_distribution().
	auto handle_dir = [&](const string& dir_path) -> int {
		TarItem.fn = dir_path;
		TarItem.size = 0;
		TarItem.is_dir = true;
		TarList->push_back(TarItem);
		return Generate_TarList(dir_path, TarList);
	};

	d = opendir(Path.c_str());
	if (d == NULL) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(Path)(strerror(errno)));
		return -1;
	}
	while ((de = readdir(d)) != NULL) {
		FileName = Path + "/" + de->d_name;

		if (de->d_type == DT_BLK || de->d_type == DT_CHR || backup_exclusions->check_skip_dirs(FileName))
			continue;
		// Defaults; concrete types overwrite size below. The is_dir reset is
		// mandatory: TarItem is reused across iterations and handle_dir sets it true.
		TarItem.fn = FileName;
		TarItem.size = 0;
		TarItem.is_dir = false;
		TarItem.is_hardlink_member = false;   // mandatory reset (TarItem is reused)
		if (de->d_type == DT_DIR) {
			ret = handle_dir(FileName);
			if (ret < 0) {
				closedir(d);  // avoid an FD leak on a recursive error
				return -1;
			}
			file_count += ret;
		} else if (de->d_type == DT_REG) {
			if (stat(FileName.c_str(), &st) != 0) {
				LOGINFO("stat() failed for '%s', skipping\n", FileName.c_str());
				continue;
			}
			TarItem.size = (uint64_t)st.st_size;
			if (st.st_nlink > 1) TarItem.is_hardlink_member = true;   // hardlink -> pipe-0 lead
			// Exact content sum — a hardlink inode ONCE (like libtar's inode
			// hash), symlinks/dirs contribute 0. Result == size_backup (restore denominator).
			if (st.st_nlink == 1 || seen_hardlink_inodes.insert(std::make_pair(st.st_dev, st.st_ino)).second) {
				exact_backup_size += (uint64_t)st.st_size;
				// count the ext-app-data share separately (same condition/bytes) -> g-header TWRP.ext_app_data_size
				if (backup_exclusions->Is_External_App_Data_Path(FileName))
					exact_ext_app_data_size += (uint64_t)st.st_size;
			}
			TarList->push_back(TarItem);
			file_count++;
		} else if (de->d_type == DT_LNK) {
			// Hardlinked symlink (nlink>1): treat like a file hardlink. The walk
			// did not stat DT_LNK, so add an lstat here just for the nlink field.
			if (lstat(FileName.c_str(), &st) == 0 && st.st_nlink > 1)
				TarItem.is_hardlink_member = true;
			TarList->push_back(TarItem);
			file_count++;
		} else if (de->d_type == DT_UNKNOWN) {
			if (lstat(FileName.c_str(), &st) == 0) {
				if (S_ISDIR(st.st_mode)) {
					ret = handle_dir(FileName);
					if (ret < 0) {
						closedir(d);
						return -1;
					}
					file_count += ret;
				} else if (S_ISREG(st.st_mode)) {
					TarItem.size = (uint64_t)st.st_size;
					if (st.st_nlink > 1) TarItem.is_hardlink_member = true;
					if (st.st_nlink == 1 || seen_hardlink_inodes.insert(std::make_pair(st.st_dev, st.st_ino)).second) {
						exact_backup_size += (uint64_t)st.st_size;   // inode-dedup, see above
						if (backup_exclusions->Is_External_App_Data_Path(FileName))   // ext-app-data share (g-header)
							exact_ext_app_data_size += (uint64_t)st.st_size;
					}
					TarList->push_back(TarItem);
					file_count++;
				} else if (S_ISLNK(st.st_mode)) {
					if (st.st_nlink > 1) TarItem.is_hardlink_member = true;
					TarList->push_back(TarItem);
					file_count++;
				}
			}
		}
	}
	closedir(d);
	return file_count;
}

// Restore-specific pipeline teardown. closeTar() calls tar_append_eof(), which
// fails on a RDONLY restore fd (write to RDONLY) — so the restore path must NOT
// use closeTar(). Instead extractTar() closes the tar fd itself via tar_close();
// the sub-children forked in openTar() (comp_pid/crypt_pid) then still need
// reaping, or zombies accumulate (2 per archive; multi-pipe with 4x100 archives
// == 800 zombies per restore).
int twrpTar::closeTarRestore() {
	// Deadlock-hardening layer 2 (belt and braces): finish_pipeline(10) reaps
	// comp→crypt via Wait_For_Child_Timeout (10s SIGKILL fallback against unknown
	// wedges — e.g. zstd CPU hang, kernel bug) and closes input_fd. Happy-path
	// latency stays 0 (the internal WNOHANG returns immediately if the child
	// already exited — typical after tar_extract_all + tar_close). report=true ->
	// a sub-child timeout/error is propagated as -1. Layer 1 (the extractTar
	// error path always calls tar_close) eliminates the concrete tar_extract_all
	// deadlock source; layer 2 is the generic backstop beneath it. No kill:
	// comp/crypt die via EOF/SIGPIPE. (output_fd is never set on restore ->
	// finish_pipeline skips it.)
	return finish_pipeline(/*timeout_secs=*/10);
}

int twrpTar::extractTar() {
	char* charRootDir = (char*) tardir.c_str();
	if (openTar() == -1)
		return -1;
	// Restore cache trim (libtar in-file trim, 128-MB gated).
	// Part 1 (output): tar_extract_regfile trims large extracted files via
	// twrp_trim_output_cache -> TWFunc::Trim_Output_Cache (per-file FADV is done
	// by extract.c itself). Part 2 (input/.win): extract.c trims the read .win
	// counter-based (FADV directly, like the backup tar_append_regfile).
	// t->input_fd distinguishes the two cases:
	//   - Pipeline (ZSTD/AES): input_fd > 0 = the .win fd read by zstd/aes via a
	//     shared OFD -> extract.c does ONE lseek64(input_fd) at the 128-MB gate
	//     (rare -> no OFD contention).
	//   - RAW: input_fd = -1 -> the .win IS t->fd, the worker reads it itself ->
	//     purely counter-based (no lseek). ADB FIFO -> lseek64=ESPIPE -> no-op.
	if (t) {
		t->output_trim_cb = twrp_trim_output_cache;
		t->input_fd       = input_fd;
		// fd ring: write-side cache trim — close extracted fds with a delay
		// (written back -> clean -> FADV actually drops). File-based restore
		// ONLY: ADB (adbbackup) is left untouched by design -> no ring. dd-image/
		// super never go through tar_extract_regfile.
		if (part_settings && !part_settings->adbbackup)
			fd_ring_setup(t, 512);   // fix-R 512 (P1); setrlimit->hard + malloc, NULL=safe
	}
	if (tar_extract_all(t, charRootDir, &progress_pipe_fd, dfp_done_fd,
	                    restore_exclude_path.empty() ? NULL : restore_exclude_path.c_str()) != 0) {
		LOGERR("Unable to extract tar archive '%s'\n", tarfn.c_str());
		gui_err("restore_error=Error during restore process.");
		// Deadlock-hardening layer 1: release the fd via tar_close so zstd's
		// write to pipes[3] gets SIGPIPE and dies naturally — otherwise
		// closeTarRestore() would later block indefinitely in waitpid(comp_pid).
		// The tar_close return code is ignored: we are already on the error path.
		fd_ring_drain(t);   // fd ring: FADV+close+free remaining fds before tar_close (NULL-safe)
		tar_close(t);
		return -1;
	}
	// Surface hardlink restore failures (soft-failed in tar_extract_hardlink via
	// return 0) ONCE, aggregated — LOGERR writes to log + GUI. No control-flow
	// change: the restore ran through, this is only a warning.
	if (t->hardlink_fail_count > 0)
		LOGERR("%d hardlink(s) could not be restored from '%s' (link failed); restore continued\n", (int)t->hardlink_fail_count, tarfn.c_str());
	// Part-2 segment close drop for RAW: the .win IS t->fd (input_fd<0) and would
	// otherwise get NO close-FADV (finish_pipeline only FADVs input_fd>=0;
	// tar_close closes t->fd without a drop). Symmetric to the backup's
	// posix_fadvise64(filefd,0,0) (append.c): drops the segment tail (<128 MB
	// behind the in-file gate + counter drift). Pipeline: t->fd = pipe -> ESPIPE
	// no-op (the .win is covered by finish_pipeline). Success path only, like the
	// backup.
	fd_ring_drain(t);   // fd ring: FADV+close+free remaining fds before tar_close (NULL-safe)
	if (input_fd < 0)
		posix_fadvise64(t->fd, 0, 0, POSIX_FADV_DONTNEED);
	if (tar_close(t) != 0) {
		LOGERR("Unable to close tar file\n");
		gui_err("restore_error=Error during restore process.");
		return -1;
	}
	// ADB TWEOF no longer lives here: at this point input_fd (FIFO read end) +
	// the zstd/aes sub-child are still open — the TWEOF went out to bu before all
	// read fds were closed. It is now sent by the single_or_adb child branch in
	// extractTarFork() AFTER closeTarRestore().
	return 0;
}

int twrpTar::extract() {
	// Type source (self-describing): ADB backups set current_archive_type from
	// the adb_compression flag (stream, no magic). ALL file-based restores
	// (single + multi) already have the type from the parent (extractTarFork ->
	// detect_archive_type) — incl. the BAES inner sniff 5<->7. No detection here;
	// openTar() (via extractTar()) dispatches on current_archive_type and the
	// pipeline decompresses self-describing. This MUST mirror the backup's DFP
	// types: the adb backup writes zstd (createTar -> COMPRESSED). The
	// old legacy type LEGACY_COMPRESSED would decompress with pigz instead of zstd
	// here (decomp_spec_for(LEGACY_COMPRESSED)=pigz) -> restore error.
	if (part_settings->adbbackup)
		current_archive_type = (part_settings->adb_compression == 1) ? COMPRESSED : UNCOMPRESSED;

	LOGINFO("extract: archive type %d\n", (int)current_archive_type);
	return extractTar();
}

int twrpTar::tarList(std::vector<TarListStruct> *TarList, unsigned thread_id) {
	struct stat st;
	char buf[PATH_MAX];
	int list_size = TarList->size(), i = 0, archive_count = 0;
	int archives_this_thread = 0;  // count of archives created by THIS pipe (logging only)
	string temp;
	char actual_filename[PATH_MAX];
	unsigned long long fs;

	// Invariant: tarList() is called only from the pipe-child path (createList),
	// where split_archives==1. There is no single-archive path anymore
	// (multi-pipe design replaced it).
	assert(split_archives == 1);
	basefn = tarfn;
	// DFP naming scheme: "%s%i%02i" — pipe i writes win[i*100 .. i*100+99].
	// Exception single_segment (Total_Backup_Size <= MAX_ARCHIVE_SIZE => 1 pipe,
	// no split possible): the first/only archive without a number suffix as plain
	// ".win" (the original unsplit scheme; mode-independent). temp stays set for
	// the split branch that is unreachable under single_segment.
	temp = basefn + "%i%02i";
	if (single_segment) {
		tarfn = basefn;
	} else {
		snprintf(actual_filename, sizeof(actual_filename), temp.c_str(), thread_id, archive_count);
		tarfn = actual_filename;
	}
	include_root_dir = true;

	if (part_settings->adbbackup)
	    LOGINFO("Writing tar file '%s' to adb backup\n", tarfn.c_str());
	else
	    LOGINFO("Creating tar file '%s'\n", tarfn.c_str());

	if (createTar() != 0) {
		LOGERR("Error creating tar '%s' for thread %i\n", tarfn.c_str(), thread_id);
		gui_err("backup_error=Error creating backup.");
		return -2;
	}
	archives_this_thread++;
	Archive_Current_Size = 0;

	while (i < list_size) {
		const std::string& fn_ref = TarList->at(i).fn;
		if (fn_ref.size() >= sizeof(buf)) {
			LOGERR("Path too long (%zu B, max %zu) in tarList() for thread %i: '%.200s...'\n",
			       fn_ref.size(), sizeof(buf) - 1, thread_id, fn_ref.c_str());
			gui_err("backup_error=Error creating backup.");
			return -5;
		}
		memcpy(buf, fn_ref.c_str(), fn_ref.size() + 1);
		// DFP invariant: the split check below fires ONLY for REG/LNK; DIR
		// entries bypass it via addFile() and do not count toward
		// Archive_Current_Size. The DIR lead at the start of pipe 0's list thus
		// lands entirely in segment <thread>00 and sits "on top" of the
		// MAX_ARCHIVE_SIZE limit.
		if (lstat(buf, &st) == 0 && (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))) { // item is a regular file
			fs = (unsigned long long)(st.st_size);
			// NEVER split adbbackup (like original TWRP `&& !adbbackup`): the adb
			// stream has ONE Write_TWFN header; multiple concatenated tar archives
			// => restore stops at the first tar EOF => rest lost. adb stays ONE
			// continuous tar stream (size irrelevant, no disk file). CLI-safe
			// (adbbackup=false).
			if (!TarList->at(i).is_hardlink_member && !(part_settings && part_settings->adbbackup) && Archive_Current_Size + fs > MAX_ARCHIVE_SIZE) {
				// single_segment invariant: with Total_Backup_Size <=
				// MAX_ARCHIVE_SIZE, Archive_Current_Size <= Total <= MAX -> the
				// split can never fire. If it does (e.g. data changed externally
				// during the backup), abort LOUDLY instead of silently writing
				// ".win" + ".win001" (inconsistent -> restore data loss).
				if (single_segment) {
					LOGERR("single_segment invariant violated for '%s' (Archive_Current_Size=%llu + fs=%llu > MAX_ARCHIVE_SIZE); aborting backup\n",
					       tarfn.c_str(), Archive_Current_Size, fs);
					gui_err("backup_error=Error creating backup.");
					return -3;
				}
				if (closeTar() != 0) {
					LOGERR("Error closing '%s' on thread %i\n", tarfn.c_str(), thread_id);
					gui_err("backup_error=Error creating backup.");
					return -3;
				}
				archive_count++;
				if (archive_count > 99) {
					LOGERR("Archive limit of 100 per pipe reached, stopping backup for thread %i\n", thread_id);
					gui_err("backup_error=Error creating backup.");
					return -4;
				}
				snprintf(actual_filename, sizeof(actual_filename), temp.c_str(), thread_id, archive_count);
				tarfn = actual_filename;
				if (createTar() != 0) {
					LOGERR("Error creating tar '%s' for thread %i\n", tarfn.c_str(), thread_id);
					gui_err("backup_error=Error creating backup.");
					return -2;
				}
				archives_this_thread++;
				Archive_Current_Size = 0;
			}
			// Hardlink members (nlink>1) do NOT count toward the segment budget
			// and do not trigger a split -> the whole set stays in segment 00 (1
			// inode hash, correct LNKTYPE). The file tick below still fires -> the
			// file/data counters stay consistent.
			if (!TarList->at(i).is_hardlink_member)
				Archive_Current_Size += fs;
			{
				// The BYTE progress now comes from tar_append_regfile (actually
				// written content bytes), NOT from the lstat st_size here —
				// otherwise symlink target lengths + hardlink duplicates would
				// count, which the restore does not reproduce (-> 99% instead of
				// 100%). The SPLIT logic still uses fs (= st_size) unchanged
				// (Archive_Current_Size above). Only the file tick (0 = increment
				// the file counter) remains here. Best-effort:
				// progress_write_best_effort() suppresses further writes after
				// EPIPE (parent read end closed), no backup data loss.
				progress_write_best_effort(progress_pipe_fd, 0ULL);
			}
		}
		if (verbose_log)   // privacy log: per-file line only with tw_verbose_log; the LOGERR below stays
			LOGINFO("addFile '%s' including root: %i\n", buf, include_root_dir);
		if (addFile(buf, include_root_dir) != 0) {
			LOGERR("Error adding file '%s' to '%s'\n", buf, tarfn.c_str());
			gui_err("backup_error=Error creating backup.");
			return -1;
		}
		// Output cache trimmer: write-behind drop of this segment's already
		// written output pages via TWFunc::Trim_Output_Cache (generic mechanics).
		// The fd choice + ADB exception are twrpTar-specific: output_fd (engine
		// modes 5-7, shared OFD because the stage writes directly) or t->fd (plain tar);
		// the ADB FIFO (adbbackup) is left untouched. Keeps the page-cache peak ~
		// active-pipes x THRESHOLD; a cheap no-op except every THRESHOLD bytes.
		if (!(part_settings && part_settings->adbbackup)) {
			int trim_fd = (output_fd >= 0) ? output_fd : (t ? t->fd : -1);
			TWFunc::Trim_Output_Cache(trim_fd, output_trim_offset);
		}
		i++;
	}
	if (closeTar() != 0) {
		LOGERR("Error closing '%s' on thread %i\n", tarfn.c_str(), thread_id);
		gui_err("backup_error=Error creating backup.");
		return -3;
	}
	LOGINFO("Thread id %i tarList done, %i archives.\n", thread_id, archives_this_thread);
	return 0;
}

void* twrpTar::createList(void *cookie) {
	twrpTar* threadTar = (twrpTar*) cookie;
	if (threadTar->tarList(threadTar->ItemList, threadTar->thread_id) != 0) {
		LOGINFO("ERROR tarList for thread ID %i\n", threadTar->thread_id);
		return (void*)-2;
	}
	LOGINFO("Thread ID %i finished successfully.\n", threadTar->thread_id);
	return (void*)0;
}

// extractMulti() was removed. It was replaced by the multi-pipe fork loop in
// extractTarFork(), which distributes archives dynamically via the SegmentClaim
// work queue (no longer statically per block prefix) over up-to-4 parallel child
// processes — instead of sequentially in a loop in a single child.

// ---------------------------------------------------------------------------
// Child exec body for the zstd/pigz compressor sub-children (compress +
// decompress). Runs in the forked child right after fork() and NEVER returns to
// the parent.
//
// FORK SAFETY: the child is async-signal-safe — ONLY setup_pipeline_child_zstd
// (sigaction/prctl/sched_setaffinity/dup2) + execv(absolute path, argv).
// path/argv are built by the PARENT (PipeOperation::fork_zstd) BEFORE the fork()
// (core_slice vector, -T/-N args, DataManager level, binary/path choice); the
// child inherits them. Reason: out of the multithreaded multi-pipe fork() the
// child must take neither malloc nor a lock — a sibling pipe thread may hold the
// malloc/DataManager lock -> futex deadlock before exec. Covers compress AND
// decompress (zstd/pigz) — the difference is entirely in path/argv. gui_err_msg
// is NOT used (no gui_err/LOGERR in the child) — the parent reaps the !=0 exit
// and reports the error.
// ---------------------------------------------------------------------------
void twrpTar::exec_comp_child(int fd_in, int fd_out, const std::vector<int>& slice,
                              const char* path, const char* const argv[], const char* gui_err_msg) {
	setup_pipeline_child_zstd(fd_in, fd_out, slice);   // child_init + Tier2Guard + slice pin + dup2
	execv(path, (char* const*)argv);
	// execv only returns on error -> report async-signal-safe (write to the inherited
	// log fd 2) + _exit. NO gui_err/LOGERR (malloc/lock) in the child.
	(void)gui_err_msg;
	static const char emsg[] = "execv compressor child ERROR!\n";
	if (write(STDERR_FILENO, emsg, sizeof(emsg) - 1) < 0) { /* nothing to do */ }
	_exit(-1);
}

// tw_bssl_aes sub-child. pw_pipe[2] = password pipe; the child closes the write
// end [1] and keeps the read end [0] (setup_pipeline_child_crypt strips CLOEXEC
// there so tw_bssl_aes sees the FD via --pwfd). FORK SAFETY: argv (incl.
// "enc"/"dec" + "--pwfd" <fd>) is built by the PARENT (PipeOperation::fork_aes)
// before the fork(); the child does ONLY setup + execv(absolute path) — no
// allocation/lock. See exec_comp_child.
void twrpTar::exec_crypt_child(int fd_in, int fd_out, int pw_pipe[2], const std::vector<int>& slice, const char* const argv[], const char* gui_err_msg) {
	close(pw_pipe[1]);
	setup_pipeline_child_crypt(fd_in, fd_out, pw_pipe[0], slice);
	execv("/system/bin/tw_bssl_aes", (char* const*)argv);
	// execv only returns on error -> report async-signal-safe + _exit (no gui_err in the child).
	(void)gui_err_msg;
	static const char emsg[] = "execv tw_bssl_aes child ERROR!\n";
	if (write(STDERR_FILENO, emsg, sizeof(emsg) - 1) < 0) { /* nothing to do */ }
	_exit(-1);
}

// ===========================================================================
// The tier-2 per-archive pipeline (PipeOperation / BackupPipeline /
// RestorePipeline + the declarative stage engine) lives in
// pipe_operation.cpp/.hpp. createTar()/openTar() below instantiate
// BackupPipeline/RestorePipeline from it; the write-through into
// comp_pid/crypt_pid keeps the internal reap_subchildren primitive untouched.
// ===========================================================================

// Consolidated writer of the self-describing PAX g-header records (TWRP.*) — as
// the very first blocks of the stream, before any file. is_plain_tar =>
// additionally TWRP.tartype=4 (the sole discriminator between this build's
// plain tar (4) and legacy plain tar (0); for 5/6/7 the magic separates them).
// TWRP.ead ONLY for /data. FATAL (-1 on the first
// error): a backup without TWRP.backup_size would later be rejected by the
// restore preflight as RV_NO_BACKUP_SIZE — a "successfully" reported but
// non-restorable backup must not exist.
int twrpTar::write_global_headers(bool is_plain_tar) {
	if (is_plain_tar &&
	    th_write_global(t, TWRP_TARTYPE_TAG, std::to_string((int)UNCOMPRESSED).c_str()) != 0) {
		LOGERR("write_global_headers: tartype failed on '%s'\n", tarfn.c_str());
		return -1;
	}
	if (th_write_global(t, "TWRP.backup_size=", std::to_string((unsigned long long)exact_backup_size).c_str()) != 0) {
		LOGERR("write_global_headers: backup_size failed on '%s'\n", tarfn.c_str());
		return -1;
	}
	if (th_write_global(t, "TWRP.ext_app_data_size=", std::to_string((unsigned long long)exact_ext_app_data_size).c_str()) != 0) {
		LOGERR("write_global_headers: ext_app_data_size failed on '%s'\n", tarfn.c_str());
		return -1;
	}
	if (partition_name == "data" &&
	    th_write_global(t, TWRP_EAD_TAG, (part_settings->external_app_data_included ? "1" : "0")) != 0) {
		LOGERR("write_global_headers: ead failed on '%s'\n", tarfn.c_str());
		return -1;
	}
	return 0;
}

int twrpTar::createTar() {
	// Output cache trimmer: a new segment => reset the trim offset. Covers the
	// initial segment AND every split (closeTar()->createTar()); output_fd/t->fd
	// is reopened right after (BackupPipeline::setup or tar_open) so the first
	// lseek64 counts from 0.
	output_trim_offset = 0;
	if (use_encryption && use_compression) {
		current_archive_type = COMPRESSED_ENCRYPTED;
		LOGINFO("Using encryption (BoringSSL %s%s) and compression...\n",
			aead_cipher_label(aead_cipher_id),
			hw_suffix(aead_cipher_id));
		BackupPipeline op(*this);
		return op.setup();
	} else if (use_compression) {
		current_archive_type = COMPRESSED;
		LOGINFO("Using compression...\n");
		BackupPipeline op(*this);
		return op.setup();
	} else if (use_encryption) {
		current_archive_type = ENCRYPTED;
		LOGINFO("Using encryption (BoringSSL %s%s)...\n",
			aead_cipher_label(aead_cipher_id),
			hw_suffix(aead_cipher_id));
		BackupPipeline op(*this);
		return op.setup();
	} else {
		// Not compressed or encrypted (plain tar, DFP) — direct path (no
		// pipeline/sub-child), outside the engine.
		char* charTarFile = (char*) tarfn.c_str();
		char* charRootDir = (char*) tardir.c_str();
		current_archive_type = UNCOMPRESSED;
		if (part_settings->adbbackup) {
			LOGINFO("Opening TW_ADB_BACKUP uncompressed stream\n");
			tar_type.writefunc = write_tar_no_buffer;
			output_fd = open(TW_ADB_BACKUP, O_WRONLY);
			// Catch fd<0 before tar_fdopen (else -1 runs into a later EBADF).
			if (output_fd < 0) {
				LOGERR("Unable to open TW_ADB_BACKUP: %s\n", strerror(errno));
				gui_err("backup_error=Error creating backup.");
				return -1;
			}
			// Verbose log: the backup handle gets TAR_TW_VERBOSE_LOG (gates
			// found-fscrypt-policy in append.c); a dedicated bit != TAR_VERBOSE
			// -> no double output.
			if(tar_fdopen(&t, output_fd, charRootDir, &tar_type, O_CLOEXEC | O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, TWTAR_FLAGS | (verbose_log ? TAR_TW_VERBOSE_LOG : 0)) != 0) {
				close(output_fd);
				LOGERR("tar_fdopen failed\n");
				return -1;
			}
		}
		else {
			tar_type.writefunc = write_tar_no_buffer;
			if (tar_open(&t, charTarFile, &tar_type, O_CLOEXEC | O_WRONLY | O_CREAT | O_LARGEFILE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, TWTAR_FLAGS | (verbose_log ? TAR_TW_VERBOSE_LOG : 0)) == -1) {   // verbose log: see adb branch
				LOGERR("tar_open error opening '%s'\n", tarfn.c_str());
				gui_err("backup_error=Error creating backup.");
				return -1;
			}
			// Self-describing PAX g-header (TWRP.tartype/backup_size/
			// ext_app_data_size/ead) as the very first blocks — consolidated in
			// write_global_headers. is_plain_tar=true: plain tar (4) additionally
			// gets TWRP.tartype (discriminator vs legacy plain tar 0; 5/6/7
			// separated by magic). th_read() skips the g-blocks on restore, standard tools
			// ignore the vendor keys. Fatal on error: the fragment is cleaned up
			// by Run_Backup (Operation_Cleanup -> removeDir).
			if (write_global_headers(true) != 0) {
				gui_err("backup_error=Error creating backup.");
				tar_close(t);
				return -1;
			}
		}
		return 0;
	}
}

int twrpTar::openTar() {
	char* charRootDir = (char*) tardir.c_str();
	char* charTarFile = (char*) tarfn.c_str();
	string Password;

	// Increase kernel pipe max for larger data pipes
	{
		int pmax_fd = open("/proc/sys/fs/pipe-max-size", O_WRONLY);
		if (pmax_fd >= 0) {
			if (write(pmax_fd, "1048576", 7) != 7)
				LOGINFO("Warning: could not set /proc/sys/fs/pipe-max-size\n");
			close(pmax_fd);
		}
	}

	// Read the cipher label for the LOGINFO banner from the header if not yet
	// determined (single-pipe path without extractTarFork). Purely cosmetic —
	// the filter decrypts self-describing from the header flags field.
	if (aead_cipher_id < 0 &&
	    (current_archive_type == ENCRYPTED ||
	     current_archive_type == COMPRESSED_ENCRYPTED)) {
		aead_cipher_id = read_baes_cipher_id(tarfn);
		if (aead_cipher_id < 0)
			aead_cipher_id = read_baes_cipher_id(tarfn + "000");
	}

	if (current_archive_type == COMPRESSED_ENCRYPTED) {
		// DFP: only zstd+BSSL-AES now (legacy gzip+OpenAES is rejected in the
		// detector detect_archive_type). Compressor fixed = zstd.
		LOGINFO("Opening zstd+BSSL-AES backup (BoringSSL %s%s)...\n",
			aead_cipher_label(aead_cipher_id),
			hw_suffix(aead_cipher_id));
		RestorePipeline op(*this);
		return op.setup();
	} else if (current_archive_type == ENCRYPTED) {
		// The GUI AES banner is deliberately NOT here (this runs per pipe child
		// -> N times); extractTarFork emits it once in the parent. Same structure
		// as the COMPRESSED_ENCRYPTED branch above (only LOGINFO + RestorePipeline).
		LOGINFO("Opening BSSL-AES backup (BoringSSL %s%s)...\n",
			aead_cipher_label(aead_cipher_id),
			hw_suffix(aead_cipher_id));
		RestorePipeline op(*this);
		return op.setup();
	} else if (current_archive_type == LEGACY_COMPRESSED ||
	           current_archive_type == COMPRESSED) {
		// Compress-only zstd (COMPRESSED) and legacy gzip (LEGACY_COMPRESSED)
		// now run through RestorePipeline instead of a dedicated direct fork. The
		// 1-stage decompress pipeline (build_stages -> {ZSTD}) forks via
		// exec_comp_child; the binary (zstd/pigz), pin strategy and thread flag
		// (-T/-p) come from decomp_spec_for(). The adbbackup input is handled in
		// RestorePipeline::open_input(), the setup-error cleanup by
		// PipeOperation::abort().
		LOGINFO("Opening %s-compressed tar...\n",
			(current_archive_type == COMPRESSED) ? "zstd" : "pigz");
		RestorePipeline op(*this);
		return op.setup();
	} else  {
		if (part_settings->adbbackup) {
			LOGINFO("Opening TW_ADB_RESTORE uncompressed stream\n");
			input_fd = open(TW_ADB_RESTORE, O_RDONLY);
			// Catch fd<0 before tar_fdopen (else -1 runs into a later EBADF).
			if (input_fd < 0) {
				LOGERR("Unable to open TW_ADB_RESTORE: %s\n", strerror(errno));
				gui_err("restore_error=Error during restore process.");
				return -1;
			}
			// Verbose log: TAR_TW_VERBOSE_LOG on ALL tar handles (backup +
			// restore) — gates the libtar-internal printf (restore: extract.c
			// "==> extracting"; backup: append.c "found fscrypt policy"). A
			// dedicated bit != TAR_VERBOSE -> no double output.
			if (tar_fdopen(&t, input_fd, charRootDir, NULL, O_CLOEXEC | O_RDONLY | O_LARGEFILE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, TWTAR_FLAGS | (verbose_log ? TAR_TW_VERBOSE_LOG : 0)) != 0) {
				LOGERR("Unable to open tar archive '%s'\n", charTarFile);
				gui_err("restore_error=Error during restore process.");
				return -1;
			}
		}
		else {
			if (tar_open(&t, charTarFile, NULL, O_CLOEXEC | O_RDONLY | O_LARGEFILE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, TWTAR_FLAGS | (verbose_log ? TAR_TW_VERBOSE_LOG : 0)) != 0) {
				LOGERR("Unable to open tar archive '%s'\n", charTarFile);
				gui_err("restore_error=Error during restore process.");
				return -1;
			}
		}
	}
	return 0;
}

string twrpTar::Strip_Root_Dir(string Path) {
	string temp;
	size_t slash;

	if (Path.substr(0, 1) == "/")
		temp = Path.substr(1, Path.size() - 1);
	else
		temp = Path;
	slash = temp.find("/");
	if (slash == string::npos)
		return temp;
	else {
		string stripped;

		stripped = temp.substr(slash, temp.size() - slash);
		return stripped;
	}
	return temp;
}

int twrpTar::addFile(string fn, bool include_root) {
	// Store the progress-pipe fd on the TAR handle so tar_append_regfile reports
	// the real content bytes (symmetric to restore). addFile is the ONLY backup
	// append choke point and covers plain-tar AND pipeline backups (the TAR is opened
	// in createTar or BackupPipeline::setup). Restore/get_size never call addFile
	// -> their TARs keep progress_fd == 0.
	if (t) {
		t->progress_fd = progress_pipe_fd;
		// In-file cache trim: give the libtar append path the seekable output fd
		// + the trim offset so tar_append_regfile trims large files every 128 MB
		// (else a cache spike up to ~active-pipes x file size). fd choice as in
		// the tarList hook (output_fd for engine modes 5-7, else t->fd for plain tar);
		// ADB (FIFO, not seekable) -> 0 = disabled. output_trim_offset = shared member.
		t->output_fd = (part_settings && part_settings->adbbackup)
			? 0 : ((output_fd >= 0) ? output_fd : (int)t->fd);
		t->output_trim_offset = &output_trim_offset;
		t->output_trim_cb = twrp_trim_output_cache;   // function pointer -> libtar calls via the pointer (no link ref to the recovery symbol)
	}
	char* charTarFile = (char*) fn.c_str();
	if (include_root) {
		if (tar_append_file(t, charTarFile, NULL) == -1)
			return -1;
	} else {
		string temp = Strip_Root_Dir(fn);
		char* charTarPath = (char*) temp.c_str();
		if (tar_append_file(t, charTarFile, charTarPath) == -1)
			return -1;
	}
	return 0;
}

// Single source of truth for the tier-2 sub-child reap (comp_pid=zstd/pigz,
// crypt_pid=tw_bssl_aes — the sub-children every pipe worker forks in
// createTar/openTar). Fixed comp→crypt order. kill_first=true sends SIGTERM
// before the reap (error/setup-abort paths where the sub-child may block);
// timeout_secs>0 uses Wait_For_Child_Timeout (restore deadlock hardening), else
// a blocking Wait_For_Child. comp_label = (LEGACY_COMPRESSED)?"pigz":"zstd" (createTar
// never uses pigz -> "zstd"; a pure log string). Returns -1 if report_failures
// && a reap return code !=0. Deliberately closes NO fds — that is per-caller.
int twrpTar::reap_subchildren(bool kill_first, int timeout_secs, bool report_failures) {
	int rc = 0, status;
	const char *comp_label = (current_archive_type == LEGACY_COMPRESSED) ? "pigz" : "zstd";
	if (comp_pid > 0) {
		if (kill_first) kill(comp_pid, SIGTERM);
		int wrc = (timeout_secs > 0)
			? TWFunc::Wait_For_Child_Timeout(comp_pid, &status, comp_label, timeout_secs)
			: TWFunc::Wait_For_Child(comp_pid, &status, comp_label);
		comp_pid = 0;
		if (report_failures && wrc != 0) rc = -1;
	}
	if (crypt_pid > 0) {
		if (kill_first) kill(crypt_pid, SIGTERM);
		int wrc = (timeout_secs > 0)
			? TWFunc::Wait_For_Child_Timeout(crypt_pid, &status, "tw_bssl_aes", timeout_secs)
			: TWFunc::Wait_For_Child(crypt_pid, &status, "tw_bssl_aes");
		crypt_pid = 0;
		if (report_failures && wrc != 0) rc = -1;
	}
	return rc;
}

// Close-stage cleanup with named intent. finish_pipeline = success close: end
// comp/crypt naturally via EOF (NO kill), report=true (the sub-child exit status
// cascades onto the return code), close input_fd + output_fd. timeout_secs=0
// (blocking, backup) or 10 (restore hardening).
int twrpTar::finish_pipeline(int timeout_secs) {
	int rc = reap_subchildren(/*kill_first=*/false, timeout_secs, /*report_failures=*/true);
	if (input_fd >= 0)  { posix_fadvise64(input_fd, 0, 0, POSIX_FADV_DONTNEED); close(input_fd);  input_fd = -1; }
	if (output_fd >= 0) { posix_fadvise64(output_fd, 0, 0, POSIX_FADV_DONTNEED); close(output_fd); output_fd = -1; }
	return rc;
}

// abort_pipeline = error close: end comp/crypt via SIGTERM + reap (report is
// irrelevant here -> false), close input_fd + output_fd. NO gui_err and NO
// unlink (the caller or PipeOperation::abort handles that). Always returns -1 so
// callers can write `return abort_pipeline(...)`. Used where NO live
// PipeOperation object exists anymore (createTarFork error path, openTar legacy
// decompress).
int twrpTar::abort_pipeline(int timeout_secs) {
	reap_subchildren(/*kill_first=*/true, timeout_secs, /*report_failures=*/false);
	if (input_fd >= 0)  { close(input_fd);  input_fd = -1; }
	if (output_fd >= 0) { close(output_fd); output_fd = -1; }
	return -1;
}

int twrpTar::closeTar() {
	LOGINFO("Closing tar\n");
	if (tar_append_eof(t) != 0) {
		LOGINFO("tar_append_eof(): %s\n", strerror(errno));
		posix_fadvise64(t->fd, 0, 0, POSIX_FADV_DONTNEED);
		tar_close(t);
		finish_pipeline(/*timeout_secs=*/0);   // reap + fd close; rc irrelevant, we fail anyway
		return -1;
	}
	posix_fadvise64(t->fd, 0, 0, POSIX_FADV_DONTNEED);
	if (tar_close(t) != 0) {
		LOGINFO("Unable to close tar archive: '%s'\n", tarfn.c_str());
		finish_pipeline(/*timeout_secs=*/0);   // reap + fd close; rc irrelevant
		return -1;
	}
	if (finish_pipeline(/*timeout_secs=*/0) != 0)
		return -1;
	if (!part_settings->adbbackup) {
		// createTar() uses only zstd '-c stdout' or tw_bssl_aes — no compressor
		// appends '.gz' to the output file. (Legacy pigz lives only in the
		// openTar()/restore path as a decompressor.)
		if (TWFunc::Get_File_Size(tarfn) == 0) {
			gui_msg(Msg(msg::kError, "backup_size=Backup file size for '{1}' is 0 bytes.")(tarfn));
			return -1;
		}
#ifndef BUILD_TWRPTAR_MAIN
		tw_set_default_metadata(tarfn.c_str());
#endif
	}
	else {
#ifndef BUILD_TWRPTAR_MAIN
		if (!twadbbu::Write_TWEOF())
			return -1;
#endif
	}
	return 0;
}

// Pre-wipe validation of the multi-archive sequence. Detects gaps in the
// archive sequence BEFORE Restore_Tar performs a destructive wipe. Scheme: each
// pipe (p) writes archives `<basefn>%i%02i` with archive ids 0..99; pipes are
// used sequentially (0, 1, 2, ...). Legacy TWRP uses `<basefn>%03i` sequentially
// 0..N-1 — the same 3-digit suffix pattern, so compatible. With a corrupt backup
// (e.g. a missing archive mid-pipe) the restore pipe worker would crash
// mid-stream after the wipe already destroyed the old data — total data loss.
// This function prevents that via an early abort.
//
// Behavior:
//   - Single archive (Path_Exists(basefn)): return true.
//   - Multi archive without a match (e.g. adbbackup stream): return true.
//   - Multi archive with a gapless sequence: return true.
//   - Multi archive with a gap: LOGERR + return false.
bool twrpTar::validate_multi_archive_sequence(const std::string& basefn) {
	// Single-archive path or adbbackup — no sequence to validate.
	if (TWFunc::Path_Exists(basefn))
		return true;

	glob_t gl;
	std::string pattern = basefn + "[0-9][0-9][0-9]";
	int rc = glob(pattern.c_str(), GLOB_NOSORT, NULL, &gl);
	if (rc != 0) {
		// No match — a legitimate "no backup found" case (the caller reports it
		// elsewhere), not corruption.
		globfree(&gl);
		return true;
	}

	// Collect 3-digit suffix indices (defensively filtered).
	std::vector<int> indices;
	indices.reserve(gl.gl_pathc);
	for (size_t k = 0; k < gl.gl_pathc; ++k) {
		const char *fn = gl.gl_pathv[k];
		size_t len = strlen(fn);
		if (len < 3) continue;
		char c1 = fn[len-3], c2 = fn[len-2], c3 = fn[len-1];
		if (c1 < '0' || c1 > '9') continue;
		if (c2 < '0' || c2 > '9') continue;
		if (c3 < '0' || c3 > '9') continue;
		int idx = (c1 - '0') * 100 + (c2 - '0') * 10 + (c3 - '0');
		indices.push_back(idx);
	}
	globfree(&gl);

	if (indices.empty())
		return true;

	std::sort(indices.begin(), indices.end());

	// Strict check: pipes sequential (0,1,2,...); within each pipe archive ids
	// sequential (0,1,2,...).
	int last_pipe = -1;
	int expected_archive = 0;
	for (int idx : indices) {
		int pipe = idx / 100;
		int archive = idx % 100;
		if (pipe != last_pipe) {
			// Transition to the next pipe.
			if (pipe != last_pipe + 1) {
				LOGERR("validate_multi_archive_sequence: pipe %d found but pipe %d missing (gap between pipes) -- backup corrupt.\n",
				       pipe, last_pipe + 1);
				return false;
			}
			if (archive != 0) {
				LOGERR("validate_multi_archive_sequence: pipe %d starts at archive %d (expected 0) -- backup corrupt.\n",
				       pipe, archive);
				return false;
			}
			last_pipe = pipe;
			expected_archive = 1;
		} else {
			if (archive != expected_archive) {
				LOGERR("validate_multi_archive_sequence: pipe %d missing archive %d (found %d) -- backup corrupt.\n",
				       pipe, expected_archive, archive);
				return false;
			}
			expected_archive++;
		}
	}
	return true;
}

unsigned long long twrpTar::get_size() {
	if (part_settings->adbbackup || TWFunc::Path_Exists(tarfn)) {
		LOGINFO("Single archive\n");
		return uncompressedSize(tarfn);
	} else {
		LOGINFO("Multiple archives\n");
		unsigned long long total_restore_size = 0;

		basefn = tarfn;
		tarfn += "000";
		thread_id = 0;
		if (!part_settings->adbbackup) {
			if (!TWFunc::Path_Exists(tarfn)) {
				LOGERR("Unable to locate '%s' or '%s'\n", basefn.c_str(), tarfn.c_str());
				return 0;
			}
			// Unified discovery via glob(). The pattern
			// `<basefn>[0-9][0-9][0-9]` matches both the DFP scheme `%s%i%02i`
			// (pipe id + 2-digit archive id, e.g. "100", "203") and the legacy
			// scheme `%s%03i` (3-digit sequence, "000", "001"...). glob has no
			// artificial limit and is tolerant of sequence gaps. Same strategy as
			// discover_segments() (restore path).
			{
				glob_t gl;
				string pattern = basefn + "[0-9][0-9][0-9]";
				if (glob(pattern.c_str(), GLOB_NOSORT, NULL, &gl) == 0) {
					for (size_t k = 0; k < gl.gl_pathc; ++k) {
						total_restore_size += uncompressedSize(gl.gl_pathv[k]);
					}
				}
				globfree(&gl);
			}
			// No `.info` cache writeback anymore. The restore size comes
			// self-describing from the PAX g-header; if that is missing, this
			// function computes it live. /super + ADB untouched.
		}
		return total_restore_size;
	}
	return 0;
}

unsigned long long twrpTar::uncompressedSize(string filename) {
	unsigned long long total_size = 0;
	string Command, result;
	vector<string> split;

	// Under the strict restore preflight, uncompressedSize is only reached by
	// legacy gzip — DFP gets the size from the g-header, legacy plain tar from
	// the .info (else reject before the wipe). Hence ONLY the gzip branch: `pigz -l`
	// reads the uncompressed size reliably from the gzip footer. The plain-tar
	// Get_File_Size fallback (confusable with corrupt DFP plain tar) and the
	// zstd-full-decompress branches are gone. Everything else -> 0 (defensive;
	// not reached under the strict preflight).
	Set_Archive_Type(BackupHeaderManager::GetFileType(filename));   // outer magic via the class
	if (current_archive_type == LEGACY_COMPRESSED) {
		// Compressed (pigz/gzip)
		Command = "pigz -l '" + filename + "'";
		TWFunc::Exec_Cmd(Command, result, false);
		if (!result.empty()) {
			/* Expected output:
			compressed original  reduced name
			95855838   179403776 -1.3%   data.yaffs2.win
			^
			split[5]
			*/
			split = TWFunc::split_string(result, ' ', true);
			// > 5 (not > 4): index 5 needs at least 6 elements — the upstream
			// guard allowed an out-of-bounds access at exactly 5 tokens. strtoull
			// not atoi: atoi (int) overflowed at > 2 GiB uncompressed size.
			if (split.size() > 5)
				total_size = strtoull(split[5].c_str(), NULL, 10);
		}
	}

	return total_size;
}



extern "C" ssize_t write_tar_no_buffer(int fd, const void *buffer, size_t size) {
	return (ssize_t) write_libtar_no_buffer(fd, buffer, size);
}

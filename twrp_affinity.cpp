/*
 * twrp_affinity.cpp -- implementation. See twrp_affinity.hpp for the API docs
 * and CPU_Affinity_Settings_Documentation.md for the configuration docs.
 */

#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>   // errno for sched_setaffinity error diagnostics
#include <algorithm>
#include <atomic>   // GUI pin state machine (phase/boost flags)

#include "twrp_affinity.hpp"
#include "twcommon.h"
#include "variables.h"   // LADDER_UNIT (size-ladder unit)

namespace tw_affinity {

	// --- Storage ---
	bool use_cpu_affinity = false;
	int  set_max_pipes = -1;
	int  max_comp_threads = -1;        // TW_MAX_COMPRESSOR_THREADS (zstd+pigz) -- MAX thread budget (counter in the law), not a fixed -T override

	// Pristine affinity mask (all allowed cores), captured ONCE in init() via
	// sched_getaffinity — BEFORE any pinning. An empty / "all -1" list means "no
	// pinning = scheduler free"; a mere no-op would keep the mask INHERITED via
	// fork() from the parent (a pinned worker or main). reset_to_default()
	// explicitly resets to this instead. Never modified -> inherited by every
	// child via fork.
	static cpu_set_t default_affinity;
	static bool      default_affinity_valid = false;

	// GUI pin state (state machine implementation at the end of the file).
	// s_gui_tid is set in init() (early, main thread) — lazy init from two
	// threads would be a formal data race even though both write the identical
	// getpid(). The lazy check in the functions remains as a defense against
	// tid=0 (sched_setaffinity(0) = wrong thread).
	static pid_t s_gui_tid = 0;                              // PID == main-thread TID (Linux)
	static std::atomic<bool> s_gui_on_efficiency(false);     // backup/restore phase active
	static std::atomic<bool> s_gui_touch_boosted(false);     // boost lifted the GUI to performance

	std::vector<int> tar_worker_cores;
	std::vector<int> zstd_cores;
	std::vector<int> enc_only_aes_cores;
	std::vector<int> enc_and_comp_aes_cores;

	int gui_performance_core = -1;
	int gui_efficiency_core  = -1;
	int mtp_core             = -1;

	int active_pipes = 1;   // runtime; init() defaults it to compute_pipe_count()

	bool tar_worker_is_cluster       = false;   // soft (range) / hard (comma list) per list, set by init()
	bool zstd_is_cluster             = false;
	bool enc_only_aes_is_cluster     = false;
	bool enc_and_comp_aes_is_cluster = false;

	// --- Helpers ---

	std::vector<int> parse_cpu_list(const char* s, bool* is_cluster) {
		if (is_cluster) *is_cluster = false;
		std::vector<int> out;
		if (!s || !*s) return out;
		std::string buf(s);
		// separators: comma or whitespace
		for (char& c : buf) if (c == ',' || c == ' ' || c == '\t') c = ' ';

		size_t pos = 0;
		while (pos < buf.size()) {
			while (pos < buf.size() && buf[pos] == ' ') pos++;
			if (pos >= buf.size()) break;
			size_t end = pos;
			while (end < buf.size() && buf[end] != ' ') end++;
			std::string tok = buf.substr(pos, end - pos);
			pos = end;

			// Range "a-b"? The first character may be '-' for a negative token.
			size_t dash = std::string::npos;
			for (size_t i = 1; i < tok.size(); i++) {
				if (tok[i] == '-') { dash = i; break; }
			}
			if (dash != std::string::npos) {
				if (is_cluster) *is_cluster = true;   // range notation -> cluster/soft pin
				int a = atoi(tok.substr(0, dash).c_str());
				int b = atoi(tok.substr(dash + 1).c_str());
				if (a <= b) for (int v = a; v <= b; v++) out.push_back(v);
				else        for (int v = a; v >= b; v--) out.push_back(v);
			} else {
				out.push_back(atoi(tok.c_str()));
			}
		}
		return out;
	}

	static std::string fmt_list(const std::vector<int>& l) {
		if (l.empty()) return "[]";
		std::string s = "[";
		for (size_t i = 0; i < l.size(); i++) {
			if (i) s += ",";
			char buf[16]; snprintf(buf, sizeof(buf), "%d", l[i]); s += buf;
		}
		s += "]";
		return s;
	}

	// --- Init ---

	void init() {
		// Capture the pristine affinity mask BEFORE anyone pins (init() runs
		// early in twrp.cpp:main(), before gui_start/MTP/backup). It serves as
		// the "all cores" target for reset_to_default() with empty/unconfigured
		// lists. sched_getaffinity(0) = the calling (main) thread's mask = the
		// full allowed set (respects any cpuset/cgroup limits of the recovery
		// better than a hand-built 0..nproc-1).
		CPU_ZERO(&default_affinity);
		default_affinity_valid =
			(sched_getaffinity(0, sizeof(default_affinity), &default_affinity) == 0);

		// Set the GUI TID (= main thread) once — init() runs before all
		// gui_set_efficiency_pin/boost callers.
		s_gui_tid = getpid();

		// Master switch — the bool is evaluated in Android.mk (makefile filter),
		// here only the define's existence is checked.
#ifdef TW_USE_CPU_AFFINITY
		use_cpu_affinity = true;
#endif
#ifdef TW_SET_MAX_PIPES
		set_max_pipes = TW_SET_MAX_PIPES;
#endif
#ifdef TW_MAX_COMPRESSOR_THREADS
		max_comp_threads = TW_MAX_COMPRESSOR_THREADS;
#endif

#ifdef TW_AFFINITY_TAR_WORKER_CORES
		tar_worker_cores = parse_cpu_list(TW_AFFINITY_TAR_WORKER_CORES, &tar_worker_is_cluster);
#endif
#ifdef TW_AFFINITY_ZSTD_CORES
		zstd_cores = parse_cpu_list(TW_AFFINITY_ZSTD_CORES, &zstd_is_cluster);
#endif
#ifdef TW_AFFINITY_ENC_ONLY_AES_CORES
		enc_only_aes_cores = parse_cpu_list(TW_AFFINITY_ENC_ONLY_AES_CORES, &enc_only_aes_is_cluster);
#endif
#ifdef TW_AFFINITY_ENC_AND_COMP_AES_CORES
		enc_and_comp_aes_cores = parse_cpu_list(TW_AFFINITY_ENC_AND_COMP_AES_CORES, &enc_and_comp_aes_is_cluster);
#endif

#ifdef TW_AFFINITY_GUI_PERFORMANCE
		gui_performance_core = TW_AFFINITY_GUI_PERFORMANCE;
#endif
#ifdef TW_AFFINITY_GUI_EFFICIENCY
		gui_efficiency_core = TW_AFFINITY_GUI_EFFICIENCY;
#endif
#ifdef TW_AFFINITY_MTP_CORE
		mtp_core = TW_AFFINITY_MTP_CORE;
#endif

		// Validation: SET_MAX_PIPES vs nproc / HARDCAP
		long nproc = sysconf(_SC_NPROCESSORS_CONF);
		if (nproc < 1) nproc = 1;

		if (set_max_pipes > (int)nproc) {
			LOGERR("[tw_affinity] WARNING: TW_SET_MAX_PIPES=%d > nproc=%ld -- clamping to %ld\n",
			       set_max_pipes, nproc, nproc);
			set_max_pipes = (int)nproc;
		}
		if (set_max_pipes > MAX_PIPELINES_HARDCAP) {
			LOGERR("[tw_affinity] WARNING: TW_SET_MAX_PIPES=%d > HARDCAP=%d -- clamping\n",
			       set_max_pipes, MAX_PIPELINES_HARDCAP);
			set_max_pipes = MAX_PIPELINES_HARDCAP;
		}

		LOGINFO("[tw_affinity] use=%d max_pipes=%d max_comp_threads=%d\n",
		        use_cpu_affinity, set_max_pipes, max_comp_threads);
		LOGINFO("[tw_affinity] tar_worker=%s zstd=%s enc_only_aes=%s enc_and_comp_aes=%s\n",
		        fmt_list(tar_worker_cores).c_str(), fmt_list(zstd_cores).c_str(),
		        fmt_list(enc_only_aes_cores).c_str(), fmt_list(enc_and_comp_aes_cores).c_str());
		LOGINFO("[tw_affinity] gui_perf=%d gui_eff=%d mtp=%d nproc=%ld\n",
		        gui_performance_core, gui_efficiency_core, mtp_core, nproc);

		// Log the soft/hard flags (1=range/soft/cluster, 0=comma/hard/sliceable).
		LOGINFO("[tw_affinity] cluster-flags tar_worker=%d zstd=%d enc_only_aes=%d enc_and_comp_aes=%d (1=Range/Soft, 0=Komma/Hard)\n",
		        tar_worker_is_cluster, zstd_is_cluster, enc_only_aes_is_cluster, enc_and_comp_aes_is_cluster);

		// Prime-core diagnostics (cpu_capacity per core, fallback cpuinfo_max_freq).
		// PURELY INFORMATIONAL — does not influence pinning (BoardConfig is the
		// basis); helps config tuning by showing which core is the strongest.
		{
			int prime = -1; long best = -1;
			for (long c = 0; c < nproc; c++) {
				char path[96]; long val = -1;
				snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%ld/cpu_capacity", c);
				FILE* f = fopen(path, "r");
				if (!f) {
					snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%ld/cpufreq/cpuinfo_max_freq", c);
					f = fopen(path, "r");
				}
				if (f) { if (fscanf(f, "%ld", &val) != 1) val = -1; fclose(f); }
				if (val > best) { best = val; prime = (int)c; }
			}
			if (prime >= 0)
				LOGINFO("[tw_affinity] detected prime core = %d (capacity/freq %ld) -- diagnostic only\n", prime, best);
			else
				LOGINFO("[tw_affinity] prime core detection unavailable (no cpu_capacity/max_freq sysfs)\n");
		}

		// active_pipes default = MAX budget -> compute_compressor_threads(MAX, *)
		// == 1 -> -T1, until a backup/restore parent sets it to the real active
		// pipe count before its fork loop.
		active_pipes = compute_pipe_count();
	}

	std::vector<int> core_slice(const std::vector<int>& cores, bool is_cluster,
	                            int active, int pipe_id) {
		if (!use_cpu_affinity || cores.empty() || pipe_id < 0)
			return {};
		// Soft pin (cluster) OR one pipe -> whole list (scheduler distributes freely).
		if (is_cluster || active <= 1)
			return cores;
		int n = (int)cores.size();
		if (active > n) active = n;             // more pipes than cores -> 1 core/slice + mod wrap
		if (pipe_id >= active) pipe_id %= active;
		int base = n / active;                  // cores per slice (minimum)
		int rest = n % active;                  // leftover cores -> to the LAST slice
		int start = pipe_id * base;
		int count = (pipe_id == active - 1) ? base + rest : base;
		std::vector<int> out;
		out.reserve(count);
		for (int i = 0; i < count && (start + i) < n; i++)
			out.push_back(cores[start + i]);
		return out;
	}

	int compute_pipe_count() {
		long nproc = sysconf(_SC_NPROCESSORS_CONF);
		if (nproc < 1) nproc = 1;

		int pc;
		if (set_max_pipes > 0) {
			pc = set_max_pipes;             // TW_SET_MAX_PIPES (1 = force single pipe)
		} else {
			pc = std::max(1L, nproc / 2);   // fallback: half the cores
		}

		if (pc > MAX_PIPELINES_HARDCAP) pc = MAX_PIPELINES_HARDCAP;
		if (pc > (int)nproc) pc = (int)nproc;
		// Central nproc-2 safety net: leaves 2 cores for the tar parents +
		// GUI/MTP. Pipe count AND thread budget (compute_compressor_threads) use
		// the same cap, so they cannot diverge when set_max_pipes > nproc-2.
		if ((int)(nproc - 2) < pc) pc = (int)(nproc - 2);
		if (pc < 1) pc = 1;
		return pc;
	}

	// Size-dependent pipe count: min( ceil(used_bytes / LADDER_UNIT), MAX budget ).
	// used_bytes==0 -> 1. The MAX/nproc/nproc-2 clamps already live in the
	// parameterless compute_pipe_count() (= cap).
	int compute_pipe_count(unsigned long long used_bytes) {
		int cap = compute_pipe_count();
		if (used_bytes == 0) return 1;
		unsigned long long needed = (used_bytes + LADDER_UNIT - 1) / LADDER_UNIT;  // ceil
		if (needed < 1) needed = 1;
		if (needed > (unsigned long long)cap) return cap;
		return (int)needed;
	}

	// zstd/pigz thread budget per pipe — distributed remainder-free. The budget
	// COUNTER is max_comp_threads (TW_MAX_COMPRESSOR_THREADS): set (>=1) = that
	// value as MAX thread budget; ==0 = all physical cores (nproc, zstd -T0
	// semantics); unset (<0) = compute_pipe_count() (= MAX pipes, nproc/2 class,
	// leaving headroom for AES + workers). The budget caps -T inside the law
	// rather than clamping -T to a fixed value. A plain budget/active would
	// floor and lose threads on uneven division (e.g. 4/3 -> 1,1,1 = 3, one
	// thread lost). Instead: base = floor, the remainder (budget % active) goes
	// to the LAST pipes (+1) — same direction as core_slice (remainder to the
	// last slice), so threads follow the wider slices. Example budget=4: 4 pipes
	// -> 1,1,1,1; 3 -> 1,1,2; 2 -> 2,2; 1 -> 4. Sum over all pipes == budget —
	// never oversubscribed. Deliberately NOT nproc-2-clamped (a user override is
	// a deliberate decision); only the default path is clamped via
	// compute_pipe_count().
	int compute_compressor_threads(int active, int pipe_id) {
		if (active < 1) active = 1;
		if (pipe_id < 0) pipe_id = 0;
		if (pipe_id >= active) pipe_id %= active;
		int budget;
		if (max_comp_threads >= 1) {
			budget = max_comp_threads;             // explicit value
		} else if (max_comp_threads == 0) {
			// 0 = zstd -T0 semantics: all physical cores. Single pipe/adb ->
			// -Tnproc (== -T0); multi-pipe -> nproc distributed over the pipes.
			long np = sysconf(_SC_NPROCESSORS_CONF);
			budget = (np >= 1) ? (int)np : 1;
		} else {
			budget = compute_pipe_count();         // unset (-1): nproc/2 fallback (headroom for AES + workers)
		}
		int base = budget / active;
		int rest = budget % active;                 // leftover threads -> to the last `rest` pipes
		int t = base + ((pipe_id >= active - rest) ? 1 : 0);
		if (t < 1) t = 1;
		return t;
	}

	// Resets the affinity to the pristine mask captured in init() (all allowed
	// cores) — "scheduler free". No-op if the capture failed (the inherited mask
	// then remains). The master switch is checked by the caller. Fixes fork
	// inheritance for empty/unconfigured lists.
	static void reset_to_default(pid_t tid) {
		if (!default_affinity_valid) return;
		if (sched_setaffinity(tid, sizeof(default_affinity), &default_affinity) != 0)
			LOGERR("[tw_affinity] reset_to_default(tid=%d) failed: %s\n", (int)tid, strerror(errno));
	}

	void apply_single_core_pin(int core, pid_t tid) {
		if (!use_cpu_affinity) return;
		// core < 0 = "not configured" -> un-pin to all cores (do NOT keep the
		// inherited mask). The master switch above covers "no pinning at all".
		if (core < 0) { reset_to_default(tid); return; }
		cpu_set_t cs;
		CPU_ZERO(&cs);
		CPU_SET(core, &cs);
		// Check the return code — pinning is the module's purpose; a silent
		// failure (e.g. EINVAL from an out-of-range BoardConfig core) would go
		// unnoticed otherwise.
		if (sched_setaffinity(tid, sizeof(cs), &cs) != 0)
			LOGERR("[tw_affinity] sched_setaffinity(tid=%d, core=%d) failed: %s\n",
			       (int)tid, core, strerror(errno));
	}

	void apply_core_list_pin(const std::vector<int>& list, pid_t tid) {
		if (!use_cpu_affinity) return;
		cpu_set_t cs;
		CPU_ZERO(&cs);
		bool any = false;
		for (int c : list) {
			if (c >= 0) { CPU_SET(c, &cs); any = true; }
		}
		// Empty list OR all -1 ("not configured" / "no pin for this pipe") =
		// un-pin to all cores. IMPORTANT: a no-op would keep the mask inherited
		// via fork() from a pinned worker (e.g. ZSTD_CORES empty + TAR_WORKER_CORES=
		// 4-7 -> zstd inherits 0xf0 instead of running free). The master switch
		// above covers "no pinning at all".
		if (!any) { reset_to_default(tid); return; }
		// Check the return code (as in apply_single_core_pin); on failure log
		// the core list for diagnostics.
		if (sched_setaffinity(tid, sizeof(cs), &cs) != 0) {
			char cores[64]; size_t off = 0; cores[0] = '\0';
			for (int c : list) {
				if (c >= 0 && off + 5 < sizeof(cores))
					off += snprintf(cores + off, sizeof(cores) - off, "%d ", c);
			}
			LOGERR("[tw_affinity] sched_setaffinity(tid=%d, cores=[%s]) failed: %s\n",
			       (int)tid, cores, strerror(errno));
		}
	}

	// --- GUI pin state machine ------------------------------------------------
	// During backup/restore the GUI sits on gui_efficiency_core so the big
	// cluster belongs to the pipe workers. Measured on-device, a lock-swipe
	// frame there costs 60-70 ms under load vs ~14 ms on the performance core —
	// touch interaction stutters. The touch boost lifts the GUI to
	// gui_performance_core for the touch duration (+5 s tail, gui.cpp) and then
	// restores the efficiency pin. The worker lists stay untouched by design.
	//
	// Thread model: gui_set_efficiency_pin runs in the action/FIFO thread
	// (GuiAffinityGuard, extractTarFork parent), gui_touch_boost_tick ONLY in
	// the GUI thread (runPages). Flags are atomic; sched_setaffinity crossings
	// in the micro-window self-heal via the flag logic on the next tick (last
	// pin wins, the tick corrects based on the flags). The state statics
	// (s_gui_tid, s_gui_on_efficiency, s_gui_touch_boosted) live with the rest
	// of the storage above; s_gui_tid is set by init().
	//
	// Logging: EVERY GUI core switch lands as LOGINFO in the recovery log —
	//   "gui pin -> efficiency/performance core N"  (backup/restore phase change)
	//   "gui touch boost ON/OFF (core N)"           (touch boost in the tick)
	// With use_cpu_affinity=false both functions are complete no-ops (no flags,
	// no logs) — no pinning happens either.

	void gui_set_efficiency_pin(bool efficiency) {
		if (!use_cpu_affinity)
			return;
		if (s_gui_tid == 0)
			s_gui_tid = getpid();
		s_gui_on_efficiency.store(efficiency);
		// A phase change ends a running boost: false pins to performance itself
		// below; true starts the phase deterministically unboosted (the next
		// touch tick re-boosts within one loop iteration).
		s_gui_touch_boosted.store(false);
		int core = efficiency ? gui_efficiency_core : gui_performance_core;
		LOGINFO("[tw_affinity] gui pin -> %s core %d\n",
		        efficiency ? "efficiency" : "performance", core);
		apply_single_core_pin(core, s_gui_tid);
	}

	void gui_touch_boost_tick(bool input_recent) {
		if (!use_cpu_affinity)
			return;
		// Kein Boost, wenn die GUI-Cores nicht konfiguriert sind (perf ODER eff < 0).
		// Der Boost braucht ein P-Ziel (ON) UND ein E-Ziel (OFF-Rueckkehr); fehlt eines,
		// wuerde apply_single_core_pin(-1) nur reset_to_default (un-pin) aufrufen ->
		// Leerlauf-Syscalls + irrefuehrende "core -1"-Logs bei jedem Touch, ohne etwas zu
		// bewegen. In dieser Config regelt der Scheduler die GUI ohnehin (gui_set_efficiency_pin
		// haelt seinen originalen reset_to_default) -> No-op ist korrekt. hotdog (7/2) unberuehrt.
		if (gui_performance_core < 0 || gui_efficiency_core < 0)
			return;
		if (input_recent) {
			if (s_gui_on_efficiency.load() && !s_gui_touch_boosted.load()) {
				if (s_gui_tid == 0)
					s_gui_tid = getpid();
				apply_single_core_pin(gui_performance_core, s_gui_tid);
				s_gui_touch_boosted.store(true);
				LOGINFO("[tw_affinity] gui touch boost ON (core %d)\n", gui_performance_core);
			}
		} else if (s_gui_touch_boosted.load()) {
			s_gui_touch_boosted.store(false);
			// Only re-pin if the efficiency phase is still running — if it ended
			// during the boost, gui_set_efficiency_pin(false) already pinned to
			// performance and cleared the phase flag (that switch was already
			// logged as "gui pin -> performance").
			if (s_gui_on_efficiency.load()) {
				apply_single_core_pin(gui_efficiency_core, s_gui_tid);
				LOGINFO("[tw_affinity] gui touch boost OFF (core %d)\n", gui_efficiency_core);
			}
		}
	}

} // namespace tw_affinity

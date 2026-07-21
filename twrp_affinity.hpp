/*
 * twrp_affinity.hpp -- CPU affinity configuration via BoardConfig flags.
 *
 * Each device decides in its BoardConfig.mk whether and how to pin — the C++
 * code is topology-agnostic. Full documentation:
 * CPU_Affinity_Settings_Documentation.md in the repo root.
 *
 * Init order: tw_affinity::init() MUST run early in twrp.cpp:main() — before
 * gui_start() and before any possible affinity site (MTP fork, log zstd,
 * backup/restore pipelines).
 *
 * -1 convention: -1 in a cores list means "no pinning for this pipe".
 * Negative values or empty lists → no sched_setaffinity call.
 */

#pragma once

#include <string>
#include <vector>

namespace tw_affinity {

	// Hard compile-time limit for array dimensions (PipeFileLists[],
	// child_pids[], pids_[]). The real pipe count at runtime can be smaller.
	// 16 covers every current and foreseeable consumer SoC.
	constexpr int MAX_PIPELINES_HARDCAP = 16;

	// --- Master configuration ---
	extern bool use_cpu_affinity;                  // false default
	extern int  set_max_pipes;                     // -1 = nproc/2 fallback (1 = force single pipe)
	// Unified MAX thread budget (TW_MAX_COMPRESSOR_THREADS) for zstd (-T) AND
	// pigz (-p). -1 = unset -> budget counter = compute_pipe_count() (= MAX_PIPES).
	// If set (>=1) it is the budget COUNTER in the compute_compressor_threads()
	// law (= budget/active), NOT a fixed -T value: it caps -T (e.g. =4 -> 4
	// pipes = -T1, 1 pipe = -T4), so max-pipes never oversubscribes.
	extern int  max_comp_threads;                  // >=1 = fixed budget counter; 0 = all cores (-T0 semantics); -1 = unset -> budget = MAX_PIPES (nproc/2 class)

	// --- Runtime state ---
	// Number of currently active pipes of the running backup/restore. The parent
	// sets it BEFORE the fork loop; pipe children + compressor sub-children
	// inherit it via fork() and read it in compute_compressor_threads() (zstd
	// thread budget). init() defaults it to compute_pipe_count() (=>
	// compute_compressor_threads==1 => -T1).
	extern int  active_pipes;

	// --- Affinity lists (element -1 = no-pin for that slot) ---
	extern std::vector<int> tar_worker_cores;      // tar parent per pipe (all modes)
	extern std::vector<int> zstd_cores;            // zstd sub-child per pipe + -T
	extern std::vector<int> enc_cores;             // AES sub-child per pipe in ENCRYPTED mode (tar + AEAD)
	extern std::vector<int> comp_enc_cores;        // AES sub-child per pipe in COMPRESSED_ENCRYPTED mode (zstd + AEAD)

	// --- Soft/hard-pin flags per list ---
	// true = range notation in BoardConfig ("4-7") = SOFT pin (cluster, never
	// sliced, scheduler distributes freely). false = comma list ("4,5,6,7") =
	// HARD pin (pipe p -> slot p at active==MAX; widened to slices when
	// active<MAX). Set by init().
	extern bool tar_worker_is_cluster;
	extern bool zstd_is_cluster;
	extern bool enc_is_cluster;
	extern bool comp_enc_is_cluster;

	// --- Single-core pinnings (-1 = no pin) ---
	extern int gui_performance_core;               // GUI while idle
	extern int gui_efficiency_core;                // GUI during backup
	extern int mtp_core;                           // MTP child

	// One-time init: reads all TW_* defines, validates, clamps, logs.
	void init();

	// Parser: "4,5,6,7" / "4-7" / "4,5,-1,-1" / "0,2-3,-1" → vector<int>.
	// -1 (or any negative) is taken literally as -1 ("no pin"). is_cluster
	// (optional out) = true if the notation contains a range ("a-b") — soft
	// pin/cluster — else false (hard pin, sliceable).
	std::vector<int> parse_cpu_list(const char* s, bool* is_cluster = nullptr);

	// Core slice for pipe pipe_id with `active` running pipes. is_cluster OR
	// active<=1 -> whole list (soft pin/cluster). Otherwise HARD pin: split the
	// list into `active` contiguous slices, leftover cores go to the LAST slice;
	// returns slice pipe_id. At active==len(list) -> one-core slices. Purely
	// index-based (BoardConfig order). Empty list / use_cpu_affinity==false /
	// pipe_id<0 -> {} (no pin). A -1 element stays in the slice and is skipped
	// by apply_core_list_pin.
	std::vector<int> core_slice(const std::vector<int>& cores, bool is_cluster,
	                            int active, int pipe_id);

	// Resolves the MAX pipe budget: TW_SET_MAX_PIPES (>0), else nproc/2 fallback.
	// Clamped to [1, min(nproc, nproc-2, MAX_PIPELINES_HARDCAP)].
	int compute_pipe_count();

	// Size-dependent pipe count = min( ceil(used_bytes / LADDER_UNIT),
	// compute_pipe_count() ). used_bytes==0 -> 1, so small partitions do not get
	// MAX_PIPES. The parameterless compute_pipe_count() remains the MAX budget
	// (also used by compute_compressor_threads).
	int compute_pipe_count(unsigned long long used_bytes);

	// zstd/pigz thread budget for pipe pipe_id — remainder-free. Budget counter =
	// max_comp_threads (TW_MAX_COMPRESSOR_THREADS, if >=1); ==0 -> nproc (all
	// cores, -T0 semantics); unset (<0) -> compute_pipe_count() (= MAX_PIPES).
	// t = base + (pipe_id among the last `budget%active` pipes ? 1 : 0),
	// base = budget/active. Sum over all pipes == budget (no thread is lost,
	// never oversubscribed). Remainder goes to the LAST pipes — same direction
	// as core_slice(). (For hard pins the caller uses slice.size() instead, see
	// twrpTar comp_thread_count.)
	int compute_compressor_threads(int active_pipes, int pipe_id);

	// sched_setaffinity to a single core. core<0 ("not configured") -> un-pin to
	// the init-time default mask (all cores), NOT keep the inherited mask.
	// Complete no-op only when use_cpu_affinity==false. tid=0 = calling thread.
	void apply_single_core_pin(int core, pid_t tid = 0);

	// sched_setaffinity to all non-(-1) cores in the list. Empty list / all -1
	// ("not configured") -> un-pin to the init-time default mask (all cores),
	// NOT keep the mask inherited from the parent. Complete no-op only when
	// use_cpu_affinity==false.
	void apply_core_list_pin(const std::vector<int>& list, pid_t tid = 0);

	// --- GUI pin state machine ---
	// gui_set_efficiency_pin(): central GUI core switch. true = backup/restore
	// phase -> gui_efficiency_core (frees the big cluster for the workers),
	// false = idle -> gui_performance_core. The only legitimate caller is
	// twrpTar::Set_GUI_Efficiency (GuiAffinityGuard RAII in Run_Backup/
	// Run_Restore + the extractTarFork parent), which delegates here. Maintains
	// the phase flag for the touch boost and ends a running boost
	// (deterministic: every phase starts unboosted, the next touch re-boosts).
	// GUI TID resolved lazily via getpid() (main-thread TID == PID, correct from
	// any calling thread).
	void gui_set_efficiency_pin(bool efficiency);
	// gui_touch_boost_tick(): once per runPages iteration from the GUI thread
	// (gui.cpp). input_recent==true (last input <= 5 s ago) during the
	// efficiency phase -> temporarily lift the GUI to gui_performance_core
	// (touch boost: lock swipe/buttons stay fluid under backup load);
	// input_recent==false -> restore the efficiency pin. If the operation ends
	// during a boost, gui_set_efficiency_pin(false) clears both flags and pins
	// to performance itself -> the tick then does nothing (self-healing, no
	// wrong re-pin). sched_setaffinity is only called on state changes, not per
	// frame.
	void gui_touch_boost_tick(bool input_recent);

} // namespace tw_affinity

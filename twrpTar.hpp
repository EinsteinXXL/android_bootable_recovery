/*
        Copyright 2012 to 2016 bigbiff/Dees_Troy TeamWin
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
}
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <signal.h>   // sigset_t (child_pipe_preamble signature)
#include <atomic>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <vector>
#include <set>        // hardlink inode dedup set
#include <utility>    // std::pair / std::make_pair
#include "exclude.hpp"
#include "progresstracking.hpp"
#include "partitions.hpp"
#include "twrp-functions.hpp"

using namespace std;

struct TarListStruct {
	std::string fn;
	unsigned  thread_id = 0;           // per-file LPT assignment; DIRs stay 0
	                                   // (they go to pipe 0 via the fill loop anyway)
	uint64_t  size = 0;                // 0 for DIR/SYM, st.st_size for REG
	bool      is_dir = false;          // directory-first processing: DIR entries go
	                                   // collectively to the head of pipe 0
	                                   // (size==0 is not enough: SYM/empty REGs)
	bool      is_hardlink_member = false;  // st_nlink>1: routed into the pipe-0 lead +
	                                       // split exemption (the whole set stays in one inode hash)
};

struct thread_data_struct {
	std::vector<TarListStruct> *TarList;
	unsigned thread_id;
};

// Compressor descriptor for the restore decompress path. Encapsulates the
// differences between zstd and pigz decompress (binary + thread flag) so both
// run through the same exec_comp_child()/RestorePipeline path.
// decomp_spec_for() (pipe_operation.cpp) derives it from Archive_Type.
struct DecompSpec {
	const char* binary;     // "zstd" | "pigz"
	bool        flag_is_p;  // true="-p<N>" (pigz); false="-T<N>" (zstd) — fork_zstd builds the arg in the parent
};

class twrpTar {
public:
	twrpTar();
	virtual ~twrpTar();
	int createTarFork(std::atomic<pid_t> *tar_fork_pid);
	int extractTarFork();
	void setfn(string fn);
	void setdir(string dir);
	void setsize(unsigned long long backup_size);
	void setpassword(string pass);
	unsigned long long get_size();
	void Set_Archive_Type(Archive_Type archive_type);
	static void Kill_Backup_Children(void);
	static void Kill_Restore_Children(void);
	// Pause/resume the restore pipeline via SIGSTOP/SIGCONT. Used by the
	// page-entry hook in PageSet::SetPage for cancel_restore_confirm.
	static void Pause_Restore_Children(void);
	static void Resume_Restore_Children(void);
	// GUI affinity switch: true = efficiency core (during backup, frees the big
	// cluster for the workers), false = performance core (idle, snappy UI).
	// Configured via TW_AFFINITY_GUI_EFFICIENCY / TW_AFFINITY_GUI_PERFORMANCE.
	// No-op if the flags are unset or TW_USE_CPU_AFFINITY=false.
	static void Set_GUI_Efficiency(bool efficiency);
	// Pre-wipe validation of the multi-archive sequence. Checks whether
	// basefn[0-9][0-9][0-9] forms a gapless sequence (per pipe archives 0..N-1,
	// pipes 0..K-1 without a jump). Returns false on any gap, true for a single
	// archive or no match (adbbackup stream). Called BEFORE the destructive wipe
	// in Restore_Tar — prevents total data loss on a corrupt backup.
	static bool validate_multi_archive_sequence(const std::string& basefn);

public:
	int use_encryption;
	int userdata_encryption;
	int use_compression;
	int split_archives;
	// Cipher agility: AEAD cipher id of the current backup/restore (0=AES-256-
	// GCM, 1=ChaCha20-Poly1305). Backup: set in createTarFork from the force
	// knob/HWCAP and passed to the filter via setenv("TW_AEAD_CIPHER"); restore:
	// read from the .win000 header. -1 = not yet determined (the banner falls
	// back to the HWCAP heuristic).
	int aead_cipher_id = -1;
	int progress_pipe_fd;
	// DFP signal fd: set in the restore child of pipe 0 to the write end of
	// dfp_pipe, else -1. extractTar() passes it through to tar_extract_all()
	// (signals at the first non-DIR header).
	int dfp_done_fd = -1;
	string partition_name;
	string backup_folder;
	// Restore-side extract exclusion: when non-empty, extractTar()/
	// tar_extract_all() skip all entries equal to/below this archive path (e.g.
	// "/media/0/Android" when the ext-app checkbox is deselected). Default empty
	// = no skip.
	string restore_exclude_path;
	PartitionSettings *part_settings;
	TWExclude *backup_exclusions;

private:
	int extract();
	int createTar();
	int write_global_headers(bool is_plain_tar);    // Writes the TWRP.* PAX g-records (consolidated for createTar plain tar + BackupPipeline::setup); is_plain_tar => +TWRP.tartype=4. -1 on the first th_write_global failure (fatal: without TWRP.backup_size the restore preflight would later reject the backup)
	int addFile(string fn, bool include_root);
	int closeTar();
	int extractTar();
	int closeTarRestore();          // restore-side reap without tar_append_eof
	// Consolidated tier-2 cleanup API with NAMED intent instead of a 3-bool flag
	// salad at the call sites. Both close input_fd/output_fd and delegate the
	// reap to reap_subchildren (comp→crypt order).
	//   finish_pipeline = success close: NO kill, report=true (a sub-child exit
	//     cascades onto the return code); timeout_secs (0=blocking backup,
	//     10=restore hardening). closeTar→(0), closeTarRestore→(10).
	//   abort_pipeline = error close: SIGTERM+reap, report=false (status
	//     irrelevant), returns -1. NO gui_err/unlink (the caller or
	//     PipeOperation::abort handles that). Used where NO PipeOperation object
	//     lives (createTarFork error path, openTar legacy).
	int finish_pipeline(int timeout_secs);
	int abort_pipeline(int timeout_secs);
	// Private reap primitive (single source of truth, comp_pid→crypt_pid). Only
	// called internally by finish_pipeline/abort_pipeline (twrpTar) +
	// PipeOperation::abort (friend) — the flags live only here, not at the call
	// sites. kill_first=SIGTERM before reap; timeout_secs>0=Wait_For_Child_
	// Timeout (restore hardening), else blocking; report_failures → -1 on
	// wrc!=0. Closes NO fds.
	int reap_subchildren(bool kill_first, int timeout_secs, bool report_failures);
	string Strip_Root_Dir(string Path);
	int openTar();
	int Generate_TarList(string Path, std::vector<TarListStruct> *TarList);
	static void* createList(void *cookie);
	int tarList(std::vector<TarListStruct> *TarList, unsigned thread_id);
	unsigned long long uncompressedSize(string filename);
	static void Signal_Kill(int signum);
		static void child_init_pipeline(void);
		// Pin via core slice (vector) instead of a single core. slice = the cores
		// computed by core_slice() for this pipe; apply_core_list_pin(slice)
		// (1 element = single core, several = cluster/soft pin). Empty slice = no pin.
		static void setup_pipeline_child_zstd(int fd_in, int fd_out, const std::vector<int>& slice);
		static void setup_pipeline_child_crypt(int fd_in, int fd_out, int pw_fd_keep, const std::vector<int>& slice);
		// Child preamble right after fork(), shared by createTarFork() +
		// extractTarFork(). progress_pipe/msg_pipe are method locals -> parameters.
		void child_pipe_preamble(int p, int progress_pipe[2], int msg_pipe[2], int sigchld_fd, const sigset_t& old_chld_mask);
		// Child exec bodies right after fork() (dead-end code, always ends in
		// execv/_exit). FORK SAFETY (multi-pipe): the child does ONLY async-
		// signal-safe setup (setup_pipeline_child_*: sigaction/prctl/
		// sched_setaffinity/dup2) + execv with an ABSOLUTE path. ALL allocation/
		// locking (core_slice vector, -T/-N args, DataManager level, binary/path
		// choice) happens in the PARENT (fork_zstd/fork_aes) BEFORE the fork();
		// path/argv are parent-built buffers inherited by the child.
		// exec_comp_child covers zstd compress AND zstd/pigz decompress (the
		// differences are in path/argv). gui_err_msg remains for signature
		// symmetry but is NOT used in the child (no gui_err/LOGERR in the child —
		// the parent reaps and reports).
		static void exec_comp_child(int fd_in, int fd_out, const std::vector<int>& slice, const char* path, const char* const argv[], const char* gui_err_msg);
		static void exec_crypt_child(int fd_in, int fd_out, int pw_pipe[2], const std::vector<int>& slice, const char* const argv[], const char* gui_err_msg);

		// The tier-2 pipeline classes encapsulate the declarative comp/crypt
		// stage engine and store the forked PIDs via write-through into
		// comp_pid/crypt_pid. PipeOperation::abort() (setup errors) uses the
		// private reap_subchildren + tw_ fds via friend. Defined in
		// pipe_operation.cpp.
		friend class PipeOperation;
		friend class BackupPipeline;
		friend class RestorePipeline;

		enum Archive_Type current_archive_type;
	unsigned long long Archive_Current_Size;
	unsigned long long Total_Backup_Size;
	// Exact content sum (every REG inode once, without symlink lengths/hardlink
	// dups == size_backup). Built in the Generate_TarList walk; feeds the
	// g-header TWRP.backup_size AND the backup bar denominator.
	// Total_Backup_Size stays untouched (pipe count/split).
	unsigned long long exact_backup_size;
	// Ext-app-data share (/data/media/0/Android) of exact_backup_size — SAME
	// accounting (inode dedup, content bytes), just the subset under the ext-app
	// inclusion. Feeds the g-header TWRP.ext_app_data_size; the restore
	// subtracts it from the denominator when the checkbox is deselected.
	unsigned long long exact_ext_app_data_size;
	std::set<std::pair<dev_t, ino_t>> seen_hardlink_inodes;   // dedup nlink>1 (reset per backup)
	bool include_root_dir;
	// Single-segment backup: Total_Backup_Size <= MAX_ARCHIVE_SIZE => 1 pipe, no
	// split possible => the first/only archive is plain ".win" without the
	// %i%02i suffix (the original unsplit scheme). Set per pipe by the parent in
	// createTarFork, read in tarList.
	bool single_segment = false;
	// Privacy log (tw_verbose_log): true = log every file/dir (backup: addFile
	// LOGINFO in tarList; restore: TAR_TW_VERBOSE_LOG prints in libtar
	// extract.c), false = errors only. Read from the DataManager in the PARENT
	// of createTarFork/extractTarFork (never in the forked child — lock hazard);
	// the children inherit the value. CLI (BUILD_TWRPTAR_MAIN, no DataManager):
	// stays true.
	bool verbose_log = true;
	TAR *t;
	tartype_t tar_type; // Only used in createTar() but variable must persist while the tar is open
	int fd;
	int input_fd;                                                                   // restore: fd of the .win input that zstd/aes read from (-1 in the plain-tar case)
	pid_t comp_pid;   // compressor/decompressor worker: zstd (backup + DFP restore) or pigz (legacy restore LEGACY_COMPRESSED=1)
	pid_t crypt_pid;
	unsigned long long file_count;

	string tardir;
	string tarfn;
	string basefn;
	string password;

	std::vector<TarListStruct> *ItemList;
	int output_fd;                                                                  // backup: seekable fd of the .win output the zstd/BAES pipeline writes to (in-file cache trim)
	// Output cache trimmer: last byte offset of the CURRENT segment dropped via
	// sync_file_range+FADV_DONTNEED (write-behind, keeps the page-cache peak
	// small). off64_t = 64-bit independent of arch/_FILE_OFFSET_BITS (segments
	// up to MAX_ARCHIVE_SIZE + DFP lead can exceed 2 GB). Reset per segment in
	// createTar(); trimmed via TWFunc::Trim_Output_Cache (caller tarList).
	off64_t output_trim_offset;
	unsigned thread_id;
};

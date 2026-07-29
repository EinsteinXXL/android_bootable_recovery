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
#include <signal.h>   // sigset_t (child_pipe_preamble signature)
#include <atomic>
#include <cstdint>
#include <memory>     // std::unique_ptr<PipeOperation> pipeline_
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

// Per-archive stage pipeline (pipe_operation.hpp). Forward-declared so twrpTar
// can hold the unique_ptr member without pulling the pipeline/engine headers
// into every includer of twrpTar.hpp; the out-of-line destructor in twrpTar.cpp
// (which does include pipe_operation.hpp) destroys it.
class PipeOperation;

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
	// knob/HWCAP and passed to the AES stage as a parameter (spawn_aes_stage ->
	// StageThread::aead_cipher_id); restore: read from the .win000 header (the stream is
	// self-describing, so decrypt never needs it). -1 = not yet determined (the
	// banner falls back to the HWCAP heuristic).
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
	int closeTarRestore();          // restore-side pipeline close (stage join, no tar_append_eof)
	// Cleanup API with NAMED intent. Both are null-safe delegates: they consume
	// pipeline_ (finish()/abort() + reset — the stage join itself lives in
	// PipeOperation::join_stages, comp→aes order), then close input_fd/output_fd
	// (the file ends belong to twrpTar; they can be open without any pipeline on
	// the plain-tar ADB paths).
	//   finish_pipeline = success close: NO poison, a stage rc cascades onto the
	//     return code; timeout_secs bounds each stage join — closeTar passes the
	//     120 s anti-wedge net, closeTarRestore 10 s (restore hardening). Both only
	//     take effect if a stage wedges; a finished stage joins instantly.
	//   abort_pipeline = error close: poison rings + join, stage status
	//     irrelevant, returns -1. NO gui_err/unlink (the caller or
	//     PipeOperation::abort_setup handles that). Called from the createTarFork
	//     error path and the stale-pipeline guards in createTar()/openTar().
	int finish_pipeline(int timeout_secs);
	int abort_pipeline(int timeout_secs);
	string Strip_Root_Dir(string Path);
	int openTar();
	// Restore source prefetch: resolved twrp.restore_prefetch budget in bytes
	// (rolling WILLNEED window ahead of the .win read position; 0 = off). Lazy,
	// cached ONCE per worker (CLI: fixed default). Callers: RestorePipeline::
	// setup (engine modes), the RAW plain-tar branch of openTar() and the
	// next-segment warm-up in extractTarFork().
	long long restore_prefetch_budget();
	int Generate_TarList(string Path, std::vector<TarListStruct> *TarList);
	static void* createList(void *cookie);
	int tarList(std::vector<TarListStruct> *TarList, unsigned thread_id);
	unsigned long long uncompressedSize(string filename);
	static void Signal_Kill(int signum);
		static void child_init_pipeline(void);
		// Child preamble right after fork(), shared by createTarFork() +
		// extractTarFork(). progress_pipe/msg_pipe are method locals -> parameters.
		void child_pipe_preamble(int p, int progress_pipe[2], int msg_pipe[2], int sigchld_fd, const sigset_t& old_chld_mask);

		// The pipeline classes encapsulate the declarative stage engine and own the
		// stage-thread + ring handles. The friend grants cover the file ends
		// (input_fd/output_fd via open_output/open_input), tarfn (open/unlink), t
		// (tar_fdopen), write_global_headers and the wiring params (password,
		// aead_cipher_id, thread_id, verbose_log, current_archive_type, tardir,
		// part_settings, restore_prefetch_budget). Defined in pipe_operation.cpp.
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
	// split possible => the first and only archive is plain ".win" without the
	// %i%02i suffix. Set per pipe by the parent in createTarFork, read in tarList.
	bool single_segment = false;
	// Privacy log (tw_verbose_log): true = log every file/dir (backup: addFile
	// LOGINFO in tarList; restore: TAR_TW_VERBOSE_LOG prints in libtar
	// extract.c), false = errors only. Read from the DataManager in the PARENT
	// of createTarFork/extractTarFork (never in the forked child — lock hazard);
	// the children inherit the value. CLI (BUILD_TWRPTAR_MAIN, no DataManager):
	// stays true.
	bool verbose_log = true;
	TAR *t;
	tartype_t tar_type; // initialised in the ctor, handed to libtar only by createTar()'s plain-tar branches; must persist while the tar is open
	// restore: fd of the input the stage threads read from (a .win segment or the
	// TW_ADB_RESTORE FIFO). Also set for a plain-tar ADB restore, which has no
	// pipeline at all; only the plain-tar FILE restore leaves it at -1.
	int input_fd;
	// Cache for restore_prefetch_budget(): -1 = unresolved, else bytes (0 = off).
	long long restore_prefetch_budget_ = -1;
	// Pipeline of the CURRENT segment: PipeOperation owns
	// the stage threads + rings. Created per segment in createTar()/openTar()
	// (engine modes only), consumed (finish/abort + reset) in finish_pipeline()/
	// abort_pipeline(). null = no active pipeline (plain tar or between
	// segments). Lives only in the worker CHILD after the fork (backup: the
	// fresh pipe_tar object, restore: `this`); the createTarFork/extractTarFork
	// parent never sets it.
	std::unique_ptr<PipeOperation> pipeline_;
	unsigned long long file_count;

	string tardir;
	string tarfn;
	string basefn;
	string password;

	std::vector<TarListStruct> *ItemList;
	// backup: fd of the output the last stage writes to (the .win file, or the
	// TW_ADB_BACKUP FIFO; also set for a plain-tar ADB backup, which has no
	// pipeline). Only in the seekable file case does it additionally drive the
	// in-file cache trim.
	int output_fd;
	// Output cache trimmer: last byte offset of the CURRENT segment dropped via
	// sync_file_range+FADV_DONTNEED (write-behind, keeps the page-cache peak
	// small). off64_t = 64-bit independent of arch/_FILE_OFFSET_BITS (segments
	// up to MAX_ARCHIVE_SIZE + DFP lead can exceed 2 GB). Reset per segment in
	// createTar(); trimmed via TWFunc::Trim_Output_Cache (caller tarList).
	off64_t output_trim_offset;
	unsigned thread_id;
};

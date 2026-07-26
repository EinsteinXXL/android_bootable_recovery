/*
        Copyright 2013 to 2017 TeamWin
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

#define __STDC_FORMAT_MACROS 1
#include <string>
#include <vector>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pthread.h>
#include <zlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>
#include <thread>
#include <chrono>
#include <android-base/properties.h>
#include "twrpAdbBuFifo.hpp"
#include "twcommon.h"
#include "data.hpp"
#include "variables.h"
#include "partitions.hpp"
#include "twrp-functions.hpp"
#include "gui/gui.hpp"
#include "gui/objects.hpp"
#include "gui/pages.hpp"
#include "gui/blanktimer.hpp"
#include "adbbu/twadbstream.h"
#include "adbbu/libtwadbbu.hpp"

twrpAdbBuFifo::twrpAdbBuFifo(void) {
	unlink(TW_ADB_FIFO);
}

// Switch the USB mode -- SSoT of the sideload mechanics, mirrored from
// twrpinstall/adb_install.cpp:64 (SetUsbConfig): set sys.usb.config, then wait
// for sys.usb.state. With a timeout so the detached lifecycle thread does not
// block forever on a USB problem (adb_install uses none -- but it runs
// synchronously in the GUI action path; we run detached).
static bool twadbd_set_usb_config(const std::string& state,
		std::chrono::milliseconds timeout = std::chrono::seconds(15)) {
	android::base::SetProperty("sys.usb.config", state);
	return android::base::WaitForProperty("sys.usb.state", state, timeout);
}

// --- twadbd mode state (file-scope) -----------------------------------------
// g_twadbd_pid: 0=inactive, -1=starting (double-trigger guard), >0=running pid.
// File-scope rather than a class member so the GUI action "adbbucancel"
// (gui/action.cpp, action_page cancel slot) can also end the mode via the free
// functions -- the twrpAdbBuFifo instance lives only locally in twrp.cpp::main.
// g_adbbu_op_ran: did a backup/restore run in this mode cycle? -> the lifecycle
// end then leaves the action_complete result page up instead of jumping to main.
static std::atomic<pid_t> g_twadbd_pid{0};
static std::atomic<bool> g_adbbu_op_ran{false};

bool twrp_adbbu_mode_active(void) {
	return g_twadbd_pid.load() > 0;
}

void twrp_adbbu_cancel_mode(void) {
	pid_t p = g_twadbd_pid;
	if (p > 0) {
		LOGINFO("adbbu cancel: signalling twadbd (pid %d)\n", p);
		kill(p, SIGTERM);
	} else {
		LOGINFO("adbbu cancel: no ADB backup mode active\n");
	}
}

// --- GUI parity mimic (operation_start/_end) ---------------------------------
// The ADB ops run in the FIFO thread but use the GUI run pages
// (backup_run/restore_run) with counters, cancel buttons and completion watchers
// (-> action_complete). For that the var state must match
// GUIAction::operation_start/operation_end (gui/action.cpp); the GUIAction
// methods themselves are not callable here (instance methods of the action
// system). Deliberately NOT mirrored: timing + vibration (cosmetic) and
// property_set("twrp.action_complete") (external watchers should keep seeing only
// real GUI actions).
void twrpAdbBuFifo::ADB_Bu_Operation_Start(const std::string& operation_name) {
	DataManager::SetValue(TW_ACTION_BUSY, 1);
	DataManager::SetValue("ui_progress", 0);
	DataManager::SetValue("ui_portion_size", 0);
	DataManager::SetValue("ui_portion_start", 0);
	DataManager::SetValue("tw_size_progress", "");
	DataManager::SetValue("tw_file_progress", "");
	DataManager::SetValue("tw_operation", operation_name);
	DataManager::SetValue("tw_operation_state", 0);
	DataManager::SetValue("tw_operation_status", 0);
}

// status: 0=success, 1=error, 2=cancel -- same semantics as operation_end /
// Run_Backup/Operation_Cleanup. The order is load-bearing:
//  1. unblank BEFORE every render (EBUSY crash rule, see Wake-on-End),
//  2. status BEFORE state: the run-page watchers AND both conditions together --
//     at the state edge status must already be right, else the wrong branch fires,
//  3. tw_back AFTER state: set/page are caller-thread actions (action.cpp
//     snapshot before the threaded actions) and DataManager::SetValue notifies
//     synchronously -> by the time SetValue(state=1) returns the watchers have
//     already set tw_back=backup/restore_select and switched to action_complete;
//     the override steers the back button (which reads %tw_back% only on click)
//     to main for ADB,
//  4. tw_adb_bu=0 AFTER the page switch: the current page is now action_complete,
//     so the var change can no longer hit the run pages' nandroid-load action.
void twrpAdbBuFifo::ADB_Bu_Operation_End(int status) {
	DataManager::SetValue("ui_progress", 100);
	blankTimer.resetTimerAndUnblank();
	DataManager::SetValue("tw_operation_status", status);
	DataManager::SetValue("tw_operation_state", 1);
	DataManager::SetValue("tw_back", "main");
	DataManager::SetValue(TW_ACTION_BUSY, 0);
	DataManager::SetValue("tw_adb_bu", 0);
}

void twrpAdbBuFifo::Check_Adb_Fifo_For_Events(void) {
	char cmd[512];

	memset(&cmd, 0, sizeof(cmd));

	if (read(adb_fifo_fd, &cmd, sizeof(cmd)) > 0) {
		LOGINFO("adb backup cmd: %s\n", cmd);
		std::string command(cmd);
		// Compare the first token (up to space/NUL) EXACTLY. The ops share the
		// "adbb..." prefix, so a prefix compare would misclassify (e.g. adbbustart
		// as a restore) and any non-adbbackup junk would blindly trigger a restore.
		// Exact token match; unknown ops are ignored.
		std::string op = command.substr(0, command.find(' '));
		if (op == ADB_BACKUP_OP) {
			std::string Options = (command.length() > strlen(ADB_BACKUP_OP))
				? command.substr(strlen(ADB_BACKUP_OP) + 1) : std::string();
			Backup_ADB_Command(Options);
		} else if (op == ADB_RESTORE_OP) {
			Restore_ADB_Backup(false);	// PC adb restore: the engine owns the completion
		} else if (op == ADB_RESTORE_STREAM_OP) {
			Restore_ADB_Backup(true);	// GUI .ab restore: the action thread owns the completion, the engine only reports status
		} else if (op == ADB_BU_MODE_START_OP) {
			Start_ADB_Bu_Mode();
		} else if (op == ADB_BU_MODE_CANCEL_OP) {
			Cancel_ADB_Bu_Mode();
		} else if (op == ADB_BU_NOTICE_OP) {
			Show_ADB_Bu_Notice();
		} else {
			LOGINFO("twrpAdbBuFifo: unknown adb fifo op '%s' -- ignored\n", op.c_str());
		}
	}
}

bool twrpAdbBuFifo::start(void) {
	LOGINFO("Starting Adb Backup FIFO\n");
	unlink(TW_ADB_FIFO);
	if (mkfifo(TW_ADB_FIFO, 06660) != 0) {
		LOGINFO("Unable to mkfifo %s\n", TW_ADB_FIFO);
		return false;
	}
	adb_fifo_fd = open(TW_ADB_FIFO, O_RDONLY | O_NONBLOCK);
	if (adb_fifo_fd < 0) {
		LOGERR("Unable to open TW_ADB_FIFO for reading.\n");
		close(adb_fifo_fd);
		return false;
	}
	while (true) {
		Check_Adb_Fifo_For_Events();
		usleep(8000);
	}
	//Shouldn't get here but cleanup anwyay
	close(adb_fifo_fd);
	return true;
}

pthread_t twrpAdbBuFifo::threadAdbBuFifo(void) {
	pthread_t thread;
	ThreadPtr adbfifo = &twrpAdbBuFifo::start;
	PThreadPtr p = *(PThreadPtr*)&adbfifo;
	pthread_create(&thread, NULL, p, this);
	return thread;
}

bool twrpAdbBuFifo::Backup_ADB_Command(std::string Options) {
	std::vector<std::string> args;
	std::string Backup_List;
	bool adbbackup = true;
	int ret = 0;
	std::string rmopt = "--";

	std::replace(Options.begin(), Options.end(), ':', ' ');
	args = TWFunc::Split_String(Options, " ");

	DataManager::SetValue(TW_USE_COMPRESSION_VAR, 0);
	DataManager::SetValue(TW_SKIP_DIGEST_GENERATE_VAR, 0);

	if (args[1].compare("--twrp") != 0) {
		gui_err("twrp_adbbu_option=--twrp option is required to enable twrp adb backup");
		if (!twadbbu::Write_TWERROR())
			LOGERR("Unable to write to ADB Backup\n");
		sleep(2);
		return false;
	}

	for (unsigned i = 2; i < args.size(); i++) {
		int compress;

		std::string::size_type size = args[i].find(rmopt);
		if (size != std::string::npos)
			args[i].erase(size, rmopt.length());

		if (args[i].compare("compress") == 0) {
			gui_msg("compression_on=Compression is on");
			DataManager::SetValue(TW_USE_COMPRESSION_VAR, 1);
			continue;
		}
		DataManager::GetValue(TW_USE_COMPRESSION_VAR, compress);
		gui_print("%s\n", args[i].c_str());
		std::string path;
		path = "/" + args[i];
		TWPartition* part = PartitionManager.Find_Partition_By_Path(path);
		if (part) {
			Backup_List += path;
			Backup_List += ";";
		}
		else {
			gui_msg(Msg(msg::kError, "partition_not_found=path: {1} not found in partition list")(path));
			if (!twadbbu::Write_TWERROR())
				LOGERR("Unable to write to TWRP ADB Backup.\n");
		return false;
	}
}

	if (Backup_List.empty()) {
		DataManager::GetValue("tw_backup_list", Backup_List);
		if (Backup_List.empty()) {
			gui_err("no_partition_selected=No partitions selected for backup.");
			return false;
		}
	}
	else
		DataManager::SetValue("tw_backup_list", Backup_List);

	// ADB backup runs through the SAME run page as GUI backups (backup_run:
	// file/MB counters from ProgressTracking, fixed cancel button -> cancelbackup,
	// completion watcher -> action_complete) rather than the bare action_page.
	// tw_adb_bu=1 suppresses the page's nandroid-load action (theme condition
	// op="!="), otherwise GUI and ADB backup would start in parallel.
	g_adbbu_op_ran = true;
	DataManager::SetValue("tw_adb_bu", 1);
	ADB_Bu_Operation_Start("ADB Backup");
	gui_changePage("backup_run");

	ret = PartitionManager.Run_Backup(adbbackup);
	DataManager::SetValue(TW_BACKUP_NAME, gui_lookup("auto_generate", "(Auto Generate)"));
	// On error/cancel (ret 1/2) end bu deterministically -- TWENDADB on the
	// control channel (symmetry with Restore_ADB_Backup, which always does this).
	// Important for twadbd mode: bu exit -> the one-shot waiter ends twadbd ->
	// the lifecycle waitpid restores USB/stock-adbd -- even on cancel/error,
	// without a blind SIGTERM (PID recycling). On success Run_Backup wrote the
	// stream trailer (TWENDADB) itself.
	if (ret != 0) {
		// LOGINFO (not LOGERR): this TWENDADB write is pure transport diagnostics
		// and runs AFTER the final marker [BACKUP FAILED/CANCELLED] (already set in
		// Run_Backup/Operation_Cleanup before control returns here -- cannot be
		// reordered). The marker should stay the last GUI console line, so any
		// error goes to the log only.
		if (!twadbbu::Write_TWENDADB())
			LOGINFO("Unable to write TWENDADB to ADB Backup after failure/cancel.\n");
	}
	// Status 0/1/2 (Run_Backup semantics == watcher semantics): the backup_run
	// watchers show Backup Complete/Failed/Cancelled on action_complete, back
	// button -> main (override in the helper). No sleep and no manual page jump --
	// the user never ends up stuck on a button-less page.
	ADB_Bu_Operation_End(ret);
	return ret == 0;
}

bool twrpAdbBuFifo::Restore_ADB_Backup(bool gui_stream) {
	int partition_count = 0;
	std::string Restore_Name;
	struct AdbBackupFileTrailer adbmd5;
	struct PartitionSettings part_settings;
	int adb_control_twrp_fd;
	int adb_control_bu_fd, ret = 0;
	char cmd[512];
	time_t rStart = 0, rStop = 0;	// restore runtime for "[RESTORE COMPLETED IN x SECONDS]" (mirror of Run_Restore)
#ifdef TWRP_RESTORE_DEMO_MODE
	// Demo Phase B: collect successful TWIMG test-restores here and verify them
	// against the live partition only AFTER the stream ends (TWENDADB) -- mirror
	// of Run_Restore Phase B (after rStop, untimed). Hashing mid-stream would only
	// needlessly block bu/host-adb on the full FIFO.
	std::vector<TWPartition*> demo_verify_parts;
#endif

	part_settings.total_restore_size = 0;

	// Per-op log: remember this ADB restore's start offset -- Restore_ADB_Backup
	// does NOT go through Run_Restore (its own funnel); saved via Save_ADB_Recovery_Log.
	PartitionManager.Mark_Operation_Log_Start();

	PartitionManager.Mount_All_Storage();
	LOGINFO("opening TW_ADB_BU_CONTROL\n");
	adb_control_bu_fd = open(TW_ADB_BU_CONTROL, O_WRONLY | O_NONBLOCK);
	LOGINFO("opening TW_ADB_TWRP_CONTROL\n");
	adb_control_twrp_fd = open(TW_ADB_TWRP_CONTROL, O_RDONLY | O_NONBLOCK);
	memset(&adbmd5, 0, sizeof(adbmd5));

	// Clear the stale cancel flag -- mirror of Run_Restore(): without the reset an
	// earlier-cancelled GUI restore would immediately abort the next ADB restore
	// (pipe children exit 253 on stop_restore). Cancel lock defaults CLOSED until
	// the first stream partition is routed (TWFN=filesystem cancelable, TWIMG=RAW
	// locked -- softbrick protection).
	PartitionManager.stop_restore.set_value(0);
	PartitionManager.Set_Restore_Cancelable(0);

	// Same run page as GUI restores (restore_run: MB counters, cancel button with
	// swipe-confirm + RAW lock via tw_restore_cancelable, completion watcher ->
	// action_complete). tw_adb_bu=1 suppresses the page's nandroid-load action (on
	// top of the existing tw_busy condition -- relevant for the direct ADB path,
	// where tw_busy is 0).
	//
	// gui_stream (GUI .ab restore): the GUI action thread (nandroid) already did
	// operation_start (tw_busy=1) AND is already on restore_run. So here NO
	// ADB_Bu_Operation_Start (would reset the action-start counters twice), NO
	// changePage, NO tw_adb_bu=1 (the nandroid-load action fired normally --
	// suppressing it would do nothing and tw_busy=1 prevents a re-fire anyway), NO
	// g_adbbu_op_ran (twadbd-mode only). The action thread owns the completion
	// (operation_end).
	if (!gui_stream) {
		g_adbbu_op_ran = true;
		DataManager::SetValue("tw_adb_bu", 1);
		ADB_Bu_Operation_Start("ADB Restore");
		gui_changePage("restore_run");
	}
	time(&rStart);	// measure runtime from here (mirror of Run_Restore, before the restore loop)

	// ONE cumulative progress tracker over the WHOLE stream (like Run_Restore over
	// all partitions) rather than one tracker PER partition (which made the
	// bar/counters jump back to 0 each partition). The grand denominator comes from
	// the stream header (total_size = estimate sum; 0 for old backups -> built up
	// incrementally per twfilehdr below). The bar is trued up per partition via
	// Finish_Partition_Exact() (restore-side counterpart, see progresstracking.cpp).
	ProgressTracking progress(0);
	bool have_stream_total = false;
	part_settings.progress = &progress;

	while (true) {
		memset(&cmd, 0, sizeof(cmd));
		if (read(adb_control_twrp_fd, cmd, sizeof(cmd)) > 0) {
			struct AdbBackupControlType cmdstruct;

			memset(&cmdstruct, 0, sizeof(cmdstruct));
			memcpy(&cmdstruct, cmd, sizeof(cmdstruct));
			std::string cmdtype = cmdstruct.get_type();
			if (cmdtype == TWSTREAMHDR) {
				struct AdbBackupStreamHeader twhdr;
				memcpy(&twhdr, cmd, sizeof(cmd));
				LOGINFO("ADB Partition count: %" PRIu64 "\n", twhdr.partition_count);
				LOGINFO("ADB version: %" PRIu64 "\n", twhdr.version);
				if (twhdr.version != ADB_BACKUP_VERSION) {
					LOGERR("Incompatible adb backup version!\n");
					ret = false;
					break;
				}
				partition_count = twhdr.partition_count;
				// Grand denominator from the stream header (estimate sum over all
				// partitions; u64-LE@44 via the lo/hi accessor). 0 = an older backup
				// without the field -> the denominator grows incrementally per
				// twfilehdr below.
				uint64_t stream_total = twhdr.get_total_size();
				if (stream_total > 0) {
					LOGINFO("ADB stream total size: %" PRIu64 "\n", stream_total);
					progress.CorrectTotalSize((long long)stream_total);
					have_stream_total = true;
				}
			}
			else if (cmdtype == MD5TRAILER) {
				LOGINFO("Reading ADB Backup MD5TRAILER\n");
				memcpy(&adbmd5, cmd, sizeof(cmd));
			}
			else if (cmdtype == TWMD5) {
				int check_digest;

				DataManager::GetValue(TW_SKIP_DIGEST_CHECK_VAR, check_digest);
				if (check_digest > 0) {
					TWFunc::GUI_Operation_Text(TW_VERIFY_DIGEST_TEXT, gui_parse_text("{@verifying_digest}"));
					gui_msg("verifying_digest=Verifying Digest");
					struct AdbBackupFileTrailer md5check;
					LOGINFO("Verifying md5sums\n");

					memset(&md5check, 0, sizeof(md5check));
					memcpy(&md5check, cmd, sizeof(cmd));
					if (strcmp(md5check.md5, adbmd5.md5) != 0) {
						LOGERR("md5 doesn't match!\n");
						LOGERR("Stored file md5: %s\n", adbmd5.md5);
						LOGERR("ADB Backup check md5: %s\n", md5check.md5);
						ret = false;
						break;
					}
					else {
						LOGINFO("ADB Backup md5 matches\n");
						LOGINFO("Stored file md5: %s\n", adbmd5.md5);
						LOGINFO("ADB Backup check md5: %s\n", md5check.md5);
						continue;
					}
				} else {
					gui_msg("skip_digest=Skipping Digest check based on user setting.");
					continue;
				}

			}
			else if (cmdtype == TWENDADB) {
				LOGINFO("received TWENDADB\n");
				ret = 1;
				break;
			}
			else {
				struct twfilehdr twimghdr;
				memcpy(&twimghdr, cmd, sizeof(cmd));
				std::string cmdstr(twimghdr.type);
				Restore_Name = twimghdr.name;
				part_settings.total_restore_size = twimghdr.size;
				if (cmdtype == TWIMG) {
					LOGINFO("ADB Type: %s\n", twimghdr.type);
					LOGINFO("ADB Restore_Name: %s\n", Restore_Name.c_str());
					LOGINFO("ADB Restore_size: %" PRIu64 "\n", part_settings.total_restore_size);
					string compression = (twimghdr.compressed == 1) ? "compressed" : "uncompressed";
					LOGINFO("ADB compression: %s\n", compression.c_str());
					// basename-tolerant name parse: the backup now writes ONLY the
					// filename into the stream (no fictitious local path). A plain
					// substr(find_last_of("/")) would be pos==npos without a '/' and
					// substr(npos) throws std::out_of_range (= FIFO-thread crash). Still
					// handles old streams WITH a path.
					std::size_t pos = Restore_Name.find_last_of("/");
					std::string Backup_FileName = (pos == std::string::npos)
						? Restore_Name : Restore_Name.substr(pos + 1);
					std::string path = "/" + Backup_FileName.substr(0, Backup_FileName.find_first_of("."));
					part_settings.Part = PartitionManager.Find_Partition_By_Path(path);
					part_settings.Backup_Folder = path;
					part_settings.partition_count = partition_count;
					part_settings.adbbackup = true;
					part_settings.adb_compression = twimghdr.compressed;
					part_settings.PM_Method = PM_RESTORE;
					part_settings.partition_size = twimghdr.size;
					// Cumulative grand tracker (see above): without a stream total,
					// grow the denominator incrementally; then roll the previous
					// partition (SetPartitionSize folds its Finish-exact amount into
					// previous_partitions_size) + set announced; then zero the stale
					// current -> the display sits cleanly on the sum of the finished
					// partitions until the first bytes flow.
					if (!have_stream_total)
						progress.CorrectTotalSize((long long)twimghdr.size);
					progress.SetPartitionSize(twimghdr.size);
					progress.UpdateSize(0);
#ifdef TWRP_RESTORE_DEMO_MODE
					// Demo: Restore_Image_Test only writes a .raw file (never to the
					// real block device) -> cancel is safe. Consistent with the GUI
					// demo (Run_Restore sets cancelable=1 for EVERY partition) and the
					// TWFN branch below. The FIFO read loop in Restore_Image_Test
					// checks stop_restore and discards the partial .raw on abort.
					PartitionManager.Set_Restore_Cancelable(1);
#else
					// Final build: cancel stays locked -- an image then goes via
					// Raw_Read_Write/dd straight to the real block device; aborting
					// mid-write = a half-written image = softbrick. Two-level lock like
					// Run_Restore (GUI button gate + C++ hard lock).
					PartitionManager.Set_Restore_Cancelable(0);
#endif
					if (!PartitionManager.Restore_Partition(&part_settings)) {
						// Cancel (stop_restore set, e.g. via the restore_run cancel
						// button) is NOT an error -> no red LOGERR into the GUI console
						// (LOGERR = gui_print_color("error"), see twcommon.h). The final
						// status classification below turns it into [RESTORE CANCELLED]
						// (op_status 2); a real error stays red.
						if (PartitionManager.stop_restore.get_value() != 0)
							LOGINFO("ADB Restore cancelled by user.\n");
						else
							LOGERR("ADB Restore failed.\n");
						ret = false;
						break;
					}
					// Align announced (image/estimate size) to the bytes actually
					// written (zstd-super: decompressed bytes).
					progress.Finish_Partition_Exact();
#ifdef TWRP_RESTORE_DEMO_MODE
					// Demo: remember the Phase-B candidate (Restore_Image_Test set
					// Demo_Test_Pending); verification happens AFTER TWENDADB.
					if (part_settings.Part && part_settings.Part->Demo_Test_Pending)
						demo_verify_parts.push_back(part_settings.Part);
#endif
				}
				else if (cmdtype == TWFN) {
					LOGINFO("ADB Type: %s\n", twimghdr.type);
					LOGINFO("ADB Restore_Name: %s\n", Restore_Name.c_str());
					LOGINFO("ADB Restore_size: %" PRIi64 "\n", part_settings.total_restore_size);
					string compression = (twimghdr.compressed == 1) ? "compressed" : "uncompressed";
					LOGINFO("ADB compression: %s\n", compression.c_str());
					// basename-tolerant name parse -- mirror of the TWIMG branch above
					// (the detailed comment is there).
					std::size_t pos = Restore_Name.find_last_of("/");
					std::string Backup_FileName = (pos == std::string::npos)
						? Restore_Name : Restore_Name.substr(pos + 1);
					std::string path = "/" + Backup_FileName.substr(0, Backup_FileName.find_first_of("."));
					part_settings.Part = PartitionManager.Find_Partition_By_Path(path);
					part_settings.Part->Set_Backup_FileName(Backup_FileName);
					PartitionManager.Set_Restore_Files(path);

					if (path.compare(PartitionManager.Get_Android_Root_Path()) == 0) {
						if (part_settings.Part->Is_Read_Only()) {
							if (!twadbbu::Write_TWERROR())
								LOGERR("Unable to write to TWRP ADB Backup.\n");
							gui_msg(Msg(msg::kError, "restore_read_only=Cannot restore {1} -- mounted read only.")(part_settings.Part->Backup_Display_Name));
							ret = false;
							break;

						}
					}
					part_settings.partition_count = partition_count;
					part_settings.adbbackup = true;
					part_settings.adb_compression = twimghdr.compressed;
					// Get_Restore_Size in the adb branch (partition.cpp) caches only
					// twimghdr.size as Restore_Size -- Restore_Tar feeds that into
					// SetPartitionSize. A `total_restore_size +=` addition is wrong
					// here: it would run on the non-existent stream "file"
					// (tar.get_size() -> 0/garbage) and skew the denominator.
					part_settings.Part->Get_Restore_Size(&part_settings);
					part_settings.PM_Method = PM_RESTORE;
					// Cumulative grand tracker: denominator/roll/current as in the
					// TWIMG branch (Restore_Tar does NOT roll itself in adb mode).
					if (!have_stream_total)
						progress.CorrectTotalSize((long long)twimghdr.size);
					progress.SetPartitionSize(twimghdr.size);
					progress.UpdateSize(0);
					// Filesystem restore: cancelable (restore_run cancel button ->
					// swipe-confirm -> cancelrestore -> stop_restore + kill of the
					// extract children; pause/resume on the confirm page included).
					PartitionManager.Set_Restore_Cancelable(1);
					if (!PartitionManager.Restore_Partition(&part_settings)) {
						// Cancel (stop_restore set, e.g. via the restore_run cancel
						// button) is NOT an error -> no red LOGERR into the GUI console
						// (LOGERR = gui_print_color("error"), see twcommon.h). The final
						// status classification below turns it into [RESTORE CANCELLED]
						// (op_status 2); a real error stays red.
						if (PartitionManager.stop_restore.get_value() != 0)
							LOGINFO("ADB Restore cancelled by user.\n");
						else
							LOGERR("ADB Restore failed.\n");
						ret = false;
						break;
					}
					PartitionManager.Set_Restore_Cancelable(0);
					// Align announced (backup estimate) to the bytes actually
					// extracted -> bar/counters byte-exact.
					progress.Finish_Partition_Exact();
				}
			}
		}
	}

	// Wake-on-End: wake/unblank the screen BEFORE the completion message +
	// changePage("main") are rendered. The ADB path does NOT go through
	// GUIAction::operation_end -- without this resetTimerAndUnblank() (mirror of
	// action.cpp:552) the final flip would hit DRM turned off by blankTimer
	// (gr_fb_blank) -> drmModePageFlip EBUSY -> gr_draw=NULL -> segfault/crash (a
	// long restore blanks mid-run and would crash at the end). GUI restores do NOT
	// crash for exactly this reason -- they have always done this here.
	blankTimer.resetTimerAndUnblank();
	time(&rStop);	// end of restore data (before verify/cleanup, mirror of Run_Restore rStop)
	// Close the cancel lock (error/cancel breaks would otherwise leave it open).
	PartitionManager.Set_Restore_Cancelable(0);
#ifdef TWRP_RESTORE_DEMO_MODE
	// Demo Phase B (UNTIMED, mirror of Run_Restore after rStop): now -- after the
	// complete stream (TWENDADB) -- hash the test-restored images against the live
	// partition (Verify_Image_Test, O_RDONLY only). Only on success: after
	// error/cancel the .raw is already discarded / the stream is incomplete. The
	// screen is awake from the unblank above (Verify prints GUI lines). The result
	// does not change op_status -- exactly as in the GUI case.
	if (ret != false) {
		for (std::vector<TWPartition*>::iterator it = demo_verify_parts.begin();
		     it != demo_verify_parts.end(); ++it) {
			if ((*it)->Demo_Test_Pending)
				(*it)->Verify_Image_Test();
		}
	}
#endif
	// Status classification like Run_Restore/Operation_Cleanup: separate cancel
	// (stop_restore set, e.g. via the restore_run cancel button) from a real error.
	int op_status;
	if (ret != false) {
		// Console closing message like the GUI restore (Run_Restore:restore_completed):
		// "[RESTORE COMPLETED IN x SECONDS]" instead of just "Restore Complete". The
		// action_complete page still shows "Restore Complete" (restore_run watcher).
		gui_msg(Msg(msg::kHighlight, "restore_completed=[RESTORE COMPLETED IN {1} SECONDS]")((int)difftime(rStop, rStart)));
		op_status = 0;
	} else if (PartitionManager.stop_restore.get_value() != 0) {
		gui_msg(Msg(msg::kHighlight, "restore_cancel=[RESTORE CANCELLED]"));
		op_status = 2;
	} else {
		// Final status marker (always the last line) like the GUI restore
		// (Operation_Cleanup:1407). The SPECIFIC error message (restore_error
		// "Error during restore process." / md5/version error) already came from the
		// restore engine or the break site -- NOT repeated here, else it doubles.
		gui_msg(Msg(msg::kError, "restore_fail=[RESTORE FAILED]"));
		op_status = 1;
	}

	// gui_stream (GUI .ab restore): record the real status HERE, BEFORE TWENDADB
	// goes out -- after that bu ends, `stream_adb_backup` returns in the GUI action
	// thread and reads the var. The order is race-free by construction (the var is
	// set before bu can end). The action thread then does the completion
	// (operation_end with this status, vibration, twrp.action_complete, back ->
	// restore_select) -- one owner, like a normal GUI restore.
	if (gui_stream)
		DataManager::SetValue("tw_adbbu_stream_status", op_status);

	if (!twadbbu::Write_TWENDADB())
		ret = false;
	// PC adb restore: the engine owns the completion (restore_run watcher ->
	// action_complete Complete/Failed/Cancelled, back -> main). NOT in the
	// gui_stream case -- the action thread does that (see above), else two state=1
	// edges.
	if (!gui_stream)
		ADB_Bu_Operation_End(op_status);
	// Save recovery.log -- mirror of GUI restore practice (both the success and
	// cleanup paths there). The ADB path used to bypass both sites (neither
	// Run_Restore nor Operation_Cleanup involved) -> no log at all. Dated name in
	// the backup root, since there is no (user-nameable) backup folder.
	PartitionManager.Save_ADB_Recovery_Log("Restore");
	// Close adb_control_twrp_fd: otherwise every ADB restore leaks a read fd on
	// /tmp/twadbtwrpcontrol (bu unlinks the FIFO at process exit, but the dead
	// inode stays open in the recovery process).
	if (adb_control_twrp_fd >= 0)
		close(adb_control_twrp_fd);
	close(adb_control_bu_fd);
	return ret;
}

// --- PTY-free ADB backup mode (twadbd) --------------------------------------
// Triggered via `adb shell adbbu start` (opcode over TW_ADB_FIFO). Mirrors
// twrp_sideload (twrpinstall/adb_install.cpp): stop stock adbd, start twadbd for
// the duration of a backup/restore, then stock adbd again. The lifecycle runs
// DETACHED so this FIFO thread stays free -- during the backup it must accept
// bu's "adbbackup ..." op and drive the engine.

bool twrpAdbBuFifo::Start_ADB_Bu_Mode(void) {
	if (g_twadbd_pid != 0) {
		gui_print("ADB backup mode is already active.\n");
		return false;
	}
	g_twadbd_pid = -1;  // double-trigger guard until the lifecycle sets the real pid
	std::thread([this]() { ADB_Bu_Mode_Lifecycle(); }).detach();
	return true;
}

bool twrpAdbBuFifo::Cancel_ADB_Bu_Mode(void) {
	// Delegates to the free function -- the same mechanics used by the GUI action
	// "adbbucancel" (action_page cancel button during the mode).
	if (twrp_adbbu_mode_active()) {
		twrp_adbbu_cancel_mode();
		return true;
	}
	LOGINFO("adbbu cancel: no ADB backup mode active\n");
	return false;
}

void twrpAdbBuFifo::Show_ADB_Bu_Notice(void) {
	// bu refused a freeze-prone stock-adbd PTY (no patch, no twadbd) -> notify the
	// user ON THE DEVICE: wake the screen, red message, show the log overlay
	// (slideout). Overlay instead of a page -> lays over the current page, tap to
	// dismiss (no action_page navbar trap).
	blankTimer.resetTimerAndUnblank();
	gui_err("adbbu_stock_refused=Direct 'adb backup/restore' is disabled here: stock adbd uses a freeze-prone PTY. On the PC run:  adb shell adbbu start  then retry your backup/restore.");
	gui_changeOverlay("slideout");
}

void twrpAdbBuFifo::ADB_Bu_Mode_Lifecycle(void) {
	// Mode cycle begins: no op has run yet (controls below whether we jump to main
	// at the end). Clear the suppress var defensively in case an earlier cycle
	// aborted hard.
	g_adbbu_op_ran = false;
	DataManager::SetValue("tw_adb_bu", 0);

	// Show the action_page (with <console>) so the user sees the mode messages
	// ("Ready. Run: adb backup ...") -- otherwise the trigger sits on the main page
	// and never sees the console text. The actual backup/restore then switches to
	// the GUI run page itself (backup_run/restore_run). Enable the action_page
	// cancel slot: the button is visible ONLY at tw_has_cancel=1 -- i.e. exactly
	// while the mode runs -- and ends twadbd immediately via the GUI action
	// "adbbucancel" (manual exit; needs no working adb: during the mode `adb shell`
	// is exactly NOT available).
	DataManager::SetValue("tw_action", "clear");
	DataManager::SetValue("tw_action_text1", "ADB Backup/Restore Mode");
	DataManager::SetValue("tw_action_text2", "");
	DataManager::SetValue("tw_cancel_action", "adbbucancel");
	DataManager::SetValue("tw_cancel_param", "");
	DataManager::SetValue("tw_has_cancel", 1);
	// Wake the screen as soon as the mode starts (`adb shell adbbu start`) -- the
	// user should see the "Ready. Run: adb backup ..." prompt even if the screen
	// was off/blanked. Unblank BEFORE changePage (EBUSY rule, see Wake-on-End);
	// thread-safe (blankTimer is mutex-protected).
	blankTimer.resetTimerAndUnblank();
	gui_changePage("action_page");

	// Shared GUI end for ALL mode exits (normal, timeout, button, USB error paths):
	// clear the cancel slot; go to the main page ONLY if no backup/restore ran --
	// otherwise action_complete is up with the result + its own buttons and must
	// not be torn away.
	auto mode_cleanup_gui = []() {
		DataManager::SetValue("tw_has_cancel", 0);
		DataManager::SetValue("tw_cancel_action", "");
		blankTimer.resetTimerAndUnblank();
		if (!g_adbbu_op_ran)
			gui_changePage("main");
	};

	// Save the initial state (usually "mtp,adb") to return there exactly afterwards
	// -> stock adbd starts via the existing rc rules.
	std::string usb_state = android::base::GetProperty("sys.usb.state", "none");

	// Mode texts in YELLOW (msg::kWarning -> console.cpp maps to the theme warning
	// color) -- clearly set apart from the normal log.
	gui_msg(Msg(msg::kWarning, "adbbu_preparing=Preparing ADB backup mode..."));
	// Short grace so the triggering `adb shell adbbu start` connection can end
	// cleanly before we stop adbd.
	usleep(800000);

	if (usb_state != "none" && !twadbd_set_usb_config("none")) {
		LOGERR("ADB backup mode: failed to stop stock adbd (usb config none)\n");
		g_twadbd_pid = 0;
		mode_cleanup_gui();
		return;
	}

	pid_t pid = fork();
	if (pid == 0) {
		execl("/system/bin/twadbd", "twadbd", (char*)nullptr);
		_exit(127);
	}
	if (pid < 0) {
		LOGERR("ADB backup mode: failed to fork twadbd\n");
		g_twadbd_pid = 0;
		twadbd_set_usb_config("none");
		if (usb_state != "none") twadbd_set_usb_config(usb_state);
		mode_cleanup_gui();
		return;
	}
	g_twadbd_pid = pid;

	// Bring USB up in the sideload config (without `start adbd`); twadbd grabs the
	// ffs.adb endpoints and sets sys.usb.ffs.ready -> WaitForProperty matches.
	if (!twadbd_set_usb_config("sideload")) {
		LOGERR("ADB backup mode: twadbd USB bring-up timed out -- aborting mode\n");
		kill(pid, SIGTERM);
		waitpid(pid, nullptr, 0);
		g_twadbd_pid = 0;
		twadbd_set_usb_config("none");
		if (usb_state != "none") twadbd_set_usb_config(usb_state);
		mode_cleanup_gui();
		return;
	}

	gui_msg(Msg(msg::kWarning, "adbbu_ready=ADB backup mode ready. On the PC you can now run your backup or restore as usual with 'adb backup/restore'."));
	// Timeout pre-warning: without the hint the automatic idle exit looks like an
	// error/connection drop.
	gui_msg(Msg(msg::kWarning, "adbbu_idle_hint=If no backup/restore follows, this mode turns off automatically after {1} minutes.")(TWADBD_IDLE_SECS / 60));

	// Wait for twadbd to end (one-shot after the backup / idle timeout / cancel).
	int status = 0;
	waitpid(pid, &status, 0);
	g_twadbd_pid = 0;
	// Distinguish idle timeout (the twadbd SIGALRM handler exits with
	// TWADBD_EXIT_IDLE_TIMEOUT) from a normal one-shot end (exit 0) and SIGTERM
	// (cancel button / adbbu cancel) -> specific end message below.
	bool timed_out = WIFEXITED(status) && WEXITSTATUS(status) == TWADBD_EXIT_IDLE_TIMEOUT;

	// Restore the normal adb state -> stock adbd back.
	twadbd_set_usb_config("none");
	if (usb_state != "none")
		twadbd_set_usb_config(usb_state);

	// Clear the cancel slot + Wake-on-End; only touch the page if no op ran
	// (otherwise action_complete is showing the backup/restore result).
	mode_cleanup_gui();
	if (timed_out)
		gui_msg(Msg(msg::kWarning, "adbbu_stopped_timeout=ADB backup mode was stopped after timeout ({1} min). Default ADB was restored.")(TWADBD_IDLE_SECS / 60));
	else
		gui_msg(Msg(msg::kWarning, "adbbu_stopped=ADB backup mode stopped. Default ADB was restored."));
}

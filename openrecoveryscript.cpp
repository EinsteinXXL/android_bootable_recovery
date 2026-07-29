/*
	Copyright 2003 to 2021 TeamWin
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <vector>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <iterator>
#include <algorithm>
#include <regex>
#include <sys/types.h>
#include <sys/wait.h>
#include <zlib.h>

#include "twrp-functions.hpp"
#include "partitions.hpp"
#include "twcommon.h"
#include "openrecoveryscript.hpp"
#include "progresstracking.hpp"
#include "variables.h"
#include "install/adb_install.h"
#include "data.hpp"
#include "fuse_sideload.h"
#include "gui/gui.hpp"
#include "gui/pages.hpp"
#include "orscmd/orscmd.h"
#include "twinstall.h"
#include "twinstall/adb_install.h"
extern "C" {
	#include "gui/gui.h"
	#include "cutils/properties.h"
}

OpenRecoveryScript::StatusFunction OpenRecoveryScript::call_after_cli_command;

#define SCRIPT_COMMAND_SIZE 512

// Defined below next to Backup_Command; needed earlier by run_script_file
// (restore password pre-check).
static bool Ors_Password_Valid(const std::string& pw);

int OpenRecoveryScript::check_for_script_file(void) {
	std::string logDir = TWFunc::get_log_dir();
	std::string orsFile;
	if (logDir == DATA_LOGS_DIR)
		orsFile = "/data/cache";
	else
		orsFile = logDir;
	orsFile += "/recovery/openrecoveryscript";
	if (!PartitionManager.Mount_By_Path(orsFile, false)) {
		LOGINFO("Unable to mount %s for OpenRecoveryScript support.\n", logDir.c_str());
		gui_msg(Msg(msg::kError, "unable_to_mount=Unable to mount {1}")(logDir.c_str()));
		return 0;
	}
	if (TWFunc::Path_Exists(orsFile)) {
		LOGINFO("Script file found: '%s'\n", orsFile.c_str());
		// Copy script file to /tmp
		TWFunc::copy_file(orsFile, SCRIPT_FILE_TMP, 0755);
		// Delete the file from cache
		unlink(orsFile.c_str());
		return 1;
	}
	return 0;
}

int OpenRecoveryScript::copy_script_file(string filename) {
	if (TWFunc::Path_Exists(filename)) {
		LOGINFO("Script file found: '%s'\n", filename.c_str());
		if (filename == SCRIPT_FILE_TMP)
			return 1; // file is already in the right place
		// Copy script file to /tmp
		TWFunc::copy_file(filename, SCRIPT_FILE_TMP, 0755);
		// Delete the old file
		unlink(filename.c_str());
		return 1;
	}
	return 0;
}

int OpenRecoveryScript::run_script_file(void) {
	int ret_val = 0, cindex, line_len, i, remove_nl, install_cmd = 0, sideload = 0;
	char script_line[SCRIPT_COMMAND_SIZE], command[SCRIPT_COMMAND_SIZE],
	     value[SCRIPT_COMMAND_SIZE], mount[SCRIPT_COMMAND_SIZE],
	     value1[SCRIPT_COMMAND_SIZE], value2[SCRIPT_COMMAND_SIZE];
	char *val_start, *tok;

	FILE *fp = fopen(SCRIPT_FILE_TMP, "r");
	if (fp != NULL) {
		// Consume the script immediately (unlink BEFORE processing): if recovery
		// dies mid-run, a leftover file would be appended to by the next twrp CLI
		// call (Insert_ORS_Command) — the stale line would then be replayed
		// unintentionally (potentially an unwanted restore) and the new one never
		// read (the loop stops at ret_val != 0). The open FILE* keeps reading the
		// unlinked inode to EOF (POSIX).
		unlink(SCRIPT_FILE_TMP);
		DataManager::SetValue(TW_SIMULATE_ACTIONS, 0);
		DataManager::SetValue("ui_progress", 0); // Reset the progress bar
		while (fgets(script_line, SCRIPT_COMMAND_SIZE, fp) != NULL && ret_val == 0) {
			cindex = 0;
			line_len = strlen(script_line);
			if (line_len < 2)
				continue; // there's a blank line or line is too short to contain a command
			//gui_print("script line: '%s'\n", script_line);
			for (i=0; i<line_len; i++) {
				if ((int)script_line[i] == 32) {
					cindex = i;
					i = line_len;
				}
			}
			memset(command, 0, sizeof(command));
			memset(value, 0, sizeof(value));
			if ((int)script_line[line_len - 1] == 10)
				remove_nl = 2;
			else
				remove_nl = 1;
			if (cindex != 0) {
				strncpy(command, script_line, cindex);
				LOGINFO("command is: '%s'\n", command);
				val_start = script_line;
				val_start += cindex + 1;
				if ((int) *val_start == 32)
					val_start++; //get rid of space
				if ((int) *val_start == 51)
					val_start++; //get rid of = at the beginning
				if ((int) *val_start == 32)
					val_start++; //get rid of space
				strncpy(value, val_start, line_len - cindex - remove_nl);
				// Password masking: for backup/restore replace everything after the
				// first ':' with '****' — the password must never reach recovery.log.
				if ((strcmp(command, "backup") == 0 || strcmp(command, "restore") == 0) && strchr(value, ':') != NULL) {
					string masked_value(value);
					masked_value = masked_value.substr(0, masked_value.find(':') + 1) + "****";
					LOGINFO("value is: '%s'\n", masked_value.c_str());
				} else {
					LOGINFO("value is: '%s'\n", value);
				}
			} else {
				strncpy(command, script_line, line_len - remove_nl + 1);
				gui_print("command is: '%s' and there is no value\n", command);
			}
			if (strcmp(command, "install") == 0) {
				// Install Zip
				DataManager::SetValue("tw_action_text2", "Installing Zip");
				ret_val = Install_Command(value);
				install_cmd = -1;
			} else if (strcmp(command, "wipe") == 0) {
				// Wipe
				if (strcmp(value, "cache") == 0 || strcmp(value, "/cache") == 0) {
					PartitionManager.Wipe_By_Path("/cache");
				} else if (strcmp(value, "system") == 0 || strcmp(value, "/system") == 0 || strcmp(value, PartitionManager.Get_Android_Root_Path().c_str()) == 0) {
					PartitionManager.Wipe_By_Path("/system");
					PartitionManager.Update_System_Details();
				} else if (strcmp(value, "dalvik") == 0 || strcmp(value, "dalvick") == 0 || strcmp(value, "dalvikcache") == 0 || strcmp(value, "dalvickcache") == 0) {
					PartitionManager.Wipe_Dalvik_Cache();
				} else if (strcmp(value, "data") == 0 || strcmp(value, "/data") == 0 || strcmp(value, "factory") == 0 || strcmp(value, "factoryreset") == 0) {
					PartitionManager.Factory_Reset();
				} else {
					LOGERR("Error with wipe command value: '%s'\n", value);
					ret_val = 1;
				}
			} else if (strcmp(command, "format") == 0) {
				// Format
				if (strcmp(value, "data") == 0 || strcmp(value, "/data") == 0 || strcmp(value, "factory") == 0 || strcmp(value, "factoryreset") == 0) {
					PartitionManager.Format_Data();
				} else {
					LOGERR("Error with format command value: '%s'\n", value);
					ret_val = 1;
				}
			} else if (strcmp(command, "backup") == 0) {
				// Backup
				DataManager::SetValue("tw_action_text2", gui_parse_text("{@backing}"));
				// Pass the whole value ("codes [name]:password") to Backup_Command —
				// it splits codes/name/password at the FIRST ':' itself, so a
				// password containing spaces is validated as a whole instead of
				// being cut at the space, and the backup name before the ':' survives.
				ret_val = Backup_Command(value);
			} else if (strcmp(command, "restore") == 0) {
				// Restore
				DataManager::SetValue("tw_action_text2", gui_parse_text("{@ors_restore}"));
				PartitionManager.Mount_All_Storage();
				DataManager::SetValue(TW_SKIP_DIGEST_CHECK_VAR, 1);
				char folder_path[512], partitions[512];

				string val = value, restore_folder, restore_partitions, Password;
				bool has_password = false;
				// Split the password at the FIRST ':' (format: <folder> [codes]:<password>).
				// Everything after it is the password (spaces are later rejected by
				// Ors_Password_Valid); "<folder> [codes]" remains for the split below.
				size_t pw_colon = val.find(':');
				if (pw_colon != string::npos) {
					Password = val.substr(pw_colon + 1);
					has_password = true;
					val = val.substr(0, pw_colon);
				}
				DataManager::SetValue("tw_restore_password", Password);
				// Split folder/codes via regex (mirrors the backup syntax): folder
				// first (may contain spaces), optional codes as the last token. The
				// alphabet is the SAME as for backup (S/D/C/R/B/A/E/M + O/X) so backup
				// code strings can be reused 1:1. O (compression) and X (encryption)
				// are silent no-ops here — both are auto-detected on restore
				// (Set_Restore_Files/tw_restore_encrypted, password via :pw) and have
				// no code branch or partition name below. A last token that is not a
				// valid code string belongs entirely to the folder, so folder names
				// with spaces are handled correctly.
				std::smatch rm;
				static const std::regex restore_mask("^(.+?)(?: +([SsDdCcRrBbAaEeOoMmXx]+))?$");
				if (std::regex_match(val, rm, restore_mask)) {
					restore_folder = rm[1].str();
					restore_partitions = rm[2].str();
				} else {
					restore_folder = val;
				}
				strcpy(partitions, restore_partitions.c_str());
				strcpy(folder_path, restore_folder.c_str());
				LOGINFO("Restore folder is: '%s' and partitions: '%s'\n", folder_path, partitions);
				gui_msg(Msg("restoring=Restoring {1}...")(folder_path));

				if (folder_path[0] != '/') {
					char backup_folder[512];
					string folder_var;
					std::vector<PartitionList> Storage_List;

					PartitionManager.Get_Partition_List("storage", &Storage_List);
					int listSize = Storage_List.size();
					for (int i = 0; i < listSize; i++) {
						if (PartitionManager.Is_Mounted_By_Path(Storage_List.at(i).Mount_Point)) {
							DataManager::SetValue("tw_storage_path", Storage_List.at(i).Mount_Point);
							DataManager::GetValue(TW_BACKUPS_FOLDER_VAR, folder_var);
							sprintf(backup_folder, "%s/%s", folder_var.c_str(), folder_path);
							if (TWFunc::Path_Exists(backup_folder)) {
								strcpy(folder_path, backup_folder);
								break;
							}
						}
					}
				} else {
					if (folder_path[strlen(folder_path) - 1] == '/')
						strcat(folder_path, ".");
					else
						strcat(folder_path, "/.");
				}
				if (!TWFunc::Path_Exists(folder_path)) {
					gui_msg(Msg(msg::kError, "locate_backup_err=Unable to locate backup '{1}'")(folder_path));
					ret_val = 1;
					continue;
				}
				DataManager::SetValue("tw_restore", folder_path);

				PartitionManager.Set_Restore_Files(folder_path);
				string Partition_List;
				int is_encrypted = 0;
				DataManager::GetValue("tw_restore_encrypted", is_encrypted);
				DataManager::GetValue("tw_restore_list", Partition_List);
				if (strlen(partitions) != 0) {
					string Restore_List;
					bool any_partition_code = false;

					memset(value2, 0, sizeof(value2));
					strcpy(value2, partitions);
					// Collect the partition names matching the codes (input order) for the message.
					string opt_names;
					for (int j = 0; value2[j]; j++) {
						const char* mp = NULL;
						switch (value2[j]) {
							case 'S': case 's': mp = "/system"; break;
							case 'D': case 'd': mp = "/data"; break;
							case 'C': case 'c': mp = "/cache"; break;
							case 'R': case 'r': mp = "/recovery"; break;
							case 'B': case 'b': mp = "/boot"; break;
							case 'A': case 'a': mp = "/and-sec"; break;
							case 'E': case 'e': mp = "/sd-ext"; break;
							default: break;
						}
						if (mp) {
							if (!opt_names.empty()) opt_names += ", ";
							opt_names += mp;
						}
					}
					string opt_suffix = opt_names.empty() ? "" : " (" + opt_names + ")";
					gui_msg(Msg("set_restore_opt=Setting restore options: '{1}'{2}:")(value2)(opt_suffix));

					// Only restore a requested partition if it is in the backup; skip
					// missing ones with a notice (mirrors the backup pre-filter).
					auto add_restore_if_present = [&](const char* mp, const char* opt_msg) {
						any_partition_code = true;
						string entry = string(mp) + ";";
						if (Partition_List.find(entry) != string::npos) {
							Restore_List += entry;
							gui_msg(opt_msg);
						} else {
							gui_msg(Msg(msg::kWarning, "ors_restore_part_missing=Partition '{1}' is not in this backup -- skipping.")(mp));
						}
					};

					line_len = strlen(value2);
					for (i=0; i<line_len; i++) {
						char c = value2[i];
						if (c == 'S' || c == 's') {
							add_restore_if_present("/system", "system=System");
						} else if (c == 'D' || c == 'd') {
							add_restore_if_present("/data", "data=Data");
						} else if (c == 'C' || c == 'c') {
							add_restore_if_present("/cache", "cache=Cache");
						} else if (c == 'R' || c == 'r') {
							add_restore_if_present("/recovery", "recovery=Recovery");
						} else if (c == 'B' || c == 'b') {
							add_restore_if_present("/boot", "boot=Boot");
						} else if (c == 'A' || c == 'a') {
							add_restore_if_present("/and-sec", "android_secure=Android Secure");
						} else if (c == 'E' || c == 'e') {
							add_restore_if_present("/sd-ext", "sdext=SD-EXT");
						} else if (c == 'M' || c == 'm') {
							DataManager::SetValue(TW_SKIP_DIGEST_CHECK_VAR, 0);
							gui_msg("digest_check_skip=Digest check skip is on");
						}
					}

					// Partitions were requested but NONE of them is in the backup -> clean abort.
					if (any_partition_code && Restore_List.empty()) {
						gui_err("ors_restore_no_match=None of the requested partitions are in this backup.");
						ret_val = 1;
						continue;
					}
					// Non-empty -> only those; switches only (M) without a partition -> everything in the backup.
					if (Restore_List.empty())
						DataManager::SetValue("tw_restore_selected", Partition_List);
					else
						DataManager::SetValue("tw_restore_selected", Restore_List);
				} else {
					// No codes -> everything in the backup. Names come from Partition_List.
					string all_names;
					size_t np_start = 0, np_end;
					while ((np_end = Partition_List.find(';', np_start)) != string::npos) {
						string np = Partition_List.substr(np_start, np_end - np_start);
						if (!np.empty()) {
							if (!all_names.empty()) all_names += ", ";
							all_names += np;
						}
						np_start = np_end + 1;
					}
					gui_msg(Msg("set_restore_opt_all=Setting restore options: all ({1}):")(all_names));
					DataManager::SetValue("tw_restore_selected", Partition_List);
				}
				if (is_encrypted) {
					// Encrypted backup: validate the password BEFORE the wipe (like the
					// GUI's decrypt_backup) — a wrong or missing password must not cost data.
					if (!has_password || Password.empty()) {
						gui_err("ors_restore_pw_required=This backup is encrypted and needs a password. Use: restore <folder> <options>:<password>");
						ret_val = 1;
					} else if (!Ors_Password_Valid(Password)) {
						gui_err("ors_pw_invalid=Password contains invalid characters -- no spaces or control characters allowed.");
						ret_val = 1;
					} else if (!TWFunc::Try_Decrypting_Backup(folder_path, Password)) {
						gui_err("ors_restore_pw_wrong=Wrong password -- unable to decrypt backup.");
						ret_val = 1;
					} else if (PartitionManager.Run_Restore(folder_path) != 0) {
						ret_val = 1;
					} else {
						gui_msg("done=Done.");
					}
				} else {
					// A superfluous password on an unencrypted backup only warns, it does
					// not abort (the GUI does not ask for a password there either).
					if (has_password)
						gui_msg(Msg(msg::kWarning, "ors_pw_not_needed=Backup is not encrypted; the given password is ignored."));
					if (PartitionManager.Run_Restore(folder_path) != 0)
						ret_val = 1;
					else
						gui_msg("done=Done.");
				}
			} else if (strcmp(command, "remountrw") == 0) {
				ret_val = remountrw();
			} else if (strcmp(command, "mount") == 0) {
				// Mount
				DataManager::SetValue("tw_action_text2", gui_parse_text("{@mounting}"));
				if (value[0] != '/') {
					strcpy(mount, "/");
					strcat(mount, value);
				} else
					strcpy(mount, value);
				if (!strcmp(mount, "/system"))
					strcpy(mount, PartitionManager.Get_Android_Root_Path().c_str());
				if (PartitionManager.Mount_By_Path(mount, true))
					gui_msg(Msg("mounted=Mounted '{1}'")(mount));
			} else if (strcmp(command, "unmount") == 0 || strcmp(command, "umount") == 0) {
				// Unmount
				DataManager::SetValue("tw_action_text2", gui_parse_text("{@unmounting}"));
				if (value[0] != '/') {
					strcpy(mount, "/");
					strcat(mount, value);
				} else
					strcpy(mount, value);
				if (!strcmp(mount, "/system"))
					strcpy(mount, PartitionManager.Get_Android_Root_Path().c_str());
				if (PartitionManager.UnMount_By_Path(mount, true))
					gui_msg(Msg("unmounted=Unounted '{1}'")(mount));
			} else if (strcmp(command, "set") == 0) {
				// Set value
				size_t len = strlen(value);
				tok = strtok(value, " ");
				strcpy(value1, tok);
				if (len > strlen(value1) + 1) {
					char *val2 = value + strlen(value1) + 1;
					gui_msg(Msg("setting=Setting '{1}' to '{2}'")(value1)(val2));
					DataManager::SetValue(value1, val2);
				} else {
					gui_msg(Msg("setting_empty=Setting '{1}' to empty")(value1));
					DataManager::SetValue(value1, "");
				}
			} else if (strcmp(command, "mkdir") == 0) {
				// Make directory (recursive)
				DataManager::SetValue("tw_action_text2", gui_parse_text("{@making_dir1}"));
				gui_msg(Msg("making_dir2=Making directory: '{1}'")(value));
				if (!TWFunc::Recursive_Mkdir(value)) {
					// error message already displayed by Recursive_Mkdir
					ret_val = 1;
				}
			} else if (strcmp(command, "reboot") == 0) {
				if (strlen(value) && strcmp(value, "recovery") == 0)
					TWFunc::tw_reboot(rb_recovery);
				else if (strlen(value) && strcmp(value, "poweroff") == 0)
					TWFunc::tw_reboot(rb_poweroff);
				else if (strlen(value) && strcmp(value, "bootloader") == 0)
					TWFunc::tw_reboot(rb_bootloader);
				else if (strlen(value) && strcmp(value, "download") == 0)
					TWFunc::tw_reboot(rb_download);
				else if (strlen(value) && strcmp(value, "edl") == 0)
					TWFunc::tw_reboot(rb_edl);
				else
					TWFunc::tw_reboot(rb_system);
			} else if (strcmp(command, "cmd") == 0) {
				DataManager::SetValue("tw_action_text2", gui_parse_text("{@running_command}"));
				if (cindex != 0) {
					TWFunc::Exec_Cmd(value);
				} else {
					LOGERR("No value given for cmd\n");
				}
			} else if (strcmp(command, "print") == 0) {
				gui_print("%s\n", value);
			} else if (strcmp(command, "sideload") == 0) {
				// ADB Sideload
				DataManager::SetValue("tw_action_text2", gui_parse_text("{@sideload}"));
				install_cmd = -1;

				int wipe_cache = 0;
				string result;

				gui_msg("start_sideload=Starting ADB sideload feature...");

				Device::BuiltinAction reboot_action = Device::REBOOT_BOOTLOADER;
				ret_val = twrp_sideload("/", &reboot_action);
				if (ret_val != 0) {
					if (ret_val == -2)
						gui_err("need_new_adb=You need adb 1.0.32 or newer to sideload to this device.");
					ret_val = 1; // failure
				} else if (TWinstall_zip(FUSE_SIDELOAD_HOST_PATHNAME, &wipe_cache) == 0) {
					if (wipe_cache)
						PartitionManager.Wipe_By_Path("/cache");
				} else {
					ret_val = 1; // failure
				}
				PartitionManager.Unlock_Block_Partitions();
				PartitionManager.Update_System_Details();
				sideload = 1; // Causes device to go to the home screen afterwards
				pid_t sideload_child_pid = GetMiniAdbdPid();
				if (sideload_child_pid != 0) {
					LOGINFO("Signaling child sideload process to exit.\n");
					struct stat st;
					// Calling stat() on this magic filename signals the minadbd
					// subprocess to shut down.
					stat(FUSE_SIDELOAD_HOST_EXIT_PATHNAME, &st);
					int status;
					LOGINFO("Waiting for child sideload process to exit.\n");
					waitpid(sideload_child_pid, &status, 0);
				}
				property_set("ctl.start", "adbd");
				gui_msg("done=Done.");
			} else if (strcmp(command, "fixperms") == 0 || strcmp(command, "fixpermissions") == 0 || strcmp(command, "fixcontexts") == 0) {
				ret_val = PartitionManager.Fix_Contexts();
				if (ret_val != 0)
					ret_val = 1; // failure
			} else if (strcmp(command, "decrypt") == 0) {
				// twrp cmd cannot decrypt a password with space, should decrypt on gui
				if (*value) {
					string tmp = value;
					std::vector<string> args = TWFunc::Split_String(tmp, " ");

					string pass = args[0];
					string userid = "0";
					if (args.size() > 1)
						userid = args[1];

					ret_val = PartitionManager.Decrypt_Device(pass, atoi(userid.c_str()));
					if (ret_val != 0)
						ret_val = 1;  // failure
				} else {
					gui_err("no_pwd=No password provided.");
					ret_val = 1;  // failure
				}
			} else if (strcmp(command, "listmounts") == 0) {
				TWFunc::List_Mounts();
			} else {
				LOGERR("Unrecognized script command: '%s'\n", command);
				ret_val = 1;
			}
		}
		fclose(fp);
		gui_msg("done_ors=Done processing script file");
	} else {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(SCRIPT_FILE_TMP)(
			strerror(errno)));
		return 1;
	}

	if (install_cmd && DataManager::GetIntValue(TW_HAS_INJECTTWRP) == 1 &&
	DataManager::GetIntValue(TW_INJECT_AFTER_ZIP) == 1) {
		gui_msg("injecttwrp=Injecting TWRP into boot image...");
		TWPartition* Boot = PartitionManager.Find_Partition_By_Path("/boot");
		if (Boot == NULL || Boot->Current_File_System != "emmc")
			TWFunc::Exec_Cmd(
			"injecttwrp --dump /tmp/backup_recovery_ramdisk.img /tmp/injected_boot.img --flash");
		else {
			string injectcmd =
			"injecttwrp --dump /tmp/backup_recovery_ramdisk.img /tmp/injected_boot.img --flash bd=" +
			Boot->Actual_Block_Device;
			TWFunc::Exec_Cmd(injectcmd.c_str());
		}
		gui_msg("done=Done.");
	}
	if (sideload)
		ret_val = 1;  // Forces booting to the home page after sideload
	return ret_val;
}

int OpenRecoveryScript::Insert_ORS_Command(string Command) {
	ofstream ORSfile(SCRIPT_FILE_TMP, ios_base::app | ios_base::out);
	if (ORSfile.is_open()) {
		LOGINFO("Inserting '%s'\n", Command.c_str());
		ORSfile << Command.c_str() << endl;
		ORSfile.close();
		return 1;
	}
	LOGERR("Unable to append '%s' to '%s'\n", Command.c_str(), SCRIPT_FILE_TMP);
	return 0;
}

int OpenRecoveryScript::Install_Command(string Zip) {
	// Install zip
	string ret_string;
	int ret_val = 0, wipe_cache = 0;
	std::vector<PartitionList> Storage_List;
	string Full_Path;

	if (Zip.substr(0, 1) == "@") {
		// This is a special file that contains a map of blocks on the data partition
		Full_Path = Zip.substr(1);
		if (!PartitionManager.Mount_By_Path(Full_Path, true) || !TWFunc::Path_Exists(Full_Path)) {
			LOGINFO("Unable to install via mapped zip '%s'\n", Full_Path.c_str());
			gui_msg(Msg(msg::kError, "zip_err=Error installing zip file '{1}'")(Zip));
			return 1;
		}
		LOGINFO("Installing mapped zip file '%s'\n", Full_Path.c_str());
		gui_msg(Msg("installing_zip=Installing zip file '{1}'")(Zip));
	} else if (!TWFunc::Path_Exists(Zip)) {
		PartitionManager.Mount_All_Storage();
		PartitionManager.Get_Partition_List("storage", &Storage_List);
		int listSize = Storage_List.size();
		for (int i = 0; i < listSize; i++) {
			if (PartitionManager.Is_Mounted_By_Path(Storage_List.at(i).Mount_Point)) {
				Full_Path = Storage_List.at(i).Mount_Point + "/" + Zip;
				if (TWFunc::Path_Exists(Full_Path)) {
					Zip = Full_Path;
					break;
				}
				Full_Path = Zip;
				LOGINFO("Trying to find zip '%s' on '%s'...\n", Full_Path.c_str(), Storage_List.at(i).Mount_Point.c_str());
				ret_string = Locate_Zip_File(Full_Path, Storage_List.at(i).Mount_Point);
				if (!ret_string.empty()) {
					Zip = ret_string;
					break;
				}
			}
		}
		if (!TWFunc::Path_Exists(Zip)) {
			// zip file doesn't exist
			gui_print("Unable to locate zip file '%s'.\n", Zip.c_str());
			ret_val = 1;
		} else
			gui_msg(Msg("installing_zip=Installing zip file '{1}'")(Zip));
	}

	ret_val = TWinstall_zip(Zip.c_str(), &wipe_cache);
	if (ret_val != 0) {
		gui_msg(Msg(msg::kError, "zip_err=Error installing zip file '{1}'")(Zip));
		ret_val = 1;
	} else if (wipe_cache)
		PartitionManager.Wipe_By_Path("/cache");

	return ret_val;
}

string OpenRecoveryScript::Locate_Zip_File(string Zip, string Storage_Root) {
	string Path = TWFunc::Get_Path(Zip);
	string File = TWFunc::Get_Filename(Zip);
	string pathCpy = Path;
	string wholePath;
	size_t pos = Path.find("/", 1);

	while (pos != string::npos)
	{
		pathCpy = Path.substr(pos, Path.size() - pos);
		wholePath = pathCpy + File;
		LOGINFO("Looking for zip at '%s'\n", wholePath.c_str());
		if (TWFunc::Path_Exists(wholePath))
			return wholePath;
		wholePath = Storage_Root + wholePath;
		LOGINFO("Looking for zip at '%s'\n", wholePath.c_str());
		if (TWFunc::Path_Exists(wholePath))
			return wholePath;

		pos = Path.find("/", pos + 1);
	}
	return "";
}

// Fail-fast validation of an ORS backup/restore password before execution
// (mirrors the GUI pre-check): non-empty, printable ASCII without space
// (0x21-0x7E). A space would otherwise silently truncate the password;
// tabs/control characters are unwanted.
static bool Ors_Password_Valid(const string& pw) {
	if (pw.empty())
		return false;
	for (unsigned char c : pw)
		if (c < 0x21 || c > 0x7E)
			return false;
	return true;
}

int OpenRecoveryScript::Backup_Command(string Options) {
	int line_len, i;
	string Backup_List;
	string Password;
	bool has_password = false;
	bool encrypt = false;

	DataManager::SetValue(TW_USE_COMPRESSION_VAR, 0);
	DataManager::SetValue(TW_SKIP_DIGEST_GENERATE_VAR, 0);

	// Format: [name] <codes>[:password] (mirrors restore <folder> <codes>:<pw>).
	// 1) Split the password at the FIRST ':' — everything after it is the password
	//    (including any spaces, which Ors_Password_Valid then rejects).
	size_t colon = Options.find(':');
	if (colon != string::npos) {
		Password = Options.substr(colon + 1);
		has_password = true;
		Options = Options.substr(0, colon);
	}

	// 2) Parse the rest via regex: optional name (may contain spaces) + codes as
	//    the last token (valid code characters only). No match -> reject (e.g.
	//    "data" fails at the 't') instead of misparsing character by character.
	string Backup_Name;
	std::smatch bm;
	static const std::regex backup_mask("^(?:(.+) )?([SsDdCcRrBbAaEeOoMmXx123]+)$");
	if (!std::regex_match(Options, bm, backup_mask)) {
		gui_err("ors_invalid_options=Invalid backup options. Use: backup [name] <SDCRBAEOMX>[:password]");
		return 1;
	}
	Backup_Name = bm[1].str();
	Options = bm[2].str();

	// Set the backup name (default = current date).
	if (!Backup_Name.empty()) {
		DataManager::SetValue(TW_BACKUP_NAME, Backup_Name);
		gui_msg(Msg("backup_folder_set=Backup folder set to '{1}'")(Backup_Name));
		if (PartitionManager.Check_Backup_Name(Backup_Name, true, true) != 0)
			return 1;
	} else {
		DataManager::SetValue(TW_BACKUP_NAME, "(Current Date)");
	}

	gui_msg("select_backup_opt=Setting backup options:");
	// Append a partition to the backup list only if it exists on this device
	// (Find_Partition_By_Path — the same primitive as the backstop in Run_Backup).
	// Prevents a character-wise-parsed word — e.g. the 'a' in "data" -> /and-sec —
	// from putting a nonexistent (legacy) partition into the list and triggering
	// the hard abort in Run_Backup later. Missing partitions get a visible warning
	// (no error/abort) and are skipped; the GUI already filters the same way via
	// Get_Partition_List (Is_Present), so ORS behaves symmetrically.
	auto add_part_if_present = [&](const char* mount_point, const char* opt_msg) {
		if (PartitionManager.Find_Partition_By_Path(mount_point) != NULL) {
			Backup_List += mount_point;
			Backup_List += ";";
			gui_msg(opt_msg);
		} else {
			gui_msg(Msg(msg::kWarning, "ors_part_not_found=Partition '{1}' not found on this device -- skipping.")(mount_point));
		}
	};

	line_len = Options.size();
	for (i=0; i<line_len; i++) {
		if (Options.substr(i, 1) == "S" || Options.substr(i, 1) == "s") {
			add_part_if_present("/system", "system=System");
		} else if (Options.substr(i, 1) == "D" || Options.substr(i, 1) == "d") {
			add_part_if_present("/data", "data=Data");
		} else if (Options.substr(i, 1) == "C" || Options.substr(i, 1) == "c") {
			add_part_if_present("/cache", "cache=Cache");
		} else if (Options.substr(i, 1) == "R" || Options.substr(i, 1) == "r") {
			add_part_if_present("/recovery", "recovery=Recovery");
		} else if (Options.substr(i, 1) == "1") {
			gui_print("%s\n", "Special1 -- No Longer Supported...");
		} else if (Options.substr(i, 1) == "2") {
			gui_print("%s\n", "Special2 -- No Longer Supported...");
		} else if (Options.substr(i, 1) == "3") {
			gui_print("%s\n", "Special3 -- No Longer Supported...");
		} else if (Options.substr(i, 1) == "B" || Options.substr(i, 1) == "b") {
			add_part_if_present("/boot", "boot=Boot");
		} else if (Options.substr(i, 1) == "A" || Options.substr(i, 1) == "a") {
			add_part_if_present("/and-sec", "android_secure=Android Secure");
		} else if (Options.substr(i, 1) == "E" || Options.substr(i, 1) == "e") {
			add_part_if_present("/sd-ext", "sdext=SD-EXT");
		} else if (Options.substr(i, 1) == "O" || Options.substr(i, 1) == "o") {
			DataManager::SetValue(TW_USE_COMPRESSION_VAR, 1);
			gui_msg("compression_on=Compression is on");
		} else if (Options.substr(i, 1) == "M" || Options.substr(i, 1) == "m") {
			DataManager::SetValue(TW_SKIP_DIGEST_GENERATE_VAR, 1);
			gui_msg("digest_off=Digest Generation is off");
		} else if (Options.substr(i, 1) == "X" || Options.substr(i, 1) == "x") {
			encrypt = true;
		}
	}

	// Encryption/password validation (fail-fast, BEFORE Run_Backup, like the GUI):
	if (encrypt) {
		if (!has_password || Password.empty()) {
			gui_err("ors_pw_required=Encryption requested (X) but no password given. Use: backup <options>[ name]:<password>");
			return 1;
		}
		if (!Ors_Password_Valid(Password)) {
			gui_err("ors_pw_invalid=Password contains invalid characters -- no spaces or control characters allowed.");
			return 1;
		}
		DataManager::SetValue("tw_encrypt_backup", 1);
		DataManager::SetValue("tw_backup_password", Password);
		gui_msg("encryption_on=Encryption is on");
	} else if (has_password) {
		gui_err("ors_pw_no_flag=A password was given but encryption is off. Add 'X' to the options to encrypt.");
		return 1;
	}

	DataManager::SetValue("tw_backup_list", Backup_List);
	int backup_rc = PartitionManager.Run_Backup(false);

	// Hardening: remove password/flag from the DataManager after use.
	if (encrypt) {
		DataManager::SetValue("tw_backup_password", "");
		DataManager::SetValue("tw_encrypt_backup", 0);
	}

	if (backup_rc != 0) {
		gui_err("backup_fail=[BACKUP FAILED]");
		return 1;
	}
	gui_msg("backup_complete=Backup Complete");
	return 0;
}

// this is called by main()
void OpenRecoveryScript::Run_OpenRecoveryScript(void) {
	DataManager::SetValue("tw_back", "main");
	DataManager::SetValue("tw_action", "openrecoveryscript");
	DataManager::SetValue("tw_action_param", "");
	DataManager::SetValue("tw_has_action2", "0");
	DataManager::SetValue("tw_action2", "");
	DataManager::SetValue("tw_action2_param", "");
#ifdef TW_OEM_BUILD
	DataManager::SetValue("tw_action_text1", gui_lookup("running_recovery_commands", "Running Recovery Commands"));
	DataManager::SetValue("tw_complete_text1", gui_lookup("recovery_commands_complete", "Recovery Commands Complete"));
#else
	DataManager::SetValue("tw_action_text1", gui_lookup("running_ors", "Running OpenRecoveryScript"));
	DataManager::SetValue("tw_complete_text1", gui_lookup("ors_complete", "OpenRecoveryScript Complete"));
#endif
	DataManager::SetValue("tw_action_text2", "");
	DataManager::SetValue("tw_has_cancel", 0);
	DataManager::SetValue("tw_show_reboot", 0);
	if (gui_startPage("action_page", 0, 1) != 0) {
		LOGERR("Failed to load OpenRecoveryScript GUI page.\n");
	}
}

// this is called by the "openrecoveryscript" GUI action called via action page from Run_OpenRecoveryScript
int OpenRecoveryScript::Run_OpenRecoveryScript_Action() {
	int op_status = 1;
	// Check for the SCRIPT_FILE_TMP first as these are AOSP recovery commands
	// that we converted to ORS commands during boot in recovery.cpp.
	// Run those first.
	int reboot = 0;
	if (TWFunc::Path_Exists(SCRIPT_FILE_TMP)) {
		gui_msg("running_recovery_commands=Running Recovery Commands");
		if (OpenRecoveryScript::run_script_file() == 0) {
			reboot = 1;
			op_status = 0;
		}
	}
	// Check for the ORS file in /cache and attempt to run those commands.
	if (OpenRecoveryScript::check_for_script_file()) {
		gui_msg("running_ors=Running OpenRecoveryScript");
		if (OpenRecoveryScript::run_script_file() == 0) {
			reboot = 1;
			op_status = 0;
		}
	}
	if (reboot) {
		// Disable stock recovery reflashing
		TWFunc::Disable_Stock_Recovery_Replace();
		usleep(2000000); // Sleep for 2 seconds before rebooting
		TWFunc::tw_reboot(rb_system);
		usleep(5000000); // Sleep for 5 seconds to allow reboot to occur
	} else {
		DataManager::SetValue("tw_page_done", 1);
	}
	return op_status;
}

// this is called by the "twcmd" GUI action when a command is received via FIFO from the "twrp" command line tool
// Returns the command status (0 = success, non-zero = failure). The status
// reaches the twrp binary as the last line of the ORS output FIFO, written by
// the GUI callback because the FIFO handle lives there. Mind the mixed contracts
// of the helpers below: run_script_file() is exit-code-like (0 = every command
// succeeded), copy_script_file() and Insert_ORS_Command() are bool-like
// (1 = success).
int OpenRecoveryScript::Run_CLI_Command(const char* command) {
	int ret = 0;
	string tmp = command;
	std::vector<string> parts =
		TWFunc::Split_String(tmp, " ");  // pats[0] is cmd, parts[1...] is args
	string cmd_str = parts[0];

	if (cmd_str == "runscript") {
		if (parts.size() > 1) {
			string filename = parts[1];
			if (OpenRecoveryScript::copy_script_file(filename) == 0) {
				LOGINFO("Unable to copy script file\n");
				ret = 1;
			} else {
				ret = OpenRecoveryScript::run_script_file();
			}
		} else {
			LOGINFO("Missing parameter: script file name\n");
			ret = 1;
		}
	} else if (cmd_str == "get") {
		if (parts.size() > 1) {
			string varname = parts[1];
			string value;
			DataManager::GetValue(varname, value);
			gui_print("%s = %s\n", varname.c_str(), value.c_str());
		} else {
			LOGINFO("Missing parameter: var name\n");
			ret = 1;
		}
	} else if (cmd_str == "decrypt") {
		// twrp cmd cannot decrypt a password with space, should decrypt on gui
		if (parts.size() == 1) {
			gui_err("no_pwd=No password provided.");
			ret = 1;
		} else {
			string pass = parts[1];
			string userid = "0";
			if (parts.size() > 2)
				userid = parts[2];

			gui_msg("decrypt_cmd=Attempting to decrypt data partition or user data via command line.");
			if (PartitionManager.Decrypt_Device(pass, atoi(userid.c_str())) == 0) {
				// set_page_done = 1;  // done by singleaction_page anyway
				std::string orsFile = TWFunc::get_log_dir() + "/openrecoveryscript";
				if (TWFunc::Path_Exists(orsFile)) {
					// The status stays that of the decrypt: this helper starts at
					// op_status = 1 and only clears it when one of ITS OWN script
					// paths ran, which are not the file probed above — folding it in
					// would report a failure for a successful decrypt.
					Run_OpenRecoveryScript_Action();
				}
			} else {
				ret = 1;
			}
		}
	} else if (OpenRecoveryScript::Insert_ORS_Command(command)) {
		ret = OpenRecoveryScript::run_script_file();
	} else {
		ret = 1;   // the command could not even be appended to the script file
	}

	// let the GUI close the output fd and restart the command listener
	call_after_cli_command(ret);
	LOGINFO("Done reading ORS command from command line\n");
	return ret;
}

int OpenRecoveryScript::remountrw(void)
{
	bool remount_system = PartitionManager.Is_Mounted_By_Path(PartitionManager.Get_Android_Root_Path());
	int op_status;
	TWPartition* Part;

	if (!PartitionManager.UnMount_By_Path(PartitionManager.Get_Android_Root_Path(), true)) {
		op_status = 1; // fail
	} else {
		Part = PartitionManager.Find_Partition_By_Path(PartitionManager.Get_Android_Root_Path());
		if (Part) {
			DataManager::SetValue("tw_mount_system_ro", 0);
			Part->Change_Mount_Read_Only(false);
		}
		if (remount_system) {
			Part->Mount(true);
		}
		op_status = 0; // success
	}

	return op_status;
}

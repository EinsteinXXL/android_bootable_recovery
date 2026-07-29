/*
	Copyright 2014 to 2021 TeamWin
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <map>
#include <vector>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <zlib.h>
#include <iostream>
#include <iomanip>
#include <sys/wait.h>
#include <linux/fs.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fstab/fstab.h>
#include <fs_avb/fs_avb.h>
#include <fs_mgr.h>
#include <fs_mgr_dm_linear.h>
#include <fs_mgr_overlayfs.h>
#include <fs_mgr/roots.h>
#include <libgsi/libgsi.h>
#include <liblp/liblp.h>
#include <libgsi/libgsi.h>
#include <liblp/builder.h>
#include <libsnapshot/snapshot.h>

#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#include "variables.h"
#include "twcommon.h"
#include "partitions.hpp"
#include "data.hpp"
#include "startupArgs.hpp"
#include "twrp-functions.hpp"
#include "infomanager.hpp"
#include "backupheadermanager.hpp"   // GetFileType() (outer magic detection)
#include "fixContexts.hpp"
#include "exclude.hpp"
#include "set_metadata.h"
#include "tw_atomic.hpp"
#include "gui/gui.hpp"
#include "progresstracking.hpp"
#include "twrpTar.hpp"
#include "twrpDigestDriver.hpp"
#include "twrpRepacker.hpp"
#include "adbbu/libtwadbbu.hpp"

#ifdef TW_HAS_MTP
#ifdef TW_HAS_LEGACY_MTP
#include "mtp/legacy/mtp_MtpServer.hpp"
#include "mtp/legacy/twrpMtp.hpp"
#include "mtp/legacy/MtpMessage.hpp"
#else
#include "mtp/ffs/mtp_MtpServer.hpp"
#include "mtp/ffs/twrpMtp.hpp"
#include "mtp/ffs/MtpMessage.hpp"
#endif
#endif

extern "C" {
	#include "cutils/properties.h"
	#include "gui/gui.h"
}

#ifdef TW_INCLUDE_CRYPTO
#include "crypto/fde/cryptfs.h"
#include "gui/rapidxml.hpp"
#include "gui/pages.hpp"
#ifdef TW_INCLUDE_FBE
#include "Decrypt.h"
#ifdef TW_INCLUDE_FBE_METADATA_DECRYPT
	#ifdef USE_FSCRYPT
	#include "MetadataCrypt.h"
	#endif
#endif
#endif
#ifdef TW_CRYPTO_USE_SYSTEM_VOLD
#include "crypto/vold_decrypt/vold_decrypt.h"
#endif
#endif

#ifdef AB_OTA_UPDATER
#include <android/hardware/boot/1.0/IBootControl.h>
using android::hardware::boot::V1_0::CommandResult;
using android::hardware::boot::V1_0::IBootControl;
#endif

using android::fs_mgr::DestroyLogicalPartition;
using android::fs_mgr::Fstab;
using android::fs_mgr::FstabEntry;
using android::fs_mgr::MetadataBuilder;

extern bool datamedia;
std::vector<users_struct> Users_List;

TWPartitionManager::TWPartitionManager(void) {
	mtp_was_enabled = false;
	mtp_write_fd = -1;
	uevent_pfd.fd = -1;
	stop_backup.set_value(0);
	stop_restore.set_value(0);
#ifdef AB_OTA_UPDATER
	char slot_suffix[PROPERTY_VALUE_MAX];
	property_get("ro.boot.slot_suffix", slot_suffix, "error");
	if (strcmp(slot_suffix, "error") == 0)
		property_get("ro.boot.slot", slot_suffix, "error");
	Active_Slot_Display = "";
	if (strcmp(slot_suffix, "_a") == 0 || strcmp(slot_suffix, "a") == 0)
		Set_Active_Slot("A");
	else
		Set_Active_Slot("B");
#endif
}

void TWPartitionManager::Set_Crypto_State() {
	char crypto_state[PROPERTY_VALUE_MAX];
	property_get("ro.crypto.state", crypto_state, "error");
	if (strcmp(crypto_state, "error") == 0)
		property_set("ro.crypto.state", "encrypted");
}

int TWPartitionManager::Set_Crypto_Type(const char* crypto_type) {
	char type_prop[PROPERTY_VALUE_MAX];
	property_get("ro.crypto.type", type_prop, "error");
	if (strcmp(type_prop, "error") == 0)
		property_set("ro.crypto.type", crypto_type);
	// Sleep for a bit so that services can start if needed
	sleep(1);
	return 0;
}

int TWPartitionManager::Process_Fstab(string Fstab_Filename, bool Display_Error, bool recovery_mode) {
	FILE *fstabFile;
	char fstab_line[MAX_FSTAB_LINE_LENGTH];
	std::map<string, Flags_Map> twrp_flags;

	fstabFile = fopen("/etc/twrp.flags", "rt");
	if (fstabFile != NULL) {
		LOGINFO("Reading /etc/twrp.flags\n");
		while (fgets(fstab_line, sizeof(fstab_line), fstabFile) != NULL) {
			size_t line_size = strlen(fstab_line);
			if (fstab_line[line_size - 1] != '\n')
				fstab_line[line_size] = '\n';
			Flags_Map line_flags;
			line_flags.Primary_Block_Device = "";
			line_flags.Alternate_Block_Device = "";
			line_flags.fstab_line = (char*)malloc(MAX_FSTAB_LINE_LENGTH);
			if (!line_flags.fstab_line) {
				LOGERR("malloc error on line_flags.fstab_line\n");
				return false;
			}
			memcpy(line_flags.fstab_line, fstab_line, MAX_FSTAB_LINE_LENGTH);
			bool found_separator = false;
			char *fs_loc = NULL;
			char *block_loc = NULL;
			char *flags_loc = NULL;
			size_t index, item_index = 0;
			for (index = 0; index < line_size; index++) {
				if (fstab_line[index] <= 32) {
					fstab_line[index] = '\0';
					found_separator = true;
				} else if (found_separator) {
					if (item_index == 0) {
						fs_loc = fstab_line + index;
					} else if (item_index == 1) {
						block_loc = fstab_line + index;
					} else if (item_index > 1) {
						char *ptr = fstab_line + index;
						if (*ptr == '/') {
							line_flags.Alternate_Block_Device = ptr;
						} else if (strlen(ptr) > strlen("flags=") && strncmp(ptr, "flags=", strlen("flags=")) == 0) {
							flags_loc = ptr;
							// Once we find the flags=, we're done scanning the line
							break;
						}
					}
					found_separator = false;
					item_index++;
				}
			}
			if (block_loc)
				line_flags.Primary_Block_Device = block_loc;
			if (fs_loc)
				line_flags.File_System = fs_loc;
			if (flags_loc)
				line_flags.Flags = flags_loc;
			string Mount_Point = fstab_line;
			twrp_flags[Mount_Point] = line_flags;
			memset(fstab_line, 0, sizeof(fstab_line));
		}
		fclose(fstabFile);
	}

	fstabFile = fopen(Fstab_Filename.c_str(), "rt");
	if (fstabFile == NULL) {
		LOGERR("Critical Error: Unable to open fstab at '%s'.\n", Fstab_Filename.c_str());
		return false;
	} else
		LOGINFO("Reading %s\n", Fstab_Filename.c_str());

	while (fgets(fstab_line, sizeof(fstab_line), fstabFile) != NULL) {
		if (strstr(fstab_line, "swap"))
			continue; // Skip swap in recovery

		if (fstab_line[0] == '#')
			continue;

		size_t line_size = strlen(fstab_line);
		if (fstab_line[line_size - 1] != '\n')
			fstab_line[line_size] = '\n';

		TWPartition* partition = new TWPartition();
		if (partition->Process_Fstab_Line(fstab_line, Display_Error, &twrp_flags))
			Partitions.push_back(partition);
		else
			delete partition;

		memset(fstab_line, 0, sizeof(fstab_line));
	}
	fclose(fstabFile);

	if (twrp_flags.size() > 0) {
		LOGINFO("Processing remaining twrp.flags\n");
		// Add any items from twrp.flags that did not exist in the recovery.fstab
		for (std::map<string, Flags_Map>::iterator mapit=twrp_flags.begin(); mapit!=twrp_flags.end(); mapit++) {
			if (Find_Partition_By_Path(mapit->first) == NULL) {
				TWPartition* partition = new TWPartition();
				if (partition->Process_Fstab_Line(mapit->second.fstab_line, Display_Error, NULL))
					Partitions.push_back(partition);
				else
					delete partition;
			}
			if (mapit->second.fstab_line)
				free(mapit->second.fstab_line);
			mapit->second.fstab_line = NULL;
		}
	}
	if (Get_Super_Status()) {
		Setup_Super_Devices();
	}
	LOGINFO("Done processing fstab files\n");

	if (recovery_mode) {
		Setup_Fstab_Partitions(Display_Error);
	}
	return true;
}

void TWPartitionManager::Setup_Fstab_Partitions(bool Display_Error) {
		TWPartition* settings_partition = NULL;
		TWPartition* andsec_partition = NULL;
		std::vector<TWPartition*>::iterator iter;
		unsigned int storageid = 1 << 16;	// upper 16 bits are for physical storage device, we pretend to have only one

		iter = Partitions.begin();
		while (iter != Partitions.end()) {
			(*iter)->Partition_Post_Processing(Display_Error);

			if ((*iter)->Is_Storage) {
				++storageid;
				(*iter)->MTP_Storage_ID = storageid;
			}

			if (!settings_partition && (*iter)->Is_Settings_Storage && (*iter)->Is_Present)
				settings_partition = (*iter);
			else
				(*iter)->Is_Settings_Storage = false;

			if (!andsec_partition && (*iter)->Has_Android_Secure && (*iter)->Is_Present)
				andsec_partition = (*iter);
			else
				(*iter)->Has_Android_Secure = false;

			if ((*iter)->Is_Super && !Prepare_Super_Volume(*iter)) {
				LOGINFO("Logical partition '%s' does not exist in super, skipping\n", (*iter)->Get_Mount_Point().c_str());
				iter = Partitions.erase(iter);
				continue;
			}
			++iter;
		}

		Unlock_Block_Partitions();

		//Setup Apex before decryption
		TWPartition* sys = PartitionManager.Find_Partition_By_Path(PartitionManager.Get_Android_Root_Path());
		TWPartition* ven = PartitionManager.Find_Partition_By_Path("/vendor");
		if (sys) {
			if (sys->Get_Super_Status()) {
				sys->Mount(true);
				if (ven) {
					ven->Mount(true);
				}
	#ifdef TW_EXCLUDE_APEX
				LOGINFO("Apex is disabled in this build\n");
	#else
				twrpApex apex;
				if (!apex.loadApexImages()) {
					LOGERR("Unable to load apex images from %s\n", APEX_DIR);
					property_set("twrp.apex.loaded", "false");
				} else {
					property_set("twrp.apex.loaded", "true");
				}
				TWFunc::check_and_run_script("/sbin/resyncapex.sh", "apex");
	#endif
			}
		}
	#ifndef USE_VENDOR_LIBS
		if (ven)
			ven->UnMount(true);
		if (sys)
			sys->UnMount(true);
	#endif

		if (!datamedia && !settings_partition && Find_Partition_By_Path("/sdcard") == NULL && Find_Partition_By_Path("/internal_sd") == NULL && Find_Partition_By_Path("/internal_sdcard") == NULL && Find_Partition_By_Path("/emmc") == NULL) {
			// Attempt to automatically identify /data/media emulated storage devices
			TWPartition* Dat = Find_Partition_By_Path("/data");
			if (Dat) {
				LOGINFO("Using automatic handling for /data/media emulated storage device.\n");
				datamedia = true;
				Dat->Setup_Data_Media();
				settings_partition = Dat;
				// Since /data was not considered a storage partition earlier, we still need to assign an MTP ID
				++storageid;
				Dat->MTP_Storage_ID = storageid;
			}
		}
		if (!settings_partition) {
			for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
				if ((*iter)->Is_Storage) {
					settings_partition = (*iter);
					break;
				}
			}
			if (!settings_partition)
				LOGERR("Unable to locate storage partition for storing settings file.\n");
		}
		if (!Write_Fstab()) {
			if (Display_Error)
				LOGERR("Error creating fstab\n");
			else
				LOGINFO("Error creating fstab\n");
		}

		if (andsec_partition) {
			Setup_Android_Secure_Location(andsec_partition);
		} else if (settings_partition) {
			Setup_Android_Secure_Location(settings_partition);
		}
		if (settings_partition) {
			Setup_Settings_Storage_Partition(settings_partition);
		}

	#ifdef TW_INCLUDE_CRYPTO
		DataManager::SetValue(TW_IS_ENCRYPTED, 1);
		Decrypt_Data();
	#endif

		Update_System_Details();
		if (Get_Super_Status())
			Setup_Super_Partition();
		UnMount_Main_Partitions();
	#ifdef AB_OTA_UPDATER
		DataManager::SetValue("tw_active_slot", Get_Active_Slot_Display());
	#endif
		setup_uevent();
}

int TWPartitionManager::Write_Fstab(void) {
	FILE *fp;
	std::vector<TWPartition*>::iterator iter;
	string Line;

	fp = fopen("/etc/fstab", "w");
	if (fp == NULL) {
		LOGINFO("Can not open /etc/fstab.\n");
		return false;
	}
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Can_Be_Mounted) {
			Line = (*iter)->Actual_Block_Device + " " + (*iter)->Mount_Point + " " + (*iter)->Current_File_System +
				((*iter)->Mount_Read_Only ? " ro " : " rw ") + "0 0\n";
			fputs(Line.c_str(), fp);
		}
		// Handle subpartition tracking
		if ((*iter)->Is_SubPartition) {
			TWPartition* ParentPartition = Find_Partition_By_Path((*iter)->SubPartition_Of);
			if (ParentPartition)
				ParentPartition->Has_SubPartition = true;
			else
				LOGERR("Unable to locate parent partition '%s' of '%s'\n", (*iter)->SubPartition_Of.c_str(), (*iter)->Mount_Point.c_str());
		}
	}
	fclose(fp);
	return true;
}

void TWPartitionManager::Decrypt_Data() {
	#ifdef TW_INCLUDE_CRYPTO
	TWPartition* Decrypt_Data = Find_Partition_By_Path("/data");
	if (Decrypt_Data && Decrypt_Data->Is_Encrypted && !Decrypt_Data->Is_Decrypted) {
		Set_Crypto_State();
		TWPartition* Key_Directory_Partition = Find_Partition_By_Path(Decrypt_Data->Key_Directory);
		if (Key_Directory_Partition != nullptr)
			if (!Key_Directory_Partition->Is_Mounted())
				Mount_By_Path(Decrypt_Data->Key_Directory, false);
		if (!Decrypt_Data->Key_Directory.empty()) {
			Set_Crypto_Type("file");
#ifdef TW_INCLUDE_FBE_METADATA_DECRYPT
#ifdef USE_FSCRYPT
			if (fscrypt_mount_metadata_encrypted(Decrypt_Data->Actual_Block_Device, Decrypt_Data->Mount_Point, false)) {
				std::string crypto_blkdev = android::base::GetProperty("ro.crypto.fs_crypto_blkdev", "error");
				Decrypt_Data->Decrypted_Block_Device = crypto_blkdev;
				LOGINFO("Successfully decrypted metadata encrypted data partition with new block device: '%s'\n", crypto_blkdev.c_str());
#endif
				Decrypt_Data->Is_Decrypted = true; // Needed to make the mount function work correctly
				int retry_count = 10;
				while (!Decrypt_Data->Mount(false) && --retry_count)
					usleep(500);
				if (Decrypt_Data->Mount(false)) {
					if (!Decrypt_Data->Decrypt_FBE_DE()) {
						LOGERR("Unable to decrypt FBE device\n");
					}

				} else {
					LOGINFO("Failed to mount data after metadata decrypt\n");
				}
			} else {
				LOGINFO("Unable to decrypt metadata encryption\n");
			}
#else
			LOGERR("Metadata FBE decrypt support not present in this TWRP\n");
#endif
		}
		if (Decrypt_Data->Is_FBE) {
			if (DataManager::GetIntValue(TW_CRYPTO_PWTYPE) == 0) {
				if (Decrypt_Device("!") == 0) {
					gui_msg("decrypt_success=Successfully decrypted with default password.");
					DataManager::SetValue(TW_IS_ENCRYPTED, 0);
				} else {
					gui_err("unable_to_decrypt=Unable to decrypt with default password.");
				}
			}
		} else {
			LOGINFO("FBE setup failed. Trying FDE...");
			Set_Crypto_State();
			Set_Crypto_Type("block");
			int password_type = cryptfs_get_password_type();
			if (password_type == CRYPT_TYPE_DEFAULT) {
				LOGINFO("Device is encrypted with the default password, attempting to decrypt.\n");
				if (Decrypt_Device("default_password") == 0) {
					gui_msg("decrypt_success=Successfully decrypted with default password.");
					DataManager::SetValue(TW_IS_ENCRYPTED, 0);
				} else {
					gui_err("unable_to_decrypt=Unable to decrypt with default password.");
				}
			} else {
				DataManager::SetValue("TW_CRYPTO_TYPE", password_type);
				DataManager::SetValue("tw_crypto_pwtype_0", password_type);
			}
		}
	}
	if (Decrypt_Data && (!Decrypt_Data->Is_Encrypted || Decrypt_Data->Is_Decrypted)) {
		Decrypt_Adopted();
	}
#endif
}

void TWPartitionManager::Setup_Settings_Storage_Partition(TWPartition* Part) {
	DataManager::SetValue("tw_storage_path", Part->Storage_Path);
}

void TWPartitionManager::Setup_Android_Secure_Location(TWPartition* Part) {
	if (Part->Has_Android_Secure)
		Part->Setup_AndSec();
	else if (!datamedia)
		Part->Setup_AndSec();
}

void TWPartitionManager::Output_Partition_Logging(void) {
	std::vector<TWPartition*>::iterator iter;

	printf("\n\nPartition Logs:\n");
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++)
		Output_Partition((*iter));
}

void TWPartitionManager::Output_Partition(TWPartition* Part) {
	unsigned long long mb = 1048576;

	printf("%s | %s | Size: %iMB", Part->Mount_Point.c_str(), Part->Actual_Block_Device.c_str(), (int)(Part->Size / mb));
	if (Part->Can_Be_Mounted) {
		printf(" Used: %iMB Free: %iMB Backup Size: %iMB", (int)(Part->Used / mb), (int)(Part->Free / mb), (int)(Part->Backup_Size / mb));
	}
	printf("\n   Flags: ");
	if (Part->Can_Be_Mounted)
		printf("Can_Be_Mounted ");
	if (Part->Can_Be_Wiped)
		printf("Can_Be_Wiped ");
	if (Part->Use_Rm_Rf)
		printf("Use_Rm_Rf ");
	if (Part->Can_Be_Backed_Up)
		printf("Can_Be_Backed_Up ");
	if (Part->Wipe_During_Factory_Reset)
		printf("Wipe_During_Factory_Reset ");
	if (Part->Wipe_Available_in_GUI)
		printf("Wipe_Available_in_GUI ");
	if (Part->Is_SubPartition)
		printf("Is_SubPartition ");
	if (Part->Has_SubPartition)
		printf("Has_SubPartition ");
	if (Part->Removable)
		printf("Removable ");
	if (Part->Is_Present)
		printf("IsPresent ");
	if (Part->Can_Be_Encrypted)
		printf("Can_Be_Encrypted ");
	if (Part->Is_Encrypted)
		printf("Is_Encrypted ");
	if (Part->Is_Decrypted)
		printf("Is_Decrypted ");
	if (Part->Has_Data_Media)
		printf("Has_Data_Media ");
	if (Part->Can_Encrypt_Backup)
		printf("Can_Encrypt_Backup ");
	if (Part->Use_Userdata_Encryption)
		printf("Use_Userdata_Encryption ");
	if (Part->Has_Android_Secure)
		printf("Has_Android_Secure ");
	if (Part->Is_Storage)
		printf("Is_Storage ");
	if (Part->Is_Settings_Storage)
		printf("Is_Settings_Storage ");
	if (Part->Ignore_Blkid)
		printf("Ignore_Blkid ");
	if (Part->Mount_To_Decrypt)
		printf("Mount_To_Decrypt ");
	if (Part->Can_Flash_Img)
		printf("Can_Flash_Img ");
	if (Part->Is_Adopted_Storage)
		printf("Is_Adopted_Storage ");
	if (Part->SlotSelect)
		printf("SlotSelect ");
	if (Part->Mount_Read_Only)
		printf("Mount_Read_Only ");
	if (Part->Is_Super)
		printf("Is_Super ");
	printf("\n");
	if (!Part->SubPartition_Of.empty())
		printf("   SubPartition_Of: %s\n", Part->SubPartition_Of.c_str());
	if (!Part->Symlink_Path.empty())
		printf("   Symlink_Path: %s\n", Part->Symlink_Path.c_str());
	if (!Part->Symlink_Mount_Point.empty())
		printf("   Symlink_Mount_Point: %s\n", Part->Symlink_Mount_Point.c_str());
	if (!Part->Primary_Block_Device.empty())
		printf("   Primary_Block_Device: %s\n", Part->Primary_Block_Device.c_str());
	if (!Part->Alternate_Block_Device.empty())
		printf("   Alternate_Block_Device: %s\n", Part->Alternate_Block_Device.c_str());
	if (!Part->Decrypted_Block_Device.empty())
		printf("   Decrypted_Block_Device: %s\n", Part->Decrypted_Block_Device.c_str());
	if (!Part->Crypto_Key_Location.empty())
		printf("   Crypto_Key_Location: %s\n", Part->Crypto_Key_Location.c_str());
	if (Part->Length != 0)
		printf("   Length: %i\n", Part->Length);
	if (!Part->Display_Name.empty())
		printf("   Display_Name: %s\n", Part->Display_Name.c_str());
	if (!Part->Storage_Name.empty())
		printf("   Storage_Name: %s\n", Part->Storage_Name.c_str());
	if (!Part->Backup_Path.empty())
		printf("   Backup_Path: %s\n", Part->Backup_Path.c_str());
	if (!Part->Backup_Name.empty())
		printf("   Backup_Name: %s\n", Part->Backup_Name.c_str());
	if (!Part->Backup_Display_Name.empty())
		printf("   Backup_Display_Name: %s\n", Part->Backup_Display_Name.c_str());
	if (!Part->Backup_FileName.empty())
		printf("   Backup_FileName: %s\n", Part->Backup_FileName.c_str());
	if (!Part->Storage_Path.empty())
		printf("   Storage_Path: %s\n", Part->Storage_Path.c_str());
	if (!Part->Current_File_System.empty())
		printf("   Current_File_System: %s\n", Part->Current_File_System.c_str());
	if (!Part->Fstab_File_System.empty())
		printf("   Fstab_File_System: %s\n", Part->Fstab_File_System.c_str());
	if (Part->Format_Block_Size != 0)
		printf("   Format_Block_Size: %lu\n", Part->Format_Block_Size);
	if (!Part->MTD_Name.empty())
		printf("   MTD_Name: %s\n", Part->MTD_Name.c_str());
	printf("   Backup_Method: %s\n", Part->Backup_Method_By_Name().c_str());
	if (Part->Mount_Flags || !Part->Mount_Options.empty())
		printf("   Mount_Flags: %i, Mount_Options: %s\n", Part->Mount_Flags, Part->Mount_Options.c_str());
	if (Part->MTP_Storage_ID)
		printf("   MTP_Storage_ID: %i\n", Part->MTP_Storage_ID);
	if (!Part->Key_Directory.empty())
		printf("   Metadata Key Directory: %s\n", Part->Key_Directory.c_str());
	printf("\n");
}

int TWPartitionManager::Mount_By_Path(string Path, bool Display_Error) {
	std::vector<TWPartition*>::iterator iter;
	int ret = false;
	bool found = false;
	string Local_Path = TWFunc::Get_Root_Path(Path);

	if (Local_Path == "/tmp" || Local_Path == "/")
		return true;

	// Iterate through all partitions
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Mount_Point == Local_Path || (!(*iter)->Symlink_Mount_Point.empty() && (*iter)->Symlink_Mount_Point == Local_Path)) {
			ret = (*iter)->Mount(Display_Error);
			found = true;
		} else if ((*iter)->Is_SubPartition && (*iter)->SubPartition_Of == Local_Path) {
			(*iter)->Mount(Display_Error);
		}
	}
	if (found) {
		return ret;
	} else if (Display_Error) {
		gui_msg(Msg(msg::kError, "unable_find_part_path=Unable to find partition for path '{1}'")(Local_Path));
	}
	return false;
}

int TWPartitionManager::UnMount_By_Path(string Path, bool Display_Error) {
	std::vector<TWPartition*>::iterator iter;
	int ret = false;
	bool found = false;
	string Local_Path = TWFunc::Get_Root_Path(Path);

	// Iterate through all partitions
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Mount_Point == Local_Path || (!(*iter)->Symlink_Mount_Point.empty() && (*iter)->Symlink_Mount_Point == Local_Path)) {
			ret = (*iter)->UnMount(Display_Error);
			found = true;
		} else if ((*iter)->Is_SubPartition && (*iter)->SubPartition_Of == Local_Path) {
			(*iter)->UnMount(Display_Error);
		}
	}
	if (found) {
		return ret;
	} else if (Display_Error) {
		gui_msg(Msg(msg::kError, "unable_find_part_path=Unable to find partition for path '{1}'")(Local_Path));
	} else {
		LOGINFO("UnMount: Unable to find partition for path '%s'\n", Local_Path.c_str());
	}
	return false;
}

int TWPartitionManager::Is_Mounted_By_Path(string Path) {
	TWPartition* Part = Find_Partition_By_Path(Path);

	if (Part)
		return Part->Is_Mounted();
	else
		LOGINFO("Is_Mounted: Unable to find partition for path '%s'\n", Path.c_str());
	return false;
}

int TWPartitionManager::Mount_Current_Storage(bool Display_Error) {
	string current_storage_path = DataManager::GetCurrentStoragePath();

	if (Mount_By_Path(current_storage_path, Display_Error)) {
		TWPartition* FreeStorage = Find_Partition_By_Path(current_storage_path);
		if (FreeStorage)
			DataManager::SetValue(TW_STORAGE_FREE_SIZE, (int)(FreeStorage->Free / 1048576LLU));
		return true;
	}
	return false;
}

int TWPartitionManager::Mount_Settings_Storage(bool Display_Error) {
	return Mount_By_Path(DataManager::GetSettingsStoragePath(), Display_Error);
}

TWPartition* TWPartitionManager::Find_Partition_By_Path(const string& Path) {
	std::vector<TWPartition*>::iterator iter;
	string Local_Path = TWFunc::Get_Root_Path(Path);

	if (Local_Path == "/system")
		Local_Path = Get_Android_Root_Path();
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Mount_Point == Local_Path || (!(*iter)->Symlink_Mount_Point.empty() && (*iter)->Symlink_Mount_Point == Local_Path))
			return (*iter);
	}
	return NULL;
}

TWPartition* TWPartitionManager::Find_Partition_By_Block_Device(const string& Block_Device) {
	std::vector<TWPartition*>::iterator iter;

	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Primary_Block_Device == Block_Device || (!(*iter)->Actual_Block_Device.empty() && (*iter)->Actual_Block_Device == Block_Device))
			return (*iter);
	}
	return NULL;
}

int TWPartitionManager::Check_Backup_Name(const std::string& Backup_Name, bool Display_Error, bool Must_Be_Unique) {
	// Check the backup name to ensure that it is the correct size and contains only valid characters
	// and that a backup with that name doesn't already exist
	char backup_name[MAX_BACKUP_NAME_LEN];
	char backup_loc[255], tw_image_dir[255];
	int copy_size;
	int index, cur_char;
	string Backup_Loc;

	copy_size = Backup_Name.size();
	// Check size
	if (copy_size > MAX_BACKUP_NAME_LEN) {
		if (Display_Error)
			gui_err("backup_name_len=Backup name is too long.");
		return -2;
	}

	// Check each character
	strncpy(backup_name, Backup_Name.c_str(), copy_size);
	if (copy_size == 1 && strncmp(backup_name, "0", 1) == 0)
		return 0; // A "0" (zero) means to use the current timestamp for the backup name
	for (index=0; index<copy_size; index++) {
		cur_char = (int)backup_name[index];
		if (cur_char == 32 || (cur_char >= 48 && cur_char <= 57) || (cur_char >= 65 && cur_char <= 91) || cur_char == 93 || cur_char == 95 || (cur_char >= 97 && cur_char <= 123) || cur_char == 125 || cur_char == 45 || cur_char == 46) {
			// These are valid characters
			// Numbers
			// Upper case letters
			// Lower case letters
			// Space
			// and -_.{}[]
		} else {
			if (Display_Error)
				gui_msg(Msg(msg::kError, "backup_name_invalid=Backup name '{1}' contains invalid character: '{1}'")(Backup_Name)((char)cur_char));
			return -3;
		}
	}

	if (Must_Be_Unique) {
		// Check to make sure that a backup with this name doesn't already exist
		DataManager::GetValue(TW_BACKUPS_FOLDER_VAR, Backup_Loc);
		strcpy(backup_loc, Backup_Loc.c_str());
		sprintf(tw_image_dir,"%s/%s", backup_loc, Backup_Name.c_str());
		if (TWFunc::Path_Exists(tw_image_dir)) {
			if (Display_Error)
				gui_err("backup_name_exists=A backup with that name already exists!");

			return -4;
		}
		// Backup is unique
	}
	// No problems found
	return 0;
}

namespace {
// RAII guard for GUI affinity during a backup OR restore. The constructor moves
// the GUI to an efficiency core, the destructor restores the performance core —
// guaranteed on all exit paths of Backup_Partition()/Restore_Partition().
// Single source of truth: identical pin logic for both paths.
struct GuiAffinityGuard {
	GuiAffinityGuard()  { twrpTar::Set_GUI_Efficiency(true);  } // operation running -> efficiency core
	~GuiAffinityGuard() { twrpTar::Set_GUI_Efficiency(false); } // operation done    -> performance core
};

// RAII guard for the CPU performance mode, like GuiAffinityGuard. The C++
// destructor guarantee on every scope exit (normal return, early return,
// exception) makes the reset forget-proof. Usage: one `PerformanceModeGuard
// perf;` at the top of the function.
struct PerformanceModeGuard {
	PerformanceModeGuard()  { TWFunc::SetPerformanceMode(true);  }
	~PerformanceModeGuard() { TWFunc::SetPerformanceMode(false); }
};
}  // namespace

// Shared subpartition walk: returns all subpartitions of `parent`
// (Is_SubPartition + SubPartition_Of == parent->Mount_Point).
// require_can_be_backed_up=true additionally filters Can_Be_Backed_Up (backup);
// restore takes all.
std::vector<TWPartition*> TWPartitionManager::Get_SubPartitions_Of(TWPartition* parent, bool require_can_be_backed_up) {
	std::vector<TWPartition*> out;
	for (TWPartition* sub : Partitions) {
		if (sub->Is_SubPartition && sub->SubPartition_Of == parent->Mount_Point
		    && (!require_can_be_backed_up || sub->Can_Be_Backed_Up))
			out.push_back(sub);
	}
	return out;
}

bool TWPartitionManager::Backup_Partition(PartitionSettings *part_settings) {
	time_t start, stop;
	int use_compression;

	if (part_settings->Part == NULL)
		return true;

	DataManager::GetValue(TW_USE_COMPRESSION_VAR, use_compression);

	time(&start);
	double digest_secs = 0.0; // total digest generation time — subtracted from backup_time (MB/s rate)
	// RAII: both guards restore automatically on every return (normal, cancel, error).
	GuiAffinityGuard     gui_affinity_guard;
	PerformanceModeGuard perf_mode_guard;

	if (part_settings->Part->Backup(part_settings, &tar_fork_pid)) {
		if (stop_backup.get_value() != 0) {
			// Convention of the backup chain (Backup_Partition, Backup_Tar,
			// twrpTar): true=success, false=failure-or-cancel. The error-vs-
			// cancel classification is done exclusively by Run_Backup via
			// stop_backup. Even if the partition technically landed on disk,
			// from the user's perspective the operation was aborted, so report
			// false and leave the final verdict to Run_Backup.
			return false;
		}
		sync();
		sync();
		string Full_Filename = part_settings->Backup_Folder + "/" + part_settings->Part->Backup_FileName;
		if (!part_settings->adbbackup && part_settings->generate_digest) {
			time_t d_start, d_stop;
			time(&d_start);
			if (!twrpDigestDriver::Make_Digest(Full_Filename)) {
				return false;
			}
			time(&d_stop);
			digest_secs += difftime(d_stop, d_start);
		}

		if (part_settings->Part->Has_SubPartition) {
			TWPartition *parentPart = part_settings->Part;
			for (TWPartition* subpart : Get_SubPartitions_Of(parentPart, /*require_can_be_backed_up=*/true)) {
				part_settings->Part = subpart;
				if (!subpart->Backup(part_settings, &tar_fork_pid)) {
					return false;
				}
				sync();
				sync();
				string Full_Filename = part_settings->Backup_Folder + "/" + part_settings->Part->Backup_FileName;
				if (!part_settings->adbbackup && part_settings->generate_digest) {
					time_t d_start, d_stop;
					time(&d_start);
					if (!twrpDigestDriver::Make_Digest(Full_Filename)) {
						return false;
					}
					time(&d_stop);
					digest_secs += difftime(d_stop, d_start);
				}
			}
		}

		time(&stop);
		int backup_time = (int) difftime(stop, start) - (int) digest_secs; // digest time excluded -> rate = pure backup throughput
		if (backup_time < 0) backup_time = 0; // seconds rounding guard
		LOGINFO("Partition Backup time: %d (digest %d s excluded)\n", backup_time, (int) digest_secs);

		if (part_settings->Part->Backup_Method == BM_FILES) {
			part_settings->file_time += backup_time;
		} else {
			part_settings->img_time += backup_time;
		}

		return true;
	}
	// Cleanup lives in Run_Backup because the error and cancel paths do
	// identical work (full removeDir + sibling recovery.log). The performance-
	// mode reset is handled automatically by the PerformanceModeGuard RAII.
	return false;
}


int TWPartitionManager::Check_Backup_Cancel() {
	return stop_backup.get_value();
}

int TWPartitionManager::Cancel_Backup() {
	// Signaling only. Cleanup (recovery.log + removeDir + gui_msg) is
	// single-sourced in Run_Backup's cancel-exit handler. Here: set stop_backup,
	// kill the children, wait synchronously for the reap (so Run_Backup does not
	// continue while tar_fork_pid is still alive).
	stop_backup.set_value(1);

	if (tar_fork_pid != 0) {
		LOGINFO("Cancelling backup, killing all children\n");
		twrpTar::Kill_Backup_Children();
		// Bounded wait instead of an endless loop. SIGUSR2 -> _exit(0) in the
		// pipe children, then createTarFork() reaps and sets *tar_fork_pid=0.
		// If a child hangs in the kernel (uninterruptible D-state, blocked IO),
		// a plain while(tar_fork_pid != 0) busywait would freeze the GUI
		// forever. 10s hard timeout, then SIGKILL as fallback + a short extra
		// wait.
		const int max_wait_iter = 100; // 100 x 100ms = 10s
		int wait_iter = 0;
		while (tar_fork_pid != 0 && wait_iter < max_wait_iter) {
			usleep(100000);
			wait_iter++;
		}
		if (tar_fork_pid != 0) {
			pid_t stuck_pid = tar_fork_pid;
			LOGERR("Cancel_Backup: SIGUSR2 wait timed out after 10s, sending SIGKILL to pid %d\n",
			       (int)stuck_pid);
			kill(stuck_pid, SIGKILL);
			for (wait_iter = 0; tar_fork_pid != 0 && wait_iter < 20; wait_iter++)
				usleep(100000); // +2s after SIGKILL
			if (tar_fork_pid != 0)
				LOGERR("Cancel_Backup: tar_fork_pid still non-zero after SIGKILL -- Run_Backup will clean up anyway\n");
		}
		LOGINFO("Cancel_Backup: children reaped, control returns to Run_Backup for cleanup\n");
	}

	return 0;
}

int TWPartitionManager::Cancel_Restore() {
	// Hard lock: during a RAW/image restore (Restore_Image -> Raw_Read_Write) a
	// mid-flight abort would leave the block device half-written -> softbrick.
	// restore_cancelable is set per partition in Run_Restore(); if it is 0,
	// either a RAW partition is running or no restore is active — in both cases
	// refuse the cancel. The GUI locks the cancel button in parallel via
	// tw_restore_cancelable; the check here is the safeguard against
	// ADB/theme/script bypass.
	if (restore_cancelable.get_value() == 0) {
		gui_msg(Msg(msg::kError, "restore_cancel_blocked=Cancel blocked: RAW partition in progress -- aborting would damage the device."));
		LOGINFO("Cancel_Restore: ignored -- restore_cancelable=0 (RAW partition or no restore active)\n");
		return -1;
	}
	stop_restore.set_value(1);
	LOGINFO("Cancelling restore, killing all children");
	twrpTar::Kill_Restore_Children();
	LOGINFO("Restore_Run stopped and returning 1, restore cancelled.\n");
	return 0;
}

// Pause/resume wrappers, called by the page-entry hook in PageSet::SetPage when
// the user enters/leaves the cancel_restore_confirm page. SIGSTOPs the restore
// pipeline children while the user thinks on the confirm page, so restore IO
// does not continue in the background; SIGCONT on leaving. Idempotent: repeated
// calls are harmless (POSIX no-op on an already stopped/running process). With
// no active restore (g_restore_children empty) both methods are no-ops.
void TWPartitionManager::Pause_Restore(void) {
	LOGINFO("Pausing restore -- user on cancel_restore_confirm\n");
	twrpTar::Pause_Restore_Children();
}

void TWPartitionManager::Resume_Restore(void) {
	LOGINFO("Resuming restore -- user back from cancel_restore_confirm\n");
	twrpTar::Resume_Restore_Children();
}

// Forward declaration (defined below): Sync_Backup_Inclusions() needs the
// backup-set list to include external_app_data only when /data is in the set.
static std::vector<std::string> split_partition_list(const std::string& list);

bool TWPartitionManager::Sync_Backup_Inclusions() {
	TWPartition* data = Find_Partition_By_Path("/data");
	if (!data || !data->Has_Data_Media)
		return false;

	// external_app_data is /data-specific: only when /data is actually in THIS
	// backup set (otherwise e.g. a metadata-only backup would trigger the
	// "Counting..." message + size accounting). This function encapsulates the
	// COMPLETE decision — the caller (Run_Backup) needs no extra flag.
	string backup_list;
	DataManager::GetValue("tw_backup_list", backup_list);
	bool data_in_set = false;
	for (const string& bp : split_partition_list(backup_list))
		if (Find_Partition_By_Path(bp) == data) { data_in_set = true; break; }
	if (!data_in_set)
		return false;

	bool include = (DataManager::GetIntValue("tw_backup_external_app_data") == 1);
	if (include) {
		string p = data->Mount_Point + "/media/0/Android";
		if (TWFunc::Path_Exists(p)) {
			gui_msg(Msg("counting_external= * Counting external app data size..."));
			LOGINFO("Including %s in /data backup\n", p.c_str());
		} else {
			gui_msg(Msg(msg::kWarning, "external_app_data_skip=External app data requested but folder '{1}' not found -- skipping.")(p));
			include = false;
		}
	}
	data->Refresh_External_App_Data_Inclusion(include);
	return include;
}

// Tokenizes a ';'-separated partition/image list: every ';'-terminated segment
// becomes an entry; a trailing token without ';' is deliberately ignored.
// Single source for the 4 walks in Run_Backup/Run_Restore.
static std::vector<std::string> split_partition_list(const std::string& list) {
	std::vector<std::string> out;
	size_t start_pos = 0, end_pos = list.find(";", start_pos);
	while (end_pos != std::string::npos && start_pos < list.size()) {
		out.push_back(list.substr(start_pos, end_pos - start_pos));
		start_pos = end_pos + 1;
		end_pos = list.find(";", start_pos);
	}
	return out;
}

int TWPartitionManager::Run_Backup(bool adbbackup) {
	PartitionSettings part_settings;
	int partition_count = 0, disable_free_space_check = 0, skip_digest = 0;
	string Backup_Name, Backup_List;
	unsigned long long total_bytes = 0, free_space = 0;
	TWPartition* storage = NULL;
	struct tm *t;
	time_t seconds, total_start, total_stop;
	stop_backup.set_value(0);
	seconds = time(0);
	t = localtime(&seconds);

	part_settings.img_bytes_remaining = 0;
	part_settings.file_bytes_remaining = 0;
	part_settings.img_time = 0;
	part_settings.file_time = 0;
	part_settings.img_bytes = 0;
	part_settings.file_bytes = 0;
	part_settings.external_app_data_size = 0;
	part_settings.external_app_data_included = false;
	part_settings.PM_Method = PM_BACKUP;

	part_settings.adbbackup = adbbackup;
	time(&total_start);

	// Per-op log: record the start offset of this backup operation (slicing in
	// Save_Recovery_Log; covers GUI, ORS and adb — all call Run_Backup).
	Mark_Operation_Log_Start();

	// Clear stale inclusion from previous backup run so Update_Size()
	// always sees a clean baseline (without external data). Sync_Backup_
	// Inclusions() re-applies it after the enumeration loop.
	TWPartition* data_part = Find_Partition_By_Path("/data");
	if (data_part)
		data_part->Refresh_External_App_Data_Inclusion(false);

	Update_System_Details();

	if (!Mount_Current_Storage(true))
		return 1;   // must be 1, not false (false would cast to 0 = success)

	DataManager::GetValue(TW_SKIP_DIGEST_GENERATE_VAR, skip_digest);
	if (skip_digest == 0)
		part_settings.generate_digest = true;
	else
		part_settings.generate_digest = false;

	DataManager::GetValue(TW_BACKUPS_FOLDER_VAR, part_settings.Backup_Folder);
	DataManager::GetValue(TW_BACKUP_NAME, Backup_Name);
	if (Backup_Name == gui_lookup("curr_date", "(Current Date)")) {
		Backup_Name = TWFunc::Get_Current_Date();
	} else if (Backup_Name == gui_lookup("auto_generate", "(Auto Generate)") || Backup_Name == "0" || Backup_Name.empty()) {
		TWFunc::Auto_Generate_Backup_Name();
		DataManager::GetValue(TW_BACKUP_NAME, Backup_Name);
	}

	LOGINFO("Backup Name is: '%s'\n", Backup_Name.c_str());
	part_settings.Backup_Folder = part_settings.Backup_Folder + "/" + Backup_Name;

	LOGINFO("Backup_Folder is: '%s'\n", part_settings.Backup_Folder.c_str());

	// Pre-calc cancel check #1: the user pressed cancel during the
	// Mount_Current_Storage or GetValue phase. Backup_Folder is valid from here
	// on — an early check avoids needless Get_Folder_Size/Recursive_Mkdir work.
	if (stop_backup.get_value() != 0)
		return Operation_Cleanup(OpType::Backup, 2, part_settings.Backup_Folder, adbbackup);

	LOGINFO("Calculating backup details...\n");
	DataManager::GetValue("tw_backup_list", Backup_List);
	LOGINFO("Backup_List: %s\n", Backup_List.c_str());
	if (!Backup_List.empty()) {
		for (const string& backup_path : split_partition_list(Backup_List)) {
			LOGINFO("backup_path: %s\n", backup_path.c_str());
			part_settings.Part = Find_Partition_By_Path(backup_path);
			if (part_settings.Part != NULL) {
				partition_count++;
				if (part_settings.Part->Backup_Method == BM_FILES)
					part_settings.file_bytes += part_settings.Part->Backup_Size;
				else
					part_settings.img_bytes += part_settings.Part->Backup_Size;
				if (part_settings.Part->Has_SubPartition) {
					std::vector<TWPartition*>::iterator subpart;

					for (subpart = Partitions.begin(); subpart != Partitions.end(); subpart++) {
						if ((*subpart)->Can_Be_Backed_Up && (*subpart)->Is_Present && (*subpart)->Is_SubPartition && (*subpart)->SubPartition_Of == part_settings.Part->Mount_Point) {
							partition_count++;
							if ((*subpart)->Backup_Method == BM_FILES)
								part_settings.file_bytes += (*subpart)->Backup_Size;
							else
								part_settings.img_bytes += (*subpart)->Backup_Size;
						}
					}
				}
			} else {
				gui_msg(Msg(msg::kError, "unable_to_locate_partition=Unable to locate '{1}' partition for backup calculations.")(backup_path));
			}
		}
	}

	// External data (/data/media/0/Android): inclusion + size accounting AFTER
	// Update_System_Details() to avoid blocking the main thread with a multi-GB
	// walk inside Update_Size() (would starve the MTP thread → USB timeout → crash).
	// Sync_Backup_Inclusions() sets the inclusion flag for the later forked
	// Generate_TarList() backup walk and returns whether inclusion was actually
	// applied (Checkbox + Path_Exists). That decision becomes the single source
	// of truth — used both for size accounting here and for the .info flag in
	// twrpTar.cpp via part_settings->external_app_data_included.
	part_settings.external_app_data_included = Sync_Backup_Inclusions();
	if (part_settings.external_app_data_included) {
		string android_path = "/data/media/0/Android";
		TWExclude tmp;
		unsigned long long ext_size = tmp.Get_Folder_Size(android_path);
		part_settings.external_app_data_size = ext_size / 1048576ULL;
		part_settings.file_bytes += ext_size;
		// tar.setsize(Backup_Size) in Backup_Partition uses the partition
		// object's Backup_Size, which was computed WITHOUT the inclusion.
		// Update it so Total_Backup_Size (sent via progress pipe) matches
		// what tarList actually backs up.
		if (data_part)
			data_part->Backup_Size += ext_size;
		LOGINFO("External data size: %llu MB added to backup total\n", ext_size / 1048576ULL);
		gui_msg("counting_external_done= * ...done");
	}

	// Pre-calc cancel check #2: Get_Folder_Size on /data/media/0/Android can
	// take several seconds for a large Android folder — the only potentially
	// long-running pre-calc operation. An early exit here keeps the cancel
	// reaction snappy.
	if (stop_backup.get_value() != 0)
		return Operation_Cleanup(OpType::Backup, 2, part_settings.Backup_Folder, adbbackup);

	if (partition_count == 0) {
		gui_msg("no_partition_selected=No partitions selected for backup.");
		return 1;
	}
	// Compute total_bytes BEFORE the stream header: the ADB stream header
	// carries the estimate sum as the restore grand-total denominator
	// (file_bytes/img_bytes are fully accumulated here, incl.
	// external_app_data). The per-partition exact correction is done by the
	// restore itself (Finish_Partition_Exact).
	total_bytes = part_settings.file_bytes + part_settings.img_bytes;
	if (adbbackup) {
		if (twadbbu::Write_ADB_Stream_Header(partition_count, total_bytes) == false) {
			return 1;
		}
	}
	ProgressTracking progress(total_bytes);
	part_settings.progress = &progress;

	gui_msg(Msg("total_partitions_backup= * Total number of partitions to back up: {1}")(partition_count));
	gui_msg(Msg("total_backup_size= * Total size of all data: {1}MB")(total_bytes / 1024 / 1024));
	storage = Find_Partition_By_Path(DataManager::GetCurrentStoragePath());
	if (storage != NULL) {
		free_space = storage->Free;
		gui_msg(Msg("available_space= * Available space: {1}MB")(free_space / 1024 / 1024));
	} else {
		gui_err("unable_locate_storage=Unable to locate storage device.");
		return 1;
	}

	DataManager::GetValue(TW_DISABLE_FREE_SPACE_VAR, disable_free_space_check);

	if (adbbackup)
		disable_free_space_check = true;

	if (!disable_free_space_check) {
		// Addition form instead of subtraction: with free_space < 32 MB an
		// unsigned subtraction would wrap to a huge value and defeat the check.
		if (free_space < total_bytes + (32ULL * 1024 * 1024)) {
			// We require an extra 32MB just in case
			gui_err("no_space=Not enough free space on storage.");
			return 1;
		}
	}
	part_settings.img_bytes_remaining = part_settings.img_bytes;
	part_settings.file_bytes_remaining = part_settings.file_bytes;

	gui_msg("backup_started=[BACKUP STARTED]");

	int is_decrypted = 0;
	int is_encrypted = 0;

	DataManager::GetValue(TW_IS_DECRYPTED, is_decrypted);
	DataManager::GetValue(TW_IS_ENCRYPTED, is_encrypted);
	if (is_encrypted && !is_decrypted)
		gui_msg((getauxval(AT_HWCAP) & HWCAP_AES) ? "aes_hw" : "aes_sw");
	// ADB backup creates NO backup folder: the stream goes to the PC; nothing
	// but the recovery.log would land in it on-device (that goes directly into
	// the backup root as ADB_Backup_<date>_Recovery.log, see
	// Save_ADB_Recovery_Log). GUI backups behave as before.
	if (!adbbackup) {
		gui_msg(Msg("backup_folder= * Backup Folder: {1}")(part_settings.Backup_Folder));
		if (!TWFunc::Recursive_Mkdir(part_settings.Backup_Folder)) {
			gui_err("fail_backup_folder=Failed to make backup folder.");
			return 1;
		}
	}

	// Pre-calc cancel check #3: the user pressed cancel between mkdir and loop
	// start. Clean pre-loop entry guarantee — all expensive pre-calc steps are
	// done, the backup folder exists (GUI; adb creates none), but nothing
	// destructive has happened yet.
	if (stop_backup.get_value() != 0)
		return Operation_Cleanup(OpType::Backup, 2, part_settings.Backup_Folder, adbbackup);

	DataManager::SetProgress(0.0);

	// Hard abort: every real per-partition failure — not found OR a
	// Backup_Partition error (e.g. pipe collapse, digest failure) — aborts the
	// ENTIRE backup, symmetric to Run_Restore. A graceful skip would report
	// partial/total failures as success-with-warning (return 0) and could not
	// distinguish "partition missing" from a corrupt archive.
	// Operation_Cleanup(status=1) discards the backup folder via removeDir +
	// reports [BACKUP FAILED]. Cancel takes precedence.
	for (const string& backup_path : split_partition_list(Backup_List)) {
		if (stop_backup.get_value() != 0) {
			break;
		}
		part_settings.Part = Find_Partition_By_Path(backup_path);
		if (part_settings.Part != NULL) {
			if (!Backup_Partition(&part_settings)) {
				// Cancel-first classification: Backup_Partition returns false
				// for both error and cancel. Run_Backup decides via stop_backup
				// which final marker applies — cancel wins, so the user does not
				// wrongly see [BACKUP FAILED] after cancelling themselves.
				if (stop_backup.get_value() != 0) {
					return Operation_Cleanup(OpType::Backup, 2, part_settings.Backup_Folder, adbbackup);
				}
				return Operation_Cleanup(OpType::Backup, 1, part_settings.Backup_Folder, adbbackup);
			}
		} else {
			// Partition not found -> hard abort (no silent skip). kError matches
			// the pre-calc loop (same message).
			gui_msg(Msg(msg::kError, "unable_to_locate_partition=Unable to locate '{1}' partition for backup calculations.")(backup_path));
			return Operation_Cleanup(OpType::Backup, 1, part_settings.Backup_Folder, adbbackup);
		}
	}

	if (stop_backup.get_value() != 0)
		return Operation_Cleanup(OpType::Backup, 2, part_settings.Backup_Folder, adbbackup);
	
	// Average BPS
	if (part_settings.img_time == 0)
		part_settings.img_time = 1;
	if (part_settings.file_time == 0)
		part_settings.file_time = 1;
	int img_bps = (int)(part_settings.img_bytes / part_settings.img_time);
	unsigned long long file_bps = part_settings.file_bytes / (int)part_settings.file_time;

	if (part_settings.file_bytes != 0)
		gui_msg(Msg("avg_backup_fs=Average backup rate for file systems: {1} MB/sec")(file_bps / (1024 * 1024)));
	if (part_settings.img_bytes != 0)
		gui_msg(Msg("avg_backup_img=Average backup rate for imaged drives: {1} MB/sec")(img_bps / (1024 * 1024)));

	time(&total_stop);
	int total_time = (int) difftime(total_stop, total_start);

	uint64_t actual_backup_size;
	if (!adbbackup) {
		TWExclude twe;
		actual_backup_size = twe.Get_Folder_Size(part_settings.Backup_Folder);
	} else
		actual_backup_size = part_settings.file_bytes + part_settings.img_bytes;
	
	actual_backup_size /= (1024LLU * 1024LLU);
	int prev_img_bps = 0, use_compression = 0;
	unsigned long long prev_file_bps = 0;
	DataManager::GetValue(TW_BACKUP_AVG_IMG_RATE, prev_img_bps);
	img_bps += (prev_img_bps * 4);
	img_bps /= 5;

	DataManager::GetValue(TW_USE_COMPRESSION_VAR, use_compression);
	if (use_compression)
		DataManager::GetValue(TW_BACKUP_AVG_FILE_COMP_RATE, prev_file_bps);
	else
		DataManager::GetValue(TW_BACKUP_AVG_FILE_RATE, prev_file_bps);
	
	file_bps += (prev_file_bps * 4);
	file_bps /= 5;
	DataManager::SetValue(TW_BACKUP_AVG_IMG_RATE, img_bps);
	
	if (use_compression)
		DataManager::SetValue(TW_BACKUP_AVG_FILE_COMP_RATE, file_bps);
	else
		DataManager::SetValue(TW_BACKUP_AVG_FILE_RATE, file_bps);

	gui_msg(Msg("total_backed_size=[{1} MB TOTAL BACKED UP]")(actual_backup_size));
	// Write recovery.log BEFORE Update_System_Details — otherwise the ~2 MB
	// recovery.log is not counted in the freshly measured storage/free size
	// (displayed value would be wrong). ADB: no backup folder -> date-named log
	// into the backup root (Save_ADB_Recovery_Log); GUI path stays intra-folder.
	if (part_settings.adbbackup)
		Save_ADB_Recovery_Log("Backup");
	else
		Save_Recovery_Log(part_settings.Backup_Folder + "/recovery.log");
	Update_System_Details();
	UnMount_Main_Partitions();
	gui_msg(Msg(msg::kHighlight, "backup_completed=[BACKUP COMPLETED IN {1} SECONDS]")(total_time)); // the end

	if (part_settings.adbbackup) {
		if (twadbbu::Write_ADB_Stream_Trailer() == false) {
			return 1;
		}
	}
	part_settings.adbbackup = false;
	DataManager::SetValue("tw_enable_adb_backup", 0);

	return 0;
}

// ---------- Backup/restore exit helper ----------
// Generic cleanup helper for both operations: the OpType discriminator
// (Backup|Restore) picks the path, the rest is shared.
//
// Only called for error/cancel exits (status==1 / status==2). Success paths
// (status==0) save the recovery log inline because they write INTRA the backup
// folder (with '/') instead of as a SIBLING ('_').
//
// The Path_Exists guard wraps the cleanup block (sibling log + removeDir), NOT
// the gui_msg — early-failed backups (mkdir errors) must still show the error.
//
// adbbackup (backup path only; default false keeps Run_Restore callers and GUI
// semantics untouched): the ADB path has NO backup folder (mkdir is adb-gated)
// and nothing to clean on the device (the backup materializes on the PC) ->
// log via Save_ADB_Recovery_Log (date name instead of folder-name sibling), no
// removeDir/"Cleaning backup folder." message.

int TWPartitionManager::Operation_Cleanup(OpType op, int status, const string& path, bool adbbackup) {
	TWFunc::SetPerformanceMode(false);

	if (op == OpType::Backup) {
		if (adbbackup) {
			Save_ADB_Recovery_Log("Backup");
		} else {
			// ALWAYS write the sibling log — recovery.log contains system/mount/
			// init events from before the mkdir, diagnostically valuable even for
			// early-failed backups. The sibling path sits at parent level (backup
			// root), not inside the Backup_Folder — the write works whether or
			// not mkdir ran. On storage/mount issues copy_file swallows the
			// open() error silently (no crash, no file).
			Save_Recovery_Log(path + "_Backup_Recovery.log");	// sibling NEXT TO the folder (underscore, no slash)

			// Announce + removeDir only if the backup folder exists. Early-
			// failed/-cancelled backups (mkdir never ran) would otherwise
			// misleadingly report "Cleaning...", and removeDir would additionally
			// throw gui_msg("error_opening_strerr").
			if (TWFunc::Path_Exists(path)) {
				if (status == 1)
					gui_msg(Msg("backup_error_clean=Backup failed. Cleaning backup folder."));
				else if (status == 2)
					gui_msg(Msg("backup_cancel_clean=Backup cancelled! Cleaning backup folder."));
				TWFunc::removeDir(path, false);	// remove folder + contents entirely (false = delete the parent too)
			}
		}

		// Final marker (always)
		if (status == 1)
			gui_msg(Msg(msg::kError,     "backup_fail=[BACKUP FAILED]"));
		else if (status == 2)
			gui_msg(Msg(msg::kHighlight, "backup_cancel=[BACKUP CANCELLED]"));
	} else { // OpType::Restore
		Set_Restore_Cancelable(0);
		// ALWAYS write the sibling log (same reasoning as the backup branch);
		// with an invalid path copy_file swallows the open() error silently.
		Save_Recovery_Log(path + "_Restore_Recovery.log");
		if (status == 1)
			gui_msg(Msg(msg::kError,     "restore_fail=[RESTORE FAILED]"));
		else if (status == 2)
			gui_msg(Msg(msg::kHighlight, "restore_cancel=[RESTORE CANCELLED]"));
	}
	return status;
}


// Per-operation log slicing: records the current byte position of
// /tmp/recovery.log as the start of the backup/restore operation about to
// begin. The FIRST call of the session additionally freezes log_ctx_end —
// everything before it (fstab/mounts/decrypt) is the boot context every per-op
// log gets as a prefix. stat errors leave the marks untouched ->
// Save_Recovery_Log then does the full copy.
void TWPartitionManager::Mark_Operation_Log_Start(void) {
	struct stat st;
	if (stat(TMP_LOG_FILE, &st) != 0)
		return;
	if (log_ctx_end < 0)
		log_ctx_end = (long long)st.st_size;
	log_op_start = (long long)st.st_size;
}

void TWPartitionManager::Save_Recovery_Log(const string& log_path) {
	// Slice only with plausible marks; EVERY edge case (marks unset because no
	// operation funnel ran; stat/IO errors; offsets beyond the file size) falls
	// back to the plain full copy.
	bool sliced = false;
	if (log_op_start >= 0 && log_ctx_end >= 0 && log_ctx_end <= log_op_start)
		sliced = TWFunc::Copy_Log_Slices(TMP_LOG_FILE, log_path, log_ctx_end, log_op_start);
	if (!sliced)
		TWFunc::copy_file("/tmp/recovery.log", log_path, 0644);
	tw_set_default_metadata(log_path.c_str());
}

// ADB backup/restore ONLY: the ADB path has no backup folder (the stream goes
// to the PC) and thus no (possibly user-defined) folder name for the GUI
// intra/sibling scheme -> date name (Get_Current_Date = backup name format)
// directly in the backup root. Used by Run_Backup success (adb),
// Operation_Cleanup (adb) and twrpAdbBuFifo::Restore_ADB_Backup (all exits —
// mirrors GUI restore practice, which stores a log on success AND
// error/cancel). Errors are swallowed silently by copy_file.
void TWPartitionManager::Save_ADB_Recovery_Log(const std::string& op) {
	string root;
	DataManager::GetValue(TW_BACKUPS_FOLDER_VAR, root);
	if (root.empty()) {
		LOGINFO("Save_ADB_Recovery_Log: no backup root set, skipping\n");
		return;
	}
	TWFunc::Recursive_Mkdir(root);   // in case no backup ever existed
	Save_Recovery_Log(root + "/ADB_" + op + "_" + TWFunc::Get_Current_Date() + "_Recovery.log");
}



bool TWPartitionManager::Restore_Partition(PartitionSettings *part_settings) {
	time_t Start, Stop;

	if (part_settings->adbbackup) {
		std::string partName = part_settings->Part->Backup_Name + "." + part_settings->Part->Current_File_System + ".win";
		LOGINFO("setting backup name: %s\n", partName.c_str());
		part_settings->Part->Set_Backup_FileName(part_settings->Part->Backup_Name + "." + part_settings->Part->Current_File_System + ".win");
	}

	// RAII: both guards restore automatically on every return (mirror of
	// Backup_Partition).
	GuiAffinityGuard     gui_affinity_guard;
	PerformanceModeGuard perf_mode_guard;

	time(&Start);

	if (!part_settings->Part->Restore(part_settings)) {
		return false;
	}
	if (stop_restore.get_value() != 0) {
		Update_System_Details();
		return false;
	}
	if (part_settings->Part->Has_SubPartition && !part_settings->adbbackup) {
		TWPartition *parentPart = part_settings->Part;
		for (TWPartition* subpart : Get_SubPartitions_Of(parentPart, /*require_can_be_backed_up=*/false)) {
			part_settings->Part = subpart;
			part_settings->Part->Set_Backup_FileName(part_settings->Part->Backup_Name + "." + part_settings->Part->Current_File_System + ".win");
			if (!subpart->Restore(part_settings)) {
				return false;
			}
			if (stop_restore.get_value() != 0) {
				Update_System_Details();
				return false;
			}
		}
	}
	time(&Stop);
	gui_msg(Msg("restore_part_done=[{1} done ({2} seconds)]")(part_settings->Part->Backup_Display_Name)((int)difftime(Stop, Start)));

	return true;
}

// Sets the cancel lock in BOTH sources (atomic restore_cancelable + DataManager
// mirror tw_restore_cancelable). Single source so the two never diverge.
void TWPartitionManager::Set_Restore_Cancelable(int v) {
	restore_cancelable.set_value(v);
	DataManager::SetValue("tw_restore_cancelable", v);
}

// Writes the SPECIFIC reject message for a Restore_Validity reason to the GUI
// console. ONE source (DRY) for both reject paths: the early GUI firewall
// Preflight_Restore_Backup AND the Run_Restore loop-1 guard (CLI/ORS backstop).
// Takes the partition, so the messages name the partition (Mount_Point, e.g.
// "/data") or the .info filename (Backup_Name+".info", e.g. "data.info")
// instead of the GUI display name — CLI/ORS restore gets the same specific
// reason as the GUI.
void TWPartitionManager::Emit_Restore_Validity_Error(Restore_Validity rv, const TWPartition* Part) {
	switch (rv) {
		case RV_NO_BACKUP_SIZE:
			gui_msg(Msg(msg::kError, "restore_invalid_dfp_size=The backup of partition {1} is corrupted. The required backup size header (TWRP.backup_size) is missing.")(Part->Mount_Point));
			break;
		case RV_LEGACY_NO_INFO:
			gui_msg(Msg(msg::kError, "restore_invalid_legacy_info=The required \"{1}\" file is missing from the selected backup for the \"{2}\" partition.")(Part->Backup_Name + ".info")(Part->Mount_Point));
			break;
		case RV_REJECT_OPENAES:
			gui_err("restore_openaes_rejected=This backup is encrypted with OpenAES and is no longer supported. OpenAES was removed from TWRP v3.7+ by the core developers.");
			break;
		case RV_WRONG_PASSWORD:
			gui_msg(Msg(msg::kError, "fail_decrypt_tar=Failed to decrypt tar file '{1}'")(Part->Backup_Display_Name));
			break;
		case RV_REJECT_UNKNOWN:
		default:
			gui_msg(Msg(msg::kError, "restore_unknown_format=The backup for the {1} partition has an unrecognized format. Its header could not be read.")(Part->Mount_Point));
			break;
	}
}

// Early GUI firewall: validates ALL file-based partitions of the chosen backup
// BEFORE the user selects partitions (tw_restore_selected = still all). Mirrors
// the validation iteration of Run_Restore loop 1 (split_partition_list ->
// Find_Partition_By_Path -> top + subpartition) but uses the shared primitive
// TWPartition::Probe_Restore_Backup (DRY). One SPECIFIC message per broken
// partition to the GUI console (which partition + reason); returns false as
// soon as ANY partition is not restorable (whole backup rejected). READ-ONLY
// (header peek + console) — NO wipe, NO partition writes. Images/super + ADB
// gate the probe themselves (RV_VALID). The loop-1 guard in Run_Restore remains
// as a backstop (CLI/ORS bypass this GUI firewall).
bool TWPartitionManager::Preflight_Restore_Backup(const string& Restore_Name) {
	// Probe_Restore_Backup detects OpenAES itself via the detection status
	// (Get_Archive_Type_From_Segments scans all segments) -> RV_REJECT_OPENAES
	// per partition. SSoT = HeaderManager.
	PartitionSettings part_settings;
	part_settings.Backup_Folder = Restore_Name;
	part_settings.Part = NULL;
	part_settings.adbbackup = false;
	part_settings.PM_Method = PM_RESTORE;

	string Restore_List;
	DataManager::GetValue("tw_restore_selected", Restore_List);
	if (Restore_List.empty())
		return true;   // nothing to check (e.g. ADB) -> do not block

	bool all_ok = true;
	for (const string& restore_path : split_partition_list(Restore_List)) {
		TWPartition* top = Find_Partition_By_Path(restore_path);
		if (top == NULL)
			continue;   // a missing partition is the Run_Restore loop-1 backstop's job, not a validity issue

		// Top partition + (if present) its subpartitions — mirrors Run_Restore loop 1.
		std::vector<TWPartition*> to_check;
		to_check.push_back(top);
		if (top->Has_SubPartition) {
			for (std::vector<TWPartition*>::iterator sp = Partitions.begin(); sp != Partitions.end(); sp++)
				if ((*sp)->Is_SubPartition && (*sp)->SubPartition_Of == top->Mount_Point)
					to_check.push_back(*sp);
		}

		for (std::vector<TWPartition*>::iterator it = to_check.begin(); it != to_check.end(); it++) {
			TWPartition* Part = *it;
			part_settings.Part = Part;
			int probe_ead = 0;
			Restore_Validity rv = Part->Probe_Restore_Backup(&part_settings, nullptr, nullptr, &probe_ead);
			// ead is purely /data-related (/data/media/0/Android). Write it ONLY
			// here, otherwise the next non-/data partition (GetEad()=-1 -> has=0)
			// would clobber the /data value. Preflight is the ONE place that
			// loads /data at setup time (R2 password-less in readBackup, R3 after
			// password in decrypt_backup). tw_has_ = fact (checkbox visibility),
			// tw_restore_ = default "on".
			if (Part->Mount_Point == "/data") {
				int has = (probe_ead == 1) ? 1 : 0;
				DataManager::SetValue("tw_has_external_app_data", has);
				DataManager::SetValue("tw_restore_external_app_data", has);
			}
			if (rv == RV_VALID)
				continue;
			all_ok = false;
			Emit_Restore_Validity_Error(rv, Part);
		}
	}
	return all_ok;
}

int TWPartitionManager::Run_Restore(const string& Restore_Name) {
	PartitionSettings part_settings;
	int check_digest;

	time_t rStart, rStop;
	time(&rStart);
	string Restore_List;

	// Per-op log: record the start offset of this restore operation (slicing in
	// Save_Recovery_Log; covers GUI and ORS — adb restore has its own funnel in
	// twrpAdbBuFifo::Restore_ADB_Backup).
	Mark_Operation_Log_Start();

	/* Clear a stale cancel flag from the previous restore. Run_Backup() does
	 * this; Run_Restore never adopted it, so after a cancel all pipe children in
	 * a multi-pipe restore would immediately exit 253 ("Pipe N: stop_restore
	 * signaled, exiting"). Upstream is affected too (single-pipe fails there the
	 * same way, just less visibly). */
	stop_restore.set_value(0);

	// Cancel lock defaults to closed: until a partition has been routed
	// (filesystem vs image), no cancel is allowed. Set per partition in the
	// restore loop below.
	Set_Restore_Cancelable(0);

	part_settings.Backup_Folder = Restore_Name;
	part_settings.Part = NULL;
	part_settings.partition_count = 0;
	part_settings.total_restore_size = 0;
	part_settings.adbbackup = false;
	part_settings.PM_Method = PM_RESTORE;

	// Refresh system/partition details (free/size, storage display) BEFORE the restore
	// -- upstream parity: original TWRP calls Update_System_Details() here at the start
	// of Run_Restore (before restore_started/Mount_Current_Storage); in this fork the
	// start call had been lost (only at restore end + in the cancel paths). Mirror of
	// Run_Backup, which also refreshes early -> loop 1 (size calc) and the GUI work with
	// current values. (Scope: refresh only, NO freespace check.)
	Update_System_Details();

	gui_msg("restore_started=[RESTORE STARTED]");
	int restore_encrypted = 0;
	DataManager::GetValue("tw_restore_encrypted", restore_encrypted);
	if (restore_encrypted)
		gui_msg((getauxval(AT_HWCAP) & HWCAP_AES) ? "aes_hw" : "aes_sw");
	gui_msg(Msg("restore_folder=Restore folder: '{1}'")(Restore_Name));

	if (!Mount_Current_Storage(true))
		return Operation_Cleanup(OpType::Restore, 1, Restore_Name);

	// OpenAES reject: no separate tw_restore_openaes flag — Get_Restore_Size ->
	// Probe returns RV_REJECT_OPENAES, loop 1 collects it (backup_validity), the
	// guard below rejects BEFORE the wipe (backstop for CLI/ORS that bypass the
	// early GUI firewall). SSoT = HeaderManager.
	DataManager::GetValue(TW_SKIP_DIGEST_CHECK_VAR, check_digest);
	if (check_digest > 0) {
		// Check Digest files first before restoring to ensure that all of them match before starting a restore
		TWFunc::GUI_Operation_Text(TW_VERIFY_DIGEST_TEXT, gui_parse_text("{@verifying_digest}"));
		gui_msg("verifying_digest=Verifying Digest");
	} else {
		gui_msg("skip_digest=Skipping Digest check based on user setting.");
	}
	gui_msg("calc_restore=Calculating restore details...");
	DataManager::GetValue("tw_restore_selected", Restore_List);

	// Fail-hard flag: if even one partition from Restore_List is not findable via
	// Find_Partition_By_Path (the backup contains it, the device list no longer
	// does), the entire restore is aborted before the destructive loop 2. Loop 1
	// collects all missings (diagnostic logging); the guard fires AFTER the
	// existing partition_count==0 check.
	bool any_partition_missing = false;
	bool any_backup_invalid = false;   // strict preflight: backup self-describing-incomplete/damaged/OpenAES (Get_Restore_Size -> Probe) -> abort before wipe
	Restore_Validity first_invalid = RV_VALID;   // first reject reason + partition -> specific message in the guard (Emit_Restore_Validity_Error)
	const TWPartition* first_invalid_part = nullptr;

	if (!Restore_List.empty()) {
		for (const string& restore_path : split_partition_list(Restore_List)) {
			part_settings.Part = Find_Partition_By_Path(restore_path);
			if (part_settings.Part != NULL) {
				if (part_settings.Part->Mount_Read_Only) {
					gui_msg(Msg(msg::kError, "restore_read_only=Cannot restore {1} -- mounted read only.")(part_settings.Part->Backup_Display_Name));
					return Operation_Cleanup(OpType::Restore, 1, Restore_Name);
				}

				string Full_Filename = part_settings.Backup_Folder + "/" + part_settings.Part->Backup_FileName;

				if (tw_get_default_metadata(Get_Android_Root_Path().c_str()) != 0) {
					gui_msg(Msg(msg::kWarning, "restore_system_context=Unable to get default context for {1} -- Android may not boot.")(Get_Android_Root_Path()));
				}

				if (check_digest > 0 && !twrpDigestDriver::Check_Digest(Full_Filename))
					return Operation_Cleanup(OpType::Restore, 1, Restore_Name);
				part_settings.partition_count++;
				part_settings.total_restore_size += part_settings.Part->Get_Restore_Size(&part_settings);
				if (part_settings.backup_validity != RV_VALID) {   // strict preflight (guard below)
					any_backup_invalid = true;
					if (first_invalid == RV_VALID) { first_invalid = part_settings.backup_validity; first_invalid_part = part_settings.Part; }
				}
				if (part_settings.Part->Has_SubPartition) {
					TWPartition *parentPart = part_settings.Part;
					std::vector<TWPartition*>::iterator subpart;

					for (subpart = Partitions.begin(); subpart != Partitions.end(); subpart++) {
						part_settings.Part = *subpart;
						if ((*subpart)->Is_SubPartition && (*subpart)->SubPartition_Of == parentPart->Mount_Point) {
							// The digest check must verify the subpartition's own
							// archive name, not the parent filename. Otherwise
							// `Full_Filename` (parent) is checked N times redundantly
							// and the sub-archives (e.g. cache.ext4.win) never —
							// corruption would stay undetected until the destructive
							// restore loop.
							string Sub_Full_Filename = part_settings.Backup_Folder + "/" +
								(*subpart)->Backup_Name + "." + (*subpart)->Current_File_System + ".win";
							if (check_digest > 0 && !twrpDigestDriver::Check_Digest(Sub_Full_Filename))
								return Operation_Cleanup(OpType::Restore, 1, Restore_Name);
							part_settings.total_restore_size += (*subpart)->Get_Restore_Size(&part_settings);
							if (part_settings.backup_validity != RV_VALID) {
								any_backup_invalid = true;
								if (first_invalid == RV_VALID) { first_invalid = part_settings.backup_validity; first_invalid_part = part_settings.Part; }
							}
						}
					}
				}
			} else {
				gui_msg(Msg(msg::kError, "restore_unable_locate=Unable to locate '{1}' partition for restoring.")(restore_path));
				any_partition_missing = true;   // diagnostic: collect all missings, abort comes after loop 1
			}
		}
	}

	if (part_settings.partition_count == 0) {
		gui_err("no_part_restore=No partitions selected for restore.");
		return Operation_Cleanup(OpType::Restore, 1, Restore_Name);
	}

	// Fail hard if at least one partition from Restore_List was not findable.
	// Guards against a silent partial restore (e.g. /system + /vendor OK, /data
	// missing -> bootloop without warning). Abort BEFORE the destructive loop 2.
	if (any_partition_missing)
		return Operation_Cleanup(OpType::Restore, 1, Restore_Name);

	// Strict preflight: a DFP backup without the g-header backup_size, a legacy
	// RAW without a usable .info, or an OpenAES backup is not restorable ->
	// reject hard BEFORE the wipe (Get_Restore_Size -> Probe set backup_validity).
	// Only gzip legacy continues without .info via pigz -l. /super image + ADB
	// are exempt (own paths). Specific reason via the shared helper -> CLI/ORS
	// gets the same message as the early GUI firewall (DRY).
	if (any_backup_invalid) {
		Emit_Restore_Validity_Error(first_invalid, first_invalid_part);
		return Operation_Cleanup(OpType::Restore, 1, Restore_Name);
	}

	gui_msg(Msg("restore_part_count=Restoring {1} partitions...")(part_settings.partition_count));
	gui_msg(Msg("total_restore_size=Total restore size is {1}MB")(part_settings.total_restore_size / 1048576));
	DataManager::SetProgress(0.0);
	ProgressTracking progress(part_settings.total_restore_size);
	part_settings.progress = &progress;

	// LOOP POLICY: hard-fail — any error/not-found of a partition aborts the
	// entire restore (Operation_Cleanup); unlike backup, NO skip.
	if (!Restore_List.empty()) {
		for (const string& restore_path : split_partition_list(Restore_List)) {
			if (stop_restore.get_value() != 0)
				break;

			part_settings.Part = Find_Partition_By_Path(restore_path);
			if (part_settings.Part != NULL) {
				// Couple the cancel lock to the UPCOMING partition:
					// filesystem (TAR/Restore_Tar) -> cancel allowed;
					// image (Restore_Image -> Raw_Read_Write/dd) -> cancel locked.
				// The routing mirrors TWPartition::Restore() (partition.cpp:
				// Is_File_System -> Restore_Tar, Is_Image -> Restore_Image). We
				// evaluate the same condition BEFORE entering Restore_Partition()
				// so the GUI cancel button is correctly locked during setup
				// (mount, wipe, pipeline init). Restore_File_System is not a
				// member; TWPartition::Restore() parses it locally via
				// Get_Restore_File_System() from the backup filename (suffix after
				// the first dot) — call the same helper here instead of member access.
				string RestoreFS = part_settings.Part->Get_Restore_File_System(&part_settings);
				int cancelable = part_settings.Part->Is_File_System(RestoreFS) ? 1 : 0;
#ifdef TWRP_RESTORE_DEMO_MODE
				// In demo mode NO restore writes to the real block device: file
				// restores extract to <storage>/TWRP/TestRestore/<part>/, dd-image
				// restores only write a <part>.emmc.win.raw test file
				// (Restore_Image_Test). So a cancel is harmless for EVERY
				// partition -> allow it generally. This relaxation exists ONLY
				// under active demo mode (compile time): in the final build this
				// #ifdef block is gone -> image restores go via Restore_Image ->
				// Raw_Read_Write/dd directly to the block device -> cancelable
				// stays the Is_File_System value (image=0) -> Cancel_Restore hard-
				// blocks (else an abort would softbrick a half-written block device).
				cancelable = 1;
#endif
				Set_Restore_Cancelable(cancelable);

				if (!Restore_Partition(&part_settings)) {
					if (stop_restore.get_value() != 0)
						return Operation_Cleanup(OpType::Restore, 2, Restore_Name);
					return Operation_Cleanup(OpType::Restore, 1, Restore_Name);
				}
			} else {
				// Defense in depth: loop 1 should have caught this already (the
				// any_partition_missing guard after loop 1), but if the partition
				// list flips between loop 1 and loop 2 (race), abort hard here.
				// Restore_Partition was NOT called for this partition — nothing
				// destructive happens.
				gui_msg(Msg(msg::kError, "restore_unable_locate=Unable to locate '{1}' partition for restoring.")(restore_path));
				return Operation_Cleanup(OpType::Restore, 1, Restore_Name);
			}
		}
	}
	if (stop_restore.get_value() != 0)
		return Operation_Cleanup(OpType::Restore, 2, Restore_Name);
	// Successful restore run — close the cancel lock again.
	Set_Restore_Cancelable(0);

	// Take rStop IMMEDIATELY at the end of restore data — BEFORE any cleanup
	// (metadata/unmount/Update_System_Details, moved to the end) and before the
	// phase-B verification. Otherwise "Updating partition details..." (and
	// formerly phase B) would flow into restore_total_time -> avg_restore_rate
	// too low.
	time(&rStop);
	int restore_total_time = (int)difftime(rStop, rStart);
	if (restore_total_time > 0 && part_settings.total_restore_size > 0)
		gui_msg(Msg("avg_restore_rate=Average restore rate: {1} MB/sec")(part_settings.total_restore_size / (unsigned long long)restore_total_time / 1048576));

#ifdef TWRP_RESTORE_DEMO_MODE
	// Demo phase B (UNTIMED): the live-partition verification of the /super test
	// restore deliberately runs AFTER rStop so the second 14-GB read does not
	// distort the restore time/rate above ("MB/s first, then hashing"). Only
	// partitions whose phase A succeeded (Demo_Test_Pending) are checked.
	{
		size_t vpos = 0, vend;
		while ((vend = Restore_List.find(";", vpos)) != string::npos && vpos < Restore_List.size()) {
			string vpath = Restore_List.substr(vpos, vend - vpos);
			TWPartition* vpart = Find_Partition_By_Path(vpath);
			if (vpart && vpart->Demo_Test_Pending)
				vpart->Verify_Image_Test();
			vpos = vend + 1;
		}
	}
#endif

	// "Updating partition details..." moved to the end (AFTER rStop +
	// avg_restore_rate and AFTER phase B) so this cleanup does not distort the
	// restore time/rate. Order only — still runs before return.
	TWFunc::GUI_Operation_Text(TW_UPDATE_SYSTEM_DETAILS_TEXT, gui_parse_text("{@updating_system_details}"));
	tw_set_default_metadata(Get_Android_Root_Path().c_str());
	UnMount_By_Path(Get_Android_Root_Path(), false);
	Update_System_Details();
	UnMount_Main_Partitions();

	TWPartition* Decrypt_Data = Find_Partition_By_Path("/data");
	if (Decrypt_Data && Decrypt_Data->Is_Encrypted)
		gui_msg(Msg(msg::kWarning, "reboot_after_restore=It is recommended to reboot Android once after first boot."));
	DataManager::SetValue("tw_file_progress", "");

	gui_msg(Msg(msg::kHighlight, "restore_completed=[RESTORE COMPLETED IN {1} SECONDS]")(restore_total_time)); // mirror of backup_completed

	// Store the persistent recovery.log as a sibling next to the source backup
	// folder (mirror of Run_Backup, which is intra-folder). Suffix
	// "_Restore_Recovery.log" to distinguish it from the backup-side recovery.log.
	Save_Recovery_Log(Restore_Name + "_Restore_Recovery.log");

	return 0;
}

void TWPartitionManager::Set_Restore_Files(string Restore_Name) {
	// Start with the default values
	string Restore_List;
	bool get_date = true, check_encryption = true;
	bool adbbackup = false;

	DataManager::SetValue("tw_restore_encrypted", 0);
	// Deterministic default: only the .ab branch below sets the flag to 1.
	// Without this reset a previous .ab selection left a stale 1 behind (folder
	// selections never cleared it) and the nandroid restore action would
	// misroute a folder restore into stream_adb_backup.
	DataManager::SetValue("tw_enable_adb_backup", 0);

	// Only a regular file can be an .ab stream: folder backups (every .win
	// selection, ORS folders, the /data mount-point calls from the ADB stream
	// restore) skip the probe entirely. Probing a directory fails with EISDIR,
	// which the short-read guard turns into a bogus "Unable to read adb backup
	// header" line on every folder selection.
	struct stat rn_st;
	bool rn_is_reg = (stat(Restore_Name.c_str(), &rn_st) == 0 && S_ISREG(rn_st.st_mode));

	if (rn_is_reg) {
		if (!twadbbu::Check_ADB_Backup_File(Restore_Name)) {
			// A selected regular file that is no valid .ab = corrupt/truncated
			// ADB backup -> hard reject with a specific red error and NO
			// partition list. The fileselector normally filters these out of
			// the restore list; this catches ORS paths and files broken after
			// listing.
			gui_msg(Msg(msg::kError, "adbbu_invalid_ab=Unable to read the ADB backup header of '{1}'. The backup file is corrupt.")(Restore_Name));
			DataManager::SetValue("tw_restore_list", "");
			DataManager::SetValue("tw_restore_selected", "");
			DataManager::SetValue("tw_has_external_app_data", 0);
			DataManager::SetValue("tw_restore_external_app_data", 0);
			return;
		}
		// Progress message for the restore_reading page: the header scan reads
		// the .ab (only ~512 B per MB since the frame seek, but still noticeable
		// on slow media); the second line is deliberately just "...Done.".
		gui_msg("adbbu_read_ab=Reading ADB backup file. Please wait...");
		vector<string> adb_files;
		adb_files = twadbbu::Get_ADB_Backup_Files(Restore_Name);
		for (unsigned int i = 0; i < adb_files.size(); ++i) {
			string adb_restore_file = adb_files.at(i);
			std::size_t pos = adb_restore_file.find_first_of(".");
			std::string path = "/" + adb_restore_file.substr(0, pos);
			Restore_List = path + ";";
			TWPartition* Part = Find_Partition_By_Path(path);
			Part->Backup_FileName = TWFunc::Get_Filename(adb_restore_file);
			adbbackup = true;
		}
		gui_msg("adbbu_read_ab_done=...Done.");
		DataManager::SetValue("tw_enable_adb_backup", 1);
	}
	else {
		DIR* d;
		d = opendir(Restore_Name.c_str());
		if (d == NULL)
		{
			gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(Restore_Name)(strerror(errno)));
			return;
		}

		struct dirent* de;
		while ((de = readdir(d)) != NULL)
		{
			// Strip off three components
			char str[256];
			char* label;
			char* fstype = NULL;
			char* extn = NULL;
			char* ptr;

			strcpy(str, de->d_name);
			if (strlen(str) <= 2)
				continue;

			if (get_date) {
				char file_path[255];
				struct stat st;

				strcpy(file_path, Restore_Name.c_str());
				strcat(file_path, "/");
				strcat(file_path, str);
				stat(file_path, &st);
				string backup_date = ctime((const time_t*)(&st.st_mtime));
				DataManager::SetValue(TW_RESTORE_FILE_DATE, backup_date);
				get_date = false;
			}

			label = str;
			ptr = label;
			while (*ptr && *ptr != '.')	 ptr++;
			if (*ptr == '.')
			{
				*ptr = 0x00;
				ptr++;
				fstype = ptr;
			}
			while (*ptr && *ptr != '.')	 ptr++;
			if (*ptr == '.')
			{
				*ptr = 0x00;
				ptr++;
				extn = ptr;
			}

			if (fstype == NULL || extn == NULL || strcmp(fstype, "log") == 0) continue;
			int extnlength = strlen(extn);
			if (extnlength != 3 && extnlength != 6) continue;
			if (extnlength >= 3 && strncmp(extn, "win", 3) != 0) continue;
			// Only consider the first segment per partition (win000 or unsplit
			// .win). This filter stays high: BackupHeaderManager::Load detects
			// the type partition-wide itself (Get_Archive_Type_From_Segments
			// scans all segments), so no per-file scan is needed here.
			if (extnlength == 6 && strncmp(extn, "win000", 6) != 0) continue;

			if (check_encryption) {
				string filename = Restore_Name + "/";
				filename += de->d_name;
				// Only the OUTER type (is it BAES?) is needed -> GetFileType
				// (4-byte magic "BA", NO decrypt). NOT Load(): Load decrypts for
				// the inner 5-vs-7 sniff and would trigger the BAES empty-password
				// guard with an empty password (red "empty password rejected").
				// Only DFP BAES triggers the password page (tw_restore_encrypted =
				// GUI page state). OpenAES is NOT marked here — the rejection is
				// done by Probe_Restore_Backup (RV_REJECT_OPENAES) in
				// Preflight/Run_Restore.
				if (BackupHeaderManager::GetFileType(filename) == ENCRYPTED) {
					LOGINFO("'%s' is encrypted\n", filename.c_str());
					DataManager::SetValue("tw_restore_encrypted", 1);
					check_encryption = false;
				}
			}

			TWPartition* Part = Find_Partition_By_Path(label);
			if (Part == NULL)
			{
				gui_msg(Msg(msg::kError, "unable_locate_part_backup_name=Unable to locate partition by backup name: '{1}'")(label));
				continue;
			}

			Part->Backup_FileName = de->d_name;
			if (strlen(extn) > 3) {
				Part->Backup_FileName.resize(Part->Backup_FileName.size() - strlen(extn) + 3);
			}

			if (!Part->Is_SubPartition) {
				if (Part->Backup_Path == Get_Android_Root_Path())
					Restore_List += "/system;";
				else
					Restore_List += Part->Backup_Path + ";";
			}
		}
		closedir(d);
	}

	if (adbbackup) {
		Restore_List = "ADB_Backup;";
		adbbackup = false;
	}

	// Set the final value
	DataManager::SetValue("tw_restore_list", Restore_List);
	DataManager::SetValue("tw_restore_selected", Restore_List);

	// External app data (/data/media/0/Android)? Self-describing: the info lives
	// in the PAX g-header (TWRP.ead) of the /data first segment. It is read in
	// the /data probe of Preflight_Restore_Backup (the ONE place that loads /data
	// at setup time — password-less R2 in readBackup, after password R3 in
	// decrypt_backup). Here just preset to 0 so a backup without /data (or ADB)
	// inherits no stale values from a previous selection.
	DataManager::SetValue("tw_has_external_app_data", 0);
	DataManager::SetValue("tw_restore_external_app_data", 0);

	return;
}

int TWPartitionManager::Wipe_By_Path(string Path) {
	std::vector<TWPartition*>::iterator iter;
	std::vector < TWPartition * >::iterator iter1;
	int ret = false;
	bool found = false;
	string Local_Path = TWFunc::Get_Root_Path(Path);

	if (Local_Path == "/system")
		Local_Path = Get_Android_Root_Path();
	if (Path == "/cache") {
		TWPartition* cache = Find_Partition_By_Path("/cache");
		if (cache == nullptr) {
			TWPartition* dat = Find_Partition_By_Path("/data");
			if (dat) {
				dat->Wipe_Data_Cache();
				found = true;
			}
		}
	}
	// Iterate through all partitions
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Mount_Point == Local_Path || (!(*iter)->Symlink_Mount_Point.empty() && (*iter)->Symlink_Mount_Point == Local_Path)) {
			// iterate through all partitions since some legacy devices uses other partitions as vendor causes issues while wiping
			(*iter)->Find_Actual_Block_Device();
			for (iter1 = Partitions.begin (); iter1 != Partitions.end (); iter1++)
			{
				(*iter1)->Find_Actual_Block_Device();
				if ((*iter)->Actual_Block_Device == (*iter1)->Actual_Block_Device && (*iter)->Mount_Point != (*iter1)->Mount_Point)
					(*iter1)->UnMount(false);
			}
			if (Path == "/and-sec")
				ret = (*iter)->Wipe_AndSec();
			else
				ret = (*iter)->Wipe();
			found = true;
		} else if ((*iter)->Is_SubPartition && (*iter)->SubPartition_Of == Local_Path) {
			(*iter)->Wipe();
		}
	}
	if (found) {
		return ret;
	} else
		gui_msg(Msg(msg::kError, "unable_find_part_path=Unable to find partition for path '{1}'")(Local_Path));
	return false;
}

int TWPartitionManager::Wipe_By_Path(string Path, string New_File_System) {
	std::vector<TWPartition*>::iterator iter;
	int ret = false;
	bool found = false;
	string Local_Path = TWFunc::Get_Root_Path(Path);

	// Iterate through all partitions
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Mount_Point == Local_Path || (!(*iter)->Symlink_Mount_Point.empty() && (*iter)->Symlink_Mount_Point == Local_Path)) {
			if (Path == "/and-sec")
				ret = (*iter)->Wipe_AndSec();
			else
				ret = (*iter)->Wipe(New_File_System);
			found = true;
		} else if ((*iter)->Is_SubPartition && (*iter)->SubPartition_Of == Local_Path) {
			(*iter)->Wipe(New_File_System);
		}
	}
	if (found) {
		return ret;
	} else
		gui_msg(Msg(msg::kError, "unable_find_part_path=Unable to find partition for path '{1}'")(Local_Path));
	return false;
}

int TWPartitionManager::Factory_Reset(void) {
	std::vector<TWPartition*>::iterator iter;
	int ret = true;

	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Wipe_During_Factory_Reset && (*iter)->Is_Present) {
#ifdef TW_OEM_BUILD
			if ((*iter)->Mount_Point == "/data") {
				if (!(*iter)->Wipe_Encryption())
					ret = false;
			} else {
#endif
				if (!(*iter)->Wipe())
					ret = false;
#ifdef TW_OEM_BUILD
			}
#endif
		} else if ((*iter)->Has_Android_Secure) {
			if (!(*iter)->Wipe_AndSec())
				ret = false;
		}
	}
	TWFunc::check_and_run_script("/system/bin/factoryreset.sh", "Factory Reset Script");
	return ret;
}

int TWPartitionManager::Wipe_Dalvik_Cache(void) {
	struct stat st;
	vector <string> dir;

	if (!Mount_By_Path("/data", true))
		return false;

	dir.push_back("/data/dalvik-cache");

	std::string cacheDir = TWFunc::get_log_dir();
	if (cacheDir == CACHE_LOGS_DIR) {
		if (!PartitionManager.Mount_By_Path(CACHE_LOGS_DIR, false)) {
			LOGINFO("Unable to mount %s for wiping cache.\n", CACHE_LOGS_DIR);
		}
		dir.push_back(cacheDir + "dalvik-cache");
		dir.push_back(cacheDir + "/dc");
	}

	TWPartition* sdext = Find_Partition_By_Path("/sd-ext");
	if (sdext && sdext->Is_Present && sdext->Mount(false))
	{
		if (stat("/sd-ext/dalvik-cache", &st) == 0)
		{
			dir.push_back("/sd-ext/dalvik-cache");
		}
	}

	if (cacheDir == CACHE_LOGS_DIR) {
		gui_msg("wiping_cache_dalvik=Wiping Dalvik Cache Directories...");
	} else {
		gui_msg("wiping_dalvik=Wiping Dalvik Directory...");
	}
	for (unsigned i = 0; i < dir.size(); ++i) {
		if (stat(dir.at(i).c_str(), &st) == 0) {
			TWFunc::removeDir(dir.at(i), false);
			gui_msg(Msg("cleaned=Cleaned: {1}...")(dir.at(i)));
		}
	}

	if (cacheDir == CACHE_LOGS_DIR) {
		gui_msg("cache_dalvik_done=-- Dalvik Cache Directories Wipe Complete!");
	} else {
		gui_msg("dalvik_done=-- Dalvik Directory Wipe Complete!");
	}

	return true;
}

int TWPartitionManager::Wipe_Rotate_Data(void) {
	if (!Mount_By_Path("/data", true))
		return false;

	unlink("/data/misc/akmd*");
	unlink("/data/misc/rild*");
	gui_print("Rotation data wiped.\n");
	return true;
}

int TWPartitionManager::Wipe_Battery_Stats(void) {
	struct stat st;

	if (!Mount_By_Path("/data", true))
		return false;

	if (0 != stat("/data/system/batterystats.bin", &st)) {
		gui_print("No Battery Stats Found. No Need To Wipe.\n");
	} else {
		remove("/data/system/batterystats.bin");
		gui_print("Cleared battery stats.\n");
	}
	return true;
}

int TWPartitionManager::Wipe_Android_Secure(void) {
	std::vector<TWPartition*>::iterator iter;
	int ret = false;
	bool found = false;

	// Iterate through all partitions
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Has_Android_Secure) {
			ret = (*iter)->Wipe_AndSec();
			found = true;
		}
	}
	if (found) {
		return ret;
	} else {
		gui_err("no_andsec=No android secure partitions found.");
	}
	return false;
}

int TWPartitionManager::Format_Data(void) {
	TWPartition* dat = Find_Partition_By_Path("/data");
	TWPartition* metadata = Find_Partition_By_Path("/metadata");
	if (metadata != NULL)
		metadata->UnMount(false);

	if (dat != NULL) {
		if (android::base::GetBoolProperty("ro.virtual_ab.enabled", false)) {
#ifndef TW_EXCLUDE_APEX
			twrpApex apex;
			apex.Unmount();
#endif
			if (metadata != NULL)
				metadata->Mount(true);
			if (!Check_Pending_Merges())
				return false;
		}
		return dat->Wipe_Encryption();
	} else {
		gui_msg(Msg(msg::kError, "unable_to_locate=Unable to locate {1}.")("/data"));
		return false;
	}
	return false;
}

int TWPartitionManager::Wipe_Media_From_Data(void) {
	TWPartition* dat = Find_Partition_By_Path("/data");

	if (dat != NULL) {
		if (!dat->Has_Data_Media) {
			LOGERR("This device does not have /data/media\n");
			return false;
		}
		if (!dat->Mount(true))
			return false;

		gui_msg("wiping_datamedia=Wiping internal storage -- /data/media...");
		Remove_MTP_Storage(dat->MTP_Storage_ID);
		TWFunc::removeDir("/data/media", false);
		dat->Recreate_Media_Folder();
		Add_MTP_Storage(dat->MTP_Storage_ID);
		return true;
	} else {
		gui_msg(Msg(msg::kError, "unable_to_locate=Unable to locate {1}.")("/data"));
		return false;
	}
	return false;
}

int TWPartitionManager::Repair_By_Path(string Path, bool Display_Error) {
	std::vector<TWPartition*>::iterator iter;
	int ret = false;
	bool found = false;
	string Local_Path = TWFunc::Get_Root_Path(Path);

	if (Local_Path == "/tmp" || Local_Path == "/")
		return true;

	// Iterate through all partitions
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Mount_Point == Local_Path || (!(*iter)->Symlink_Mount_Point.empty() && (*iter)->Symlink_Mount_Point == Local_Path)) {
			ret = (*iter)->Repair();
			found = true;
		} else if ((*iter)->Is_SubPartition && (*iter)->SubPartition_Of == Local_Path) {
			(*iter)->Repair();
		}
	}
	if (found) {
		return ret;
	} else if (Display_Error) {
		gui_msg(Msg(msg::kError, "unable_find_part_path=Unable to find partition for path '{1}'")(Local_Path));
	} else {
		LOGINFO("Repair: Unable to find partition for path '%s'\n", Local_Path.c_str());
	}
	return false;
}

int TWPartitionManager::Resize_By_Path(string Path, bool Display_Error) {
	std::vector<TWPartition*>::iterator iter;
	int ret = false;
	bool found = false;
	string Local_Path = TWFunc::Get_Root_Path(Path);

	if (Local_Path == "/tmp" || Local_Path == "/")
		return true;

	// Iterate through all partitions
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Mount_Point == Local_Path || (!(*iter)->Symlink_Mount_Point.empty() && (*iter)->Symlink_Mount_Point == Local_Path)) {
			ret = (*iter)->Resize();
			found = true;
		} else if ((*iter)->Is_SubPartition && (*iter)->SubPartition_Of == Local_Path) {
			(*iter)->Resize();
		}
	}
	if (found) {
		return ret;
	} else if (Display_Error) {
		gui_msg(Msg(msg::kError, "unable_find_part_path=Unable to find partition for path '{1}'")(Local_Path));
	} else {
		LOGINFO("Resize: Unable to find partition for path '%s'\n", Local_Path.c_str());
	}
	return false;
}

void TWPartitionManager::Update_System_Details(void) {
	std::vector<TWPartition*>::iterator iter;
	int data_size = 0;

	gui_msg("update_part_details=Updating partition details...");
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		(*iter)->Update_Size(true);
		if ((*iter)->Can_Be_Mounted) {
			if ((*iter)->Mount_Point == Get_Android_Root_Path()) {
				int backup_display_size = (int)((*iter)->Backup_Size / 1048576LLU);
				DataManager::SetValue(TW_BACKUP_SYSTEM_SIZE, backup_display_size);
				TWFunc::Is_TWRP_App_In_System();
			} else if ((*iter)->Mount_Point == "/data" || (*iter)->Mount_Point == "/datadata") {
				data_size += (int)((*iter)->Backup_Size / 1048576LLU);
			} else if ((*iter)->Mount_Point == "/cache") {
				int backup_display_size = (int)((*iter)->Backup_Size / 1048576LLU);
				DataManager::SetValue(TW_BACKUP_CACHE_SIZE, backup_display_size);
			} else if ((*iter)->Mount_Point == "/sd-ext") {
				int backup_display_size = (int)((*iter)->Backup_Size / 1048576LLU);
				DataManager::SetValue(TW_BACKUP_SDEXT_SIZE, backup_display_size);
				if ((*iter)->Backup_Size == 0) {
					DataManager::SetValue(TW_HAS_SDEXT_PARTITION, 0);
					DataManager::SetValue(TW_BACKUP_SDEXT_VAR, 0);
				} else
					DataManager::SetValue(TW_HAS_SDEXT_PARTITION, 1);
			} else if ((*iter)->Has_Android_Secure) {
				int backup_display_size = (int)((*iter)->Backup_Size / 1048576LLU);
				DataManager::SetValue(TW_BACKUP_ANDSEC_SIZE, backup_display_size);
				if ((*iter)->Backup_Size == 0) {
					DataManager::SetValue(TW_HAS_ANDROID_SECURE, 0);
					DataManager::SetValue(TW_BACKUP_ANDSEC_VAR, 0);
				} else
					DataManager::SetValue(TW_HAS_ANDROID_SECURE, 1);
			} else if ((*iter)->Mount_Point == "/boot") {
				int backup_display_size = (int)((*iter)->Backup_Size / 1048576LLU);
				DataManager::SetValue(TW_BACKUP_BOOT_SIZE, backup_display_size);
				if ((*iter)->Backup_Size == 0) {
					DataManager::SetValue("tw_has_boot_partition", 0);
					DataManager::SetValue(TW_BACKUP_BOOT_VAR, 0);
				} else
					DataManager::SetValue("tw_has_boot_partition", 1);
			}
		} else {
			// Handle unmountable partitions in case we reset defaults
			if ((*iter)->Mount_Point == "/boot") {
				int backup_display_size = (int)((*iter)->Backup_Size / 1048576LLU);
				DataManager::SetValue(TW_BACKUP_BOOT_SIZE, backup_display_size);
				if ((*iter)->Backup_Size == 0) {
					DataManager::SetValue(TW_HAS_BOOT_PARTITION, 0);
					DataManager::SetValue(TW_BACKUP_BOOT_VAR, 0);
				} else
					DataManager::SetValue(TW_HAS_BOOT_PARTITION, 1);
			} else if ((*iter)->Mount_Point == "/recovery") {
				int backup_display_size = (int)((*iter)->Backup_Size / 1048576LLU);
				DataManager::SetValue(TW_BACKUP_RECOVERY_SIZE, backup_display_size);
				if ((*iter)->Backup_Size == 0) {
					DataManager::SetValue(TW_HAS_RECOVERY_PARTITION, 0);
					DataManager::SetValue(TW_BACKUP_RECOVERY_VAR, 0);
				} else
					DataManager::SetValue(TW_HAS_RECOVERY_PARTITION, 1);
			} else if ((*iter)->Mount_Point == "/data") {
				data_size += (int)((*iter)->Backup_Size / 1048576LLU);
			}
		}
	}
	gui_msg("update_part_details_done=...done");
	DataManager::SetValue(TW_BACKUP_DATA_SIZE, data_size);
	string current_storage_path = DataManager::GetCurrentStoragePath();
	TWPartition* FreeStorage = Find_Partition_By_Path(current_storage_path);
	if (FreeStorage != NULL) {
		// Attempt to mount storage
		if (!FreeStorage->Mount(false)) {
			gui_msg(Msg(msg::kWarning, "unable_to_mount_storage=Unable to mount storage"));
			DataManager::SetValue(TW_STORAGE_FREE_SIZE, 0);
		} else {
			DataManager::SetValue(TW_STORAGE_FREE_SIZE, (int)(FreeStorage->Free / 1048576LLU));
		}
	} else {
		LOGINFO("Unable to find storage partition '%s'.\n", current_storage_path.c_str());
	}
	if (!Write_Fstab())
		LOGERR("Error creating fstab\n");
	return;
}

void TWPartitionManager::Post_Decrypt(const string& Block_Device) {
	TWPartition* dat = Find_Partition_By_Path("/data");

	if (dat != NULL) {
		// reparse for /cache/recovery/command
		static constexpr const char* COMMAND_FILE = "/data/cache/command";
		if (TWFunc::Path_Exists(COMMAND_FILE)) {
			startupArgs startup;
			std::string content;
			TWFunc::read_file(COMMAND_FILE, content);
			std::vector<std::string> args = {content};
			startup.processRecoveryArgs(args, 0);
		}

		DataManager::SetValue(TW_IS_DECRYPTED, 1);
		dat->Is_Decrypted = true;
		if (!Block_Device.empty()) {
			dat->Decrypted_Block_Device = Block_Device;
			gui_msg(Msg("decrypt_success_dev=Data successfully decrypted, new block device: '{1}'")(Block_Device));
		} else {
			gui_msg("decrypt_success_nodev=Data successfully decrypted");
		}
		property_set("twrp.decrypt.done", "true");
		dat->Setup_File_System(false);
		dat->Current_File_System = dat->Fstab_File_System;  // Needed if we're ignoring blkid because encrypted devices start out as emmc

		sleep(1); // Sleep for a bit so that the device will be ready
		if (dat->Has_Data_Media && dat->Mount(false) && TWFunc::Path_Exists("/data/media/0")) {
			dat->Storage_Path = "/data/media/0";
			dat->Symlink_Path = dat->Storage_Path;
			DataManager::SetValue("tw_storage_path", "/data/media/0");
			DataManager::SetValue("tw_settings_path", TW_STORAGE_PATH);
		}
		DataManager::LoadTWRPFolderInfo();
		Update_System_Details();
		Output_Partition(dat);
		if (!android::base::StartsWith(dat->Actual_Block_Device, "/dev/block/mmcblk")) {
			if (!dat->Bind_Mount(false))
				LOGERR("Unable to bind mount /sdcard to %s\n", dat->Storage_Path.c_str());
		}
	} else
		LOGERR("Unable to locate data partition.\n");
}

void TWPartitionManager::Parse_Users() {
#ifdef TW_INCLUDE_FBE
	char user_check_result[PROPERTY_VALUE_MAX];
	for (int userId = 0; userId <= 9999; userId++) {
		string prop = "twrp.user." + to_string(userId) + ".decrypt";
		property_get(prop.c_str(), user_check_result, "-1");
		if (strcmp(user_check_result, "-1") != 0) {
			if (userId < 0 || userId > 9999) {
				LOGINFO("Incorrect user id %d\n", userId);
				continue;
			}
			struct users_struct user;
			user.userId = to_string(userId);

			// Attempt to get name of user. Fallback to user ID if this fails.
			std::string path = "/data/system/users/" + to_string(userId) + ".xml";
			if ((atoi(TWFunc::System_Property_Get("ro.build.version.sdk").c_str()) > 30) && TWFunc::Path_Exists(path)) {
				if(!TWFunc::Check_Xml_Format(path))
					user.userName = to_string(userId);
			}
			else {
				char* userFile = PageManager::LoadFileToBuffer(path, NULL);
				if (userFile == NULL) {
					user.userName = to_string(userId);
				}
				else {
					xml_document<> *userXml = new xml_document<>();
					userXml->parse<0>(userFile);
					xml_node<>* userNode = userXml->first_node("user");
					if (userNode == nullptr) {
						user.userName = to_string(userId);
					} else {
						xml_node<>* nameNode = userNode->first_node("name");
						if (nameNode == nullptr)
							user.userName = to_string(userId);
						else {
							string userName = nameNode->value();
							user.userName = userName + " (" + to_string(userId) + ")";
						}
					}
				}
			}

			string filename;
			user.type = Get_Password_Type(userId, filename);

			user.isDecrypted = false;
			if (strcmp(user_check_result, "1") == 0)
				user.isDecrypted = true;
			Users_List.push_back(user);
		}
	}
	Check_Users_Decryption_Status();
#endif
}

std::vector<users_struct>* TWPartitionManager::Get_Users_List() {
	return &Users_List;
}

void TWPartitionManager::Mark_User_Decrypted(int userID) {
#ifdef TW_INCLUDE_FBE
	std::vector<users_struct>::iterator iter;
	for (iter = Users_List.begin(); iter != Users_List.end(); iter++) {
		if (atoi((*iter).userId.c_str()) == userID) {
			(*iter).isDecrypted = true;
			string user_prop_decrypted = "twrp.user." + to_string(userID) + ".decrypt";
			property_set(user_prop_decrypted.c_str(), "1");
			break;
		}
	}
	Check_Users_Decryption_Status();
#endif
}

void TWPartitionManager::Check_Users_Decryption_Status() {
#ifdef TW_INCLUDE_FBE
	int all_is_decrypted = 1;
	std::vector<users_struct>::iterator iter;
	for (iter = Users_List.begin(); iter != Users_List.end(); iter++) {
		if (!(*iter).isDecrypted) {
			LOGINFO("User %s is not decrypted.\n", (*iter).userId.c_str());
			all_is_decrypted = 0;
			break;
		}
	}
	if (all_is_decrypted == 1) {
		LOGINFO("All found users are decrypted.\n");
		DataManager::SetValue("tw_all_users_decrypted", "1");
		property_set("twrp.all.users.decrypted", "true");
	} else
		DataManager::SetValue("tw_all_users_decrypted", "0");
#endif
}

int TWPartitionManager::Decrypt_Device(string Password, int user_id) {
#ifdef TW_INCLUDE_CRYPTO
	char crypto_blkdev[PROPERTY_VALUE_MAX];
	std::vector<TWPartition*>::iterator iter;

	// Mount any partitions that need to be mounted for decrypt
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Mount_To_Decrypt) {
			(*iter)->Mount(true);
		}
	}
	property_set("twrp.mount_to_decrypt", "1");

	Set_Crypto_State();
	Set_Crypto_Type("block");

	if (DataManager::GetIntValue(TW_IS_FBE)) {
#ifdef TW_INCLUDE_FBE
		if (!Mount_By_Path("/data", true)) // /data has to be mounted for FBE
			return -1;

		bool user_need_decrypt = false;
		std::vector<users_struct>::iterator iter;
		for (iter = Users_List.begin(); iter != Users_List.end(); iter++) {
			if (atoi((*iter).userId.c_str()) == user_id && !(*iter).isDecrypted) {
				user_need_decrypt = true;
			}
		}
		if (!user_need_decrypt) {
			LOGINFO("User %d does not require decryption\n", user_id);
			return 0;
		}

		int retry_count = 10;
		while (!TWFunc::Path_Exists("/data/system/users/gatekeeper.password.key") && --retry_count)
			usleep(2000); // A small sleep is needed after mounting /data to ensure reliable decrypt...maybe because of DE?
		gui_msg(Msg("decrypting_user_fbe=Attempting to decrypt FBE for user {1}...")(user_id));
		if (Decrypt_User(user_id, Password)) {
			gui_msg(Msg("decrypt_user_success_fbe=User {1} Decrypted Successfully")(user_id));
			Mark_User_Decrypted(user_id);
			if (user_id == 0) {
				// When decrypting user 0 also try all other users
				std::vector<users_struct>::iterator iter;
				for (iter = Users_List.begin(); iter != Users_List.end(); iter++) {
					if ((*iter).userId == "0" || (*iter).isDecrypted)
						continue;

					int tmp_user_id = atoi((*iter).userId.c_str());
					gui_msg(Msg("decrypting_user_fbe=Attempting to decrypt FBE for user {1}...")(tmp_user_id));
					if (Decrypt_User(tmp_user_id, Password) ||
					(Password != "!" && Decrypt_User(tmp_user_id, "!"))) { // "!" means default password
						gui_msg(Msg("decrypt_user_success_fbe=User {1} Decrypted Successfully")(tmp_user_id));
						Mark_User_Decrypted(tmp_user_id);
					} else {
						gui_msg(Msg("decrypt_user_fail_fbe=Failed to decrypt user {1}")(tmp_user_id));
					}
				}
				Post_Decrypt("");
			}

			return 0;
		} else {
			gui_msg(Msg(msg::kError, "decrypt_user_fail_fbe=Failed to decrypt user {1}")(user_id));
		}
#else
		LOGERR("FBE support is not present\n");
#endif
		return -1;
	}

	char isdecrypteddata[PROPERTY_VALUE_MAX];
	property_get("twrp.decrypt.done", isdecrypteddata, "");
	if (strcmp(isdecrypteddata, "true") == 0) {
		LOGINFO("Data has no decryption required\n");
		return 0;
	}

	int pwret = -1;
	pid_t pid = fork();
	if (pid < 0) {
		LOGERR("fork failed\n");
		return -1;
	} else if (pid == 0) {
		// Child process
		char cPassword[255];
		strcpy(cPassword, Password.c_str());
		int ret = cryptfs_check_passwd(cPassword);
		exit(ret);
	} else {
		// Parent
		int status;
		if (TWFunc::Wait_For_Child_Timeout(pid, &status, "Decrypt", 30))
			pwret = -1;
		else
			pwret = WEXITSTATUS(status) ? -1 : 0;
	}

#ifdef TW_CRYPTO_USE_SYSTEM_VOLD
	if (pwret != 0) {
		pwret = vold_decrypt(Password);
		switch (pwret) {
			case VD_SUCCESS:
				break;
			case VD_ERR_MISSING_VDC:
				gui_msg(Msg(msg::kError, "decrypt_data_vold_os_missing=Missing files needed for vold decrypt: {1}")("/system/bin/vdc"));
				break;
			case VD_ERR_MISSING_VOLD:
				gui_msg(Msg(msg::kError, "decrypt_data_vold_os_missing=Missing files needed for vold decrypt: {1}")("/system/bin/vold"));
				break;
		}
	}
#endif // TW_CRYPTO_USE_SYSTEM_VOLD

	// Unmount any partitions that were needed for decrypt
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Mount_To_Decrypt) {
			(*iter)->UnMount(false);
		}
	}
	property_set("twrp.mount_to_decrypt", "0");

	if (pwret != 0) {
		gui_err("fail_decrypt=Failed to decrypt data.");
		return -1;
	}

	property_get("ro.crypto.fs_crypto_blkdev", crypto_blkdev, "error");
	if (strcmp(crypto_blkdev, "error") == 0) {
		LOGERR("Error retrieving decrypted data block device.\n");
	} else {
		Post_Decrypt(crypto_blkdev);
	}
	return 0;
#else
	gui_err("no_crypto_support=No crypto support was compiled into this build.");
	return -1;
#endif
	return 1;
}

int TWPartitionManager::Fix_Contexts(void) {
	std::vector<TWPartition*>::iterator iter;
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Has_Data_Media) {
			if ((*iter)->Mount(true)) {
				if (fixContexts::fixDataMediaContexts((*iter)->Mount_Point) != 0)
					return -1;
			}
		}
	}
	UnMount_Main_Partitions();
	gui_msg("done=Done.");
	return 0;
}

TWPartition* TWPartitionManager::Find_Next_Storage(string Path, bool Exclude_Data_Media) {
	std::vector<TWPartition*>::iterator iter = Partitions.begin();

	if (!Path.empty()) {
		string Search_Path = TWFunc::Get_Root_Path(Path);
		for (; iter != Partitions.end(); iter++) {
			if ((*iter)->Mount_Point == Search_Path) {
				iter++;
				break;
			}
		}
	}

	for (; iter != Partitions.end(); iter++) {
		if (Exclude_Data_Media && (*iter)->Has_Data_Media) {
			// do nothing, do not return this type of partition
		} else if ((*iter)->Is_Storage && (*iter)->Is_Present) {
			return (*iter);
		}
	}

	return NULL;
}

int TWPartitionManager::Open_Lun_File(string Partition_Path, string Lun_File) {
	TWPartition* Part = Find_Partition_By_Path(Partition_Path);

	if (Part == NULL) {
		LOGINFO("Unable to locate '%s' for USB storage mode.", Partition_Path.c_str());
		gui_msg(Msg(msg::kError, "unable_find_part_path=Unable to find partition for path '{1}'")(Partition_Path));
		return false;
	}
	LOGINFO("USB mount '%s', '%s' > '%s'\n", Partition_Path.c_str(), Part->Actual_Block_Device.c_str(), Lun_File.c_str());
	if (!Part->UnMount(true) || !Part->Is_Present)
		return false;

	if (!TWFunc::write_to_file(Lun_File, Part->Actual_Block_Device)) {
		LOGERR("Unable to write to ums lunfile '%s': (%s)\n", Lun_File.c_str(), strerror(errno));
		return false;
	}
	return true;
}

int TWPartitionManager::usb_storage_enable(void) {
	char lun_file[255];
	bool has_multiple_lun = false;

	string Lun_File_str = CUSTOM_LUN_FILE;
	size_t found = Lun_File_str.find("%");
	if (found != string::npos) {
		sprintf(lun_file, CUSTOM_LUN_FILE, 1);
		if (TWFunc::Path_Exists(lun_file))
			has_multiple_lun = true;
	}
	mtp_was_enabled = TWFunc::Toggle_MTP(false); // Must disable MTP for USB Storage
	if (!has_multiple_lun) {
		LOGINFO("Device doesn't have multiple lun files, mount current storage\n");
		sprintf(lun_file, CUSTOM_LUN_FILE, 0);
		if (TWFunc::Get_Root_Path(DataManager::GetCurrentStoragePath()) == "/data") {
			TWPartition* Mount = Find_Next_Storage("", true);
			if (Mount) {
				if (!Open_Lun_File(Mount->Mount_Point, lun_file)) {
					goto error_handle;
				}
			} else {
				gui_err("unable_locate_storage=Unable to locate storage device.");
				goto error_handle;
			}
		} else if (!Open_Lun_File(DataManager::GetCurrentStoragePath(), lun_file)) {
			goto error_handle;
		}
	} else {
		LOGINFO("Device has multiple lun files\n");
		TWPartition* Mount1;
		TWPartition* Mount2;
		sprintf(lun_file, CUSTOM_LUN_FILE, 0);
		Mount1 = Find_Next_Storage("", true);
		if (Mount1) {
			if (!Open_Lun_File(Mount1->Mount_Point, lun_file)) {
				goto error_handle;
			}
			sprintf(lun_file, CUSTOM_LUN_FILE, 1);
			Mount2 = Find_Next_Storage(Mount1->Mount_Point, true);
			if (Mount2 && Mount2->Mount_Point != Mount1->Mount_Point) {
				Open_Lun_File(Mount2->Mount_Point, lun_file);
			// Mimic single lun code: Mount CurrentStoragePath if it's not /data
			} else if (TWFunc::Get_Root_Path(DataManager::GetCurrentStoragePath()) != "/data") {
				Open_Lun_File(DataManager::GetCurrentStoragePath(), lun_file);
			}
		// Mimic single lun code: Mount CurrentStoragePath if it's not /data
		} else if (TWFunc::Get_Root_Path(DataManager::GetCurrentStoragePath()) != "/data" && !Open_Lun_File(DataManager::GetCurrentStoragePath(), lun_file)) {
			gui_err("unable_locate_storage=Unable to locate storage device.");
			goto error_handle;
		}
	}
	property_set("sys.storage.ums_enabled", "1");
	property_set("sys.usb.config", "mass_storage,adb");
	return true;
error_handle:
	if (mtp_was_enabled)
		if (!Enable_MTP())
			Disable_MTP();
	return false;
}

int TWPartitionManager::usb_storage_disable(void) {
	int index, ret = 0;
	char lun_file[255], ch[2] = {0, 0};
	string str = ch;

	for (index=0; index<2; index++) {
		sprintf(lun_file, CUSTOM_LUN_FILE, index);
		if (!TWFunc::write_to_file(lun_file, str)) {
			break;
			ret = -1;
		}
	}
	Mount_All_Storage();
	Update_System_Details();
	UnMount_Main_Partitions();
	property_set("sys.storage.ums_enabled", "0");
	property_set("sys.usb.config", "adb");
	if (mtp_was_enabled)
		if (!Enable_MTP())
			Disable_MTP();
	if (ret < 0 && index == 0) {
		LOGERR("Unable to write to ums lunfile '%s'.", lun_file);
		return false;
	} else {
		return true;
	}
	return true;
}

void TWPartitionManager::Mount_All_Storage(void) {
	std::vector<TWPartition*>::iterator iter;

	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Is_Storage)
			(*iter)->Mount(false);
	}
}

void TWPartitionManager::UnMount_Main_Partitions(void) {
	// Unmounts system and data if data is not data/media
	// Also unmounts boot if boot is mountable
	LOGINFO("Unmounting main partitions...\n");

	TWPartition *Partition = Find_Partition_By_Path ("/vendor");

	if (Partition != NULL) UnMount_By_Path("/vendor", false);
	UnMount_By_Path (Get_Android_Root_Path(), true);
	Partition = Find_Partition_By_Path ("/product");
	if (Partition != NULL) UnMount_By_Path("/product", false);
	if (!datamedia)
		UnMount_By_Path("/data", true);

	Partition = Find_Partition_By_Path ("/boot");
	if (Partition != NULL && Partition->Can_Be_Mounted)
		Partition->UnMount(true);
}

int TWPartitionManager::Partition_SDCard(void) {
	char temp[255];
	string Storage_Path, Command, Device, fat_str, ext_str, start_loc, end_loc, ext_format, sd_path, tmpdevice;
	int ext, swap, total_size = 0, fat_size;

	gui_msg("start_partition_sd=Partitioning SD Card...");

	// Locate and validate device to partition
	TWPartition* SDCard = Find_Partition_By_Path(DataManager::GetCurrentStoragePath());

	if (SDCard->Is_Adopted_Storage)
		SDCard->Revert_Adopted();

	if (SDCard == NULL || !SDCard->Removable || SDCard->Has_Data_Media) {
		gui_err("partition_sd_locate=Unable to locate device to partition.");
		return false;
	}

	// Unmount everything
	if (!SDCard->UnMount(true))
		return false;
	TWPartition* SDext = Find_Partition_By_Path("/sd-ext");
	if (SDext != NULL) {
		if (!SDext->UnMount(true))
			return false;
	}
	char* swappath = getenv("SWAPPATH");
	if (swappath != NULL) {
		LOGINFO("Unmounting swap at '%s'\n", swappath);
		umount(swappath);
	}

	// Determine block device
	if (SDCard->Alternate_Block_Device.empty()) {
		SDCard->Find_Actual_Block_Device();
		Device = SDCard->Actual_Block_Device;
		// Just use the root block device
		Device.resize(strlen("/dev/block/mmcblkX"));
	} else {
		Device = SDCard->Alternate_Block_Device;
	}

	// Find the size of the block device:
	total_size = (int)(TWFunc::IOCTL_Get_Block_Size(Device.c_str()) / (1048576));

	DataManager::GetValue("tw_sdext_size", ext);
	DataManager::GetValue("tw_swap_size", swap);
	DataManager::GetValue("tw_sdpart_file_system", ext_format);
	fat_size = total_size - ext - swap;
	LOGINFO("sd card mount point %s block device is '%s', sdcard size is: %iMB, fat size: %iMB, ext size: %iMB, ext system: '%s', swap size: %iMB\n", DataManager::GetCurrentStoragePath().c_str(), Device.c_str(), total_size, fat_size, ext, ext_format.c_str(), swap);

	// Determine partition sizes
	if (swap == 0 && ext == 0) {
		fat_str = "-0";
	} else {
		memset(temp, 0, sizeof(temp));
		sprintf(temp, "%i", fat_size);
		fat_str = temp;
		fat_str += "MB";
	}
	if (swap == 0) {
		ext_str = "-0";
	} else {
		memset(temp, 0, sizeof(temp));
		sprintf(temp, "%i", ext);
		ext_str = "+";
		ext_str += temp;
		ext_str += "MB";
	}

	if (ext + swap > total_size) {
		gui_err("ext_swap_size=EXT + Swap size is larger than sdcard size.");
		return false;
	}

	gui_msg("remove_part_table=Removing partition table...");
	Command = "sgdisk --zap-all " + Device;
	LOGINFO("Command is: '%s'\n", Command.c_str());
	if (TWFunc::Exec_Cmd(Command) != 0) {
		gui_err("unable_rm_part=Unable to remove partition table.");
		Update_System_Details();
		return false;
	}
	gui_msg(Msg("create_part=Creating {1} partition...")("FAT32"));
	Command = "sgdisk  --new=0:0:" + fat_str + " --change-name=0:\"Microsoft basic data\" --typecode=0:EBD0A0A2-B9E5-4433-87C0-68B6B72699C7 " + Device;
	LOGINFO("Command is: '%s'\n", Command.c_str());
	if (TWFunc::Exec_Cmd(Command) != 0) {
		gui_msg(Msg(msg::kError, "unable_to_create_part=Unable to create {1} partition.")("FAT32"));
		return false;
	}
	if (ext > 0) {
		gui_msg(Msg("create_part=Creating {1} partition...")("EXT"));
		Command = "sgdisk --new=0:0:" + ext_str + " --change-name=0:\"Linux filesystem\" " + Device;
		LOGINFO("Command is: '%s'\n", Command.c_str());
		if (TWFunc::Exec_Cmd(Command) != 0) {
			gui_msg(Msg(msg::kError, "unable_to_create_part=Unable to create {1} partition.")("EXT"));
			Update_System_Details();
			return false;
		}
	}
	if (swap > 0) {
		gui_msg(Msg("create_part=Creating {1} partition...")("swap"));
		Command = "sgdisk --new=0:0:-0 --change-name=0:\"Linux swap\" --typecode=0:0657FD6D-A4AB-43C4-84E5-0933C84B4F4F " + Device;
		LOGINFO("Command is: '%s'\n", Command.c_str());
		if (TWFunc::Exec_Cmd(Command) != 0) {
			gui_msg(Msg(msg::kError, "unable_to_create_part=Unable to create {1} partition.")("swap"));
			Update_System_Details();
			return false;
		}
	}

	// Convert GPT to MBR
	Command = "sgdisk --gpttombr " + Device;
	if (TWFunc::Exec_Cmd(Command) != 0)
		LOGINFO("Failed to covert partition GPT to MBR\n");

	// Tell the kernel to rescan the partition table
	int fd = open(Device.c_str(), O_RDONLY);
	ioctl(fd, BLKRRPART, 0);
	close(fd);

	string format_device = Device;
	if (Device.substr(0, 17) == "/dev/block/mmcblk")
		format_device += "p";

	// Format new partitions to proper file system
	if (fat_size > 0) {
		Command = "mkfs.fat " + format_device + "1";
		TWFunc::Exec_Cmd(Command);
	}
	if (ext > 0) {
		if (SDext == NULL) {
			Command = "mke2fs -t " + ext_format + " -m 0 " + format_device + "2";
			gui_msg(Msg("format_sdext_as=Formatting sd-ext as {1}...")(ext_format));
			LOGINFO("Formatting sd-ext after partitioning, command: '%s'\n", Command.c_str());
			TWFunc::Exec_Cmd(Command);
		} else {
			SDext->Wipe(ext_format);
		}
	}
	if (swap > 0) {
		Command = "mkswap " + format_device;
		if (ext > 0)
			Command += "3";
		else
			Command += "2";
		TWFunc::Exec_Cmd(Command);
	}

	// recreate TWRP folder and rewrite settings - these will be gone after sdcard is partitioned
	if (SDCard->Mount(true)) {
		string TWRP_Folder = SDCard->Mount_Point + "/TWRP";
		mkdir(TWRP_Folder.c_str(), 0777);
		DataManager::Flush();
	}

	Update_System_Details();
	gui_msg("part_complete=Partitioning complete.");
	return true;
}

void TWPartitionManager::Get_Partition_List(string ListType, std::vector<PartitionList> *Partition_List) {
	std::vector<TWPartition*>::iterator iter;
	if (ListType == "mount") {
		for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
			if ((*iter)->Can_Be_Mounted) {
				struct PartitionList part;
				part.Display_Name = (*iter)->Display_Name;
				part.Mount_Point = (*iter)->Mount_Point;
				part.selected = (*iter)->Is_Mounted();
				Partition_List->push_back(part);
			}
		}
	} else if (ListType == "storage") {
		string Current_Storage = DataManager::GetCurrentStoragePath();
		for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
			if ((*iter)->Is_Storage) {
				struct PartitionList part;
				std::string unit;
				std::string num = TWFunc::Bytes_To_Readable_Size((*iter)->Free, unit);
				part.Display_Name = (*iter)->Storage_Name + " (" + num + unit + ")";
				part.Mount_Point = (*iter)->Storage_Path;
				if ((*iter)->Storage_Path == Current_Storage)
					part.selected = 1;
				else
					part.selected = 0;
				Partition_List->push_back(part);
			}
		}
	} else if (ListType == "backup") {
		unsigned long long Backup_Size;
		for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
			if ((*iter)->Can_Be_Backed_Up && !(*iter)->Is_SubPartition && (*iter)->Is_Present) {
				struct PartitionList part;
				Backup_Size = (*iter)->Backup_Size;
				if ((*iter)->Has_SubPartition) {
					std::vector<TWPartition*>::iterator subpart;

					for (subpart = Partitions.begin(); subpart != Partitions.end(); subpart++) {
						if ((*subpart)->Is_SubPartition && (*subpart)->Can_Be_Backed_Up && (*subpart)->Is_Present && (*subpart)->SubPartition_Of == (*iter)->Mount_Point)
							Backup_Size += (*subpart)->Backup_Size;
					}
				}
				std::string unit;
				std::string num = TWFunc::Bytes_To_Readable_Size(Backup_Size, unit);
				part.Display_Name = (*iter)->Backup_Display_Name + " (" + num + unit + ")";
				part.Mount_Point = (*iter)->Backup_Path;
				part.selected = 0;
				Partition_List->push_back(part);
			}
		}
	} else if (ListType == "restore") {
		string Restore_List, restore_path;
		TWPartition* restore_part = NULL;

		DataManager::GetValue("tw_restore_list", Restore_List);
		if (!Restore_List.empty()) {
			size_t start_pos = 0, end_pos = Restore_List.find(";", start_pos);
			while (end_pos != string::npos && start_pos < Restore_List.size()) {
				restore_path = Restore_List.substr(start_pos, end_pos - start_pos);
				struct PartitionList part;
				if (restore_path.compare("ADB_Backup") == 0) {
					part.Display_Name = "ADB Backup";
					part.Mount_Point = "ADB Backup";
					part.selected = 1;
					Partition_List->push_back(part);
					break;
				}
				if ((restore_part = Find_Partition_By_Path(restore_path)) != NULL) {
					if ((restore_part->Backup_Name == "recovery" && !restore_part->Can_Be_Backed_Up) || restore_part->Is_SubPartition) {
						// Don't allow restore of recovery (causes problems on some devices)
						// Don't add subpartitions to the list of items
					} else {
						part.Display_Name = restore_part->Backup_Display_Name;
						part.Mount_Point = restore_part->Backup_Path;
						part.selected = 1;
						Partition_List->push_back(part);
					}
				} else {
					gui_msg(Msg(msg::kError, "restore_unable_locate=Unable to locate '{1}' partition for restoring.")(restore_path));
				}
				start_pos = end_pos + 1;
				end_pos = Restore_List.find(";", start_pos);
			}
		}
	} else if (ListType == "wipe") {
		struct PartitionList dalvik;
		dalvik.Display_Name = gui_parse_text("{@dalvik}");
		dalvik.Mount_Point = "DALVIK";
		dalvik.selected = 0;
		Partition_List->push_back(dalvik);
		for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
			if ((*iter)->Wipe_Available_in_GUI && !(*iter)->Is_SubPartition) {
				struct PartitionList part;
				part.Display_Name = (*iter)->Display_Name;
				part.Mount_Point = (*iter)->Mount_Point;
				part.selected = 0;
				Partition_List->push_back(part);
			}
			if ((*iter)->Has_Android_Secure) {
				struct PartitionList part;
				part.Display_Name = (*iter)->Backup_Display_Name;
				part.Mount_Point = (*iter)->Backup_Path;
				part.selected = 0;
				Partition_List->push_back(part);
			}
			if ((*iter)->Has_Data_Media) {
				struct PartitionList datamedia;
				datamedia.Display_Name = (*iter)->Storage_Name;
				datamedia.Mount_Point = "INTERNAL";
				datamedia.selected = 0;
				Partition_List->push_back(datamedia);
			}
		}
	} else if (ListType == "flashimg") {
		for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
			if ((*iter)->Can_Flash_Img && (*iter)->Is_Present) {
				struct PartitionList part;
				part.Display_Name = (*iter)->Backup_Display_Name;
				part.Mount_Point = (*iter)->Backup_Path;
				part.selected = 0;
				Partition_List->push_back(part);
			}
		}
		if (DataManager::GetIntValue("tw_has_repack_tools") != 0 && DataManager::GetIntValue("tw_has_boot_slots") != 0) {
			TWPartition* boot = Find_Partition_By_Path("/boot");
			if (boot) {
				// Allow flashing kernels and ramdisks
				struct PartitionList repack_ramdisk;
				repack_ramdisk.Display_Name = gui_lookup("install_twrp_ramdisk", "Install Recovery Ramdisk");
				repack_ramdisk.Mount_Point = "/repack_ramdisk";
				repack_ramdisk.selected = 0;
				Partition_List->push_back(repack_ramdisk);
				/*struct PartitionList repack_kernel; For now let's leave repacking kernels under advanced only
				repack_kernel.Display_Name = gui_lookup("install_kernel", "Install Kernel");
				repack_kernel.Mount_Point = "/repack_kernel";
				repack_kernel.selected = 0;
				Partition_List->push_back(repack_kernel);*/
			}
		}
	} else {
		LOGERR("Unknown list type '%s' requested for TWPartitionManager::Get_Partition_List\n", ListType.c_str());
	}
}

int TWPartitionManager::Fstab_Processed(void) {
	return Partitions.size();
}

void TWPartitionManager::Output_Storage_Fstab(void) {
	std::vector<TWPartition*>::iterator iter;
	char storage_partition[255];
	std::string Temp;
	std::string cacheDir = TWFunc::get_log_dir();

	if (cacheDir.empty()) {
		LOGINFO("Unable to find cache directory\n");
		return;
	}

	std::string storageFstab = TWFunc::get_log_dir() + "recovery/storage.fstab";
	FILE *fp = fopen(storageFstab.c_str(), "w");

	if (fp == NULL) {
		gui_msg(Msg(msg::kError, "unable_to_open=Unable to open '{1}'.")(storageFstab));
		return;
	}

	// Iterate through all partitions
	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Is_Storage) {
			Temp = (*iter)->Storage_Path + ";" + (*iter)->Storage_Name + ";\n";
			strcpy(storage_partition, Temp.c_str());
			fwrite(storage_partition, sizeof(storage_partition[0]), strlen(storage_partition) / sizeof(storage_partition[0]), fp);
		}
	}
	fclose(fp);
}

TWPartition *TWPartitionManager::Get_Default_Storage_Partition()
{
	TWPartition *res = NULL;
	for (std::vector<TWPartition*>::iterator iter = Partitions.begin(); iter != Partitions.end(); ++iter) {
		if (!(*iter)->Is_Storage)
			continue;

		if ((*iter)->Is_Settings_Storage)
			return *iter;

		if (!res)
			res = *iter;
	}
	return res;
}

bool TWPartitionManager::Enable_MTP(void) {
#ifdef TW_HAS_MTP
	if (mtppid) {
		gui_err("mtp_already_enabled=MTP already enabled");
		return true;
	}

	int mtppipe[2];

	if (pipe2(mtppipe, O_CLOEXEC) < 0) {
		LOGERR("Error creating MTP pipe\n");
		return false;
	}

	char old_value[PROPERTY_VALUE_MAX];
	property_get("sys.usb.config", old_value, "");
	if (strcmp(old_value, "mtp,adb") != 0) {
		char vendor[PROPERTY_VALUE_MAX];
		char product[PROPERTY_VALUE_MAX];
		property_set("sys.usb.config", "none");
		property_get("usb.vendor", vendor, "18D1");
		property_get("usb.product.mtpadb", product, "4EE2");
		string vendorstr = vendor;
		string productstr = product;
		TWFunc::write_to_file("/sys/class/android_usb/android0/idVendor", vendorstr);
		TWFunc::write_to_file("/sys/class/android_usb/android0/idProduct", productstr);
		property_set("sys.usb.config", "mtp,adb");
	}
	/* To enable MTP debug, use the twrp command line feature:
	 * twrp set tw_mtp_debug 1
	 */
	twrpMtp *mtp = new twrpMtp(DataManager::GetIntValue("tw_mtp_debug"));
	mtppid = mtp->forkserver(mtppipe);
	if (mtppid) {
		close(mtppipe[0]); // Host closes read side
		mtp_write_fd = mtppipe[1];
		DataManager::SetValue("tw_mtp_enabled", 1);
		Add_All_MTP_Storage();
		return true;
	} else {
		close(mtppipe[0]);
		close(mtppipe[1]);
		gui_err("mtp_fail=Failed to enable MTP");
		return false;
	}
#else
	gui_err("no_mtp=MTP support not included");
#endif
	DataManager::SetValue("tw_mtp_enabled", 0);
	return false;
}

void TWPartitionManager::Add_All_MTP_Storage(void) {
#ifdef TW_HAS_MTP
	std::vector<TWPartition*>::iterator iter;

	if (!mtppid)
		return; // MTP is not enabled

	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Is_Storage && (*iter)->Is_Present && (*iter)->Mount(false))
			Add_Remove_MTP_Storage((*iter), MTP_MESSAGE_ADD_STORAGE);
	}
#else
	return;
#endif
}

bool TWPartitionManager::Disable_MTP(void) {
	char old_value[PROPERTY_VALUE_MAX];
	property_set("sys.usb.ffs.mtp.ready", "0");
	property_get("sys.usb.config", old_value, "");
	if (strcmp(old_value, "adb") != 0) {
		char vendor[PROPERTY_VALUE_MAX];
		char product[PROPERTY_VALUE_MAX];
		property_set("sys.usb.config", "none");
		property_get("usb.vendor", vendor, "18D1");
		property_get("usb.product.adb", product, "D001");
		string vendorstr = vendor;
		string productstr = product;
		TWFunc::write_to_file("/sys/class/android_usb/android0/idVendor", vendorstr);
		TWFunc::write_to_file("/sys/class/android_usb/android0/idProduct", productstr);
		usleep(2000);
	}
#ifdef TW_HAS_MTP
	if (mtppid) {
		LOGINFO("Disabling MTP\n");
		int status;
		kill(mtppid, SIGKILL);
		mtppid = 0;
		// We don't care about the exit value, but this prevents a zombie process
		waitpid(mtppid, &status, 0);
		close(mtp_write_fd);
		mtp_write_fd = -1;
	}
#endif
	property_set("sys.usb.config", "adb");
#ifdef TW_HAS_MTP
	DataManager::SetValue("tw_mtp_enabled", 0);
	return true;
#endif
	return false;
}

TWPartition* TWPartitionManager::Find_Partition_By_MTP_Storage_ID(unsigned int Storage_ID) {
	std::vector<TWPartition*>::iterator iter;

	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->MTP_Storage_ID == Storage_ID)
			return (*iter);
	}
	return NULL;
}

bool TWPartitionManager::Add_Remove_MTP_Storage(TWPartition* Part, int message_type) {
#ifdef TW_HAS_MTP
	struct mtpmsg mtp_message;

	if (!mtppid)
		return false; // MTP is disabled

	if (mtp_write_fd < 0) {
		LOGINFO("MTP: mtp_write_fd is not set\n");
		return false;
	}

	if (Part) {
		if (Part->MTP_Storage_ID == 0)
			return false;
		if (message_type == MTP_MESSAGE_REMOVE_STORAGE) {
			mtp_message.message_type = MTP_MESSAGE_REMOVE_STORAGE; // Remove
			LOGINFO("sending message to remove %i\n", Part->MTP_Storage_ID);
			mtp_message.storage_id = Part->MTP_Storage_ID;
			if (write(mtp_write_fd, &mtp_message, sizeof(mtp_message)) <= 0) {
				LOGINFO("error sending message to remove storage %i\n", Part->MTP_Storage_ID);
				return false;
			} else {
				LOGINFO("Message sent, remove storage ID: %i\n", Part->MTP_Storage_ID);
				return true;
			}
		} else if (message_type == MTP_MESSAGE_ADD_STORAGE && Part->Is_Mounted()) {
			mtp_message.message_type = MTP_MESSAGE_ADD_STORAGE; // Add
			mtp_message.storage_id = Part->MTP_Storage_ID;
			if (Part->Storage_Path.size() >= sizeof(mtp_message.path)) {
				LOGERR("Storage path '%s' too large for mtpmsg\n", Part->Storage_Path.c_str());
				return false;
			}
			strcpy(mtp_message.path, Part->Storage_Path.c_str());
			if (Part->Storage_Name.size() >= sizeof(mtp_message.display)) {
				LOGERR("Storage name '%s' too large for mtpmsg\n", Part->Storage_Name.c_str());
				return false;
			}
			strcpy(mtp_message.display, Part->Storage_Name.c_str());
			mtp_message.maxFileSize = Part->Get_Max_FileSize();
			LOGINFO("sending message to add %i '%s' '%s'\n", mtp_message.storage_id, mtp_message.path, mtp_message.display);
			if (write(mtp_write_fd, &mtp_message, sizeof(mtp_message)) <= 0) {
				LOGINFO("error sending message to add storage %i\n", Part->MTP_Storage_ID);
				return false;
			} else {
				LOGINFO("Message sent, add storage ID: %i '%s'\n", Part->MTP_Storage_ID, mtp_message.path);
				return true;
			}
		} else {
			LOGERR("Unknown MTP message type: %i\n", message_type);
		}
	} else {
		// This hopefully never happens as the error handling should
		// occur in the calling function.
		LOGINFO("TWPartitionManager::Add_Remove_MTP_Storage NULL partition given\n");
	}
	return true;
#else
	gui_err("no_mtp=MTP support not included");
	DataManager::SetValue("tw_mtp_enabled", 0);
	return false;
#endif
}

bool TWPartitionManager::Add_MTP_Storage(string Mount_Point) {
#ifdef TW_HAS_MTP
	TWPartition* Part = PartitionManager.Find_Partition_By_Path(Mount_Point);
	if (Part) {
		return PartitionManager.Add_Remove_MTP_Storage(Part, MTP_MESSAGE_ADD_STORAGE);
	} else {
		LOGINFO("TWFunc::Add_MTP_Storage unable to locate partition for '%s'\n", Mount_Point.c_str());
	}
#endif
	return false;
}

bool TWPartitionManager::Add_MTP_Storage(unsigned int Storage_ID) {
#ifdef TW_HAS_MTP
	TWPartition* Part = PartitionManager.Find_Partition_By_MTP_Storage_ID(Storage_ID);
	if (Part) {
		return PartitionManager.Add_Remove_MTP_Storage(Part, MTP_MESSAGE_ADD_STORAGE);
	} else {
		LOGINFO("TWFunc::Add_MTP_Storage unable to locate partition for %i\n", Storage_ID);
	}
#endif
	return false;
}

bool TWPartitionManager::Remove_MTP_Storage(string Mount_Point) {
#ifdef TW_HAS_MTP
	TWPartition* Part = PartitionManager.Find_Partition_By_Path(Mount_Point);
	if (Part) {
		return PartitionManager.Add_Remove_MTP_Storage(Part, MTP_MESSAGE_REMOVE_STORAGE);
	} else {
		LOGINFO("TWFunc::Remove_MTP_Storage unable to locate partition for '%s'\n", Mount_Point.c_str());
	}
#endif
	return false;
}

bool TWPartitionManager::Remove_MTP_Storage(unsigned int Storage_ID) {
#ifdef TW_HAS_MTP
	TWPartition* Part = PartitionManager.Find_Partition_By_MTP_Storage_ID(Storage_ID);
	if (Part) {
		return PartitionManager.Add_Remove_MTP_Storage(Part, MTP_MESSAGE_REMOVE_STORAGE);
	} else {
		LOGINFO("TWFunc::Remove_MTP_Storage unable to locate partition for %i\n", Storage_ID);
	}
#endif
	return false;
}

bool TWPartitionManager::Flash_Image(string& path, string& filename) {
	twrpRepacker repacker;
	int partition_count = 0;
	TWPartition* flash_part = NULL;
	string Flash_List, flash_path, full_filename;
	size_t start_pos = 0, end_pos = 0;

	full_filename = path + "/" + filename;

	gui_msg("image_flash_start=[IMAGE FLASH STARTED]");
	gui_msg(Msg("img_to_flash=Image to flash: '{1}'")(full_filename));

	if (!TWFunc::Path_Exists(full_filename)) {
		if (!Mount_By_Path(full_filename, true)) {
			return false;
		}
		if (!TWFunc::Path_Exists(full_filename)) {
			gui_msg(Msg(msg::kError, "unable_to_locate=Unable to locate {1}.")(full_filename));
			return false;
		}
	}

	DataManager::GetValue("tw_flash_partition", Flash_List);
	Repack_Type repack = REPLACE_NONE;
	if (Flash_List == "/repack_ramdisk;") {
		repack = REPLACE_RAMDISK;
	} else if (Flash_List == "/repack_kernel;") {
		repack = REPLACE_KERNEL;
	}
	if (repack != REPLACE_NONE) {
		Repack_Options_struct Repack_Options;
		Repack_Options.Type = repack;
		Repack_Options.Disable_Verity = false;
		Repack_Options.Disable_Force_Encrypt = false;
		Repack_Options.Backup_First = DataManager::GetIntValue("tw_repack_backup_first") != 0;
		return repacker.Repack_Image_And_Flash(full_filename, Repack_Options);
	}
	PartitionSettings part_settings;
	part_settings.Backup_Folder = path;
	unsigned long long total_bytes = TWFunc::Get_File_Size(full_filename);
	ProgressTracking progress(total_bytes);
	part_settings.progress = &progress;
	part_settings.adbbackup = false;
	part_settings.PM_Method = PM_RESTORE;
	gui_msg("calc_restore=Calculating restore details...");
	if (!Flash_List.empty()) {
		end_pos = Flash_List.find(";", start_pos);
		while (end_pos != string::npos && start_pos < Flash_List.size()) {
			flash_path = Flash_List.substr(start_pos, end_pos - start_pos);
			flash_part = Find_Partition_By_Path(flash_path);
			if (flash_part != NULL) {
				partition_count++;
				if (partition_count > 1) {
					gui_err("too_many_flash=Too many partitions selected for flashing.");
					return false;
				}
			} else {
				gui_msg(Msg(msg::kError, "flash_unable_locate=Unable to locate '{1}' partition for flashing.")(flash_path));
				return false;
			}
			start_pos = end_pos + 1;
			end_pos = Flash_List.find(";", start_pos);
		}
	}

	if (partition_count == 0) {
		gui_err("no_part_flash=No partitions selected for flashing.");
		return false;
	}

	DataManager::SetProgress(0.0);
	if (flash_part) {
		flash_part->Backup_FileName = filename;
		if (!flash_part->Flash_Image(&part_settings))
			return false;
	} else {
		gui_err("invalid_flash=Invalid flash partition specified.");
		return false;
	}
	gui_highlight("flash_done=IMAGE FLASH COMPLETED]");
	return true;
}

void TWPartitionManager::Translate_Partition(const char* path, const char* resource_name, const char* default_value) {
	TWPartition* part = PartitionManager.Find_Partition_By_Path(path);
	if (part) {
		if (part->Is_Adopted_Storage) {
			part->Display_Name = part->Display_Name + " - " + gui_lookup("data", "Data");
			part->Backup_Display_Name = part->Display_Name;
			part->Storage_Name = part->Storage_Name + " - " + gui_lookup("adopted_storage", "Adopted Storage");
		} else {
			part->Display_Name = gui_lookup(resource_name, default_value);
			part->Backup_Display_Name = part->Display_Name;
		}
	}
}

void TWPartitionManager::Translate_Partition(const char* path, const char* resource_name, const char* default_value, const char* storage_resource_name, const char* storage_default_value) {
	TWPartition* part = PartitionManager.Find_Partition_By_Path(path);
	if (part) {
		if (part->Is_Adopted_Storage) {
			part->Backup_Display_Name = part->Display_Name + " - " + gui_lookup("data_backup", "Data (excl. storage)");
			part->Display_Name = part->Display_Name + " - " + gui_lookup("data", "Data");
			part->Storage_Name = part->Storage_Name + " - " + gui_lookup("adopted_storage", "Adopted Storage");
		} else {
			part->Display_Name = gui_lookup(resource_name, default_value);
			part->Backup_Display_Name = part->Display_Name;
			if (part->Is_Storage)
				part->Storage_Name = gui_lookup(storage_resource_name, storage_default_value);
		}
	}
}

void TWPartitionManager::Translate_Partition(const char* path, const char* resource_name, const char* default_value, const char* storage_resource_name, const char* storage_default_value, const char* backup_name, const char* backup_default) {
	TWPartition* part = PartitionManager.Find_Partition_By_Path(path);
	if (part) {
		if (part->Is_Adopted_Storage) {
			part->Backup_Display_Name = part->Display_Name + " - " + gui_lookup(backup_name, backup_default);
			part->Display_Name = part->Display_Name + " - " + gui_lookup("data", "Data");
			part->Storage_Name = part->Storage_Name + " - " + gui_lookup("adopted_storage", "Adopted Storage");
		} else {
			part->Display_Name = gui_lookup(resource_name, default_value);
			part->Backup_Display_Name = gui_lookup(backup_name, backup_default);
			if (part->Is_Storage)
				part->Storage_Name = gui_lookup(storage_resource_name, storage_default_value);
		}
	}
}

void TWPartitionManager::Translate_Partition_Display_Names() {
	LOGINFO("Translating partition display names\n");
	Translate_Partition("/system", "system", "System");
	Translate_Partition("/system_image", "system_image", "System Image");
	Translate_Partition("/vendor", "vendor", "Vendor");
	Translate_Partition("/vendor_image", "vendor_image", "Vendor Image");
	Translate_Partition("/cache", "cache", "Cache");
	Translate_Partition("/boot", "boot", "Boot");
	Translate_Partition("/recovery", "recovery", "Recovery");
	if (!datamedia) {
		Translate_Partition("/data", "data", "Data", "internal", "Internal Storage");
		Translate_Partition("/sdcard", "sdcard", "SDCard", "sdcard", "SDCard");
		Translate_Partition("/internal_sd", "sdcard", "SDCard", "sdcard", "SDCard");
		Translate_Partition("/internal_sdcard", "sdcard", "SDCard", "sdcard", "SDCard");
		Translate_Partition("/emmc", "sdcard", "SDCard", "sdcard", "SDCard");
	} else {
		Translate_Partition("/data", "data", "Data", "internal", "Internal Storage", "data_backup", "Data (excl. storage)");
	}
	Translate_Partition("/external_sd", "microsd", "Micro SDCard", "microsd", "Micro SDCard", "data_backup", "Data (excl. storage)");
	Translate_Partition("/external_sdcard", "microsd", "Micro SDCard", "microsd", "Micro SDCard", "data_backup", "Data (excl. storage)");
	Translate_Partition("/usb-otg", "usbotg", "USB OTG", "usbotg", "USB OTG");
	Translate_Partition("/sd-ext", "sdext", "SD-EXT");

	// Android secure is a special case
	TWPartition* part = PartitionManager.Find_Partition_By_Path("/and-sec");
	if (part)
		part->Backup_Display_Name = gui_lookup("android_secure", "Android Secure");

	std::vector<TWPartition*>::iterator sysfs;
	for (sysfs = Partitions.begin(); sysfs != Partitions.end(); sysfs++) {
		if (!(*sysfs)->Sysfs_Entry.empty()) {
			Translate_Partition((*sysfs)->Mount_Point.c_str(), "autostorage", "Storage", "autostorage", "Storage");
		}
	}

	// This updates the text on all of the storage selection buttons in the GUI
	DataManager::SetBackupFolder();
}

bool TWPartitionManager::Decrypt_Adopted() {
#ifdef TW_INCLUDE_CRYPTO
	bool ret = false;
	if (!Mount_By_Path("/data", false)) {
		LOGERR("Cannot decrypt adopted storage because /data will not mount\n");
		return false;
	}

	// In Android 12 xml format changed. Previously it was human-readable format with xml tags
	// now it's ABX (Android Binary Xml). Sadly, rapidxml can't parse it, so check xml format firstly
	std::string path = "/data/system/storage.xml";
	if ((atoi(TWFunc::System_Property_Get("ro.build.version.sdk").c_str()) > 30) && TWFunc::Path_Exists(path))
		if(!TWFunc::Check_Xml_Format(path)) {
			LOGINFO("Android 12+: storage.xml is in ABX format. Skipping adopted storage decryption\n");
			return false;
		}

	DataManager::SetValue("tw_settings_path", TW_STORAGE_PATH);
	LOGINFO("Decrypt adopted storage starting\n");
	char* xmlFile = PageManager::LoadFileToBuffer("/data/system/storage.xml", NULL);
	xml_document<> *doc = NULL;
	xml_node<>* volumes = NULL;
	string Primary_Storage_UUID = "";
	if (xmlFile != NULL) {
		LOGINFO("successfully loaded storage.xml\n");
		doc = new xml_document<>();
		doc->parse<0>(xmlFile);
		volumes = doc->first_node("volumes");
		if (volumes) {
			xml_attribute<>* psuuid = volumes->first_attribute("primaryStorageUuid");
			if (psuuid) {
				Primary_Storage_UUID = psuuid->value();
			}
		}
	} else {
		LOGINFO("No /data/system/storage.xml for adopted storage\n");
		return false;
	}
	std::vector<TWPartition*>::iterator adopt;
	for (adopt = Partitions.begin(); adopt != Partitions.end(); adopt++) {
		if ((*adopt)->Removable && !(*adopt)->Is_Present && (*adopt)->Adopted_Mount_Delay > 0) {
			// On some devices, the external mmc driver takes some time
			// to recognize the card, in which case the "actual block device"
			// would not have been found yet. We wait the specified delay
			// and then try again.
			LOGINFO("Sleeping %d seconds for adopted storage.\n", (*adopt)->Adopted_Mount_Delay);
			sleep((*adopt)->Adopted_Mount_Delay);
			(*adopt)->Find_Actual_Block_Device();
		}

		if ((*adopt)->Removable && (*adopt)->Is_Present) {
			if ((*adopt)->Decrypt_Adopted() == 0) {
				ret = true;
				if (volumes) {
					xml_node<>* volume = volumes->first_node("volume");
					while (volume) {
						xml_attribute<>* guid = volume->first_attribute("partGuid");
						if (guid) {
							string GUID = (*adopt)->Adopted_GUID.c_str();
							GUID.insert(8, "-");
							GUID.insert(13, "-");
							GUID.insert(18, "-");
							GUID.insert(23, "-");

							if (strcasecmp(GUID.c_str(), guid->value()) == 0) {
								xml_attribute<>* attr = volume->first_attribute("nickname");
								if (attr && attr->value() && strlen(attr->value()) > 0) {
									(*adopt)->Storage_Name = attr->value();
									(*adopt)->Display_Name = (*adopt)->Storage_Name;
									(*adopt)->Backup_Display_Name = (*adopt)->Storage_Name;
									LOGINFO("storage name from storage.xml is '%s'\n", attr->value());
								}
								attr = volume->first_attribute("fsUuid");
								if (attr && !Primary_Storage_UUID.empty() && strcmp(Primary_Storage_UUID.c_str(), attr->value()) == 0) {
									TWPartition* Dat = Find_Partition_By_Path("/data");
									if (Dat) {
										LOGINFO("Internal storage is found on adopted storage '%s'\n", (*adopt)->Display_Name.c_str());
										LOGINFO("Changing '%s' to point to '%s'\n", Dat->Symlink_Mount_Point.c_str(), (*adopt)->Storage_Path.c_str());
										(*adopt)->Symlink_Mount_Point = Dat->Symlink_Mount_Point;
										Dat->Symlink_Mount_Point = "";
										// Toggle mounts to ensure that the symlink mount point (probably /sdcard) is mounted to the right location
										Dat->UnMount(false);
										Dat->Mount(false);
										(*adopt)->UnMount(false);
										(*adopt)->Mount(false);
									}
								}
								break;
							}
						}
						volume = volume->next_sibling("volume");
					}
				}
				Update_System_Details();
				Output_Partition((*adopt));
			}
		}
	}
	if (xmlFile) {
		doc->clear();
		delete doc;
		free(xmlFile);
	}
	return ret;
#else
	LOGINFO("Decrypt_Adopted: no crypto support\n");
	return false;
#endif
}

void TWPartitionManager::Remove_Partition_By_Path(string Path) {
	std::vector<TWPartition*>::iterator iter;
	string Local_Path = TWFunc::Get_Root_Path(Path);

	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if ((*iter)->Mount_Point == Local_Path || (!(*iter)->Symlink_Mount_Point.empty() && (*iter)->Symlink_Mount_Point == Local_Path)) {
			LOGINFO("Found and erasing '%s' from partition list\n", Local_Path.c_str());
			Partitions.erase(iter);
			return;
		}
	}
}

void TWPartitionManager::Override_Active_Slot(const string& Slot) {
	LOGINFO("Overriding slot to '%s'\n", Slot.c_str());
	Active_Slot_Display = Slot;
	DataManager::SetValue("tw_active_slot", Slot);
	PartitionManager.Update_System_Details();
}

void TWPartitionManager::Set_Active_Slot(const string& Slot) {
	if (Slot != "A" && Slot != "B") {
		LOGERR("Set_Active_Slot invalid slot '%s'\n", Slot.c_str());
		return;
	}
	if (Active_Slot_Display == Slot)
		return;
	LOGINFO("Setting active slot %s\n", Slot.c_str());
#ifdef AB_OTA_UPDATER
	if (!Active_Slot_Display.empty()) {
		android::sp<IBootControl> module = IBootControl::getService();
		if (module == nullptr) {
			LOGERR("Error getting bootctrl module.\n");
		} else {
			uint32_t slot_number = 0;
			if (Slot == "B")
				slot_number = 1;
			CommandResult result;
			auto ret = module->setActiveBootSlot(slot_number, [&result]
					(const CommandResult &cb_result) { result = cb_result; });
			if (!ret.isOk() || !result.success)
				gui_msg(Msg(msg::kError, "unable_set_boot_slot=Error changing bootloader boot slot to {1}")(Slot));
		}
		DataManager::SetValue("tw_active_slot", Slot); // Doing this outside of this if block may result in a seg fault because the DataManager may not be ready yet
	}
#else
	LOGERR("Boot slot feature not present\n");
#endif
	Active_Slot_Display = Slot;
	if (Fstab_Processed())
		Update_System_Details();
}
string TWPartitionManager::Get_Active_Slot_Suffix() {
	if (Active_Slot_Display == "A")
		return "_a";
	return "_b";
}
string TWPartitionManager::Get_Active_Slot_Display() {
	return Active_Slot_Display;
}

string TWPartitionManager::Get_Android_Root_Path() {
	return "/system_root";
}

void TWPartitionManager::Remove_Uevent_Devices(const string& Mount_Point) {
	std::vector<TWPartition*>::iterator iter;

	for (iter = Partitions.begin(); iter != Partitions.end(); ) {
		if ((*iter)->Is_SubPartition && (*iter)->SubPartition_Of == Mount_Point) {
			TWPartition *part = *iter;
			LOGINFO("%s was removed by uevent data\n", (*iter)->Mount_Point.c_str());
			(*iter)->UnMount(false);
			rmdir((*iter)->Mount_Point.c_str());
			iter = Partitions.erase(iter);
			delete part;
		} else {
			iter++;
		}
	}
}

void TWPartitionManager::Handle_Uevent(const Uevent_Block_Data& uevent_data) {
	std::vector<TWPartition*>::iterator iter;

	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if (!(*iter)->Sysfs_Entry.empty()) {
			string device;
			size_t wildcard = (*iter)->Sysfs_Entry.find("*");
			if (wildcard != string::npos) {
				device = (*iter)->Sysfs_Entry.substr(0, wildcard);
			} else {
				device = (*iter)->Sysfs_Entry;
			}
			if (device == uevent_data.sysfs_path.substr(0, device.size())) {
				// Found a match
				if (uevent_data.action == "add") {
					(*iter)->Primary_Block_Device = "/dev/block/" + uevent_data.block_device;
					(*iter)->Alternate_Block_Device = (*iter)->Primary_Block_Device;
					(*iter)->Is_Present = true;
					LOGINFO("Found a match '%s' '%s'\n", uevent_data.block_device.c_str(), device.c_str());
					if (!Decrypt_Adopted()) {
						LOGINFO("No adopted storage so finding actual block device\n");
						(*iter)->Find_Actual_Block_Device();
					}
					return;
				} else if (uevent_data.action == "remove") {
					(*iter)->Is_Present = false;
					(*iter)->Primary_Block_Device = "";
					(*iter)->Actual_Block_Device = "";
					Remove_Uevent_Devices((*iter)->Mount_Point);
					return;
				}
			}
		}
	}

	if (!PartitionManager.Get_Super_Status())
		LOGINFO("Found no matching fstab entry for uevent device '%s' - %s\n", uevent_data.sysfs_path.c_str(), uevent_data.action.c_str());
}

void TWPartitionManager::setup_uevent() {
	struct sockaddr_nl nls;

	if (uevent_pfd.fd >= 0) {
		LOGINFO("uevent already set up\n");
		return;
	}

	// Open hotplug event netlink socket
	memset(&nls,0,sizeof(struct sockaddr_nl));
	nls.nl_family = AF_NETLINK;
	nls.nl_pid = getpid();
	nls.nl_groups = -1;
	uevent_pfd.events = POLLIN;
	uevent_pfd.fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (uevent_pfd.fd==-1) {
		LOGERR("uevent not root\n");
		return;
	}

	// Listen to netlink socket
	if (::bind(uevent_pfd.fd, (struct sockaddr *) &nls, sizeof(struct sockaddr_nl)) < 0) {
		LOGERR("Bind failed\n");
		return;
	}
	set_select_fd();
	Coldboot();
}

Uevent_Block_Data TWPartitionManager::get_event_block_values(char *buf, int len) {
	Uevent_Block_Data ret;
	ret.subsystem = "";
	char *ptr = buf;
	const char *end = buf + len;

	buf[len - 1] = '\0';
	while (ptr < end) {
		if (strncmp(ptr, "ACTION=", strlen("ACTION=")) == 0) {
			ptr += strlen("ACTION=");
			ret.action = ptr;
		} else if (strncmp(ptr, "SUBSYSTEM=", strlen("SUBSYSTEM=")) == 0) {
			ptr += strlen("SUBSYSTEM=");
			ret.subsystem = ptr;
		} else if (strncmp(ptr, "DEVTYPE=", strlen("DEVTYPE=")) == 0) {
			ptr += strlen("DEVTYPE=");
			ret.type = ptr;
		} else if (strncmp(ptr, "DEVPATH=", strlen("DEVPATH=")) == 0) {
			ptr += strlen("DEVPATH=");
			ret.sysfs_path += ptr;
		} else if (strncmp(ptr, "DEVNAME=", strlen("DEVNAME=")) == 0) {
			ptr += strlen("DEVNAME=");
			ret.block_device += ptr;
		} else if (strncmp(ptr, "MAJOR=", strlen("MAJOR=")) == 0) {
			ptr += strlen("MAJOR=");
			ret.major = atoi(ptr);
		} else if (strncmp(ptr, "MINOR=", strlen("MINOR=")) == 0) {
			ptr += strlen("MINOR=");
			ret.minor = atoi(ptr);
		}
		ptr += strlen(ptr) + 1;
	}
	return ret;
}

void TWPartitionManager::read_uevent() {
	char buf[1024];

	int len = recv(uevent_pfd.fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (len == -1) {
		LOGINFO("recv error on uevent\n");
		return;
	}
	/*int i = 0; // Print all uevent output for test /debug
	while (i<len) {
		printf("%s\n", buf+i);
		i += strlen(buf+i)+1;
	}*/
	Uevent_Block_Data uevent_data = get_event_block_values(buf, len);
	if (uevent_data.subsystem == "block" && uevent_data.type == "disk") {
		PartitionManager.Handle_Uevent(uevent_data);
	}
}

void TWPartitionManager::close_uevent() {
	if (uevent_pfd.fd > 0)
		close(uevent_pfd.fd);
	uevent_pfd.fd = -1;
}

void TWPartitionManager::Add_Partition(TWPartition* Part) {
	Partitions.push_back(Part);
}

void TWPartitionManager::Coldboot_Scan(std::vector<string> *sysfs_entries, const string& Path, int depth) {
	string Real_Path = Path;
	char real_path[PATH_MAX];
	if (realpath(Path.c_str(), &real_path[0])) {
		string Real_Path = real_path;
		std::vector<string>::iterator iter;
		for (iter = sysfs_entries->begin(); iter != sysfs_entries->end(); iter++) {
			if (Real_Path.find((*iter)) != string::npos) {
				string Write_Path = Real_Path + "/uevent";
				if (TWFunc::Path_Exists(Write_Path)) {
					const char* write_val = "add\n";
					TWFunc::write_to_file(Write_Path, write_val);
					break;
				}
			}
		}
	}

	DIR* d = opendir(Path.c_str());
	if (d != NULL) {
		struct dirent* de;
		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] == '.' || (de->d_type != DT_DIR && depth > 0))
				continue;
			if (strlen(de->d_name) >= 4 && (strncmp(de->d_name, "ram", 3) == 0 || strncmp(de->d_name, "loop", 4) == 0))
				continue;

			string item = Path + "/";
			item.append(de->d_name);
			Coldboot_Scan(sysfs_entries, item, depth + 1);
		}
		closedir(d);
	}
}

void TWPartitionManager::Coldboot() {
	std::vector<TWPartition*>::iterator iter;
	std::vector<string> sysfs_entries;

	for (iter = Partitions.begin(); iter != Partitions.end(); iter++) {
		if (!(*iter)->Sysfs_Entry.empty()) {
			size_t wildcard_pos = (*iter)->Sysfs_Entry.find("*");
			if (wildcard_pos == string::npos)
				wildcard_pos = (*iter)->Sysfs_Entry.size();
			sysfs_entries.push_back((*iter)->Sysfs_Entry.substr(0, wildcard_pos));
		}
	}

	if (sysfs_entries.size() > 0)
		Coldboot_Scan(&sysfs_entries, "/sys/block", 0);
}

bool TWPartitionManager::Prepare_Empty_Folder(const std::string& Folder) {
	if (TWFunc::Path_Exists(Folder))
		TWFunc::removeDir(Folder, false);
	return TWFunc::Recursive_Mkdir(Folder);
}

std::string TWPartitionManager::Get_Bare_Partition_Name(std::string Mount_Point) {
	if (Mount_Point == "/system_root")
		return "system";
	else
		return TWFunc::Remove_Beginning_Slash(Mount_Point);
}

bool TWPartitionManager::Prepare_Super_Volume(TWPartition* twrpPart) {
    Fstab fstab;
	std::string bare_partition_name = Get_Bare_Partition_Name(twrpPart->Get_Mount_Point());

	Super_Partition_List.push_back(bare_partition_name);
	LOGINFO("Trying to prepare %s from super partition\n", bare_partition_name.c_str());

	std::string blk_device_partition;
#ifdef AB_OTA_UPDATER
	blk_device_partition = bare_partition_name + PartitionManager.Get_Active_Slot_Suffix();
#else
	blk_device_partition = bare_partition_name;
#endif

	FstabEntry fstabEntry = {
        .blk_device =  blk_device_partition,
        .mount_point = twrpPart->Get_Mount_Point(),
        .fs_type = twrpPart->Current_File_System,
        .fs_mgr_flags.logical = twrpPart->Is_Super,
    };

    fstab.emplace_back(fstabEntry);
    if (!fs_mgr_update_logical_partition(&fstabEntry)) {
        LOGINFO("unable to update logical partition: %s\n", twrpPart->Get_Mount_Point().c_str());
        return false;
    }

	while (access(fstabEntry.blk_device.c_str(), F_OK) != 0) {
		usleep(100);
	}

	twrpPart->Set_Block_Device(fstabEntry.blk_device);
	twrpPart->Update_Size(true);
	twrpPart->Set_Can_Be_Backed_Up(false);
	twrpPart->Set_Can_Be_Wiped(false);
	if (access(("/dev/block/bootdevice/by-name/" + bare_partition_name).c_str(), F_OK) == -1) {
		LOGINFO("Symlinking %s => /dev/block/bootdevice/by-name/%s \n", fstabEntry.blk_device.c_str(), bare_partition_name.c_str());
		symlink(fstabEntry.blk_device.c_str(), ("/dev/block/bootdevice/by-name/" + bare_partition_name).c_str());
		property_set("twrp.super.symlinks_created", "true");
	}

    return true;
}

bool TWPartitionManager::Prepare_All_Super_Volumes() {
	bool status = true;
	std::vector<TWPartition*>::iterator iter = Partitions.begin();

	while (iter != Partitions.end()) {
		if ((*iter)->Is_Super) {
			if (!Prepare_Super_Volume(*iter)) {
				status = false;
				LOGINFO("Logical partition '%s' does not exist in super, skipping\n", (*iter)->Get_Mount_Point().c_str());
				iter = Partitions.erase(iter);
				continue;
			}
			PartitionManager.Output_Partition(*iter);
		}
		++iter;
	}
	Update_System_Details();
	return status;
}

std::string TWPartitionManager::Get_Super_Partition() {
	int slot_number = Get_Active_Slot_Display() == "A" ? 0 : 1;
	std::string super_device = fs_mgr_get_super_partition_name(slot_number);
	return "/dev/block/by-name/" + super_device;
}

void TWPartitionManager::Setup_Super_Devices() {
	std::string superPart = Get_Super_Partition();
	android::fs_mgr::CreateLogicalPartitions(superPart);
}

void TWPartitionManager::Setup_Super_Partition() {
	TWPartition* superPartition = new TWPartition();
	std::string superPart = Get_Super_Partition();

	superPartition->Backup_Path = "/super";
	superPartition->Mount_Point = "/super";
	superPartition->Actual_Block_Device = superPart;
	superPartition->Alternate_Block_Device = superPart;
	superPartition->Backup_Display_Name = "Super (";
	// Add first 4 items to fstab as logical that you would like to display in Backup_Display_Name
	// for the Super partition
	int list_size = Super_Partition_List.size();
	int orig_list_size = list_size;
	int max_display_size = 3; // total of 4 items since we start at 0

	for (auto partition: Super_Partition_List) {
		superPartition->Backup_Display_Name = superPartition->Backup_Display_Name + partition;
		if ((orig_list_size - list_size) == max_display_size) {
			break;
		}
		if (list_size != 1)
			superPartition->Backup_Display_Name = superPartition->Backup_Display_Name + " ";
		list_size--;
	}
	superPartition->Backup_Display_Name += ")";
	superPartition->Can_Flash_Img = true;
	superPartition->Current_File_System = "emmc";
	superPartition->Can_Be_Backed_Up = true;
	superPartition->Is_Present = true;
	superPartition->Is_SubPartition = false;
	superPartition->Setup_Image();
	Add_Partition(superPartition);
	PartitionManager.Output_Partition(superPartition);
}

bool TWPartitionManager::Get_Super_Status() {
	std::string fastboot_mode = android::base::GetProperty("sys.usb.config", "");
	if (fastboot_mode == "fastboot") {
		return false;
	}
	else
		return access(Get_Super_Partition().c_str(), F_OK) == 0;
}

bool TWPartitionManager::Recreate_Logs_Dir() {
#ifdef TW_INCLUDE_FBE
	struct passwd pd;
	struct passwd *pwdptr = &pd;
	struct passwd *tempPd;
	char pwdBuf[512];
	int uid = 0, gid = 0;

	if ((getpwnam_r("system", pwdptr, pwdBuf, sizeof(pwdBuf), &tempPd)) != 0) {
		LOGERR("unable to get system user id\n");
		return false;
	} else {
		struct group grp;
		struct group *grpptr = &grp;
		struct group *tempGrp;
		char grpBuf[512];

		if ((getgrnam_r("cache", grpptr, grpBuf, sizeof(grpBuf), &tempGrp)) != 0) {
			LOGERR("unable to get cache group id\n");
			return false;
		} else {
			uid = pd.pw_uid;
			gid = grp.gr_gid;
			std::string abLogsRecoveryDir(DATA_LOGS_DIR);
			abLogsRecoveryDir += "/recovery/";

			if (!TWFunc::Create_Dir_Recursive(abLogsRecoveryDir, S_IRWXU | S_IRWXG | S_IWGRP | S_IXGRP, uid, gid)) {
				LOGERR("Unable to recreate %s\n", abLogsRecoveryDir.c_str());
				return false;
			}
			if (setfilecon(abLogsRecoveryDir.c_str(), "u:object_r:cache_file:s0") != 0) {
				LOGERR("Unable to set contexts for %s\n", abLogsRecoveryDir.c_str());
				return false;
			}
		}
	}
#endif
	return true;
}

void TWPartitionManager::Unlock_Block_Partitions() {
	int fd, OFF = 0;

	const std::string block_path = "/dev/block/";
	DIR* d = opendir(block_path.c_str());
	if (d != NULL) {
		struct dirent* de;
		while ((de = readdir(d)) != NULL) {
			if (de->d_type == DT_BLK) {
				std::string block_device = block_path + de->d_name;
				if ((fd = open(block_device.c_str(), O_RDONLY | O_CLOEXEC)) < 0) {
					LOGERR("unable to open block device %s: %s\n", block_device.c_str(), strerror(errno));
					continue;
				}
				if (ioctl(fd, BLKROSET, &OFF) == -1) {
					LOGERR("Unable to unlock %s: %s\n", block_device.c_str());
					continue;
				}
				close(fd);
			}
		}
		closedir(d);
	}
}

bool TWPartitionManager::Unmap_Super_Devices() {
	bool destroyed = false;
#ifndef TW_EXCLUDE_APEX
	twrpApex apex;
	apex.Unmount();
#endif
	for (auto iter = Partitions.begin(); iter != Partitions.end();) {
		LOGINFO("Checking partition: %s\n", (*iter)->Get_Mount_Point().c_str());
		if ((*iter)->Is_Super) {
			TWPartition *part = *iter;
			std::string bare_partition_name = Get_Bare_Partition_Name((*iter)->Get_Mount_Point());
			std::string blk_device_partition = bare_partition_name;
			if (DataManager::GetStrValue(TW_VIRTUAL_AB_ENABLED) == "1")
				blk_device_partition.append(PartitionManager.Get_Active_Slot_Suffix());
			(*iter)->UnMount(false);
			LOGINFO("removing dynamic partition: %s\n", blk_device_partition.c_str());
			destroyed = DestroyLogicalPartition(blk_device_partition);
			std::string cow_partition = blk_device_partition + "-cow";
			std::string cow_partition_path = "/dev/block/mapper/" + cow_partition;
			struct stat st;
			if (lstat(cow_partition_path.c_str(), &st) == 0) {
				LOGINFO("removing cow partition: %s\n", cow_partition.c_str());
				destroyed = DestroyLogicalPartition(cow_partition);
			}
			iter = Partitions.erase(iter);
			delete part;
			if (!destroyed) {
				return false;
			}
		} else {
			++iter;
		}
	}
	return true;
}


bool TWPartitionManager::Check_Pending_Merges() {
	auto sm = android::snapshot::SnapshotManager::NewForFirstStageMount();
	if (!sm) {
		LOGERR("Unable to call snapshot manager\n");
		return false;
	}

	if (!Unmap_Super_Devices()) {
		LOGERR("Unable to unmap dynamic partitions.\n");
		return false;
	}

	auto callback = [&]() -> void {
		double progress;
		sm->GetUpdateState(&progress);
		LOGINFO("waiting for merge to complete: %.2f\n", progress);
	};

	LOGINFO("checking for merges\n");
	if (!sm->HandleImminentDataWipe(callback)) {
		LOGERR("Unable to check merge status\n");
		return false;
	}
	return true;
}

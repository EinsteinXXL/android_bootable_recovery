/*
	Copyright 2013 to 2021 TeamWin
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
#include <errno.h>

#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <iostream>
#include <libgen.h>
#include <zlib.h>
#include <sstream>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <libsnapshot/snapshot.h>

#include "cutils/properties.h"
#include "libblkid/include/blkid.h"
#include "variables.h"
#include "twcommon.h"
#include "partitions.hpp"
#include "data.hpp"
#include "twrp-functions.hpp"
#include "twrpTar.hpp"
#include "stage_engine.hpp"   // ZstdStream (in-process zstd for the dd/image paths)
#include "twrp_affinity.hpp"
#include "exclude.hpp"
#include "infomanager.hpp"
#include "backupheadermanager.hpp"
#include "set_metadata.h"
#include "gui/gui.hpp"
#include "adbbu/libtwadbbu.hpp"
#include "twrpDigest/twrpDigest.hpp"
#include "twrpDigest/twrpSHA.hpp"
#ifdef TW_INCLUDE_CRYPTO
	#include "crypto/fde/cryptfs.h"
	#include "Decrypt.h"
#else
	#define CRYPT_FOOTER_OFFSET 0x4000
#endif
extern "C" {
	#include "mtdutils/mtdutils.h"
	#include "mtdutils/mounts.h"
#ifdef USE_EXT4
	// #include "make_ext4fs.h" TODO need ifdef for android8
	#include <ext4_utils/make_ext4fs.h>
#endif
#ifdef TW_INCLUDE_CRYPTO
	#include "gpt/gpt.h"
#endif
}
#include <selinux/selinux.h>
#include <selinux/label.h>
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#ifdef HAVE_CAPABILITIES
#include <sys/capability.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#endif
#include <sparse_format.h>
#include "progresstracking.hpp"

using namespace std;

static int auto_index = 0; // v2 fstab allows you to specify a mount point of "auto" with no /. These items are given a mount point of /auto* where * == auto_index

extern struct selabel_handle *selinux_handle;
extern bool datamedia;

struct flag_list {
	const char *name;
	unsigned long flag;
};

const struct flag_list mount_flags[] = {
	{ "noatime",          MS_NOATIME },
	{ "noexec",           MS_NOEXEC },
	{ "nosuid",           MS_NOSUID },
	{ "nodev",            MS_NODEV },
	{ "nodiratime",       MS_NODIRATIME },
	{ "ro",               MS_RDONLY },
	{ "rw",               0 },
	{ "remount",          MS_REMOUNT },
	{ "bind",             MS_BIND },
	{ "rec",              MS_REC },
#ifdef MS_UNBINDABLE
	{ "unbindable",       MS_UNBINDABLE },
#endif
#ifdef MS_PRIVATE
	{ "private",          MS_PRIVATE },
#endif
#ifdef MS_SLAVE
	{ "slave",            MS_SLAVE },
#endif
#ifdef MS_SHARED
	{ "shared",           MS_SHARED },
#endif
	{ "sync",             MS_SYNCHRONOUS },
	{ 0,                  0 },
};

const char *ignored_mount_items[] = {
	"defaults=",
	"errors=",
	"latemount",
	"sysfs_path=",
	NULL
};

enum TW_FSTAB_FLAGS {
	TWFLAG_DEFAULTS, // Retain position
	TWFLAG_ANDSEC,
	TWFLAG_BACKUP,
	TWFLAG_BACKUPNAME,
	TWFLAG_BLOCKSIZE,
	TWFLAG_CANBEWIPED,
	TWFLAG_CANENCRYPTBACKUP,
	TWFLAG_DISPLAY,
	TWFLAG_ENCRYPTABLE,
	TWFLAG_FILEENCRYPTION,
	TWFLAG_METADATA_ENCRYPTION,
	TWFLAG_FLASHIMG,
	TWFLAG_FORCEENCRYPT,
	TWFLAG_FSFLAGS,
	TWFLAG_IGNOREBLKID,
	TWFLAG_LENGTH,
	TWFLAG_MOUNTTODECRYPT,
	TWFLAG_QUOTA,
	TWFLAG_REMOVABLE,
	TWFLAG_SETTINGSSTORAGE,
	TWFLAG_STORAGE,
	TWFLAG_STORAGENAME,
	TWFLAG_SUBPARTITIONOF,
	TWFLAG_SYMLINK,
	TWFLAG_USERDATAENCRYPTBACKUP,
	TWFLAG_USERMRF,
	TWFLAG_WIPEDURINGFACTORYRESET,
	TWFLAG_WIPEINGUI,
	TWFLAG_SLOTSELECT,
	TWFLAG_WAIT,
	TWFLAG_VERIFY,
	TWFLAG_CHECK,
	TWFLAG_ALTDEVICE,
	TWFLAG_NOTRIM,
	TWFLAG_VOLDMANAGED,
	TWFLAG_FORMATTABLE,
	TWFLAG_RESIZE,
	TWFLAG_KEYDIRECTORY,
	TWFLAG_WRAPPEDKEY,
	TWFLAG_ADOPTED_MOUNT_DELAY,
	TWFLAG_DM_USE_ORIGINAL_PATH,
	TWFLAG_FS_COMPRESS,
	TWFLAG_LOGICAL,
};

/* Flags without a trailing '=' are considered dual format flags and can be
 * written as either 'flagname' or 'flagname=', where the character following
 * the '=' is Y,y,1 for true and false otherwise.
 */
const struct flag_list tw_flags[] = {
	{ "andsec",                 TWFLAG_ANDSEC },
	{ "backup",                 TWFLAG_BACKUP },
	{ "backupname=",            TWFLAG_BACKUPNAME },
	{ "blocksize=",             TWFLAG_BLOCKSIZE },
	{ "canbewiped",             TWFLAG_CANBEWIPED },
	{ "canencryptbackup",       TWFLAG_CANENCRYPTBACKUP },
	{ "defaults",               TWFLAG_DEFAULTS },
	{ "display=",               TWFLAG_DISPLAY },
	{ "encryptable=",           TWFLAG_ENCRYPTABLE },
	{ "fileencryption=",        TWFLAG_FILEENCRYPTION },
	{ "metadata_encryption=",   TWFLAG_METADATA_ENCRYPTION },
	{ "flashimg",               TWFLAG_FLASHIMG },
	{ "forceencrypt=",          TWFLAG_FORCEENCRYPT },
	{ "fsflags=",               TWFLAG_FSFLAGS },
	{ "ignoreblkid",            TWFLAG_IGNOREBLKID },
	{ "length=",                TWFLAG_LENGTH },
	{ "mounttodecrypt",         TWFLAG_MOUNTTODECRYPT },
	{ "quota",                  TWFLAG_QUOTA },
	{ "removable",              TWFLAG_REMOVABLE },
	{ "settingsstorage",        TWFLAG_SETTINGSSTORAGE },
	{ "storage",                TWFLAG_STORAGE },
	{ "storagename=",           TWFLAG_STORAGENAME },
	{ "subpartitionof=",        TWFLAG_SUBPARTITIONOF },
	{ "symlink=",               TWFLAG_SYMLINK },
	{ "userdataencryptbackup",  TWFLAG_USERDATAENCRYPTBACKUP },
	{ "usermrf",                TWFLAG_USERMRF },
	{ "wipeduringfactoryreset", TWFLAG_WIPEDURINGFACTORYRESET },
	{ "wipeingui",              TWFLAG_WIPEINGUI },
	{ "slotselect",             TWFLAG_SLOTSELECT },
	{ "wait",                   TWFLAG_WAIT },
	{ "verify",                 TWFLAG_VERIFY },
	{ "check",                  TWFLAG_CHECK },
	{ "altdevice",              TWFLAG_ALTDEVICE },
	{ "notrim",                 TWFLAG_NOTRIM },
	{ "voldmanaged=",           TWFLAG_VOLDMANAGED },
	{ "formattable",            TWFLAG_FORMATTABLE },
	{ "resize",                 TWFLAG_RESIZE },
	{ "keydirectory=",          TWFLAG_KEYDIRECTORY },
	{ "wrappedkey",             TWFLAG_WRAPPEDKEY },
	{ "adopted_mount_delay=",   TWFLAG_ADOPTED_MOUNT_DELAY },
	{ "dm_use_original_path",   TWFLAG_DM_USE_ORIGINAL_PATH },
	{ "fscompress",             TWFLAG_FS_COMPRESS },
	{ "logical",                TWFLAG_LOGICAL },
	{ 0,                        0 },
};

TWPartition::TWPartition() {
	Can_Be_Mounted = false;
	Can_Be_Wiped = false;
	Can_Be_Backed_Up = false;
	Use_Rm_Rf = false;
	Wipe_During_Factory_Reset = false;
	Wipe_Available_in_GUI = false;
	Is_SubPartition = false;
	Has_SubPartition = false;
	SubPartition_Of = "";
	Symlink_Path = "";
	Symlink_Mount_Point = "";
	Mount_Point = "";
	Backup_Path = "";
	Wildcard_Block_Device = false;
	Sysfs_Entry = "";
	Actual_Block_Device = "";
	Primary_Block_Device = "";
	Alternate_Block_Device = "";
	Removable = false;
	Is_Present = false;
	Length = 0;
	Size = 0;
	Used = 0;
	Free = 0;
	Backup_Size = 0;
	Restore_Size = 0;   // close a latent uninit: loop 1 (Get_Restore_Size) sets it before Restore_Tar; the 0-init makes the cache guard in Restore_Tar watertight
	Can_Be_Encrypted = false;
	Is_Encrypted = false;
	Is_Decrypted = false;
	Is_FBE = false;
	Mount_To_Decrypt = false;
	Decrypted_Block_Device = "";
	Display_Name = "";
	Backup_Display_Name = "";
	Storage_Name = "";
	Backup_Name = "";
	Backup_FileName = "";
	MTD_Name = "";
	Backup_Method = BM_NONE;
	Can_Encrypt_Backup = false;
	Use_Userdata_Encryption = false;
	Has_Data_Media = false;
	Has_Android_Secure = false;
	Is_Storage = false;
	Is_Settings_Storage = false;
	Storage_Path = "";
	Current_File_System = "";
	Fstab_File_System = "";
	Mount_Flags = 0;
	Mount_Options = "";
	Format_Block_Size = 0;
	Ignore_Blkid = false;
	Crypto_Key_Location = "";
	MTP_Storage_ID = 0;
	Can_Flash_Img = false;
	Mount_Read_Only = false;
	Is_Adopted_Storage = false;
	Adopted_GUID = "";
	SlotSelect = false;
	Key_Directory = "";
	Is_Super = false;
	Adopted_Mount_Delay = 0;
	Original_Path = "";
	Use_Original_Path = false;
	Needs_Fs_Compress = false;
}

TWPartition::~TWPartition(void) {
	// Do nothing
}

bool TWPartition::Process_Fstab_Line(const char *fstab_line, bool Display_Error, std::map<string, Flags_Map> *twrp_flags) {
	char full_line[MAX_FSTAB_LINE_LENGTH];
	char twflags[MAX_FSTAB_LINE_LENGTH] = "";
	char* ptr;
	int line_len = strlen(fstab_line), index = 0, item_index = 0;
	bool skip = false;
	int fstab_version = 1, mount_point_index = 0, fs_index = 1, block_device_index = 2;
	TWPartition *additional_entry = NULL;
	std::map<string, Flags_Map>::iterator it;

	strlcpy(full_line, fstab_line, sizeof(full_line));

	for (index = 0; index < line_len; index++) {
		if (full_line[index] == 34)
			skip = !skip;
		if (!skip && full_line[index] <= 32)
			full_line[index] = '\0';
	}
	if (line_len < 10)
		return false; // There can't possibly be a valid fstab line that is less than 10 chars
	if (fstab_line[0] == '#')
		return false; // skip comments

	if (strncmp(fstab_line, "/dev/", strlen("/dev/")) == 0 || strncmp(fstab_line, "/devices/", strlen("/devices/")) == 0) {
		fstab_version = 2;
		block_device_index = 0;
		mount_point_index = 1;
		fs_index = 2;
	}

	if (fstab_line[0] != '/') {
		block_device_index = 0;
		fstab_version = 2;
		mount_point_index = 1;
		fs_index = 2;
	}

	index = 0;
	while (index < line_len) {
		while (index < line_len && full_line[index] == '\0')
			index++;
		if (index >= line_len)
			continue;
		ptr = full_line + index;
		if (item_index == mount_point_index) {
			Mount_Point = ptr;
			if (fstab_version == 2 && Is_Super == false) {
				additional_entry = PartitionManager.Find_Partition_By_Path(Mount_Point);
				if (additional_entry) {
					LOGINFO("Found an additional entry for '%s'\n", Mount_Point.c_str());
				}
			}
			LOGINFO("Processing '%s'\n", Mount_Point.c_str());
			Backup_Path = Mount_Point;
			Storage_Path = Mount_Point;
			Display_Name = ptr + 1;
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
			item_index++;
		} else if (item_index == fs_index) {
			// File System
			Fstab_File_System = ptr;
			Current_File_System = ptr;
			item_index++;
		} else if (item_index == block_device_index) {
			// Primary Block Device
			if (Fstab_File_System == "mtd" || Fstab_File_System == "yaffs2") {
				MTD_Name = ptr;
				Find_MTD_Block_Device(MTD_Name);
			} else if (Fstab_File_System == "bml") {
				if (Mount_Point == "/boot")
					MTD_Name = "boot";
				else if (Mount_Point == "/recovery")
					MTD_Name = "recovery";
				Primary_Block_Device = ptr;
				if (*ptr != '/')
					LOGERR("Until we get better BML support, you will have to find and provide the full block device path to the BML devices e.g. /dev/block/bml9 instead of the partition name\n");
			} else {
				Primary_Block_Device = ptr;
				if (*ptr == '/')
					Find_Real_Block_Device(Primary_Block_Device, Display_Error);
			}
			item_index++;
		} else if (item_index > 2) {
			if (fstab_version == 2) {
				if (item_index == 3) {
					Process_FS_Flags(ptr);
					if (additional_entry) {
						additional_entry->Save_FS_Flags(Fstab_File_System, Mount_Flags, Mount_Options);
						return false; // We save the extra fs flags in the other partition entry and by returning false, this entry will be deleted
					}
				} else {
					strlcpy(twflags, ptr, sizeof(twflags));
				}
				item_index++;
			} else if (*ptr == '/') { // v2 fstab does not allow alternate block devices
				// Alternate Block Device
				Alternate_Block_Device = ptr;
				Find_Real_Block_Device(Alternate_Block_Device, Display_Error);
			} else if (strlen(ptr) > 7 && strncmp(ptr, "length=", 7) == 0) {
				// Partition length
				ptr += 7;
				Length = atoi(ptr);
			} else if (strlen(ptr) > 6 && strncmp(ptr, "flags=", 6) == 0) {
				// Custom flags, save for later so that new values aren't overwritten by defaults
				ptr += 6;
				strlcpy(twflags, ptr, sizeof(twflags));
			} else if (strlen(ptr) == 4 && (strncmp(ptr, "NULL", 4) == 0 || strncmp(ptr, "null", 4) == 0 || strncmp(ptr, "null", 4) == 0)) {
				// Do nothing
			} else {
				// Unhandled data
				LOGINFO("Unhandled fstab information '%s' in fstab line '%s'\n", ptr, fstab_line);
			}
		}
		while (index < line_len && full_line[index] != '\0')
			index++;
	}

	// override block devices from the v2 fstab with the ones we read from the twrp.flags file in case they are different
	if (fstab_version == 2 && twrp_flags && twrp_flags->size() > 0) {
		it = twrp_flags->find(Mount_Point);
		if (it != twrp_flags->end()) {
			if (!it->second.Primary_Block_Device.empty()) {
				Primary_Block_Device = it->second.Primary_Block_Device;
				Find_Real_Block_Device(Primary_Block_Device, Display_Error);
			}
			if (!it->second.Alternate_Block_Device.empty()) {
				Alternate_Block_Device = it->second.Alternate_Block_Device;
				Find_Real_Block_Device(Alternate_Block_Device, Display_Error);
			}
		}
	}

	if (strncmp(fstab_line, "/devices/", strlen("/devices/")) == 0) {
		Sysfs_Entry = Primary_Block_Device;
		Primary_Block_Device = "";
		Is_Storage = true;
		Removable = true;
		Wipe_Available_in_GUI = true;
		Wildcard_Block_Device = true;
	}
	if (Primary_Block_Device.find("*") != string::npos)
		Wildcard_Block_Device = true;

	if (Mount_Point == "auto") {
		Mount_Point = "/auto";
		char autoi[5];
		sprintf(autoi, "%i", auto_index);
		Mount_Point += autoi;
		Backup_Path = Mount_Point;
		Storage_Path = Mount_Point;
		Backup_Name = Mount_Point.substr(1);
		auto_index++;
		Setup_File_System(Display_Error);
		Display_Name = "Storage";
		Backup_Display_Name = Display_Name;
		Storage_Name = Display_Name;
		Can_Be_Backed_Up = false;
		Wipe_Available_in_GUI = true;
		Is_Storage = true;
		Removable = true;
		Wipe_Available_in_GUI = true;
	} else if (!Is_File_System(Fstab_File_System) && !Is_Image(Fstab_File_System)) {
		if (Display_Error)
			LOGERR("Unknown File System: '%s'\n", Fstab_File_System.c_str());
		else
			LOGINFO("Unknown File System: '%s'\n", Fstab_File_System.c_str());
		return false;
	} else if (Is_File_System(Fstab_File_System)) {
		Find_Actual_Block_Device();
		Setup_File_System(Display_Error);
		Backup_Name = Display_Name = Mount_Point.substr(1, Mount_Point.size() - 1);
		if (Mount_Point == "/" || Mount_Point == "/system" || Mount_Point == "/system_root") {
			Mount_Point = PartitionManager.Get_Android_Root_Path();
			Backup_Path = Mount_Point;
			Storage_Path = Mount_Point;
			Display_Name = "System";
			Backup_Name = "system";
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
			Wipe_Available_in_GUI = false;
			Can_Be_Backed_Up = false;
			Can_Be_Wiped = false;
			Make_Dir(PartitionManager.Get_Android_Root_Path(), true);
		} else if (Mount_Point == "/system_ext") {
			Display_Name = "System_EXT";
			Backup_Name = "System_EXT";
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
			Can_Be_Backed_Up = Wipe_Available_in_GUI = Is_Super ? false : true;
		} else if (Mount_Point == "/product") {
			Display_Name = "Product";
			Backup_Name = "Product";
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
			Can_Be_Backed_Up = Wipe_Available_in_GUI = Is_Super ? false : true;
		} else if (Mount_Point == "/odm") {
			Display_Name = "ODM";
			Backup_Name = "ODM";
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
			Can_Be_Backed_Up = Wipe_Available_in_GUI = Is_Super ? false : true;
		} else if (Mount_Point == "/data") {
			Display_Name = "Data";
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
			Wipe_Available_in_GUI = true;
			Wipe_During_Factory_Reset = true;
			Can_Be_Backed_Up = true;
			Can_Encrypt_Backup = true;
			Use_Userdata_Encryption = true;
		} else if (Mount_Point == "/cache") {
			Display_Name = "Cache";
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
			Wipe_Available_in_GUI = true;
			Wipe_During_Factory_Reset = true;
			Can_Be_Backed_Up = true;
		} else if (Mount_Point == "/datadata") {
			Wipe_During_Factory_Reset = true;
			Display_Name = "DataData";
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
			Is_SubPartition = true;
			SubPartition_Of = "/data";
			DataManager::SetValue(TW_HAS_DATADATA, 1);
			Can_Be_Backed_Up = true;
			Can_Encrypt_Backup = true;
			Use_Userdata_Encryption = false; // This whole partition should be encrypted
		} else if (Mount_Point == "/sd-ext") {
			Wipe_During_Factory_Reset = true;
			Display_Name = "SD-Ext";
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
			Wipe_Available_in_GUI = true;
			Removable = true;
			Can_Be_Backed_Up = true;
			Can_Encrypt_Backup = true;
			Use_Userdata_Encryption = true;
		} else if (Mount_Point == "/boot") {
			Display_Name = "Boot";
			Backup_Display_Name = Display_Name;
			DataManager::SetValue("tw_boot_is_mountable", 1);
			Can_Be_Backed_Up = true;
		} else if (Mount_Point == "/vendor") {
			Display_Name = "Vendor";
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
		} else if (Mount_Point == "/metadata") {
			Display_Name = "Metadata";
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
		} else if (Mount_Point == "/odm_dlkm") {
			Display_Name = "ODM DLKM";
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
		} else if (Mount_Point == "/vendor_dlkm") {
			Display_Name = "Vendor DLKM";
			Backup_Display_Name = Display_Name;
			Storage_Name = Display_Name;
		}
#ifdef TW_EXTERNAL_STORAGE_PATH
		if (Mount_Point == EXPAND(TW_EXTERNAL_STORAGE_PATH)) {
			Is_Storage = true;
			Storage_Path = EXPAND(TW_EXTERNAL_STORAGE_PATH);
			Removable = true;
			Wipe_Available_in_GUI = true;
#else
		if (Mount_Point == "/sdcard" || Mount_Point == "/external_sd" || Mount_Point == "/external_sdcard") {
			Is_Storage = true;
			Removable = true;
			Wipe_Available_in_GUI = true;
#endif
		}
#ifdef TW_INTERNAL_STORAGE_PATH
		if (Mount_Point == EXPAND(TW_INTERNAL_STORAGE_PATH)) {
			Is_Storage = true;
			Is_Settings_Storage = true;
			Storage_Path = EXPAND(TW_INTERNAL_STORAGE_PATH);
			Wipe_Available_in_GUI = true;
		}
#else
		if (Mount_Point == "/emmc" || Mount_Point == "/internal_sd" || Mount_Point == "/internal_sdcard") {
			Is_Storage = true;
			Is_Settings_Storage = true;
			Wipe_Available_in_GUI = true;
		}
#endif
	} else if (Is_Image(Fstab_File_System)) {
		Find_Actual_Block_Device();
		Setup_Image();
		if (Mount_Point == "/boot") {
			Display_Name = "Boot";
			Backup_Display_Name = Display_Name;
			Can_Be_Backed_Up = true;
			Can_Flash_Img = true;
		} else if (Mount_Point == "/init_boot") {
			Display_Name = "Init Boot";
			Backup_Display_Name = Display_Name;
			Can_Be_Backed_Up = true;
			Can_Flash_Img = true;
		} else if (Mount_Point == "/recovery") {
			Display_Name = "Recovery";
			Backup_Display_Name = Display_Name;
			Can_Flash_Img = true;
		} else if (Mount_Point == "/system_image") {
			Display_Name = "System Image";
			Backup_Display_Name = Display_Name;
			Can_Flash_Img = true;
			Can_Be_Backed_Up = true;
		} else if (Mount_Point == "/vendor_image") {
			Display_Name = "Vendor Image";
			Backup_Display_Name = Display_Name;
			Can_Flash_Img = true;
			Can_Be_Backed_Up = true;
		}
	}

	// Process TWRP fstab flags
	if (strlen(twflags) > 0) {
		string Prev_Display_Name = Display_Name;
		string Prev_Storage_Name = Storage_Name;
		string Prev_Backup_Display_Name = Backup_Display_Name;
		Display_Name = "";
		Storage_Name = "";
		Backup_Display_Name = "";

		Process_TW_Flags(twflags, (fstab_version == 1), fstab_version);
		Save_FS_Flags(Fstab_File_System, Mount_Flags, Mount_Options);

		bool has_display_name = !Display_Name.empty();
		bool has_storage_name = !Storage_Name.empty();
		bool has_backup_name = !Backup_Display_Name.empty();
		if (!has_display_name) Display_Name = Prev_Display_Name;
		if (!has_storage_name) Storage_Name = Prev_Storage_Name;
		if (!has_backup_name) Backup_Display_Name = Prev_Backup_Display_Name;

		if (has_display_name && !has_storage_name)
			Storage_Name = Display_Name;
		if (!has_display_name && has_storage_name)
			Display_Name = Storage_Name;
		if (has_display_name && !has_backup_name && Backup_Display_Name != "Android Secure")
			Backup_Display_Name = Display_Name;
		if (!has_display_name && has_backup_name)
			Display_Name = Backup_Display_Name;
	}

	if (fstab_version == 2 && twrp_flags && twrp_flags->size() > 0) {
		it = twrp_flags->find(Mount_Point);
		if (it != twrp_flags->end()) {
			char twrpflags[MAX_FSTAB_LINE_LENGTH] = "";
			int skip = 0;
			string Flags = it->second.Flags;
			strcpy(twrpflags, Flags.c_str());
			if (strlen(twrpflags) > strlen("flags=") && strncmp(twrpflags, "flags=", strlen("flags=")) == 0)
				skip += strlen("flags=");
			char* flagptr = twrpflags;
			flagptr += skip;
			Process_TW_Flags(flagptr, Display_Error, 1); // Forcing the fstab to ver 1 because this data is coming from the /etc/twrp.flags which should be using the TWRP v1 flags format
		}
	}

	if (Mount_Point == "/persist" && Can_Be_Mounted) {
		bool mounted = Is_Mounted();
		if (mounted || Mount(false)) {
			TWFunc::Fixup_Time_On_Boot("/persist/time/");
			if (!mounted)
				UnMount(false);
		}
	}

	return true;
}

void TWPartition::Partition_Post_Processing(bool Display_Error) {
	if (Mount_Point == "/data")
		Setup_Data_Partition(Display_Error);
	else if (Mount_Point == "/cache")
		Setup_Cache_Partition(Display_Error);
}

void TWPartition::ExcludeAll(const string& path) {
	backup_exclusions.add_absolute_dir(path);
	wipe_exclusions.add_absolute_dir(path);
}

void TWPartition::Setup_Data_Partition(bool Display_Error) {
	if (Mount_Point != "/data")
		return;

	// Ensure /data is not mounted as tmpfs for qcom hardware decrypt
	UnMount(false);

#ifdef TW_INCLUDE_CRYPTO
	#ifdef TW_PREPARE_DATA_MEDIA_EARLY
	if (datamedia)
		Setup_Data_Media();
	#endif
	Can_Be_Encrypted = true;
	char crypto_blkdev[255];
	property_get("ro.crypto.fs_crypto_blkdev", crypto_blkdev, "error");
	if (strcmp(crypto_blkdev, "error") != 0) {
		Set_FBE_Status();
		Decrypted_Block_Device = crypto_blkdev;
		LOGINFO("Data already decrypted, new block device: '%s'\n", crypto_blkdev);
		#ifndef TW_PREPARE_DATA_MEDIA_EARLY
		if (datamedia)
			Setup_Data_Media();
		#endif
		DataManager::SetValue(TW_IS_ENCRYPTED, 0);
	} else if (!Mount(false)) {
		if (Is_Present) {
			if (Key_Directory.empty()) {
				set_partition_data(Use_Original_Path ? Original_Path.c_str() : Actual_Block_Device.c_str(), Crypto_Key_Location.c_str(),
				Fstab_File_System.c_str());
				if (cryptfs_check_footer() == 0) {
					Is_Encrypted = true;
					Is_Decrypted = false;
					Can_Be_Mounted = false;
					Current_File_System = "emmc";
					Setup_Image();
					DataManager::SetValue(TW_CRYPTO_PWTYPE, cryptfs_get_password_type());
					DataManager::SetValue("tw_crypto_pwtype_0", cryptfs_get_password_type());
					DataManager::SetValue(TW_CRYPTO_PASSWORD, "");
					DataManager::SetValue("tw_crypto_display", "");
					if (datamedia)
						Setup_Data_Media();
				} else {
					gui_err("mount_data_footer=Could not mount /data and unable to find crypto footer.");
				}
			} else {
				Is_Encrypted = true;
				Is_Decrypted = false;
				if (datamedia)
					Setup_Data_Media();
			}
		} else if (Key_Directory.empty()) {
			LOGERR("Primary block device '%s' for mount point '%s' is not present!\n",
			Primary_Block_Device.c_str(), Mount_Point.c_str());
		}
	} else {
		Set_FBE_Status();
		int is_device_fbe;
		DataManager::GetValue(TW_IS_FBE, is_device_fbe);
		char crypto_state[255];
		property_get("ro.crypto.state", crypto_state, "error");
		if (!Decrypt_FBE_DE() && strcmp(crypto_state, "error") != 0) {
			if (is_device_fbe == 1)
				LOGERR("Unable to decrypt FBE device\n");
		} else {
			DataManager::SetValue(TW_IS_ENCRYPTED, 0);
			#ifndef TW_PREPARE_DATA_MEDIA_EARLY
			if (datamedia)
				Setup_Data_Media();
			#endif
		}
	}
	if (datamedia && (!Is_Encrypted || (Is_Encrypted && Is_Decrypted))) {
		Setup_Data_Media();
		Recreate_Media_Folder();
	}
#else
	if (datamedia) {
		Setup_Data_Media();
		Recreate_Media_Folder();
	}
#endif
}

void TWPartition::Set_FBE_Status() {
	DataManager::SetValue(TW_IS_DECRYPTED, 1);
	Is_Encrypted = true;
	Is_Decrypted = true;
	if (Key_Directory.empty()) {
		Is_FBE = false;
		DataManager::SetValue(TW_IS_FBE, 0);
	} else {
		LOGINFO("Setup_Data_Partition::Key_Directory::%s\n", Key_Directory.c_str());
		Is_FBE = true;
		DataManager::SetValue(TW_IS_FBE, 1);
	}
}

bool TWPartition::Decrypt_FBE_DE() {
	if (TWFunc::Path_Exists("/data/unencrypted/key/version")) {
		DataManager::SetValue(TW_IS_FBE, 1);
		PartitionManager.Set_Crypto_State();
		PartitionManager.Set_Crypto_Type("file");
		LOGINFO("File Based Encryption is present\n");
#ifdef TW_INCLUDE_FBE
	Is_FBE = true;
	ExcludeAll(Mount_Point + "/convert_fbe");
	ExcludeAll(Mount_Point + "/unencrypted");
	ExcludeAll(Mount_Point + "/misc/vold/user_keys");
	ExcludeAll(Mount_Point + "/misc/vold/volume_keys");
	ExcludeAll(Mount_Point + "/system/gatekeeper.password.key");
	ExcludeAll(Mount_Point + "/system/gatekeeper.pattern.key");
	ExcludeAll(Mount_Point + "/system/locksettings.db");
	ExcludeAll(Mount_Point + "/system/locksettings.db-wal");
	ExcludeAll(Mount_Point + "/system/locksettings.db-shm");
	ExcludeAll(Mount_Point + "/misc/gatekeeper");
	ExcludeAll(Mount_Point + "/misc/keystore");
	ExcludeAll(Mount_Point + "/drm/kek.dat");
	ExcludeAll(Mount_Point + "/system_de/0/spblob");  // contains data needed to decrypt synthetic password
	ExcludeAll(Mount_Point + "/system/users/0/gatekeeper.password.key");
	ExcludeAll(Mount_Point + "/system/users/0/gatekeeper.pattern.key");
	ExcludeAll(Mount_Point + "/cache");
	ExcludeAll(Mount_Point + "/per_boot"); // removed each boot by init
	ExcludeAll(Mount_Point + "/gsi"); // cow devices

	int retry_count = 3;
	while (!Decrypt_DE() && --retry_count)
		usleep(2000);
	if (retry_count > 0) {
		PartitionManager.Set_Crypto_State();
		Is_Encrypted = true;
		Is_Decrypted = false;
		DataManager::SetValue(TW_IS_ENCRYPTED, 1);
		string filename;
		int pwd_type = Get_Password_Type(0, filename);
		if (pwd_type < 0) {
			LOGERR("This TWRP does not have synthetic password decrypt support\n");
			pwd_type = 0;  // default password
		}
		PartitionManager.Parse_Users();  // after load_all_de_keys() to parse_users
		std::vector<users_struct>::iterator iter;
		std::vector<users_struct>* userList = PartitionManager.Get_Users_List();
		for (iter = userList->begin(); iter != userList->end(); iter++) {
			if (atoi((*iter).userId.c_str()) != 0) {
				ExcludeAll(Mount_Point + "/system_de/" + (*iter).userId + "/spblob");
				ExcludeAll(Mount_Point + "/system/users/" + (*iter).userId + "/gatekeeper.password.key");
				ExcludeAll(Mount_Point + "/system/users/" + (*iter).userId + "/gatekeeper.pattern.key");
				ExcludeAll(Mount_Point + "/system/users/" + (*iter).userId + "/locksettings.db");
				ExcludeAll(Mount_Point + "/system/users/" + (*iter).userId + "/locksettings.db-wal");
				ExcludeAll(Mount_Point + "/system/users/" + (*iter).userId + "/locksettings.db-shm");
			}
		}
		DataManager::SetValue(TW_CRYPTO_PWTYPE, pwd_type);
		DataManager::SetValue("tw_crypto_pwtype_0", pwd_type);
		DataManager::SetValue(TW_CRYPTO_PASSWORD, "");
		DataManager::SetValue("tw_crypto_display", "");
		return true;
	}
#else
		LOGERR("FBE found but FBE support not present in TWRP\n");
#endif
	}
	DataManager::SetValue(TW_IS_FBE, 0);
	return false;
}

void TWPartition::Setup_Cache_Partition(bool Display_Error __unused) {
	if (Mount_Point != "/cache")
		return;

	if (!Mount(true))
		return;

	if (!TWFunc::Path_Exists("/cache/recovery/.")) {
		LOGINFO("Recreating /cache/recovery folder\n");
		if (mkdir("/cache/recovery", S_IRWXU | S_IRWXG | S_IWGRP | S_IXGRP) != 0)
			LOGERR("Could not create /cache/recovery\n");
	}
}

void TWPartition::Process_FS_Flags(const char *str) {
	char *options = strdup(str);
	char *ptr, *savep;

	Mount_Options = "";

	// Avoid issues with potentially nested strtok by using strtok_r
	for (ptr = strtok_r(options, ",", &savep); ptr; ptr = strtok_r(NULL, ",", &savep)) {
		char *equals = strstr(ptr, "=");
		size_t name_len;

		if (!equals)
			name_len = strlen(ptr);
		else
			name_len = equals - ptr;

		// There are some flags that we want to ignore in TWRP
		bool found_match = false;
		for (const char** ignored_mount_item = ignored_mount_items; *ignored_mount_item; ignored_mount_item++) {
			if (strncmp(ptr, *ignored_mount_item, name_len) == 0) {
				found_match = true;
				break;
			}
		}
		if (found_match)
			continue;

		// mount_flags are never postfixed by '='
		if (!equals) {
			const struct flag_list* mount_flag = mount_flags;
			for (; mount_flag->name; mount_flag++) {
				if (strcmp(ptr, mount_flag->name) == 0) {
					if (mount_flag->flag == MS_RDONLY)
						Mount_Read_Only = true;
					else
						Mount_Flags |= (unsigned)mount_flag->flag;
					found_match = true;
					break;
				}
			}
			if (found_match)
				continue;
		}

		// If we aren't ignoring this flag and it's not a mount flag, then it must be a mount option
		if (!Mount_Options.empty())
			Mount_Options += ",";
		Mount_Options += ptr;
	}
	free(options);
}

void TWPartition::Save_FS_Flags(const string& local_File_System, int local_Mount_Flags, const string& local_Mount_Options) {
	partition_fs_flags_struct flags;
	flags.File_System = local_File_System;
	flags.Mount_Flags = local_Mount_Flags;
	flags.Mount_Options = local_Mount_Options;
	fs_flags.push_back(flags);
}

void TWPartition::Apply_TW_Flag(const unsigned flag, const char* str, const bool val) {
	switch (flag) {
		case TWFLAG_ANDSEC:
			Has_Android_Secure = val;
			break;
		case TWFLAG_BACKUP:
			Can_Be_Backed_Up = val;
			break;
		case TWFLAG_BACKUPNAME:
			Backup_Display_Name = str;
			break;
		case TWFLAG_BLOCKSIZE:
			Format_Block_Size = (unsigned long)(atol(str));
			break;
		case TWFLAG_CANBEWIPED:
			Can_Be_Wiped = val;
			break;
		case TWFLAG_CANENCRYPTBACKUP:
			Can_Encrypt_Backup = val;
			break;
		case TWFLAG_DEFAULTS:
		case TWFLAG_WAIT:
		case TWFLAG_VERIFY:
		case TWFLAG_CHECK:
		case TWFLAG_NOTRIM:
		case TWFLAG_VOLDMANAGED:
		case TWFLAG_RESIZE:
			// Do nothing
			break;
		case TWFLAG_DISPLAY:
			Display_Name = str;
			break;
		case TWFLAG_ENCRYPTABLE:
		case TWFLAG_FORCEENCRYPT:
			Crypto_Key_Location = str;
			break;
		case TWFLAG_FILEENCRYPTION:
			// This flag isn't used by TWRP but is needed in 9.0 FBE decrypt
			// fileencryption=ice:aes-256-heh
			{
				std::string FBE = str;
				size_t colon_loc = FBE.find(":");
				if (colon_loc == std::string::npos) {
					property_set("fbe.contents", FBE.c_str());
					property_set("fbe.filenames", "");
					LOGINFO("FBE contents '%s', filenames ''\n", FBE.c_str());
					break;
				}
				std::string FBE_contents, FBE_filenames;
				FBE_contents = FBE.substr(0, colon_loc);
				FBE_filenames = FBE.substr(colon_loc + 1);
				property_set("fbe.contents", FBE_contents.c_str());
				property_set("fbe.filenames", FBE_filenames.c_str());
				LOGINFO("FBE contents '%s', filenames '%s'\n", FBE_contents.c_str(), FBE_filenames.c_str());
			}
			break;
		case TWFLAG_METADATA_ENCRYPTION:
			// This flag isn't used by TWRP but is needed for FBEv2 metadata decryption
			// metadata_encryption=aes-256-xts:wrappedkey_v0
			{
				std::string META = str;
				size_t colon_loc = META.find(":");
				if (colon_loc == std::string::npos) {
					property_set("metadata.contents", META.c_str());
					property_set("metadata.filenames", "");
					LOGINFO("Metadata contents '%s', filenames ''\n", META.c_str());
					break;
				}
				std::string META_contents, META_filenames;
				META_contents = META.substr(0, colon_loc);
				META_filenames = META.substr(colon_loc + 1);
				property_set("metadata.contents", META_contents.c_str());
				property_set("metadata.filenames", META_filenames.c_str());
				LOGINFO("Metadata contents '%s', filenames '%s'\n", META_contents.c_str(), META_filenames.c_str());
			}
			break;
		case TWFLAG_WRAPPEDKEY:
			// no more processing needed. leaving it here in case we want to do something in the future
			break;
		case TWFLAG_FLASHIMG:
			Can_Flash_Img = val;
			break;
		case TWFLAG_FSFLAGS:
			Process_FS_Flags(str);
			break;
		case TWFLAG_IGNOREBLKID:
			Ignore_Blkid = val;
			break;
		case TWFLAG_LENGTH:
			Length = atoi(str);
			break;
		case TWFLAG_MOUNTTODECRYPT:
			Mount_To_Decrypt = val;
			break;
		case TWFLAG_QUOTA:
			// Filesystem flag - TWRP does not need to process
			break;
		case TWFLAG_REMOVABLE:
			Removable = val;
			break;
		case TWFLAG_SETTINGSSTORAGE:
			Is_Settings_Storage = val;
			if (Is_Settings_Storage)
				Is_Storage = true;
			break;
		case TWFLAG_STORAGE:
			Is_Storage = val;
			break;
		case TWFLAG_STORAGENAME:
			Storage_Name = str;
			break;
		case TWFLAG_SUBPARTITIONOF:
			Is_SubPartition = true;
			SubPartition_Of = str;
			break;
		case TWFLAG_SYMLINK:
			Symlink_Path = str;
			break;
		case TWFLAG_USERDATAENCRYPTBACKUP:
			Use_Userdata_Encryption = val;
			if (Use_Userdata_Encryption)
				Can_Encrypt_Backup = true;
			break;
		case TWFLAG_USERMRF:
			Use_Rm_Rf = val;
			break;
		case TWFLAG_WIPEDURINGFACTORYRESET:
			Wipe_During_Factory_Reset = val;
			if (Wipe_During_Factory_Reset) {
				Can_Be_Wiped = true;
				Wipe_Available_in_GUI = true;
			}
			break;
		case TWFLAG_WIPEINGUI:
		case TWFLAG_FORMATTABLE:
			Wipe_Available_in_GUI = val;
			if (Wipe_Available_in_GUI)
				Can_Be_Wiped = true;
			break;
		case TWFLAG_SLOTSELECT:
			SlotSelect = true;
			break;
		case TWFLAG_ALTDEVICE:
			Alternate_Block_Device = str;
			break;
		case TWFLAG_ADOPTED_MOUNT_DELAY:
			Adopted_Mount_Delay = atoi(str);
			break;
		case TWFLAG_KEYDIRECTORY:
			Key_Directory = str;
			LOGINFO("setting Key_Directory to: %s\n", Key_Directory.c_str());
			break;
		case TWFLAG_DM_USE_ORIGINAL_PATH:
			Use_Original_Path = true;
			break;
		case TWFLAG_LOGICAL:
			Is_Super = true;
			break;
		case TWFLAG_FS_COMPRESS:
			#ifdef TW_ENABLE_FS_COMPRESSION
				Needs_Fs_Compress = true;
				LOGINFO("Enabling 'fs compression'\n");
			#else
				LOGINFO("Ignoring the 'fscompress' fstab flag\n");
			#endif
			break;
		default:
			// Should not get here
			LOGINFO("Flag identified for processing, but later unmatched: %i\n", flag);
			break;
	}
}

void TWPartition::Process_TW_Flags(char *flags, bool Display_Error, int fstab_ver) {
	char separator[2] = {'\n', 0};
	char *ptr, *savep;
	char source_separator = ';';

	if (fstab_ver == 2)
		source_separator = ',';

	// Semicolons within double-quotes are not forbidden, so replace
	// only the semicolons intended as separators with '\n' for strtok
	for (unsigned i = 0, skip = 0; i < strlen(flags); i++) {
		if (flags[i] == '\"')
			skip = !skip;
		if (!skip && flags[i] == source_separator)
			flags[i] = separator[0];
	}

	// Avoid issues with potentially nested strtok by using strtok_r
	ptr = strtok_r(flags, separator, &savep);
	while (ptr) {
		int ptr_len = strlen(ptr);
		const struct flag_list* tw_flag = tw_flags;

		for (; tw_flag->name; tw_flag++) {
			int flag_len = strlen(tw_flag->name);

			if (strncmp(ptr, tw_flag->name, flag_len) == 0) {
				bool flag_val = false;

				if (ptr_len > flag_len && (tw_flag->name)[flag_len-1] != '='
						&& ptr[flag_len] != '=') {
					// Handle flags with same starting string
					// (e.g. backup and backupname)
					continue;
				} else if (ptr_len > flag_len && ptr[flag_len] == '=') {
					// Handle flags with dual format: Part 1
					// (e.g. backup and backup=y. backup=y handled here)
					ptr += flag_len + 1;
					TWFunc::Strip_Quotes(ptr);
					// Skip flags with empty argument
					// (e.g. backup=)
					if (strlen(ptr) == 0) {
						LOGINFO("Flag missing argument or should not include '=': %s=\n", tw_flag->name);
						break;
					}
					flag_val = strchr("yY1", *ptr) != NULL;
				} else if (ptr_len == flag_len
						&& (tw_flag->name)[flag_len-1] == '=') {
					// Skip flags missing argument after =
					// (e.g. backupname=)
					LOGINFO("Flag missing argument: %s\n", tw_flag->name);
					break;
				} else if (ptr_len > flag_len
						&& (tw_flag->name)[flag_len-1] == '=') {
					// Handle arguments to flags
					// (e.g. backupname="My Stuff")
					ptr += flag_len;
					TWFunc::Strip_Quotes(ptr);
					// Skip flags with empty argument
					// (e.g. backupname="")
					if (strlen(ptr) == 0) {
						LOGINFO("Flag missing argument: %s\n", tw_flag->name);
						break;
					}
				} else if (ptr_len == flag_len) {
					// Handle flags with dual format: Part 2
					// (e.g. backup and backup=y. backup handled here)
					flag_val = true;
				} else {
					LOGINFO("Flag matched, but could not be processed: %s\n", ptr);
					break;
				}

				Apply_TW_Flag(tw_flag->flag, ptr, flag_val);
				break;
			}
		}
		if (tw_flag->name == 0) {
			if (Display_Error)
				LOGERR("Unhandled flag: '%s'\n", ptr);
			else
				LOGINFO("Unhandled flag: '%s'\n", ptr);
		}
		ptr = strtok_r(NULL, separator, &savep);
	}
}

bool TWPartition::Is_File_System(string File_System) {
	if (File_System == "ext2" ||
		File_System == "ext3" ||
		File_System == "ext4" ||
		File_System == "vfat" ||
		File_System == "ntfs" ||
		File_System == "yaffs2" ||
		File_System == "exfat" ||
		File_System == "f2fs" ||
		File_System == "erofs" ||
		File_System == "squashfs" ||
		File_System == "auto")
		return true;
	else
		return false;
}

bool TWPartition::Is_Image(string File_System) {
	if (File_System == "emmc" || File_System == "mtd" || File_System == "bml")
		return true;
	else
		return false;
}

bool TWPartition::Make_Dir(string Path, bool Display_Error) {
	if (TWFunc::Get_D_Type_From_Stat(Path) != S_IFDIR)
		unlink(Path.c_str());
	if (!TWFunc::Path_Exists(Path)) {
		if (mkdir(Path.c_str(), 0777) == -1) {
			if (Display_Error)
				gui_msg(Msg(msg::kError, "create_folder_strerr=Can not create '{1}' folder ({2}).")(Path)(strerror(errno)));
			else
				LOGINFO("Can not create '%s' folder.\n", Path.c_str());
			return false;
		} else {
			LOGINFO("Created '%s' folder.\n", Path.c_str());
			return true;
		}
	}
	return true;
}

void TWPartition::Setup_File_System(bool Display_Error) {
	Can_Be_Mounted = true;
	Can_Be_Wiped = true;

	// Make the mount point folder if it doesn't exist
	Make_Dir(Mount_Point, Display_Error);
	Backup_Method = BM_FILES;
}

void TWPartition::Setup_Image() {
	Display_Name = Mount_Point.substr(1, Mount_Point.size() - 1);
	Backup_Name = Display_Name;
	if (Current_File_System == "emmc")
		Backup_Method = BM_DD;
	else if (Current_File_System == "mtd" || Current_File_System == "bml")
		Backup_Method = BM_FLASH_UTILS;
	else
		LOGINFO("Unhandled file system '%s' on image '%s'\n", Current_File_System.c_str(), Display_Name.c_str());
}

void TWPartition::Setup_AndSec(void) {
	Backup_Display_Name = "Android Secure";
	Backup_Name = "and-sec";
	Can_Be_Backed_Up = true;
	Has_Android_Secure = true;
	Symlink_Path = Mount_Point + "/.android_secure";
	Symlink_Mount_Point = "/and-sec";
	Backup_Path = Symlink_Mount_Point;
	Make_Dir("/and-sec", true);
	Recreate_AndSec_Folder();
	Mount_Storage_Retry(true);
}

void TWPartition::Setup_Data_Media() {
	LOGINFO("Setting up '%s' as data/media emulated storage.\n", Mount_Point.c_str());
	if (Storage_Name.empty() || Storage_Name == "Data")
		Storage_Name = "Internal Storage";
	Has_Data_Media = true;
	Is_Storage = true;
	Storage_Path = Mount_Point + "/media";
	Symlink_Path = Storage_Path;
	if (Mount_Point == "/data") {
		Is_Settings_Storage = true;
		if (strcmp(EXPAND(TW_EXTERNAL_STORAGE_PATH), "/sdcard") == 0) {
			Make_Dir("/emmc", false);
			Symlink_Mount_Point = "/emmc";
		} else {
			Make_Dir("/sdcard", false);
			Symlink_Mount_Point = "/sdcard";
		}
		#ifdef TW_PREPARE_DATA_MEDIA_EARLY
		if (Mount(false) && TWFunc::Path_Exists(Mount_Point + "/media/0")) {
		#else
		Mount(false);
		if (TWFunc::Path_Exists(Mount_Point + "/media/0")) {
		#endif
			Storage_Path = Mount_Point + "/media/0";
			Symlink_Path = Storage_Path;
			DataManager::SetValue(TW_INTERNAL_PATH, Mount_Point + "/media/0");
			#ifndef TW_INCLUDE_CRYPTO
				DataManager::SetValue("tw_settings_path", TW_STORAGE_PATH);
			#endif
			UnMount(true);
		}
		DataManager::SetValue("tw_has_internal", 1);
		DataManager::SetValue("tw_has_data_media", 1);
		backup_exclusions.add_absolute_dir("/data/data/com.google.android.music/files");
		backup_exclusions.add_absolute_dir("/data/per_boot"); // DJ9,14Jan2020 - exclude this dir to prevent "error 255" on AOSP ROMs that create and lock it
		backup_exclusions.add_absolute_dir("/data/vendor/dumpsys");
		backup_exclusions.add_absolute_dir("/data/cache");
        backup_exclusions.add_absolute_dir("/data/misc/apexdata/com.android.art"); // exclude this dir to prevent "error 255" on AOSP Android 12
		backup_exclusions.add_absolute_dir("/data/extm"); //exclude this dir to prevent "error 255" on MIUI
		backup_exclusions.add_absolute_dir("/data/gsi"); // Contains huge files (DSU System image + Userdata image), and won't work after restoration (requires configuration files in metadata)
		backup_exclusions.add_absolute_dir("/data/adb/ksu/modules.img"); //After ksu 0.8.x the modules.img file became 1tb, which is inhibiting the execution of backups
		wipe_exclusions.add_absolute_dir(Mount_Point + "/misc/vold"); // adopted storage keys
		ExcludeAll(Mount_Point + "/system/storage.xml");

		// board-customisable exclusions
		#ifdef TW_BACKUP_EXCLUSIONS
			std::vector<std::string> user_extra_exclusions = TWFunc::Split_String(TW_BACKUP_EXCLUSIONS, ",");
			std::string s1;
			for (const std::string& extra_x : user_extra_exclusions) {
				s1 = android::base::Trim(extra_x);
				if (!s1.empty()) {
					backup_exclusions.add_absolute_dir(s1);
					LOGINFO("Adding user-defined path '%s' to the backup exclusions\n", s1.c_str());
				}
			}
		#endif
	} else {
		int i;
		string path;
		for (i = 2; i <= 9; i++) {
			path = "/sdcard" + TWFunc::to_string(i);
			if (!TWFunc::Path_Exists(path)) {
				Make_Dir(path, false);
				Symlink_Mount_Point = path;
				LOGINFO("'%s' data/media emulated storage symlinked to %s.\n", Mount_Point.c_str(), Symlink_Mount_Point.c_str());
				break;
			}
		}
		if (Mount(true) && TWFunc::Path_Exists(Mount_Point + "/media/0")) {
			Storage_Path = Mount_Point + "/media/0";
			Symlink_Path = Storage_Path;
			UnMount(true);
		}
	}
	ExcludeAll(Mount_Point + "/media");
	// The inclusion of /data/media/0/Android is not set here. The decision is
	// made per backup run by TWPartitionManager::Sync_Backup_Inclusions() — so
	// toggling the checkbox takes effect immediately, without a TWRP reboot.
}

void TWPartition::Refresh_External_App_Data_Inclusion(bool include) {
	backup_exclusions.Clear_External_App_Data_Inclusion();
	if (!include)
		return;
	string p = Mount_Point + "/media/0/Android";
	if (TWFunc::Path_Exists(p))
		backup_exclusions.Add_External_App_Data_Inclusion(p);
}

void TWPartition::Find_Real_Block_Device(string& Block, bool Display_Error) {
	char device[PATH_MAX], realDevice[PATH_MAX];

	Original_Path = Block;

	strcpy(device, Block.c_str());
	memset(realDevice, 0, sizeof(realDevice));
	while (readlink(device, realDevice, sizeof(realDevice)) > 0)
	{
		strcpy(device, realDevice);
		memset(realDevice, 0, sizeof(realDevice));
	}

	Block = device;
	return;
}

bool TWPartition::Mount_Storage_Retry(bool Display_Error) {
	// On some devices, storage doesn't want to mount right away, retry and sleep
	if (!Mount(Display_Error)) {
		int retry_count = 5;
		while (retry_count > 0 && !Mount(false)) {
			usleep(500000);
			retry_count--;
		}
		return Mount(Display_Error);
	}
	return true;
}

bool TWPartition::Find_MTD_Block_Device(string MTD_Name) {
	FILE *fp = NULL;
	char line[255];

	fp = fopen("/proc/mtd", "rt");
	if (fp == NULL) {
		LOGERR("Device does not support /proc/mtd\n");
		return false;
	}

	while (fgets(line, sizeof(line), fp) != NULL)
	{
		char device[32], label[32];
		unsigned long size = 0;
		int deviceId;

		sscanf(line, "%s %lx %*s %*c%s", device, &size, label);

		// Skip header and blank lines
		if ((strcmp(device, "dev:") == 0) || (strlen(line) < 8))
			continue;

		// Strip off the trailing " from the label
		label[strlen(label)-1] = '\0';

		if (strcmp(label, MTD_Name.c_str()) == 0) {
			// We found our device
			// Strip off the trailing : from the device
			device[strlen(device)-1] = '\0';
			if (sscanf(device,"mtd%d", &deviceId) == 1) {
				sprintf(device, "/dev/block/mtdblock%d", deviceId);
				Primary_Block_Device = device;
				fclose(fp);
				return true;
			}
		}
	}
	fclose(fp);

	return false;
}

bool TWPartition::Get_Size_Via_statfs(bool Display_Error) {
	struct statfs st;
	string Local_Path = Mount_Point + "/.";

	if (!Mount(Display_Error))
		return false;

	if (statfs(Local_Path.c_str(), &st) != 0) {
		if (!Removable) {
			if (Display_Error)
				LOGERR("Unable to statfs '%s'\n", Local_Path.c_str());
			else
				LOGINFO("Unable to statfs '%s'\n", Local_Path.c_str());
		}
		return false;
	}
	Size = (st.f_blocks * st.f_bsize);
	Used = ((st.f_blocks - st.f_bfree) * st.f_bsize);
	Free = (st.f_bfree * st.f_bsize);
	Backup_Size = Used;
	return true;
}

bool TWPartition::Get_Size_Via_df(bool Display_Error) {
	FILE* fp;
	char command[255], line[512];
	int include_block = 1;
	unsigned int min_len;

	if (!Mount(Display_Error))
		return false;

	min_len = Actual_Block_Device.size() + 2;
	sprintf(command, "df %s > /tmp/dfoutput.txt", Mount_Point.c_str());
	TWFunc::Exec_Cmd(command);
	fp = fopen("/tmp/dfoutput.txt", "rt");
	if (fp == NULL) {
		LOGINFO("Unable to open /tmp/dfoutput.txt.\n");
		return false;
	}

	while (fgets(line, sizeof(line), fp) != NULL)
	{
		unsigned long blocks, used, available;
		char device[64];
		char tmpString[64];

		if (strncmp(line, "Filesystem", 10) == 0)
			continue;
		if (strlen(line) < min_len) {
			include_block = 0;
			continue;
		}
		if (include_block) {
			sscanf(line, "%s %lu %lu %lu", device, &blocks, &used, &available);
		} else {
			// The device block string is so long that the df information is on the next line
			int space_count = 0;
			sprintf(tmpString, "/dev/block/%s", Actual_Block_Device.c_str());
			while (tmpString[space_count] == 32)
				space_count++;
			sscanf(line + space_count, "%lu %lu %lu", &blocks, &used, &available);
		}

		// Adjust block size to byte size
		Size = blocks * 1024ULL;
		Used = used * 1024ULL;
		Free = available * 1024ULL;
		Backup_Size = Used;
	}
	fclose(fp);
	return true;
}

unsigned long long TWPartition::IOCTL_Get_Block_Size() {
	Find_Actual_Block_Device();

	return TWFunc::IOCTL_Get_Block_Size(Actual_Block_Device.c_str());
}

bool TWPartition::Find_Partition_Size(void) {
	FILE* fp;
	char line[512];
	string tmpdevice;

	fp = fopen("/proc/dumchar_info", "rt");
	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp) != NULL)
		{
			char label[32], device[32];
			unsigned long size = 0;

			sscanf(line, "%s %lx %*x %*u %s", label, &size, device);

			// Skip header, annotation	and blank lines
			if ((strncmp(device, "/dev/", 5) != 0) || (strlen(line) < 8))
				continue;

			tmpdevice = "/dev/";
			tmpdevice += label;
			if (tmpdevice == Primary_Block_Device || tmpdevice == Alternate_Block_Device) {
				Size = size;
				fclose(fp);
				return true;
			}
		}
	}

	unsigned long long ioctl_size = IOCTL_Get_Block_Size();
	if (ioctl_size) {
		Size = ioctl_size;
		return true;
	}

	// In this case, we'll first get the partitions we care about (with labels)
	fp = fopen("/proc/partitions", "rt");
	if (fp == NULL)
		return false;

	while (fgets(line, sizeof(line), fp) != NULL)
	{
		unsigned long major, minor, blocks;
		char device[512];

		if (strlen(line) < 7 || line[0] == 'm')	 continue;
		sscanf(line + 1, "%lu %lu %lu %s", &major, &minor, &blocks, device);

		tmpdevice = "/dev/block/";
		tmpdevice += device;
		if (tmpdevice == Primary_Block_Device || tmpdevice == Alternate_Block_Device) {
			// Adjust block size to byte size
			Size = blocks * 1024ULL;
			fclose(fp);
			return true;
		}
	}
	fclose(fp);
	return false;
}

bool TWPartition::Is_Mounted(void) {
	if (!Can_Be_Mounted)
		return false;

	struct stat st1, st2;
	string test_path;

	// Check to see if the mount point directory exists
	test_path = Mount_Point + "/.";
	if (stat(test_path.c_str(), &st1) != 0)  return false;

	// Check to see if the directory above the mount point exists
	test_path = Mount_Point + "/../.";
	if (stat(test_path.c_str(), &st2) != 0)  return false;

	// Compare the device IDs -- if they match then we're (probably) using tmpfs instead of an actual device
	if (st1.st_dev != st2.st_dev)
		return true;

	// Fallback (adapted from cherry-pick 17061196): a partition reachable via a symlink
	// mount point (e.g. /data via /sdcard) may be mounted even when the device-id check
	// above is inconclusive. Scanned only here, not in the common path, to avoid reading
	// /proc/mounts on every Is_Mounted() call.
	if (!Symlink_Mount_Point.empty()) {
		scan_mounted_volumes();
		const MountedVolume* sml = find_mounted_volume_by_mount_point(Symlink_Mount_Point.c_str());
		if (sml != nullptr)
			return true;
	}

	return false;
}

bool TWPartition::Is_File_System_Writable(void) {
	if (!Is_File_System(Current_File_System) || !Is_Mounted())
		return false;

	string test_path = Mount_Point + "/.";
	return (access(test_path.c_str(), W_OK) == 0);
}

bool TWPartition::Mount(bool Display_Error) {
	int exfat_mounted = 0;
	unsigned int flags = Mount_Flags;

	if (Is_Mounted()) {
		return true;
	} else if (!Can_Be_Mounted) {
		return false;
	}

	Find_Actual_Block_Device();

	// Check the current file system before mounting
	Check_FS_Type();
	if (Current_File_System == "exfat" && TWFunc::Path_Exists("/system/bin/exfat-fuse")) {
		string cmd = "/system/bin/exfat-fuse -o big_writes,max_read=131072,max_write=131072 " + Actual_Block_Device + " " + Mount_Point;
		LOGINFO("cmd: %s\n", cmd.c_str());
		string result;
		if (TWFunc::Exec_Cmd(cmd, result, false) != 0) {
			LOGINFO("exfat-fuse failed to mount with result '%s', trying vfat\n", result.c_str());
			Current_File_System = "vfat";
		} else {
#ifdef TW_NO_EXFAT_FUSE
			UnMount(false);
			// We'll let the kernel handle it but using exfat-fuse to detect if the file system is actually exfat
			// Some kernels let us mount vfat as exfat which doesn't work out too well
#else
			exfat_mounted = 1;
#endif
		}
	}

	if (Current_File_System == "ntfs" && !TWFunc::Path_Exists("/sys/module/tntfs") && (TWFunc::Path_Exists("/system/bin/ntfs-3g") || TWFunc::Path_Exists("/system/bin/mount.ntfs"))) {
		string cmd;
		string Ntfsmount_Binary = "";

		if (TWFunc::Path_Exists("/system/bin/ntfs-3g"))
			Ntfsmount_Binary = "ntfs-3g";
		else if (TWFunc::Path_Exists("/system/bin/mount.ntfs"))
			Ntfsmount_Binary = "mount.ntfs";

		if (Mount_Read_Only)
			cmd = "/system/bin/" + Ntfsmount_Binary + " -o ro " + Actual_Block_Device + " " + Mount_Point;
		else
			cmd = "/system/bin/" + Ntfsmount_Binary + " " + Actual_Block_Device + " " + Mount_Point;
		LOGINFO("cmd: '%s'\n", cmd.c_str());

		if (TWFunc::Exec_Cmd(cmd) == 0) {
			return true;
		} else {
			LOGINFO("ntfs-3g failed to mount, trying regular mount method.\n");
		}
	} else {
		if (Current_File_System == "ntfs" && TWFunc::Path_Exists("/sys/module/tntfs"))
			Current_File_System = "tntfs";
	}

	if (Mount_Read_Only)
		flags |= MS_RDONLY;

	if (Fstab_File_System == "yaffs2") {
		// mount an MTD partition as a YAFFS2 filesystem.
		flags = MS_NOATIME | MS_NODEV | MS_NODIRATIME;
		if (Mount_Read_Only)
			flags |= MS_RDONLY;
		if (mount(Actual_Block_Device.c_str(), Mount_Point.c_str(), Fstab_File_System.c_str(), flags, NULL) < 0) {
			if (mount(Actual_Block_Device.c_str(), Mount_Point.c_str(), Fstab_File_System.c_str(), flags | MS_RDONLY, NULL) < 0) {
				if (Display_Error)
					gui_msg(Msg(msg::kError, "fail_mount=Failed to mount '{1}' ({2})")(Mount_Point)(strerror(errno)));
				else
					LOGINFO("Failed to mount '%s' (MTD)\n", Mount_Point.c_str());
				return false;
			} else {
				LOGINFO("Mounted '%s' (MTD) as RO\n", Mount_Point.c_str());
				return true;
			}
		} else {
			struct stat st;
			string test_path = Mount_Point;
			if (stat(test_path.c_str(), &st) < 0) {
				if (Display_Error)
					gui_msg(Msg(msg::kError, "fail_mount=Failed to mount '{1}' ({2})")(Mount_Point)(strerror(errno)));
				else
					LOGINFO("Failed to mount '%s' (MTD)\n", Mount_Point.c_str());
				return false;
			}
			mode_t new_mode = st.st_mode | S_IXUSR | S_IXGRP | S_IXOTH;
			if (new_mode != st.st_mode) {
				LOGINFO("Fixing execute permissions for %s\n", Mount_Point.c_str());
				if (chmod(Mount_Point.c_str(), new_mode) < 0) {
					if (Display_Error)
						LOGERR("Couldn't fix permissions for %s: %s\n", Mount_Point.c_str(), strerror(errno));
					else
						LOGINFO("Couldn't fix permissions for %s: %s\n", Mount_Point.c_str(), strerror(errno));
					return false;
				}
			}
			return true;
		}
	}

	string mount_fs = Current_File_System;
	if (Current_File_System == "exfat" && TWFunc::Path_Exists("/sys/module/texfat"))
		mount_fs = "texfat";

	if (!exfat_mounted &&
		mount(Actual_Block_Device.c_str(), Mount_Point.c_str(), mount_fs.c_str(), flags, Mount_Options.c_str()) != 0 &&
		mount(Actual_Block_Device.c_str(), Mount_Point.c_str(), mount_fs.c_str(), flags, NULL) != 0) {
#ifdef TW_NO_EXFAT_FUSE
		if (Current_File_System == "exfat") {
			LOGINFO("Mounting exfat failed, trying vfat...\n");
			if (mount(Actual_Block_Device.c_str(), Mount_Point.c_str(), "vfat", 0, NULL) != 0) {
				if (Display_Error)
					gui_msg(Msg(msg::kError, "fail_mount=Failed to mount '{1}' ({2})")(Mount_Point)(strerror(errno)));
				else
					LOGINFO("Unable to mount '%s'\n", Mount_Point.c_str());
				LOGINFO("Actual block device: '%s', current file system: '%s', flags: 0x%8x, options: '%s'\n", Actual_Block_Device.c_str(), Current_File_System.c_str(), flags, Mount_Options.c_str());
				return false;
			}
		} else {
#endif
			if (!Removable && Display_Error)
				gui_msg(Msg(msg::kError, "fail_mount=Failed to mount '{1}' ({2})")(Mount_Point)(strerror(errno)));
			else
				LOGINFO("Unable to mount '%s'\n", Mount_Point.c_str());
			LOGINFO("Actual block device: '%s', current file system: '%s'\n", Actual_Block_Device.c_str(), Current_File_System.c_str());
			return false;
#ifdef TW_NO_EXFAT_FUSE
		}
#endif
	}

	if (Removable)
		Update_Size(Display_Error);

	if (!Symlink_Mount_Point.empty()) {
		if (!Bind_Mount(false))
			return false;
	}
	return true;
}

bool TWPartition::Bind_Mount(bool Display_Error) {
	if (TWFunc::Path_Exists(Symlink_Path)) {
		if (mount(Symlink_Path.c_str(), Symlink_Mount_Point.c_str(), "", MS_BIND, NULL) < 0) {
			return false;
		}
	}
	return true;
}

bool TWPartition::UnMount(bool Display_Error) {
	if (Is_Mounted()) {
		int never_unmount_system;

		DataManager::GetValue(TW_DONT_UNMOUNT_SYSTEM, never_unmount_system);
		if (never_unmount_system == 1 && Mount_Point == PartitionManager.Get_Android_Root_Path())
			return true; // Never unmount system if you're not supposed to unmount it

		if (Is_Storage && MTP_Storage_ID > 0)
			PartitionManager.Remove_MTP_Storage(MTP_Storage_ID);

		if (!Symlink_Mount_Point.empty())
			umount(Symlink_Mount_Point.c_str());

		umount(Mount_Point.c_str());
		if (Is_Mounted()) {
			if (Display_Error)
				gui_msg(Msg(msg::kError, "fail_unmount=Failed to unmount '{1}' ({2})")(Mount_Point)(strerror(errno)));
			else
				LOGINFO("Unable to unmount '%s'\n", Mount_Point.c_str());
			return false;
		} else {
			return true;
		}
	} else {
		return true;
	}
}

bool TWPartition::ReMount(bool Display_Error) {
	if (UnMount(Display_Error))
		return Mount(Display_Error);
	return false;
}

bool TWPartition::ReMount_RW(bool Display_Error) {
	// No need to remount if already mounted rw
	if (Is_File_System_Writable())
		return true;

	bool ro = Mount_Read_Only;
	int flags = Mount_Flags;

	Mount_Read_Only = false;
	Mount_Flags &= ~MS_RDONLY;

	bool ret = ReMount(Display_Error);

	Mount_Read_Only = ro;
	Mount_Flags = flags;

	return ret;
}

bool TWPartition::BlkDiscard() {
	string cmd;
	LOGINFO("Perform BLKDISCARD on block device %s\n", Actual_Block_Device.c_str());
	cmd = "/system/bin/toybox blkdiscard " + Actual_Block_Device;
	return (TWFunc::Exec_Cmd(cmd) == 0);
}

bool TWPartition::Wipe(string New_File_System) {
	bool wiped = false, update_crypt = false, recreate_media = true;
	int check;

	if (!Can_Be_Wiped) {
		gui_msg(Msg(msg::kError, "cannot_wipe=Partition {1} cannot be wiped.")(Display_Name));
		return false;
	}

	if (Mount_Point == "/cache")
		Log_Offset = 0;

	if (Mount_Point == PartitionManager.Get_Android_Root_Path()) {
		if (tw_get_default_metadata(PartitionManager.Get_Android_Root_Path().c_str()) != 0) {
			gui_msg(Msg(msg::kWarning, "restore_system_context=Unable to get default context for {1} -- Android may not boot.")(PartitionManager.Get_Android_Root_Path()));
		}
	}

	if (Has_Data_Media && Current_File_System == New_File_System) {
		wiped = Wipe_Data_Without_Wiping_Media();
		if (Mount_Point == "/data" && TWFunc::get_log_dir() == DATA_LOGS_DIR) {
			bool created = PartitionManager.Recreate_Logs_Dir();
			if (!created)
				LOGERR("Unable to create log directory for TWRP\n");
		}
		recreate_media = false;
	} else {
		DataManager::GetValue(TW_RM_RF_VAR, check);
		if (check || Use_Rm_Rf)
			wiped = Wipe_RMRF();
		else if (New_File_System == "ext4")
			wiped = Wipe_EXT4();
		else if (New_File_System == "ext2" || New_File_System == "ext3")
			wiped = Wipe_EXTFS(New_File_System);
		else if (New_File_System == "exfat")
			wiped = Wipe_EXFAT();
		else if (New_File_System == "ntfs" || Current_File_System == "tntfs")
			wiped = Wipe_NTFS();
		else if (New_File_System == "yaffs2")
			wiped = Wipe_MTD();
		else if (New_File_System == "f2fs")
			wiped = Wipe_F2FS();
		else if (New_File_System == "vfat")
			wiped = Wipe_FAT();
		else {
			LOGERR("Unable to wipe '%s' -- unknown file system '%s'\n", Mount_Point.c_str(), New_File_System.c_str());
			return false;
		}
		update_crypt = wiped;
		update_crypt = false;
	}

	if (wiped) {
		if (Mount_Point == "/cache" && TWFunc::get_log_dir() != DATA_LOGS_DIR)
			DataManager::Output_Version();

		if (Mount_Point == PartitionManager.Get_Android_Root_Path()) {
			tw_set_default_metadata(PartitionManager.Get_Android_Root_Path().c_str());
		}
		if (update_crypt) {
			Setup_File_System(false);
			if (Is_Encrypted && !Is_Decrypted) {
				// just wiped an encrypted partition back to its unencrypted state
				Is_Encrypted = false;
				Is_Decrypted = false;
				Decrypted_Block_Device = "";
				if (Mount_Point == "/data") {
					DataManager::SetValue(TW_IS_ENCRYPTED, 0);
					DataManager::SetValue(TW_IS_DECRYPTED, 0);
				}
			}
		}

		if (Is_Storage && Mount(false) && !Is_FBE)
			PartitionManager.Add_MTP_Storage(MTP_Storage_ID);
	}

	return wiped;
}

bool TWPartition::Wipe() {
	if (Is_File_System(Current_File_System))
		return Wipe(Current_File_System);
	else
		return Wipe(Fstab_File_System);
}

bool TWPartition::Wipe_AndSec(void) {
	if (!Has_Android_Secure)
		return false;

	if (!Mount(true))
		return false;

	gui_msg(Msg("wiping=Wiping {1}")(Backup_Display_Name));
	TWFunc::removeDir(Mount_Point + "/.android_secure/", true);
	return true;
}

bool TWPartition::Wipe_Data_Cache(void) {
	if (!Mount(true))
		return false;
	gui_msg(Msg("wiping=Wiping {1}")(Mount_Point + "/cache/"));
	TWFunc::removeDir(Mount_Point + "/cache/", true);
	return true;
}

bool TWPartition::Can_Repair() {
	if (Mount_Read_Only)
		return false;
	if (Current_File_System == "vfat" && TWFunc::Path_Exists("/system/bin/fsck.fat"))
		return true;
	else if ((Current_File_System == "ext2" || Current_File_System == "ext3" || Current_File_System == "ext4") && TWFunc::Path_Exists("/system/bin/e2fsck"))
		return true;
	else if (Current_File_System == "exfat" && TWFunc::Path_Exists("/system/bin/fsck.exfat"))
		return true;
	else if (Current_File_System == "f2fs" && TWFunc::Path_Exists("/system/bin/fsck.f2fs"))
		return true;
	else if ((Current_File_System == "ntfs" || Current_File_System == "tntfs") && (TWFunc::Path_Exists("/system/bin/ntfsfix") || TWFunc::Path_Exists("/system/bin/fsck.ntfs")))
		return true;
	return false;
}

bool TWPartition::Repair() {
	string command;

	if (Current_File_System == "vfat") {
		if (!TWFunc::Path_Exists("/system/bin/fsck.fat")) {
			gui_msg(Msg(msg::kError, "repair_not_exist={1} does not exist! Cannot repair!")("fsck.fat"));
			return false;
		}
		if (!UnMount(true))
			return false;
		gui_msg(Msg("repairing_using=Repairing {1} using {2}...")(Display_Name)("fsck.fat"));
		Find_Actual_Block_Device();
		command = "/system/bin/fsck.fat -y " + Actual_Block_Device;
		LOGINFO("Repair command: %s\n", command.c_str());
		if (TWFunc::Exec_Cmd(command) == 0) {
			gui_msg("done=Done.");
			return true;
		} else {
			gui_msg(Msg(msg::kError, "unable_repair=Unable to repair {1}.")(Display_Name));
			return false;
		}
	}
	if (Current_File_System == "ext2" || Current_File_System == "ext3" || Current_File_System == "ext4") {
		if (!TWFunc::Path_Exists("/system/bin/e2fsck")) {
			gui_msg(Msg(msg::kError, "repair_not_exist={1} does not exist! Cannot repair!")("e2fsck"));
			return false;
		}
		if (!UnMount(true))
			return false;
		gui_msg(Msg("repairing_using=Repairing {1} using {2}...")(Display_Name)("e2fsck"));
		Find_Actual_Block_Device();
		command = "/system/bin/e2fsck -fp " + Actual_Block_Device;
		LOGINFO("Repair command: %s\n", command.c_str());
		if (TWFunc::Exec_Cmd(command) == 0) {
			gui_msg("done=Done.");
			return true;
		} else {
			gui_msg(Msg(msg::kError, "unable_repair=Unable to repair {1}.")(Display_Name));
			return false;
		}
	}
	if (Current_File_System == "exfat") {
		if (!TWFunc::Path_Exists("/system/bin/fsck.exfat")) {
			gui_msg(Msg(msg::kError, "repair_not_exist={1} does not exist! Cannot repair!")("fsck.exfat"));
			return false;
		}
		if (!UnMount(true))
			return false;
		gui_msg(Msg("repairing_using=Repairing {1} using {2}...")(Display_Name)("fsck.exfat"));
		Find_Actual_Block_Device();
		command = "/system/bin/fsck.exfat " + Actual_Block_Device;
		LOGINFO("Repair command: %s\n", command.c_str());
		if (TWFunc::Exec_Cmd(command) == 0) {
			gui_msg("done=Done.");
			return true;
		} else {
			gui_msg(Msg(msg::kError, "unable_repair=Unable to repair {1}.")(Display_Name));
			return false;
		}
	}
	if (Current_File_System == "f2fs") {
		if (!TWFunc::Path_Exists("/system/bin/fsck.f2fs")) {
			gui_msg(Msg(msg::kError, "repair_not_exist={1} does not exist! Cannot repair!")("fsck.f2fs"));
			return false;
		}
		if (!UnMount(true))
			return false;
		gui_msg(Msg("repairing_using=Repairing {1} using {2}...")(Display_Name)("fsck.f2fs"));
		Find_Actual_Block_Device();
		command = "/system/bin/fsck.f2fs -a " + Actual_Block_Device;
		LOGINFO("Repair command: %s\n", command.c_str());
		if (TWFunc::Exec_Cmd(command) == 0) {
			gui_msg("done=Done.");
			return true;
		} else {
			gui_msg(Msg(msg::kError, "unable_repair=Unable to repair {1}.")(Display_Name));
			return false;
		}
	}
	if (Current_File_System == "ntfs" || Current_File_System == "tntfs") {
		string Ntfsfix_Binary;
		if (TWFunc::Path_Exists("/system/bin/ntfsfix"))
			Ntfsfix_Binary = "ntfsfix";
		else if (TWFunc::Path_Exists("/system/bin/fsck.ntfs"))
			Ntfsfix_Binary = "fsck.ntfs";
		else {
			gui_msg(Msg(msg::kError, "repair_not_exist={1} does not exist! Cannot repair!")("ntfsfix"));
			return false;
		}
		if (!UnMount(true))
			return false;
		gui_msg(Msg("repairing_using=Repairing {1} using {2}...")(Display_Name)(Ntfsfix_Binary));
		Find_Actual_Block_Device();
		command = "/system/bin/" + Ntfsfix_Binary + " " + Actual_Block_Device;
		LOGINFO("Repair command: %s\n", command.c_str());
		if (TWFunc::Exec_Cmd(command) == 0) {
			gui_msg("done=Done.");
			return true;
		} else {
			gui_msg(Msg(msg::kError, "unable_repair=Unable to repair {1}.")(Display_Name));
			return false;
		}
	}
	return false;
}

bool TWPartition::Can_Resize() {
	if (Mount_Read_Only)
		return false;
	if ((Current_File_System == "ext2" || Current_File_System == "ext3" || Current_File_System == "ext4") && TWFunc::Path_Exists("/system/bin/resize2fs"))
		return true;
	return false;
}

bool TWPartition::Resize() {
	string command;

	if (Current_File_System == "ext2" || Current_File_System == "ext3" || Current_File_System == "ext4") {
		if (!Can_Repair()) {
			LOGINFO("Cannot resize %s because %s cannot be repaired before resizing.\n", Display_Name.c_str(), Display_Name.c_str());
			gui_msg(Msg(msg::kError, "cannot_resize=Cannot resize {1}.")(Display_Name));
			return false;
		}
		if (!TWFunc::Path_Exists("/system/bin/resize2fs")) {
			LOGINFO("resize2fs does not exist! Cannot resize!\n");
			gui_msg(Msg(msg::kError, "cannot_resize=Cannot resize {1}.")(Display_Name));
			return false;
		}
		// Repair will unmount so no need to do it twice
		gui_msg(Msg("repair_resize=Repairing {1} before resizing.")( Display_Name));
		if (!Repair())
			return false;
		gui_msg(Msg("resizing=Resizing {1} using {2}...")(Display_Name)("resize2fs"));
		Find_Actual_Block_Device();
		command = "/system/bin/resize2fs " + Actual_Block_Device;
		if (Length != 0) {
			unsigned long long Actual_Size = IOCTL_Get_Block_Size();
			if (Actual_Size == 0)
				return false;

			unsigned long long Block_Count;
			if (Length < 0) {
				// Reduce overall size by this length
				Block_Count = (Actual_Size / 1024LLU) - ((unsigned long long)(Length * -1) / 1024LLU);
			} else {
				// This is the size, not a size reduction
				Block_Count = ((unsigned long long)(Length) / 1024LLU);
			}
			char temp[256];
			sprintf(temp, "%llu", Block_Count);
			command += " ";
			command += temp;
			command += "K";
		}
		LOGINFO("Resize command: %s\n", command.c_str());
		if (TWFunc::Exec_Cmd(command) == 0) {
			Update_Size(true);
			gui_msg("done=Done.");
			return true;
		} else {
			Update_Size(true);
			gui_msg(Msg(msg::kError, "unable_resize=Unable to resize {1}.")(Display_Name));
			return false;
		}
	}
	return false;
}

bool TWPartition::Backup(PartitionSettings *part_settings, std::atomic<pid_t> *tar_fork_pid) {
	if (Backup_Method == BM_FILES)
		return Backup_Tar(part_settings, tar_fork_pid);
	else if (Backup_Method == BM_DD)
		return Backup_Image(part_settings);
	else if (Backup_Method == BM_FLASH_UTILS)
		return Backup_Dump_Image(part_settings);
	LOGERR("Unknown backup method for '%s'\n", Mount_Point.c_str());
	return false;
}

bool TWPartition::Restore(PartitionSettings *part_settings) {
	TWFunc::GUI_Operation_Text(TW_RESTORE_TEXT, Display_Name, gui_parse_text("{@restoring_hdr}"));
	LOGINFO("Restore filename is: %s/%s\n", part_settings->Backup_Folder.c_str(), Backup_FileName.c_str());

	string Restore_File_System = Get_Restore_File_System(part_settings);

	if (Is_File_System(Restore_File_System))
		return Restore_Tar(part_settings);
	else if (Is_Image(Restore_File_System))
		return Restore_Image(part_settings);

	LOGERR("Unknown restore method for '%s'\n", Mount_Point.c_str());
	return false;
}

string TWPartition::Get_Restore_File_System(PartitionSettings *part_settings) {
	size_t first_period, second_period;
	string Restore_File_System;

	// Parse backup filename to extract the file system before wiping
	first_period = Backup_FileName.find(".");
	if (first_period == string::npos) {
		LOGERR("Unable to find file system (first period).\n");
		return string();
	}
	Restore_File_System = Backup_FileName.substr(first_period + 1, Backup_FileName.size() - first_period - 1);
	second_period = Restore_File_System.find(".");
	if (second_period == string::npos) {
		LOGERR("Unable to find file system (second period).\n");
		return string();
	}
	Restore_File_System.resize(second_period);
	LOGINFO("Restore file system is: '%s'.\n", Restore_File_System.c_str());
	return Restore_File_System;
}

string TWPartition::Backup_Method_By_Name() {
	if (Backup_Method == BM_NONE)
		return "none";
	else if (Backup_Method == BM_FILES)
		return "files";
	else if (Backup_Method == BM_DD)
		return "dd";
	else if (Backup_Method == BM_FLASH_UTILS)
		return "flash_utils";
	else
		return "undefined";
	return "ERROR!";
}

bool TWPartition::Decrypt(string Password) {
	LOGINFO("STUB TWPartition::Decrypt, password: '%s'\n", Password.c_str());
	// Is this needed?
	return 1;
}

bool TWPartition::Wipe_Encryption() {
	bool Save_Data_Media = Has_Data_Media;
	bool ret = false;
	BasePartition* base_partition = make_partition();

	if (!base_partition->PreWipeEncryption())
		goto exit;

	Find_Actual_Block_Device();
	if (!Is_Present) {
		LOGINFO("Block device not present, cannot format %s.\n", Display_Name.c_str());
		gui_msg(Msg(msg::kError, "unable_to_wipe=Unable to wipe {1}.")(Display_Name));
		return false;
	}

#ifdef TW_INCLUDE_CRYPTO
	if (!UnMount(true))
		return false;
	if (Is_Decrypted && !Decrypted_Block_Device.empty()) {
		if (delete_crypto_blk_dev((char*)("userdata")) != 0) {
			LOGERR("Error deleting crypto block device, continuing anyway.\n");
		}
	}
#endif
	Has_Data_Media = false;
	Decrypted_Block_Device = "";
	Is_Decrypted = false;
	Is_Encrypted = false;
	if (Wipe(Fstab_File_System)) {
		Has_Data_Media = Save_Data_Media;
		DataManager::SetValue(TW_IS_ENCRYPTED, 0);
#ifndef TW_OEM_BUILD
		gui_msg("format_data_msg=You may need to reboot recovery to be able to use /data again.");
#endif
		if (Is_FBE) {
			gui_msg(Msg(msg::kWarning, "data_media_fbe_msg=TWRP will not recreate /data/media on an FBE device. Please reboot into your rom to create /data/media."));
		} else {
			if (Has_Data_Media && !Symlink_Mount_Point.empty()) {
				if (Mount(false))
					PartitionManager.Add_MTP_Storage(MTP_Storage_ID);
			}
		}

		ret = true;
		if (!Key_Directory.empty())
			ret = PartitionManager.Wipe_By_Path(Key_Directory);
		if (ret)
			ret = base_partition->PostWipeEncryption();
		goto exit;
	} else {
		Has_Data_Media = Save_Data_Media;
		gui_err("format_data_err=Unable to format to remove encryption.");
		if (Has_Data_Media && Mount(false))
			PartitionManager.Add_MTP_Storage(MTP_Storage_ID);
		goto exit;
	}
exit:
	delete base_partition;
	return ret;
}

void TWPartition::Check_FS_Type() {
	const char* type;
	blkid_probe pr;

	if (Fstab_File_System == "yaffs2" || Fstab_File_System == "mtd" || Fstab_File_System == "bml" || Ignore_Blkid)
		return; // Running blkid on some mtd devices causes a massive crash or needs to be skipped

	Find_Actual_Block_Device();
	if (!Is_Present)
		return;

	pr = blkid_new_probe_from_filename(Actual_Block_Device.c_str());
	if (blkid_do_fullprobe(pr)) {
		blkid_free_probe(pr);
		LOGINFO("Can't probe device %s\n", Actual_Block_Device.c_str());
		return;
	}

	if (blkid_probe_lookup_value(pr, "TYPE", &type, NULL) < 0) {
		blkid_free_probe(pr);
		LOGINFO("can't find filesystem on device %s\n", Actual_Block_Device.c_str());
		return;
	}

	Current_File_System = type;
	blkid_free_probe(pr);
	if (fs_flags.size() > 1) {
		std::vector<partition_fs_flags_struct>::iterator iter;
		std::vector<partition_fs_flags_struct>::iterator found = fs_flags.begin();

		for (iter = fs_flags.begin(); iter != fs_flags.end(); iter++) {
			if (iter->File_System == Current_File_System) {
				found = iter;
				break;
			}
		}
		// If we don't find a match, we default the flags to the first set of flags that we received from the fstab
		if (Mount_Flags != found->Mount_Flags || Mount_Options != found->Mount_Options) {
			Mount_Flags = found->Mount_Flags;
			Mount_Options = found->Mount_Options;
			LOGINFO("Mount_Flags: %i, Mount_Options: %s\n", Mount_Flags, Mount_Options.c_str());
		}
	}
}

bool TWPartition::Wipe_EXTFS(string File_System) {
	if (!UnMount(true))
		return false;

#if PLATFORM_SDK_VERSION < 28
	if (!TWFunc::Path_Exists("/system/bin/mke2fs"))
#else
	if (!TWFunc::Path_Exists("/system/bin/mke2fs") || !TWFunc::Path_Exists("/system/bin/e2fsdroid"))
#endif
		return Wipe_RMRF();

	int ret;
	bool NeedPreserveFooter = true;

	Find_Actual_Block_Device();
	if (!Is_Present) {
		LOGINFO("Block device not present, cannot wipe %s.\n", Display_Name.c_str());
		gui_msg(Msg(msg::kError, "unable_to_wipe=Unable to wipe {1}.")(Display_Name));
		return false;
	}

	/**
	 * On decrypted devices, IOCTL_Get_Block_Size calculates size on device mapper,
	 * so there's no need to preserve footer.
	 */
	if ((Is_Decrypted && !Decrypted_Block_Device.empty()) ||
			Crypto_Key_Location != "footer") {
		NeedPreserveFooter = false;
	}

	unsigned long long dev_sz = TWFunc::IOCTL_Get_Block_Size(Actual_Block_Device.c_str());
	if (!dev_sz)
		return false;

	if (NeedPreserveFooter)
		Length < 0 ? dev_sz += Length : dev_sz -= CRYPT_FOOTER_OFFSET;

	char dout[16];
	sprintf(dout, "%llu", dev_sz / 4096);

	//string size_str =to_string(dev_sz / 4096);
	string size_str = dout;
	string Command;

	gui_msg(Msg("formatting_using=Formatting {1} using {2}...")(Display_Name)("mke2fs"));

	// Execute mke2fs to create empty ext4 filesystem
	Command = "mke2fs -t " + File_System + " -b 4096 " + Actual_Block_Device + " " + size_str;
	LOGINFO("mke2fs command: %s\n", Command.c_str());
	ret = TWFunc::Exec_Cmd(Command);
	if (ret) {
		gui_msg(Msg(msg::kError, "unable_to_wipe=Unable to wipe {1}.")(Display_Name));
		return false;
	}

	if (TWFunc::Path_Exists("/system/bin/e2fsdroid")) {
		const string& File_Contexts_Entry = (Mount_Point == "/system_root" ? "/" : Mount_Point);
		char *secontext = NULL;
		if (!selinux_handle || selabel_lookup(selinux_handle, &secontext, File_Contexts_Entry.c_str(), S_IFDIR) < 0) {
			LOGINFO("Cannot lookup security context for '%s'\n", Mount_Point.c_str());
		} else {
			// Execute e2fsdroid to initialize selinux context
			if (Mount_Point == "/persist") {
				Mount(true);
				TWFunc::removeDir("/persist/lost+found", false);
				UnMount(true);
			}
			Command = "e2fsdroid -e -S /file_contexts -a " + File_Contexts_Entry + " " + Actual_Block_Device;
			LOGINFO("e2fsdroid command: %s\n", Command.c_str());
			ret = TWFunc::Exec_Cmd(Command);
			if (ret) {
				gui_msg(Msg(msg::kError, "unable_to_wipe=Unable to wipe {1}.")(Display_Name));
				return false;
			}
		}
	} else {
		LOGINFO("e2fsdroid not present\n");
	}

	if (NeedPreserveFooter)
		Wipe_Crypto_Key();
	Current_File_System = File_System;
	Recreate_AndSec_Folder();
	gui_msg("done=Done.");
	return true;
}

bool TWPartition::Wipe_EXT4() {
#ifdef USE_EXT4
	int ret;
	bool NeedPreserveFooter = true;

	if (!UnMount(true))
		return false;

	Find_Actual_Block_Device();
	if (!Is_Present) {
		LOGINFO("Block device not present, cannot wipe %s.\n", Display_Name.c_str());
		gui_msg(Msg(msg::kError, "unable_to_wipe=Unable to wipe {1}.")(Display_Name));
		return false;
	}

	/**
	 * On decrypted devices, IOCTL_Get_Block_Size calculates size on device mapper,
	 * so there's no need to preserve footer.
	 */
	if ((Is_Decrypted && !Decrypted_Block_Device.empty()) ||
			Crypto_Key_Location != "footer") {
		NeedPreserveFooter = false;
	}

	unsigned long long dev_sz = TWFunc::IOCTL_Get_Block_Size(Actual_Block_Device.c_str());
	if (!dev_sz)
		return false;

	if (NeedPreserveFooter)
		Length < 0 ? dev_sz += Length : dev_sz -= CRYPT_FOOTER_OFFSET;

	char *secontext = NULL;

	gui_msg(Msg("formatting_using=Formatting {1} using {2}...")(Display_Name)("make_ext4fs"));

	if (!selinux_handle || selabel_lookup(selinux_handle, &secontext, Mount_Point.c_str(), S_IFDIR) < 0) {
		LOGINFO("Cannot lookup security context for '%s'\n", Mount_Point.c_str());
		ret = make_ext4fs(Actual_Block_Device.c_str(), dev_sz, Mount_Point.c_str(), NULL);
	} else {
		ret = make_ext4fs(Actual_Block_Device.c_str(), dev_sz, Mount_Point.c_str(), selinux_handle);
	}
	if (ret != 0) {
		gui_msg(Msg(msg::kError, "unable_to_wipe=Unable to wipe {1}.")(Display_Name));
		return false;
	} else {
		if (NeedPreserveFooter)
			Wipe_Crypto_Key();
		string sedir = Mount_Point + "/lost+found";
		PartitionManager.Mount_By_Path(sedir.c_str(), true);
		rmdir(sedir.c_str());
		mkdir(sedir.c_str(), S_IRWXU | S_IRWXG | S_IWGRP | S_IXGRP);
		return true;
	}
#else
	return Wipe_EXTFS("ext4");
#endif
}

bool TWPartition::Wipe_FAT() {
	string command;

	if (!UnMount(true))
		return false;

	if (TWFunc::Path_Exists("/system/bin/mkfs.fat")) {
		gui_msg(Msg("formatting_using=Formatting {1} using {2}...")(Display_Name)("mkfs.fat"));
		Find_Actual_Block_Device();
		command = "mkfs.fat " + Actual_Block_Device;
		if (TWFunc::Exec_Cmd(command) == 0) {
			Current_File_System = "vfat";
			Recreate_AndSec_Folder();
			gui_msg("done=Done.");
			return true;
		} else {
			gui_msg(Msg(msg::kError, "unable_to_wipe=Unable to wipe {1}.")(Display_Name));
			return false;
		}
		return true;
	}
	else
		return Wipe_RMRF();

	return false;
}

bool TWPartition::Wipe_EXFAT() {
	string command;

	if (!UnMount(true))
		return false;
	if (TWFunc::Path_Exists("/system/bin/mkexfatfs")) {
		gui_msg(Msg("formatting_using=Formatting {1} using {2}...")(Display_Name)("mkexfatfs"));
		Find_Actual_Block_Device();
		command = "mkexfatfs " + Actual_Block_Device;
		if (TWFunc::Exec_Cmd(command) == 0) {
			Recreate_AndSec_Folder();
			gui_msg("done=Done.");
			return true;
		} else {
			gui_msg(Msg(msg::kError, "unable_to_wipe=Unable to wipe {1}.")(Display_Name));
			return false;
		}
		return true;
	}
	return false;
}

bool TWPartition::Wipe_MTD() {
	if (!UnMount(true))
		return false;

	gui_msg(Msg("formatting_using=Formatting {1} using {2}...")(Display_Name)("MTD"));

	mtd_scan_partitions();
	const MtdPartition* mtd = mtd_find_partition_by_name(MTD_Name.c_str());
	if (mtd == NULL) {
		LOGERR("No mtd partition named '%s'", MTD_Name.c_str());
		return false;
	}

	MtdWriteContext* ctx = mtd_write_partition(mtd);
	if (ctx == NULL) {
		LOGERR("Can't write '%s', failed to format.", MTD_Name.c_str());
		return false;
	}
	if (mtd_erase_blocks(ctx, -1) == -1) {
		mtd_write_close(ctx);
		LOGERR("Failed to format '%s'", MTD_Name.c_str());
		return false;
	}
	if (mtd_write_close(ctx) != 0) {
		LOGERR("Failed to close '%s'", MTD_Name.c_str());
		return false;
	}
	Current_File_System = "yaffs2";
	Recreate_AndSec_Folder();
	gui_msg("done=Done.");
	return true;
}

bool TWPartition::Wipe_RMRF() {
	if (!Mount(true))
		return false;
	// This is the only wipe that leaves the partition mounted, so we
	// must manually remove the partition from MTP if it is a storage
	// partition.
	if (Is_Storage)
		PartitionManager.Remove_MTP_Storage(MTP_Storage_ID);

	gui_msg(Msg("remove_all=Removing all files under '{1}'")(Mount_Point));
	TWFunc::removeDir(Mount_Point, true);
	Recreate_AndSec_Folder();
	return true;
}

bool TWPartition::Wipe_F2FS() {
	std::string f2fs_command;

	if (!UnMount(true))
		return false;

	if (TWFunc::Path_Exists("/system/bin/mkfs.f2fs"))
		f2fs_command = "/system/bin/mkfs.f2fs";
	else if (TWFunc::Path_Exists("/system/bin/make_f2fs"))
		f2fs_command = "/system/bin/make_f2fs -g android";
	else {
		LOGINFO("mkfs.f2fs binary not found, using rm -rf to wipe.\n");
		return Wipe_RMRF();
	}

	bool NeedPreserveFooter = true;
	bool needs_casefold = false;
  	bool needs_projid = false;

	Find_Actual_Block_Device();
	if (!Is_Present) {
		LOGINFO("Block device not present, cannot wipe %s.\n", Display_Name.c_str());
		gui_msg(Msg(msg::kError, "unable_to_wipe=Unable to wipe {1}.")(Display_Name));
		return false;
	}

	needs_casefold = android::base::GetBoolProperty("external_storage.casefold.enabled", false);
	needs_projid = android::base::GetBoolProperty("external_storage.projid.enabled", false);
	unsigned long long dev_sz = TWFunc::IOCTL_Get_Block_Size(Actual_Block_Device.c_str());
	if (!dev_sz)
		return false;

	if (NeedPreserveFooter)
		Length < 0 ? dev_sz += Length : dev_sz -= CRYPT_FOOTER_OFFSET;
	char dev_sz_str[48];
	sprintf(dev_sz_str, "%llu", (dev_sz / 4096));
	if(needs_projid)
		f2fs_command += " -O project_quota,extra_attr";

	if(needs_casefold)
		f2fs_command += " -O casefold -C utf8";

	if (Needs_Fs_Compress)
		f2fs_command += " -O compression,extra_attr";

	f2fs_command += " " + Actual_Block_Device + " " + dev_sz_str;

	if (TWFunc::Path_Exists("/system/bin/sload_f2fs")) {
		f2fs_command += " && sload_f2fs -t /data " + Actual_Block_Device;
	}

	/**
	 * On decrypted devices, IOCTL_Get_Block_Size calculates size on device mapper,
	 * so there's no need to preserve footer.
	 */
	if ((Is_Decrypted && !Decrypted_Block_Device.empty()) ||
			Crypto_Key_Location != "footer") {
		NeedPreserveFooter = false;
	}
	LOGINFO("mkfs.f2fs command: %s\n", f2fs_command.c_str());
	if (TWFunc::Exec_Cmd(f2fs_command) == 0) {
		if (NeedPreserveFooter)
			Wipe_Crypto_Key();
		Recreate_AndSec_Folder();
		gui_msg("done=Done.");
		return true;
	} else {
		gui_msg(Msg(msg::kError, "unable_to_wipe=Unable to wipe {1}.")(Display_Name));
		return false;
	}
	return true;
}

bool TWPartition::Wipe_NTFS() {
	string command;
	string Ntfsmake_Binary;

	if (!UnMount(true))
		return false;

	if (TWFunc::Path_Exists("/system/bin/mkntfs"))
		Ntfsmake_Binary = "mkntfs";
	else if (TWFunc::Path_Exists("/system/bin/mkfs.ntfs"))
		Ntfsmake_Binary = "mkfs.ntfs";
	else
		return false;

	gui_msg(Msg("formatting_using=Formatting {1} using {2}...")(Display_Name)(Ntfsmake_Binary));
	Find_Actual_Block_Device();
	command = "/system/bin/" + Ntfsmake_Binary + " " + Actual_Block_Device;
	if (TWFunc::Exec_Cmd(command) == 0) {
		Recreate_AndSec_Folder();
		gui_msg("done=Done.");
		return true;
	} else {
		gui_msg(Msg(msg::kError, "unable_to_wipe=Unable to wipe {1}.")(Display_Name));
		return false;
	}
	return false;
}

bool TWPartition::Wipe_Data_Without_Wiping_Media() {
#ifdef TW_OEM_BUILD
	// In an OEM Build we want to do a full format
	return Wipe_Encryption();
#else
	bool ret = false;

	if (!Mount(true))
		return false;

	gui_msg("wiping_data=Wiping data without wiping /data/media ...");
	ret = Wipe_Data_Without_Wiping_Media_Func(Mount_Point + "/");
	if (ret)
		gui_msg("done=Done.");
	return ret;
#endif // ifdef TW_OEM_BUILD
}

bool TWPartition::Wipe_Data_Without_Wiping_Media_Func(const string& parent __unused) {
	string dir;

	DIR* d;
	d = opendir(parent.c_str());
	if (d != NULL) {
		struct dirent* de;
		while ((de = readdir(d)) != NULL) {
			if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)	 continue;

			dir = parent;
			dir.append(de->d_name);
			if (wipe_exclusions.check_skip_dirs(dir)) {
				LOGINFO("skipped '%s'\n", dir.c_str());
				continue;
			}
			if (de->d_type == DT_DIR) {
				dir.append("/");
				if (!Wipe_Data_Without_Wiping_Media_Func(dir)) {
					closedir(d);
					return false;
				}
				rmdir(dir.c_str());
			} else if (de->d_type == DT_REG || de->d_type == DT_LNK || de->d_type == DT_FIFO || de->d_type == DT_SOCK) {
				if (unlink(dir.c_str()) != 0)
					LOGINFO("Unable to unlink '%s': %s\n", dir.c_str(), strerror(errno));
			}
		}
		closedir(d);

		return true;
	}
	gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(Mount_Point)(strerror(errno)));
	return false;
}

void TWPartition::Wipe_Crypto_Key() {
	Find_Actual_Block_Device();
	if (Crypto_Key_Location.empty())
		return;
	else if (Crypto_Key_Location == "footer") {
		int fd = open(Actual_Block_Device.c_str(), O_RDWR);
		if (fd < 0) {
			gui_print_color("warning", "Unable to open '%s' to wipe crypto key\n", Actual_Block_Device.c_str());
			return;
		}

		unsigned int block_count;
		if ((ioctl(fd, BLKGETSIZE, &block_count)) == -1) {
			gui_print_color("warning", "Unable to get block size for wiping crypto footer.\n");
		} else {
			int newlen = Length < 0 ? -Length : CRYPT_FOOTER_OFFSET;
			off64_t offset = ((off64_t)block_count * 512) - newlen;
			if (lseek64(fd, offset, SEEK_SET) == -1) {
				gui_print_color("warning", "Unable to lseek64 for wiping crypto footer.\n");
			} else {
				void* buffer = malloc(newlen);
				if (!buffer) {
					gui_print_color("warning", "Failed to malloc for wiping crypto footer.\n");
				} else {
					memset(buffer, 0, newlen);
					int ret = write(fd, buffer, newlen);
					if (ret != newlen) {
						gui_print_color("warning", "Failed to wipe crypto footer.\n");
					} else {
						LOGINFO("Successfully wiped crypto footer.\n");
					}
					free(buffer);
				}
			}
		}
		close(fd);
	} else {
		if (TWFunc::IOCTL_Get_Block_Size(Crypto_Key_Location.c_str()) >= 16384LLU) {
			string Command = "dd of='" + Crypto_Key_Location + "' if=/dev/zero bs=16384 count=1";
			TWFunc::Exec_Cmd(Command);
		} else {
			LOGINFO("Crypto key location reports size < 16K so not wiping crypto footer.\n");
		}
	}
}

bool TWPartition::Backup_Tar(PartitionSettings *part_settings, std::atomic<pid_t> *tar_fork_pid) {
	string Full_FileName;
	twrpTar tar;

	if (!Mount(true))
		return false;

	// The empty-password guard MUST come before GUI_Operation_Text + the
	// "backing_up" gui_msg. Otherwise the user first sees "Backing up X..." and
	// then the abort error — confusing, and it writes a phantom backup line to
	// the log. Defense in depth: PBKDF2(empty, salt) yields a key derivable from
	// the salt alone — semantically unsafe, so the GUI layer should prevent it too.
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
	string Password;
	if (Can_Encrypt_Backup) {
		DataManager::GetValue("tw_encrypt_backup", tar.use_encryption);
		if (tar.use_encryption) {
			DataManager::GetValue("tw_backup_password", Password);
			if (Password.empty()) {
				LOGERR("Backup_Tar: encryption requested but password is empty -- aborting backup.\n");
				gui_print_color("error", "Encryption is enabled but the backup password is empty -- backup aborted.\n");
				return false;
			}
		} else {
			tar.use_encryption = 0;
		}
	}
#endif

	TWFunc::GUI_Operation_Text(TW_BACKUP_TEXT, Backup_Display_Name, gui_parse_text("{@backing}"));
	gui_msg(Msg("backing_up=Backing up {1}...")(Backup_Display_Name));

	DataManager::GetValue(TW_USE_COMPRESSION_VAR, tar.use_compression);

#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
	if (Can_Encrypt_Backup && tar.use_encryption) {
		if (Use_Userdata_Encryption)
			tar.userdata_encryption = tar.use_encryption;
		tar.setpassword(Password);
	}
#endif

	Backup_FileName = Backup_Name + "." + Current_File_System + ".win";
	Full_FileName = part_settings->Backup_Folder + "/" + Backup_FileName;
	if (Has_Data_Media) {
		// When external app data (/data/media/0/Android) is included, the blanket
		// "no internal storage" warning is wrong — external app data physically
		// lives in internal storage; use the more precise _ext variant then.
		if (Mount_Point == "/data" && part_settings->external_app_data_included)
			gui_msg(Msg(msg::kWarning, "backup_storage_warning_ext=Backups of {1} include external app data but still exclude media such as pictures and downloads.")(Display_Name));
		else
			gui_msg(Msg(msg::kWarning, "backup_storage_warning=Backups of {1} do not include any files in internal storage such as pictures or downloads.")(Display_Name));
	}
	if (Mount_Point == "/data" && DataManager::GetIntValue(TW_IS_FBE)) {
		std::vector<users_struct>::iterator iter;
		std::vector<users_struct>* userList = PartitionManager.Get_Users_List();
		for (iter = userList->begin(); iter != userList->end(); iter++) {
			if (!(*iter).isDecrypted && (*iter).userId != "0") {
				gui_msg(Msg(msg::kWarning,
				"backup_storage_undecrypt_warning=Backup will not include some files from user {1} "
				"because the user is not decrypted.")((*iter).userId));
				backup_exclusions.add_absolute_dir("/data/system_ce/" + (*iter).userId);
				backup_exclusions.add_absolute_dir("/data/misc_ce/" + (*iter).userId);
				backup_exclusions.add_absolute_dir("/data/vendor_ce/" + (*iter).userId);
				backup_exclusions.add_absolute_dir("/data/media/" + (*iter).userId);
				backup_exclusions.add_absolute_dir("/data/user/" + (*iter).userId);
			}
		}
	}
	tar.part_settings = part_settings;
	tar.backup_exclusions = &backup_exclusions;
	tar.setdir(Backup_Path);
	tar.setfn(Full_FileName);
	tar.setsize(Backup_Size);
	tar.partition_name = Backup_Name;
	tar.backup_folder = part_settings->Backup_Folder;
	if (Mount_Point == "/data" && DataManager::GetIntValue("tw_backup_external_app_data") == 1) {
		unsigned long long ext_mb = part_settings->external_app_data_size;
		if (ext_mb > 0)
			gui_msg(Msg("backup_external_app_data_size=Including {1} MB external app data from internal storage")(ext_mb));
		}
	if (tar.createTarFork(tar_fork_pid) != 0)
		return false;
	return true;
}

bool TWPartition::Backup_Image(PartitionSettings *part_settings) {
	string Full_FileName, adb_file_name;

	TWFunc::GUI_Operation_Text(TW_BACKUP_TEXT, Display_Name, gui_parse_text("{@backing}"));
	gui_msg(Msg("backing_up=Backing up {1}...")(Backup_Display_Name));

	Backup_FileName = Backup_Name + "." + Current_File_System + ".win";

	if (part_settings->adbbackup) {
		Full_FileName = TW_ADB_BACKUP;
		// Only the filename in the TWIMG header: the former Backup_Folder prefix
		// was a fictional local path that never exists for an adb stream (mirror
		// of the Write_TWFN fix in twrpTar.cpp; restore sides use only the
		// basename anyway).
		adb_file_name  = Backup_FileName;
	}
	else
		Full_FileName = part_settings->Backup_Folder + "/" + Backup_FileName;

	// Per-partition size for the progress bar (Raw_Read_Write reads
	// partition_size in SetPartitionSize). NOT total_restore_size — that is the
	// restore grand total and must not be overwritten here.
	part_settings->partition_size = Backup_Size;

	if (part_settings->adbbackup) {
		if (!twadbbu::Write_TWIMG(adb_file_name, Backup_Size))
			return false;
	}

	// Optionally back up the /super image zstd-compressed (single stage).
	// Condition: only /super, no ADB backup (own TWIMG stream format), checkbox
	// on. The filename stays super.emmc.win (dd image); zstd is only a stream
	// stage, the uncompressed size is self-describing in the frame header
	// (Frame_Content_Size). All other image partitions stay raw. Raw and zstd
	// mechanics are unified in Raw_Read_Write (compress parameter).
	bool compress_super = !part_settings->adbbackup
	    && Mount_Point == "/super"
	    && DataManager::GetIntValue("tw_use_compression") == 1
	    && DataManager::GetIntValue("tw_compress_super") == 1;
	if (!Raw_Read_Write(part_settings, compress_super))
		return false;

	if (part_settings->adbbackup) {
		if (!twadbbu::Write_TWEOF())
			return false;
	}
	return true;
}

// The two image paths that need compression (Raw_Read_Write with compress=true,
// and Restore_Image_Test) drive zstd through an in-process ZstdStream
// (stage_engine.hpp):
//   compress:   caller --write_all()--> [ring] --> stage thread --> .win file
//   decompress: .win file --> stage thread --> [ring] --read_full()--> caller
// The caller keeps its own loop (progress, cancel, hashing) and only touches the
// ring. finish() returns the stage's error status; abort() cancels the stage on
// the exit: paths.

// Bidirectional dd path for image partitions: backup (block device ->
// .win file/ADB FIFO), restore/flash (file/FIFO -> block device). With
// compress=true (GUI backup ONLY, /super) the stream runs through an in-process
// zstd stage into the .win file. Self-describing: the announced
// frame_content_size lands in the zstd frame header (Frame_Content_Size), which
// the restore reads later — NO .info dependency. Deadlock-free (the caller only
// reads the block device + fills the ring; the stage drains it and writes the
// file -> no cyclic wait).
bool TWPartition::Raw_Read_Write(PartitionSettings *part_settings, bool compress) {
	unsigned long long RW_Block_Size, Remain = Backup_Size;
	int src_fd = -1, dest_fd = -1;
	ssize_t bs;
	bool ret = false;
	void* buffer = NULL;
	unsigned long long backedup_size = 0;
	string srcfn, destfn;
	ZstdStream zstream;
	const char* op = (part_settings->PM_Method == PM_RESTORE) ? "Restore" : "Backup"; // GUI/log context for LOGERR
	// ADB RESTORE is the only case with a FIFO SOURCE (srcfn = TW_ADB_RESTORE)
	// and an already-rolled stream counter (twrpAdbBuFifo TWIMG branch) — both
	// need special handling below. ADB BACKUP reads from the block device (the
	// FIFO is the DESTINATION there) and rolls exclusively here -> treated like GUI.
	const bool adb_restore_fifo = (part_settings->adbbackup && part_settings->PM_Method == PM_RESTORE);

	// compress is defined ONLY for the GUI backup: ADB streams images raw
	// (TWIMG format), and restore/flash never decompress here (demo:
	// Restore_Image_Test; final: raw dd). Misuse would be a programming error ->
	// reject hard instead of silently writing a raw image.
	if (compress && (part_settings->PM_Method != PM_BACKUP || part_settings->adbbackup)) {
		LOGERR("%s: Raw_Read_Write: compress is GUI-backup-only\n", op);
		return false;
	}

	if (part_settings->PM_Method == PM_BACKUP) {
		srcfn = Actual_Block_Device;
		if (part_settings->adbbackup)
			destfn = TW_ADB_BACKUP;
		else {
			destfn = part_settings->Backup_Folder + "/" + Backup_FileName;
		}
	}
	else {
#ifdef TW_ENABLE_BLKDISCARD
		BlkDiscard();
#endif
		destfn = Actual_Block_Device;
		if (part_settings->adbbackup) {
			srcfn = TW_ADB_RESTORE;
		} else {
			srcfn = part_settings->Backup_Folder + "/" + Backup_FileName;
			Remain = TWFunc::Get_File_Size(srcfn);
		}
	}

	src_fd = open(srcfn.c_str(), O_RDONLY | O_LARGEFILE);
	if (src_fd < 0) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(srcfn.c_str())(strerror(errno)));
		return false;
	}
	// Sequential read hint: enlarges the kernel read-ahead window for src_fd.
	// Works both ways: backup reads from the block device, restore reads from
	// the .win image file. Pure hint, no I/O.
	posix_fadvise64(src_fd, 0, 0, POSIX_FADV_SEQUENTIAL);

	dest_fd = open(destfn.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, S_IRUSR | S_IWUSR);
	if (dest_fd < 0) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(destfn.c_str())(strerror(errno)));
		goto exit;
	}

	if (compress) {
		// In-process zstd stage: this loop fills the ring, the stage writes dest_fd.
		// The announced frame_content_size == Backup_Size lands in the zstd frame
		// header -> self-describing, NO .info at restore (and zstd enforces it, so a
		// short/long stream fails instead of producing a silently wrong image).
		// Thread count from the compressor budget (TW_MAX_COMPRESSOR_THREADS,
		// falling back to MAX_PIPES when unset): /super is single-pipe, so it gets
		// the full budget (active=1).
		int worker_count = tw_affinity::compute_compressor_threads(1, 0);
		// Compression level from the GUI slider (tw_zstd_level, 1-19); default 1.
		// Read HERE in the caller (DataManager is recovery-only and must not be
		// touched from the stage thread) — identical to the file-based backup path.
		int lev = DataManager::GetIntValue("tw_zstd_level");
		if (lev < 1 || lev > 19) lev = 1;
		if (zstream.start_compress(dest_fd, lev, worker_count,
		                           (unsigned long long)Backup_Size, "Raw_Read_Write") < 0)
			goto exit;
		LOGINFO("Reading '%s', compressing (zstd) to '%s'\n", srcfn.c_str(), destfn.c_str());
	} else {
		LOGINFO("Reading '%s', writing '%s'\n", srcfn.c_str(), destfn.c_str());
	}

	if (part_settings->adbbackup) {
		RW_Block_Size = MAX_ADB_READ;
		bs = MAX_ADB_READ;
	}
	else {
		// 4 MB read/write chunks keep the read()/write() syscall count low. RAM
		// budget is uncritical (1 buffer per Raw_Read_Write call, no multi-pipe
		// multiplication).
		RW_Block_Size = 4ULL * 1024ULL * 1024ULL;
		bs = (ssize_t)(RW_Block_Size);
	}

	buffer = malloc((size_t)bs);
	if (!buffer) {
		LOGERR("%s: Raw_Read_Write failed to malloc\n", op);
		goto exit;
	}

	// ADB restore: NO roll here — the cumulative stream tracker was already
	// rolled by the FIFO thread (Restore_ADB_Backup, TWIMG branch), and
	// SetPartitionSize is NOT idempotent (previous_partitions_size += current
	// partition_size): a second call would count the partition twice in the
	// grand total (mirror of the !adbbackup guards in Restore_Tar and
	// Restore_Image_Test). GUI backup, ADB backup and GUI restore roll exactly
	// here (the sole roll of these paths).
	if (part_settings->progress && !adb_restore_fifo)
		part_settings->progress->SetPartitionSize(part_settings->partition_size);

	while (Remain > 0) {
		if (Remain < RW_Block_Size)
			bs = (ssize_t)(Remain);
		if (adb_restore_fifo) {
			// FIFO source: read() may legitimately return LESS than bs (bu pumps
			// 128-KB blocks ADB_DATA_BUFFER_SIZE > PIPE_BUF -> not atomic) — this
			// is NOT an error but requires a re-read (principle of tar_io_read,
			// libtar/block.c; identical in the demo branch Restore_Image_Test).
			// A "!= bs" single check would wrongly abort here. Only EOF (=pipe
			// break) or a real error aborts; EINTR is retried.
			size_t got = 0;
			while (got < (size_t)bs) {
				ssize_t r = read(src_fd, (char*)buffer + got, (size_t)bs - got);
				if (r < 0 && errno == EINTR)
					continue;
				if (r <= 0) {
					LOGERR("%s: Error reading ADB stream (%s)\n", op,
					       (r == 0) ? "unexpected EOF" : strerror(errno));
					goto exit;
				}
				got += (size_t)r;
			}
		} else if (read(src_fd, buffer, bs) != bs) {
			LOGERR("%s: Error reading source fd (%s)\n", op, strerror(errno));
			goto exit;
		}
		if (compress) {
			// write_all() transfers the WHOLE block (the ring loops internally) and
			// returns -1 only if the stage failed, so no partial-write/EINTR retry
			// loop is needed here.
			if (zstream.write_all(buffer, (size_t)bs) != 0) {
				LOGERR("%s: Error writing to zstd stage\n", op);
				goto exit;
			}
		} else if (write(dest_fd, buffer, bs) != bs) {
			LOGERR("%s: Error writing destination fd (%s)\n", op, strerror(errno));
			goto exit;
		}
		backedup_size += (unsigned long long)(bs);
		Remain -= (unsigned long long)(bs);
		if (part_settings->progress)
			part_settings->progress->UpdateSize(backedup_size);
		// DELIBERATELY only Check_Backup_Cancel(), NO stop_restore check:
		// Raw_Read_Write() serves both backup (block device -> file) and restore
		// (file -> block device, via Restore_Image). On restore the dd writes to
		// a live block device (e.g. boot, modem, dtbo). A cancel mid-write would
		// leave a half-flashed image -> softbrick.
		// The cancel lock for restore is enforced on two levels (see
		// partitionmanager.cpp Run_Restore + Cancel_Restore):
		//   1. GUI: the cancel button on the restore_run page is locked via
		//      tw_restore_cancelable=0 for RAW partitions (shows an info page
		//      instead of the cancel_restore_confirm swipe).
		//   2. C++: Cancel_Restore() refuses stop_restore.set_value(1) while
		//      restore_cancelable=0 — blocks ADB/script bypass.
		// Do NOT add a stop_restore.get_value() check here, or the lock becomes
		// useless as soon as someone copies the backup path as a template.
		if (PartitionManager.Check_Backup_Cancel() != 0)
			goto exit;
	}
	if (part_settings->progress)
		part_settings->progress->UpdateDisplayDetails(true);

	// compress: signal EOF to the stage (ring write side) -> join it (flush of the
	// final frame + error status) -> THEN fsync. Order encapsulated in finish();
	// on error -> exit: cleanup.
	if (compress && zstream.finish("Raw_Read_Write") < 0)
		goto exit;

	fsync(dest_fd);

	if (!part_settings->adbbackup && part_settings->PM_Method == PM_BACKUP) {
		tw_set_default_metadata(destfn.c_str());
		LOGINFO("Restored default metadata for %s\n", destfn.c_str());
	}

	ret = true;
exit:
	// On abort with a still-live stage: poison the ring (wakes it) + join. MUST run
	// BEFORE the close()s below — the stage writes dest_fd until it is joined.
	// No-op in the raw case and after a clean finish().
	zstream.abort();
	if (src_fd >= 0)
		close(src_fd);
	if (dest_fd >= 0) {
		// DONTNEED only in backup mode: dest is then a real file (.win image),
		// where trashing the cache would be counterproductive. On restore dest
		// is a block device -> the hint is pointless and can be skipped.
		if (ret && part_settings->PM_Method == PM_BACKUP && !part_settings->adbbackup)
			posix_fadvise64(dest_fd, 0, 0, POSIX_FADV_DONTNEED);
		close(dest_fd);
	}
	if (buffer)
		free(buffer);
	return ret;
}

bool TWPartition::Backup_Dump_Image(PartitionSettings *part_settings) {
	string Full_FileName, Command;

	TWFunc::GUI_Operation_Text(TW_BACKUP_TEXT, Display_Name, gui_parse_text("{@backing}"));
	gui_msg(Msg("backing_up=Backing up {1}...")(Backup_Display_Name));

	if (part_settings->progress)
		part_settings->progress->SetPartitionSize(Backup_Size);

	Backup_FileName = Backup_Name + "." + Current_File_System + ".win";
	Full_FileName = part_settings->Backup_Folder + "/" + Backup_FileName;

	Command = "dump_image " + MTD_Name + " '" + Full_FileName + "'";

	LOGINFO("Backup command: '%s'\n", Command.c_str());
	TWFunc::Exec_Cmd(Command);
	tw_set_default_metadata(Full_FileName.c_str());
	if (TWFunc::Get_File_Size(Full_FileName) == 0) {
		// Actual size may not match backup size due to bad blocks on MTD devices so just check for 0 bytes
		gui_msg(Msg(msg::kError, "backup_size=Backup file size for '{1}' is 0 bytes.")(Full_FileName));
		return false;
	}
	if (part_settings->progress)
		part_settings->progress->UpdateSize(Backup_Size);

	return true;
}

// Parses the zstd frame header (RFC 8878) from the first bytes and returns the
// uncompressed size (Frame_Content_Size). 18 bytes cover any possible header
// (max at did=3: 4 magic + 1 FHD + 1 window + 4 DID + 8 FCS). Returns true only
// for a valid zstd frame WITH a present FCS; else false (the caller treats that
// as "raw" / size unknown). NO .info reference.
static bool parse_zstd_frame_content_size(const unsigned char* buf, size_t n, uint64_t& out_size) {
	out_size = 0;
	if (n < 5)
		return false;
	// Magic 0x28 0xB5 0x2F 0xFD
	if (!(buf[0] == 0x28 && buf[1] == 0xB5 && buf[2] == 0x2F && buf[3] == 0xFD))
		return false;
	unsigned char fhd = buf[4];
	// The reserved bit (bit 3) MUST be 0 (RFC 8878). Check ONLY 0x08 — bit 4 is
	// "Unused" and a decoder MUST ignore it; checking 0x18 would wrongly reject
	// valid frames from conformant encoders.
	if (fhd & 0x08)
		return false;
	unsigned int fcs_flag   = (fhd >> 6) & 0x3;
	unsigned int single_seg = (fhd >> 5) & 0x1;
	unsigned int did_flag   = fhd & 0x3;
	unsigned int did_size   = (did_flag == 0) ? 0u : (1u << (did_flag - 1)); // {0,1,2,4}
	unsigned int fcs_size;
	switch (fcs_flag) {
		case 0:  fcs_size = single_seg ? 1u : 0u; break;
		case 1:  fcs_size = 2u; break;
		case 2:  fcs_size = 4u; break;
		default: fcs_size = 8u; break; // flag 3
	}
	if (fcs_size == 0)
		return false; // no size in the header (impossible for our image backups: they announce frame_content_size)
	size_t offset = 5u + (single_seg ? 0u : 1u) /*Window_Descriptor*/ + did_size;
	if (offset + fcs_size > n)
		return false;
	uint64_t v = 0;
	for (unsigned int i = 0; i < fcs_size; i++)
		v |= ((uint64_t)buf[offset + i]) << (8u * i); // little-endian
	if (fcs_size == 2)
		v += 256; // RFC special case for the 2-byte FCS field
	out_size = v;
	return true;
}

// Opens an image backup, reads the first bytes and returns — if it is a zstd
// frame with an embedded Frame_Content_Size (which our image backups always
// announce) — the uncompressed size. Else false (raw/not zstd/no FCS). Serves the
// correct restore progress (denominator = decompressed bytes), NO .info.
static bool peek_zstd_uncompressed_size(const string& path, uint64_t& out_size) {
	out_size = 0;
	int fd = open(path.c_str(), O_RDONLY | O_LARGEFILE);
	if (fd < 0)
		return false;
	unsigned char hdr[18];
	ssize_t n = read(fd, hdr, sizeof(hdr));
	close(fd);
	if (n < 4)
		return false;
	if (!(hdr[0] == 0x28 && hdr[1] == 0xB5 && hdr[2] == 0x2F && hdr[3] == 0xFD))
		return false; // not zstd -> raw
	return parse_zstd_frame_content_size(hdr, (size_t)n, out_size);
}

// Classifies the validity of a FILE-BASED backup from ONE BackupHeaderManager
// load (+ legacy .info) and returns the self-described size facts. Pure logic —
// NO gui_err / NO DataManager write: the technical reason goes to the log via
// LOGINFO, the GUI console message is made by the caller
// (Preflight_Restore_Backup) from the return enum. Factored out of
// Get_Restore_Size (DRY): Get_Restore_Size delegates the reject here, the early
// GUI firewall uses the same primitive. The valid/invalid decision mirrors
// Get_Restore_Size 1:1 (OpenAES-with-.info -> valid size here, reject only at
// extraction); the reject subtypes differentiate ONLY the message.
// Images/super (dd) + ADB the method gates itself (-> RV_VALID), so it is safe
// to call for ANY partition.
//   out_size    (optional): self-described size if known — DFP g-header
//                           backup_size or legacy plain-tar .info backup_size; 0 for
//                           gzip (caller computes via get_size).
//   out_ext_app (optional): DFP ext-app-data share (bytes) for the denominator subtraction; else 0.
Restore_Validity TWPartition::Probe_Restore_Backup(PartitionSettings *part_settings,
		unsigned long long *out_size, unsigned long long *out_ext_app, int *out_ead) {
	if (out_size)    *out_size = 0;
	if (out_ext_app) *out_ext_app = 0;
	if (out_ead)     *out_ead = 0;

	// Images/super (dd) + ADB are not part of the file-based preflight -> do not
	// block. (Makes Probe safe to call for ANY partition — the GUI firewall
	// iterates over all.)
	if (part_settings->adbbackup || Is_Image(Get_Restore_File_System(part_settings)))
		return RV_VALID;

	string Password;
	DataManager::GetValue("tw_restore_password", Password);
	// First segment: DFP split <Backup_FileName>000 first, else unsplit ".win".
	string seg000 = part_settings->Backup_Folder + "/" + Backup_FileName + "000";
	string probe = TWFunc::Path_Exists(seg000)
	             ? seg000
	             : part_settings->Backup_Folder + "/" + Backup_FileName;

	BackupHeaderManager hdr;
	hdr.Load(probe, Password);
	Archive_Type magic = hdr.GetType();   // outer type (even on reject)
	if (out_ead) *out_ead = hdr.GetEad(); // ead marker for the /data checkbox (caller uses it ONLY for /data)

	// OpenAES (legacy, unsupported): hdr.Load scanned ALL segments of
	// the partition via Get_Archive_Type_From_Segments (heterogeneous: win000
	// often plain gzip, "OA" only from win100..), so the outer type is reliably
	// LEGACY_ENCRYPTED here. Reject directly; the specific message is made by
	// the caller (Preflight or the Run_Restore guard via Emit_Restore_Validity_Error).
	if (magic == LEGACY_ENCRYPTED)
		return RV_REJECT_OPENAES;

	if (!hdr.IsLegacy()) {
		// DFP is self-describing: the size MUST come from the g-header, else incomplete.
		unsigned long long g = hdr.GetBackupSize();
		if (g > 0) {
			if (out_size)    *out_size = g;
			if (out_ext_app) *out_ext_app = hdr.GetExtAppDataSize();
			return RV_VALID;
		}
		LOGINFO("Probe_Restore_Backup: DFP backup '%s' without usable g-header backup_size -> reject\n", Backup_Name.c_str());
		return RV_NO_BACKUP_SIZE;
	}

	// Legacy: size from the native `.info` (backup_size > 0; 0/missing = unusable).
	InfoManager restore_info(part_settings->Backup_Folder + "/" + Backup_Name + ".info");
	unsigned long long info_size = 0;
	if (restore_info.LoadValues() == 0
	    && restore_info.GetValue("backup_size", info_size) == 0
	    && info_size > 0) {
		if (out_size) *out_size = info_size;
		return RV_VALID;
	}

	// No usable `.info`: ONLY gzip may fall back to pigz -l (unambiguous magic,
	// reliable gzip footer) -> RV_VALID with out_size=0 (caller: tar.get_size()).
	// Same valid/invalid decision as Get_Restore_Size `magic != LEGACY_COMPRESSED`; the
	// reject subtypes are only differentiated for the GUI console.
	if (magic == LEGACY_COMPRESSED)
		return RV_VALID;
	if (hdr.GetStatus() == DET_WRONG_PASSWORD) {
		LOGINFO("Probe_Restore_Backup: '%s' decrypt probe failed -> reject\n", Backup_Name.c_str());
		return RV_WRONG_PASSWORD;
	}
	if (hdr.GetStatus() == DET_REJECT_UNKNOWN) {
		LOGINFO("Probe_Restore_Backup: '%s' unknown/corrupt format -> reject\n", Backup_Name.c_str());
		return RV_REJECT_UNKNOWN;
	}
	LOGINFO("Probe_Restore_Backup: legacy plain-tar '%s' without usable .info backup_size -> reject\n", Backup_Name.c_str());
	return RV_LEGACY_NO_INFO;
}

unsigned long long TWPartition::Get_Restore_Size(PartitionSettings *part_settings) {
	part_settings->backup_validity = RV_VALID;   // strict preflight: reset per call (caller accumulates)

	// ADB stream: there is NO file to measure — the size already arrived in the
	// stream's twfilehdr (twimghdr.size -> total_restore_size, set by the
	// twrpAdbBuFifo loop BEFORE this call). Just cache it here for Restore_Tar
	// (SetPartitionSize uses Restore_Size). Otherwise tar.get_size() below would
	// run on the nonexistent stream "file" (Restore_Size=0/garbage ->
	// SetPartitionSize(0) -> broken ADB restore bar).
	if (part_settings->adbbackup) {
		Restore_Size = part_settings->total_restore_size;
		return Restore_Size;
	}

	// Self-describing: a zstd-compressed image backup (e.g. super.emmc.win)
	// carries its uncompressed size in the zstd frame header (Frame_Content_Size).
	// Return that as the restore size so the progress bar uses the DECOMPRESSED
	// bytes as denominator — not the compressed file size or a .info value.
	// (Raw images fall through via false to the legacy logic.)
	if (!part_settings->adbbackup) {
		string Img_FileName = part_settings->Backup_Folder + "/" + Backup_FileName;
		if (Is_Image(Get_Restore_File_System(part_settings))) {
			uint64_t uncompressed = 0;
			if (peek_zstd_uncompressed_size(Img_FileName, uncompressed)) {
				Restore_Size = uncompressed;
				LOGINFO("Get_Restore_Size: zstd image '%s', uncompressed size = %llu\n",
				        Backup_FileName.c_str(), (unsigned long long)Restore_Size);
				return Restore_Size;
			}
		}
	}

	// Strict restore preflight (size + validation) — the classification
	// (DFP/legacy/gzip, valid/invalid) is factored into Probe_Restore_Backup
	// (DRY: the early GUI firewall Preflight_Restore_Backup uses the same
	// primitive). Here only: reject (backup_validity, before the wipe) or adopt
	// the self-described size. Images/super (above) + ADB are exempt.
	if (!part_settings->adbbackup && !Is_Image(Get_Restore_File_System(part_settings))) {
		unsigned long long probe_size = 0, probe_ext = 0;
		Restore_Validity rv = Probe_Restore_Backup(part_settings, &probe_size, &probe_ext);
		if (rv != RV_VALID) {
			LOGINFO("Get_Restore_Size: backup '%s' not restorable (rv=%d) -> reject before wipe\n",
			        Backup_Name.c_str(), (int)rv);
			part_settings->backup_validity = rv;
			return 0;
		}
		if (probe_size > 0) {
			// The DFP g-header or legacy plain-tar .info provided the size directly.
			Restore_Size = probe_size;
			// When the ext-app checkbox is deselected, the /data/media/0/Android
			// entries are NOT extracted (extract skip) -> subtract the same
			// amount from the denominator, otherwise the bar ends < 100%.
			if (Has_Data_Media && Mount_Point == "/data"
			    && DataManager::GetIntValue("tw_has_external_app_data") == 1
			    && DataManager::GetIntValue("tw_restore_external_app_data") != 1) {
				unsigned long long ead = probe_ext;
				if (ead > Restore_Size) ead = Restore_Size;   // underflow guard
				Restore_Size -= ead;
				LOGINFO("Get_Restore_Size: ext-app-data excluded -> minus %llu B\n", (unsigned long long)ead);
			}
			LOGINFO("Get_Restore_Size: self-describing restore size = %llu\n", (unsigned long long)Restore_Size);
			return Restore_Size;
		}
		// probe_size == 0 -> legacy gzip: falls through to tar.get_size() below (-> uncompressedSize -> pigz -l).
	}

	string Full_FileName = part_settings->Backup_Folder + "/" + Backup_FileName;
	string Restore_File_System = Get_Restore_File_System(part_settings);

	if (Is_Image(Restore_File_System)) {
		Restore_Size = TWFunc::Get_File_Size(Full_FileName);
		return Restore_Size;
	}

	twrpTar tar;
	tar.setdir(Backup_Path);
	tar.setfn(Full_FileName);
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
	string Password;
	DataManager::GetValue("tw_restore_password", Password);
	if (!Password.empty())
		tar.setpassword(Password);
#endif
	tar.partition_name = Backup_Name;
	tar.backup_folder = part_settings->Backup_Folder;
	tar.part_settings = part_settings;
	Restore_Size = tar.get_size();
	return Restore_Size;
}

#ifdef TWRP_RESTORE_DEMO_MODE
// === Restore demo mode: consolidated TestRestore root (SSoT) ===
// All demo restores land under ONE root "/data/TestRestore", each partition its
// own subfolder <Backup_Name> (data/metadata/boot/super/modem/...). File restore
// (Restore_Tar) uses the root directly as setdir — the partition subfolder is
// created there from the archive path itself (include_root_dir=true -> entries
// start with data/..., metadata/..., etc.). dd-image restore
// (Restore_Image_Test) appends <Backup_Name> explicitly. This helper is the ONLY
// source of the root path. WHY exactly /data/TestRestore (and NOT
// /data/media/...): see the fscrypt comment in the body. Returns the root path,
// or "" on a mkdir error.
string TWPartition::Ensure_TestRestore_Root() {
	// IMPORTANT (fscrypt): the root MUST be at the /data top level
	// ("/data/TestRestore"), NOT under /data/media/0/... . Reason: /data/media
	// carries a CE fscrypt policy that is INHERITED by every newly created
	// subfolder. On a file restore libtar (extract.c:
	// fscrypt_policy_set_struct(realname,...)) calls
	// FS_IOC_SET_ENCRYPTION_POLICY for the per-dir policy stored in the backup
	// -> EEXIST (the folder already has the inherited CE policy), the error is
	// only logged+ignored -> the restore silently keeps the uniform inherited
	// descriptor instead of the original policy. /data/TestRestore (top level of
	// /data) lies OUTSIDE the encrypted subtrees -> a per-dir policy can be set
	// (empirically verified on-device). A tmpfs root (e.g. /TestRestore) is out
	// entirely: FS_IOC_SET_ENCRYPTION_POLICY -> ENOTTY.
	string root = "/data/TestRestore";
	if (mkdir(root.c_str(), 0755) != 0 && errno != EEXIST) {
		LOGERR("Ensure_TestRestore_Root: cannot create '%s': %s\n", root.c_str(), strerror(errno));
		return string();
	}
	return root;
}
#endif

bool TWPartition::Restore_Tar(PartitionSettings *part_settings) {
	string Full_FileName;
	bool ret = false;
	string Restore_File_System = Get_Restore_File_System(part_settings);
	// Name it more clearly when external app data (/data/media/0/Android) is restored too.
	string shown_name = Backup_Display_Name;
	if (Has_Data_Media && Mount_Point == "/data" && DataManager::GetIntValue("tw_restore_external_app_data") == 1)
		shown_name = gui_lookup("data_backup_ext", "Data (incl. external app data, excl. media)");

#ifdef TWRP_RESTORE_DEMO_MODE
	// === Restore demo mode ===
	// The restore target is redirected to the consolidated root /data/TestRestore
	// (partition subfolder via the archive path, below); wipe, removeDir and
	// capability operations are skipped so the daily-driver device can be tested
	// safely. The define stays active until the final build (daily-driver
	// protection); remove only after explicit user approval.
	LOGINFO("Restore_Tar: DEMO MODE active for partition '%s'\n", Backup_Display_Name.c_str());
	gui_msg(Msg("restoring=Restoring {1}...")(shown_name));
	if (!Mount(true)) {
		LOGERR("Restore_Tar DEMO: failed to mount %s\n", Mount_Point.c_str());
		return false;
	}
	if (!ReMount_RW(true)) {
		LOGERR("Restore_Tar DEMO: failed to remount %s RW\n", Mount_Point.c_str());
		return false;
	}
	// Consolidated root (SSoT): /data/TestRestore. setdir is the root here — the
	// partition subfolder (e.g. data/) is created during extraction from the
	// archive path itself (include_root_dir=true).
	string demo_dir = Ensure_TestRestore_Root();
	if (demo_dir.empty())
		return false;
	LOGINFO("Restore_Tar DEMO: target root = %s\n", demo_dir.c_str());
#else
	// Pre-wipe validation: multi-archive sequence check BEFORE the destructive
	// wipe runs. With gaps in the archive sequence the restore pipe worker would
	// crash mid-stream after the old data is already wiped — total data loss. An
	// early abort here keeps the old data intact.
	{
		string check_filename = part_settings->Backup_Folder + "/" + Backup_FileName;
		if (!twrpTar::validate_multi_archive_sequence(check_filename)) {
			LOGERR("Restore_Tar: archive sequence validation failed for '%s' -- aborting BEFORE wipe to preserve old data.\n", check_filename.c_str());
			gui_print_color("error", "Backup is corrupt or incomplete (gap in archive sequence) -- restore aborted before wipe. Old data preserved.\n");
			return false;
		}
	}

	if (Has_Android_Secure) {
		if (!Wipe_AndSec())
			return false;
	} else {
		gui_msg(Msg("wiping=Wiping {1}")(Backup_Display_Name));
		if (Has_Data_Media && Mount_Point == "/data" && Restore_File_System != Current_File_System) {
			gui_msg(Msg(msg::kWarning, "datamedia_fs_restore=WARNING: This /data backup was made with {1} file system! The backup may not boot unless you change back to {1}.")(Restore_File_System));
			if (!Wipe_Data_Without_Wiping_Media())
				return false;
		} else {
			if (!Wipe(Restore_File_System))
				return false;
		}
	}
	TWFunc::GUI_Operation_Text(TW_RESTORE_TEXT, shown_name, gui_parse_text("{@restoring_hdr}"));
	gui_msg(Msg("restoring=Restoring {1}...")(shown_name));

	// Remount as read/write as needed so we can restore the backup
	if (!ReMount_RW(true))
		return false;

	// If backup includes external app data and user opted in, wipe old folder first
	if (Has_Data_Media && Mount_Point == "/data"
	    && DataManager::GetIntValue("tw_restore_external_app_data") == 1) {
		gui_msg(Msg("removing_external_app_data=Removing previous external app data..."));
		TWFunc::removeDir(Mount_Point + "/media/0/Android", true);
	}
#endif

	Full_FileName = part_settings->Backup_Folder + "/" + Backup_FileName;
	twrpTar tar;
	tar.part_settings = part_settings;
#ifdef TWRP_RESTORE_DEMO_MODE
	tar.setdir(demo_dir);   // consolidated root; partition subfolder comes from the archive path
#else
	tar.setdir(Backup_Path);
#endif
	tar.setfn(Full_FileName);

	// Self-describing: the archive type is NOT read from `.info backup_type` but
	// determined directly from the archive by BackupHeaderManager::Load, driven
	// from extractTarFork() (4-byte magic + PAX-g marker for RAW + BAES inner sniff
	// 5<->7). Legacy vs this build's own layout follows from is_legacy_type(). For
	// this build's archives the restore size likewise comes from the PAX g-header
	// (Get_Restore_Size, TWRP.backup_size); only legacy backups still read a
	// `.info`. setpassword() below sets this->password BEFORE detection.

#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
	string Password;
	DataManager::GetValue("tw_restore_password", Password);
	if (!Password.empty())
		tar.setpassword(Password);
#endif
	// Loop 1 (Run_Restore size calc) already set Restore_Size for this
	// (sub)partition (it ALWAYS runs before Restore_Tar). Use the cache -> a
	// second hdr.Load is avoided (one PBKDF2 saved for BAES). Fallback only if,
	// against expectation, it was not measured (Restore_Size == 0).
	if (Restore_Size == 0)
		Get_Restore_Size(part_settings);   // sets Restore_Size internally
	// ADB restore: the partition roll is done by the twrpAdbBuFifo loop itself
	// (uniform for TWFN AND TWIMG — the raw path has no counterpart here) and
	// then corrected via Finish_Partition_Exact. A second roll here would
	// increase previous_partitions_size twice.
	if (!part_settings->adbbackup)
		part_settings->progress->SetPartitionSize(Restore_Size);
	// ext-app checkbox off -> exclude /media/0/Android from extraction (no wipe
	// needed; applies in demo + normal, all pipe workers).
	if (Has_Data_Media && Mount_Point == "/data"
	    && DataManager::GetIntValue("tw_has_external_app_data") == 1
	    && DataManager::GetIntValue("tw_restore_external_app_data") != 1) {
		tar.restore_exclude_path = Mount_Point + "/media/0/Android";   // include_root_dir=true -> archive path WITH /data (no Strip_Root_Dir)
		LOGINFO("Restore_Tar: ext-app-data checkbox off -> excluding %s from extraction\n", tar.restore_exclude_path.c_str());
	}
	if (tar.extractTarFork() != 0)
		ret = false;
	else
		ret = true;
#ifdef HAVE_CAPABILITIES
#ifndef TWRP_RESTORE_DEMO_MODE
	// Restore capabilities to the run-as binary
	// (Demo mode: deliberately skipped -- /system/bin/run-as is a real filesystem target)
	if (Mount_Point == PartitionManager.Get_Android_Root_Path() && Mount(true) && TWFunc::Path_Exists("/system/bin/run-as")) {
		struct vfs_cap_data cap_data;
		uint64_t capabilities = (1 << CAP_SETUID) | (1 << CAP_SETGID);

		memset(&cap_data, 0, sizeof(cap_data));
		cap_data.magic_etc = VFS_CAP_REVISION | VFS_CAP_FLAGS_EFFECTIVE;
		cap_data.data[0].permitted = (uint32_t) (capabilities & 0xffffffff);
		cap_data.data[0].inheritable = 0;
		cap_data.data[1].permitted = (uint32_t) (capabilities >> 32);
		cap_data.data[1].inheritable = 0;
		if (setxattr("/system/bin/run-as", XATTR_NAME_CAPS, &cap_data, sizeof(cap_data), 0) < 0) {
			LOGINFO("Failed to reset capabilities of /system/bin/run-as binary.\n");
		} else {
			LOGINFO("Reset capabilities of /system/bin/run-as binary successful.\n");
		}
	}
#endif
#endif
	if (Mount_Read_Only || Mount_Flags & MS_RDONLY)
		// Remount as read only when restoration is complete
		ReMount(true);

	return ret;
}

#ifdef TWRP_RESTORE_DEMO_MODE
// Demo/test-only restore for ANY image partition (super/boot/modem/dtbo/...):
// NEVER writes to the block device. Two sources:
//  - GUI/file: reads the backup (<name>.emmc.win), detects the zstd magic; if
//    compressed it is decompressed through an in-process ZstdStream stage, else
//    copied raw (to EOF).
//  - ADB stream (part_settings->adbbackup): reads exactly partition_size
//    (= twimghdr.size, set by twrpAdbBuFifo) bytes from the data FIFO
//    TW_ADB_RESTORE — ALWAYS raw (Backup_Image streams images over adb only via
//    Raw_Read_Write; twimghdr.compressed is uninitialized stack garbage for
//    TWIMG, Write_TWIMG never sets it -> deliberately ignored). NO header
//    peek/lseek/fadvise on the FIFO: not seekable, and the 18 peek bytes would
//    be missing from the stream (desyncing later partitions). Count-limited
//    consumption in MAX_ADB_READ blocks = mirror of Raw_Read_Write -> the
//    stream stays synchronous for TWENDADB/MD5.
// The image lands at /data/TestRestore/<Backup_Name>/<name>.emmc.win.raw and is
// hashed inline with SHA256 while writing. The result (hash + byte count) is
// stored in Demo_Test_*; the comparison against the live partition is done by
// Verify_Image_Test() AFTER the restore end, untimed (GUI: Run_Restore after
// rStop; ADB: Restore_ADB_Backup after TWENDADB). The size comes from the zstd
// frame header or the TWIMG stream header, NOT from a .info.
bool TWPartition::Restore_Image_Test(PartitionSettings *part_settings) {
	const unsigned long long RW_Block_Size = 4ULL * 1024ULL * 1024ULL;
	bool ret = false;
	int in_fd = -1, out_fd = -1;
	ZstdStream zstream;
	void* buffer = NULL;
	twrpDigest* digest_out = NULL;
	bool is_zstd = false, have_size = false;
	bool adb_stream = (part_settings->adbbackup != 0);          // source = data FIFO instead of a local backup file
	uint64_t content_size = 0;
	unsigned char hdr[18];
	ssize_t hn = 0;
	unsigned long long done_size = 0;
	string srcfn = adb_stream ? string(TW_ADB_RESTORE)
	                          : part_settings->Backup_Folder + "/" + Backup_FileName;
	string demo_root = Ensure_TestRestore_Root();               // /data/TestRestore (SSoT root, fscrypt-capable)
	string demo_dir = demo_root + "/" + Backup_Name;            // per-partition subfolder (data/boot/super/modem/...)
	string destfn = demo_dir + "/" + Backup_FileName + ".raw";
	string hash_out;

	LOGINFO("Restore_Image_Test: DEMO/TEST restore for '%s' from %s (never writes block device)\n",
	        Backup_Display_Name.c_str(), adb_stream ? "ADB stream" : "backup file");
	gui_msg(Msg("restoring=Restoring {1}...")(Backup_Display_Name));

	if (demo_root.empty())
		goto exit;   // root could not be created (Ensure_TestRestore_Root already logged it)

	in_fd = open(srcfn.c_str(), O_RDONLY | O_LARGEFILE);
	if (in_fd < 0) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(srcfn.c_str())(strerror(errno)));
		return false;
	}
	if (!adb_stream) {
		// File source only: read-ahead hint + zstd magic peek (+ lseek back).
		// Both would be wrong on the ADB FIFO: it is not seekable, and the 18
		// peek bytes belong to the stream's partition_size payload.
		posix_fadvise64(in_fd, 0, 0, POSIX_FADV_SEQUENTIAL);

		hn = read(in_fd, hdr, sizeof(hdr));
		if (hn < 4) {
			LOGERR("Restore_Image_Test: short header read (%zd)\n", hn);
			goto exit;
		}
		if (lseek(in_fd, 0, SEEK_SET) != (off_t)0) {
			LOGERR("Restore_Image_Test: lseek failed (%s)\n", strerror(errno));
			goto exit;
		}
		is_zstd = (hdr[0] == 0x28 && hdr[1] == 0xB5 && hdr[2] == 0x2F && hdr[3] == 0xFD);
		if (is_zstd) {
			have_size = parse_zstd_frame_content_size(hdr, (size_t)hn, content_size);
			if (have_size)
				LOGINFO("Restore_Image_Test: zstd backup, Frame_Content_Size = %llu\n", (unsigned long long)content_size);
			else
				LOGINFO("Restore_Image_Test: zstd backup, Frame_Content_Size unknown (decompress to EOF)\n");
		} else {
			LOGINFO("Restore_Image_Test: raw (uncompressed) backup detected\n");
		}
	} else {
		LOGINFO("Restore_Image_Test: ADB stream, raw copy of %llu bytes\n",
		        (unsigned long long)part_settings->partition_size);
	}

	// Progress/comparison size: for zstd the uncompressed size from the header
	// (NO .info), otherwise the partition size. Do NOT touch it for ADB:
	// partition_size already carries twimghdr.size there (twrpAdbBuFifo.cpp, the
	// stream truth) — setting it unconditionally would overwrite the correct
	// value (mirror of the comment in Restore_Image).
	if (!adb_stream) {
		if (is_zstd && have_size)
			part_settings->partition_size = content_size;
		else
			part_settings->partition_size = Backup_Size;
	}

	// Create the per-partition TestRestore subfolder (the root /data/TestRestore
	// was already created by Ensure_TestRestore_Root(); only the partition level
	// here; EEXIST ok).
	if (mkdir(demo_dir.c_str(), 0755) != 0 && errno != EEXIST) {
		LOGERR("Restore_Image_Test: cannot create '%s': %s\n", demo_dir.c_str(), strerror(errno));
		goto exit;
	}

	// Free-space check: the DECOMPRESSED image (partition_size) must fit on
	// internal storage. Reject conservatively up front instead of ENOSPC
	// mid-write.
	{
		struct statfs sfs;
		if (statfs(demo_dir.c_str(), &sfs) == 0) {
			unsigned long long freeb = (unsigned long long)sfs.f_bavail * (unsigned long long)sfs.f_bsize;
			if (freeb < part_settings->partition_size) {
				LOGERR("Restore_Image_Test: not enough free space (%llu < %llu) at %s\n",
				       freeb, (unsigned long long)part_settings->partition_size, demo_dir.c_str());
				gui_print_color("error", "Test restore aborted: not enough free space for the decompressed super image.\n");
				goto exit;
			}
		} else {
			LOGINFO("Restore_Image_Test: statfs failed (%s), skipping free-space check\n", strerror(errno));
		}
	}

	out_fd = open(destfn.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, S_IRUSR | S_IWUSR);
	if (out_fd < 0) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(destfn.c_str())(strerror(errno)));
		goto exit;
	}

	buffer = malloc((size_t)RW_Block_Size);
	if (!buffer) {
		LOGERR("Restore_Image_Test failed to malloc\n");
		goto exit;
	}

	digest_out = new twrpSHA256();
	digest_out->init();

	// ADB: NO SetPartitionSize here — the cumulative stream tracker was already
	// rolled by Restore_ADB_Backup (TWIMG branch). SetPartitionSize is NOT
	// idempotent (previous_partitions_size += current partition_size): a second
	// call would count the partition twice in the grand total (mirror of the
	// !adbbackup guard around Restore_Tar's roll).
	if (part_settings->progress && !adb_stream)
		part_settings->progress->SetPartitionSize(part_settings->partition_size);

	LOGINFO("Restore_Image_Test: extracting to '%s'\n", destfn.c_str());

	if (adb_stream) {
		// ADB: exactly partition_size (= twimghdr.size) bytes from the data FIFO
		// in MAX_ADB_READ blocks (mirror of Raw_Read_Write's adb branch: same
		// block size, same count-limited consumption -> the stream stays
		// byte-synchronous for later partitions/MD5TRAILER/TWENDADB). No EOF
		// loop: a premature EOF/short read = pipe break = error (like
		// Raw_Read_Write; bu writes 512-byte blocks -> the FIFO yields full
		// MAX_ADB_READ reads).
		unsigned long long Remain = part_settings->partition_size;
		ssize_t bs = MAX_ADB_READ;
		while (Remain > 0) {
			if (Remain < (unsigned long long)bs)
				bs = (ssize_t)Remain;
			// FIFO short reads are real (bu pumps 128-KB blocks > PIPE_BUF ->
			// not atomic): read() may return less than bs even though the stream
			// continues. So re-read block-exactly (principle of tar_io_read,
			// libtar/block.c) instead of a fragile "!= bs" single check; only
			// EOF (=pipe break) or a real error aborts. EINTR is retried
			// (process-wide signal landscape, e.g. SIGCHLD).
			{
				size_t got = 0;
				while (got < (size_t)bs) {
					ssize_t r = read(in_fd, (char*)buffer + got, (size_t)bs - got);
					if (r < 0 && errno == EINTR)
						continue;
					if (r <= 0) {
						LOGERR("Restore: Error reading ADB stream (%s)\n",
						       (r == 0) ? "unexpected EOF" : strerror(errno));
						goto exit;
					}
					got += (size_t)r;
				}
			}
			if (write(out_fd, buffer, (size_t)bs) != bs) {
				LOGERR("Restore: Error writing test file (%s)\n", strerror(errno));
				goto exit;
			}
			digest_out->update((const unsigned char*)buffer, (size_t)bs);
			done_size += (unsigned long long)bs;
			Remain -= (unsigned long long)bs;
			if (part_settings->progress)
				part_settings->progress->UpdateSize(done_size);
			// Demo/test restore: check the correct restore cancel flag (see RAW branch).
			// In demo mode the ADB image restore is cancelable (Restore_ADB_Backup
			// sets cancelable=1, since only a .raw file is written) -> this check
			// fires actively and aborts; the exit handler discards the partial .raw.
			// In the final build cancelable stays 0 (dd to the block device), no-op.
			if (PartitionManager.stop_restore.get_value() != 0)
				goto exit;
		}
	} else if (!is_zstd) {
		// RAW: backup file directly -> test file, hash inline (to EOF).
		ssize_t rb;
		while ((rb = read(in_fd, buffer, (size_t)RW_Block_Size)) > 0) {
			if (write(out_fd, buffer, (size_t)rb) != rb) {
				LOGERR("Restore: Error writing test file (%s)\n", strerror(errno));
				goto exit;
			}
			digest_out->update((const unsigned char*)buffer, (size_t)rb);
			done_size += (unsigned long long)rb;
			if (part_settings->progress)
				part_settings->progress->UpdateSize(done_size);
			// Demo/test restore: check the correct restore cancel flag (NOT
			// Check_Backup_Cancel()/stop_backup — that was always 0 during a
			// restore, a dead no-op). Behavior-neutral for /super (stop_restore is
			// 0 there anyway via the Cancel_Restore hard lock).
			if (PartitionManager.stop_restore.get_value() != 0)
				goto exit;
		}
		if (rb < 0) {
			LOGERR("Restore: Error reading backup file (%s)\n", strerror(errno));
			goto exit;
		}
	} else {
		// ZSTD: an in-process stage reads the backup file (in_fd) and pushes the
		// plaintext through the ring; this loop pulls it, writes the test file and
		// hashes inline (deadlock-free). zstd decompression is single-threaded by
		// design, so there is no worker count to pass.
		if (zstream.start_decompress(in_fd, "Restore_Image_Test") < 0)
			goto exit;
		// NOTE: in_fd stays OPEN here — the stage THREAD reads this very fd until
		// finish()/abort() joins it, so closing it now would yank it out from under
		// a live thread.
		// The exit: path closes it, and only AFTER zstream.abort()/finish().
		ssize_t rb;
		while ((rb = zstream.read_full(buffer, (size_t)RW_Block_Size)) > 0) {
			if (write(out_fd, buffer, (size_t)rb) != rb) {
				LOGERR("Restore: Error writing test file (%s)\n", strerror(errno));
				goto exit;
			}
			digest_out->update((const unsigned char*)buffer, (size_t)rb);
			done_size += (unsigned long long)rb;
			if (part_settings->progress)
				part_settings->progress->UpdateSize(done_size);
			// Demo/test restore: check the correct restore cancel flag (see RAW branch).
			if (PartitionManager.stop_restore.get_value() != 0)
				goto exit;
		}
		if (rb < 0) {
			LOGERR("Restore: Error reading from zstd stage\n");
			goto exit;
		}
		if (zstream.finish("Restore_Image_Test") < 0)
			goto exit;
	}

	fsync(out_fd);
	// Post-loop flush (identical to Backup_Image): forces the final state (100%)
	// to render NOW, while tw_busy=1 and BEFORE the multi-second phase-B
	// verification. Otherwise the screen would stay stuck at the throttled 99%,
	// because the only later 100% write (operation end) lands right before the
	// page change (operation_end -> tw_busy=0) and gets no render frame.
	if (part_settings->progress)
		part_settings->progress->UpdateDisplayDetails(true);
	hash_out = digest_out->return_digest_string();
	LOGINFO("Restore_Image_Test: extracted %llu bytes, sha256=%s\n", done_size, hash_out.c_str());

	// This function ends here (decompress + write + inline hash) and only stores
	// the result. The live-partition hash + comparison runs separately in
	// Verify_Image_Test(), called from Run_Restore AFTER rStop, or on ADB restore
	// from Restore_ADB_Backup AFTER the stream end (TWENDADB), untimed — keeping
	// the second 14-GB read out of this timed region, which would otherwise distort
	// "done (X seconds)" and avg_restore_rate.
	Demo_Test_Hash = hash_out;
	Demo_Test_Size = done_size;
	Demo_Test_Pending = true;
	ret = true;

exit:
	// Poison + join the stage FIRST: it reads in_fd and writes nothing else, so it
	// must be gone before in_fd is closed below. No-op after a clean finish().
	zstream.abort();
	if (in_fd >= 0)
		close(in_fd);
	if (out_fd >= 0) {
		// fsync only on success — on abort (cancel) or error, flushing the 14-GB
		// partial file achieves nothing and would drag out the cancel needlessly
		// (against the UFS wear reduction this is meant to serve).
		if (ret)
			fsync(out_fd);
		close(out_fd);
		// On abort/error discard the incomplete TestRestore file instead of
		// leaving a multi-GB partial on internal storage. On success it stays
		// (overwritten anyway on the next demo restore via O_TRUNC).
		if (!ret)
			unlink(destfn.c_str());
	}
	if (digest_out)
		delete digest_out;
	if (buffer)
		free(buffer);
	return ret;
}

// UNTIMED verification step: compares the live partition against the hash that
// Restore_Image_Test() computed while writing. Called from Run_Restore AFTER
// rStop so the second 14-GB read does not distort the restore time/rate ("done
// (X seconds)" / avg_restore_rate). Reads the partition ONLY O_RDONLY — never
// writes to the block device. Size/hash source: exclusively the Demo_Test_*
// values recorded by Restore_Image_Test() (NO .info).
bool TWPartition::Verify_Image_Test() {
	const unsigned long long RW_Block_Size = 4ULL * 1024ULL * 1024ULL;
	bool ret = false;
	int blk_fd = -1;
	void* buffer = NULL;
	twrpDigest* digest_src = NULL;
	unsigned long long Remain = Demo_Test_Size;
	time_t vStart, vStop;
	string hash_src;

	Demo_Test_Pending = false;   // whatever the outcome: do not verify again

	gui_print("Verifying %s test-restore against live partition (SHA256)...\n", Backup_Name.c_str());
	LOGINFO("Verify_Image_Test: hashing live '%s' (%llu bytes)\n",
	        Actual_Block_Device.c_str(), (unsigned long long)Demo_Test_Size);
	time(&vStart);

	blk_fd = open(Actual_Block_Device.c_str(), O_RDONLY | O_LARGEFILE);
	if (blk_fd < 0) {
		LOGERR("Verify_Image_Test: cannot open block device '%s' (%s)\n", Actual_Block_Device.c_str(), strerror(errno));
		goto exit;
	}
	posix_fadvise64(blk_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
	buffer = malloc((size_t)RW_Block_Size);
	if (!buffer) {
		LOGERR("Verify_Image_Test failed to malloc\n");
		goto exit;
	}
	digest_src = new twrpSHA256();
	digest_src->init();
	while (Remain > 0) {
		ssize_t want = (Remain < RW_Block_Size) ? (ssize_t)Remain : (ssize_t)RW_Block_Size;
		ssize_t rb = read(blk_fd, buffer, (size_t)want);
		if (rb != want) {
			LOGERR("Restore: Error reading block device for hash (%s)\n", strerror(errno));
			goto exit;
		}
		digest_src->update((const unsigned char*)buffer, (size_t)rb);
		Remain -= (unsigned long long)rb;
	}
	hash_src = digest_src->return_digest_string();
	time(&vStop);
	{
		int vsec = (int)difftime(vStop, vStart);
		if (vsec > 0)
			gui_print("Verify read rate: %llu MB/sec\n", Demo_Test_Size / (unsigned long long)vsec / 1048576);
	}
	LOGINFO("Verify_Image_Test: live '%s' sha256=%s\n", Backup_Name.c_str(), hash_src.c_str());

	if (Demo_Test_Hash == hash_src) {
		gui_print_color("highlight", "%s test-restore MATCH: decompressed image is byte-exact to the live partition (dd-restore would be safe).\n", Backup_Name.c_str());
		LOGINFO("Verify_Image_Test: MATCH (%s)\n", hash_src.c_str());
		ret = true;
	} else {
		gui_print_color("error", "%s test-restore MISMATCH: decompressed image differs from live partition!\n", Backup_Name.c_str());
		LOGERR("Verify_Image_Test: MISMATCH out=%s src=%s\n", Demo_Test_Hash.c_str(), hash_src.c_str());
		ret = false;
	}

exit:
	if (blk_fd >= 0)
		close(blk_fd);
	if (digest_src)
		delete digest_src;
	if (buffer)
		free(buffer);
	return ret;
}
#endif // TWRP_RESTORE_DEMO_MODE

bool TWPartition::Restore_Image(PartitionSettings *part_settings) {
	string Full_FileName;
	string Restore_File_System = Get_Restore_File_System(part_settings);

#ifdef TWRP_RESTORE_DEMO_MODE
	// === Restore demo mode ===
	// NO real dd restore on the daily driver: EVERY image partition (super,
	// boot, modem, dtbo, ...) is instead test-restored into a file under
	// /data/TestRestore/<Backup_Name>/ (Restore_Image_Test) + a SHA256 round-trip
	// comparison against the live partition (Verify_Image_Test, O_RDONLY only).
	// NEVER writes to the block device. Applies to GUI AND ADB restores: the ADB
	// branch reads raw from the data FIFO TW_ADB_RESTORE (details in the
	// Restore_Image_Test header); the verification is triggered there by
	// Restore_ADB_Backup after the stream end. The destructive
	// Raw_Read_Write/BlkDiscard path below is unreachable for images in demo mode.
	if (!Restore_Image_Test(part_settings))
		return false;
	// bu waits for TWEOF after EVERY image partition (closing the data FIFO,
	// freeing the stream for the next partition or the final TWENDADB). The real
	// restore path below sends it (adbbackup branch at the function end) — in
	// demo mode it MUST happen here too, otherwise bu spins forever after the
	// LAST dd image (livelock with Restore_ADB_Backup, proven on-device). Mirror
	// of the adbbackup branch at the real function end.
	if (part_settings->adbbackup) {
		if (!twadbbu::Write_TWEOF())
			return false;
	}
	return true;
#endif

	TWFunc::GUI_Operation_Text(TW_RESTORE_TEXT, Backup_Display_Name, gui_parse_text("{@restoring_hdr}"));
	gui_msg(Msg("restoring=Restoring {1}...")(Backup_Display_Name));

	if (part_settings->adbbackup)
		Full_FileName = TW_ADB_RESTORE;
	else
		Full_FileName = part_settings->Backup_Folder + "/" + Backup_FileName;

	if (Restore_File_System == "emmc") {
		// Set partition_size deliberately ONLY in the !adbbackup branch. For ADB,
		// Full_FileName == TW_ADB_RESTORE is a FIFO -> Get_File_Size would be
		// pointless (-1/0/blocks). The authoritative size is set per image in the
		// ADB path from the TWIMG stream header (twrpAdbBuFifo.cpp,
		// part_settings.partition_size = twimghdr.size, BEFORE Restore_Partition)
		// -> never stale. Setting it unconditionally here would overwrite that
		// correct value.
		if (!part_settings->adbbackup)
			part_settings->partition_size = (uint64_t)(TWFunc::Get_File_Size(Full_FileName));
		if (!Raw_Read_Write(part_settings))
			return false;
	} else if (Restore_File_System == "mtd" || Restore_File_System == "bml") {
		if (!Flash_Image_FI(Full_FileName, part_settings->progress))
			return false;
	}

	if (part_settings->adbbackup) {
		if (!twadbbu::Write_TWEOF())
			return false;
	}
	return true;
}

bool TWPartition::Update_Size(bool Display_Error) {
	bool ret = false, Was_Already_Mounted = false, ro = false;

	Find_Actual_Block_Device();

	if (Actual_Block_Device.empty())
		return false;

	ro = Mount_Read_Only;
	Mount_Read_Only = true;

	if (!Can_Be_Mounted && !Is_Encrypted) {
		if (TWFunc::Path_Exists(Actual_Block_Device) && Find_Partition_Size()) {
			Used = Size;
			Backup_Size = Size;
			goto success;
		}
		goto fail;
	}

	Was_Already_Mounted = Is_Mounted();

	if (Removable || Is_Encrypted) {
		if (!Mount(false))
			goto success;
	} else if (!Mount(Display_Error))
		goto fail;

	ret = Get_Size_Via_statfs(Display_Error);
	if (!ret || Size == 0) {
		if (!Get_Size_Via_df(Display_Error)) {
			if (!Was_Already_Mounted)
				UnMount(false);
			goto fail;
		}
	}

	if (Has_Data_Media) {
		if (Mount(Display_Error)) {
			Used = backup_exclusions.Get_Folder_Size(Mount_Point);
			Backup_Size = Used;
			int bak = (int)(Used / 1048576LLU);
			int fre = (int)(Free / 1048576LLU);
			LOGINFO("Data backup size is %iMB, free: %iMB.\n", bak, fre);
		} else {
			if (!Was_Already_Mounted)
				UnMount(false);
			goto fail;
		}
	} else if (Has_Android_Secure) {
		if (Mount(Display_Error))
			Backup_Size = backup_exclusions.Get_Folder_Size(Backup_Path);
		else {
			if (!Was_Already_Mounted)
				UnMount(false);
			goto fail;
		}
	}
	if (!Was_Already_Mounted)
		UnMount(false);
success:
	Mount_Read_Only = ro;
	return true;
fail:
	Mount_Read_Only = ro;
	return false;
}

bool TWPartition::Find_Wildcard_Block_Devices(const string& Device) {
	int mount_point_index = 0; // we will need to create separate mount points for each partition found and we use this index to name each one
	string Path = TWFunc::Get_Path(Device);
	string Dev = TWFunc::Get_Filename(Device);
	size_t wildcard_index = Dev.find("*");
	if (wildcard_index != string::npos)
		Dev = Dev.substr(0, wildcard_index);
	wildcard_index = Dev.size();
	DIR* d = opendir(Path.c_str());
	if (d == NULL) {
		LOGINFO("Error opening '%s': %s\n", Path.c_str(), strerror(errno));
		return false;
	}
	struct dirent* de;
	while ((de = readdir(d)) != NULL) {
		if (de->d_type != DT_BLK || strlen(de->d_name) <= wildcard_index || strncmp(de->d_name, Dev.c_str(), wildcard_index) != 0)
			continue;

		string item = Path + "/";
		item.append(de->d_name);
		if (PartitionManager.Find_Partition_By_Block_Device(item))
			continue;
		TWPartition *part = new TWPartition;
		char buffer[MAX_FSTAB_LINE_LENGTH];
		sprintf(buffer, "%s %s-%i auto defaults defaults", item.c_str(), Mount_Point.c_str(), ++mount_point_index);
		part->Process_Fstab_Line(buffer, false, NULL);
		char display[MAX_FSTAB_LINE_LENGTH];
		sprintf(display, "%s %i", Storage_Name.c_str(), mount_point_index);
		part->Storage_Name = display;
		part->Display_Name = display;
		part->Primary_Block_Device = item;
		part->Wildcard_Block_Device = false;
		part->Is_SubPartition = true;
		part->SubPartition_Of = Mount_Point;
		part->Is_Storage = Is_Storage;
		part->Can_Be_Mounted = true;
		part->Removable = true;
		part->Can_Be_Wiped = Can_Be_Wiped;
		part->Wipe_Available_in_GUI = Wipe_Available_in_GUI;
		part->Find_Actual_Block_Device();
		part->Update_Size(false);
		Has_SubPartition = true;
		PartitionManager.Output_Partition(part);
		PartitionManager.Add_Partition(part);
	}
	closedir(d);
	return (mount_point_index > 0);
}

void TWPartition::Find_Actual_Block_Device(void) {
	if (!Sysfs_Entry.empty() && Primary_Block_Device.empty() && Decrypted_Block_Device.empty()) {
		/* Sysfs_Entry.empty() indicates if this is a sysfs entry that begins with /device/
		 * If we have a syfs entry then we are looking for this device from a uevent add.
		 * The uevent add will set the primary block device based on the data we receive from
		 * after checking for adopted storage. If the device ends up being adopted, then the
		 * decrypted block device will be set instead of the primary block device. */
		Is_Present = false;
		return;
	}
	if (Wildcard_Block_Device && !Is_Adopted_Storage) {
		Is_Present = false;
		Actual_Block_Device = "";
		Can_Be_Mounted = false;
		if (!Find_Wildcard_Block_Devices(Primary_Block_Device)) {
			string Dev = Primary_Block_Device.substr(0, Primary_Block_Device.find("*"));
			if (TWFunc::Path_Exists(Dev)) {
				Is_Present = true;
				Can_Be_Mounted = true;
				Actual_Block_Device = Dev;
			}
		}
		return;
	} else if (Is_Decrypted && !Decrypted_Block_Device.empty()) {
		Actual_Block_Device = Decrypted_Block_Device;
		if (TWFunc::Path_Exists(Decrypted_Block_Device)) {
			Is_Present = true;
			return;
		}
	} else if (SlotSelect && TWFunc::Path_Exists(Primary_Block_Device + PartitionManager.Get_Active_Slot_Suffix())) {
		Actual_Block_Device = Primary_Block_Device + PartitionManager.Get_Active_Slot_Suffix();
		unlink(Primary_Block_Device.c_str());
		symlink(Actual_Block_Device.c_str(), Primary_Block_Device.c_str()); // we create a non-slot symlink pointing to the currently selected slot which may assist zips with installing
		Is_Present = true;
		return;
	} else if (TWFunc::Path_Exists(Primary_Block_Device)) {
		Is_Present = true;
		Actual_Block_Device = Primary_Block_Device;
		return;
	}
	if (!Alternate_Block_Device.empty() && TWFunc::Path_Exists(Alternate_Block_Device)) {
		Actual_Block_Device = Alternate_Block_Device;
		Is_Present = true;
	} else {
		Is_Present = false;
	}
}

void TWPartition::Recreate_Media_Folder(void) {
	string Command;
	string Media_Path = Mount_Point + "/media";

	if (Is_FBE) {
		LOGINFO("Not recreating media folder on FBE\n");
		return;
	}
	if (!Mount(true)) {
		gui_msg(Msg(msg::kError, "recreate_folder_err=Unable to recreate {1} folder.")(Media_Path));
	} else if (!TWFunc::Path_Exists(Media_Path)) {
		PartitionManager.Mount_By_Path(Symlink_Mount_Point, true);
		LOGINFO("Recreating %s folder.\n", Media_Path.c_str());
		mkdir(Media_Path.c_str(), 0770);
		string Internal_path = DataManager::GetStrValue("tw_internal_path");
		if (!Internal_path.empty()) {
			LOGINFO("Recreating %s folder.\n", Internal_path.c_str());
			mkdir(Internal_path.c_str(), 0770);
		}
#ifdef TW_INTERNAL_STORAGE_PATH
		mkdir(EXPAND(TW_INTERNAL_STORAGE_PATH), 0770);
#endif

		// Afterwards, we will try to set the
		// default metadata that we were hopefully able to get during
		// early boot.
		tw_set_default_metadata(Media_Path.c_str());
		if (!Internal_path.empty())
			tw_set_default_metadata(Internal_path.c_str());

		// Toggle mount to ensure that "internal sdcard" gets mounted
		PartitionManager.UnMount_By_Path(Symlink_Mount_Point, true);
		PartitionManager.Mount_By_Path(Symlink_Mount_Point, true);
	}
}

void TWPartition::Recreate_AndSec_Folder(void) {
	if (!Has_Android_Secure)
		return;
	LOGINFO("Creating %s: %s\n", Backup_Display_Name.c_str(), Symlink_Path.c_str());
	if (!Mount(true)) {
		gui_msg(Msg(msg::kError, "recreate_folder_err=Unable to recreate {1} folder.")(Backup_Name));
	} else if (!TWFunc::Path_Exists(Symlink_Path)) {
		LOGINFO("Recreating %s folder.\n", Backup_Name.c_str());
		PartitionManager.Mount_By_Path(Symlink_Mount_Point, true);
		mkdir(Symlink_Path.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		PartitionManager.UnMount_By_Path(Symlink_Mount_Point, true);
	}
}

uint64_t TWPartition::Get_Max_FileSize() {
	uint64_t maxFileSize = 0;
	const uint64_t constGB = (uint64_t) 1024 * 1024 * 1024;
	const uint64_t constTB = (uint64_t) constGB * 1024;
	const uint64_t constPB = (uint64_t) constTB * 1024;
	if (Current_File_System == "ext4")
		maxFileSize = 16 * constTB; //16 TB
	else if (Current_File_System == "vfat")
		maxFileSize = 4 * constGB; //4 GB
	else if (Current_File_System == "ntfs" || Current_File_System == "tntfs")
		maxFileSize = 256 * constTB; //256 TB
	else if (Current_File_System == "exfat")
		maxFileSize = 16 * constPB; //16 PB
	else if (Current_File_System == "ext3")
		maxFileSize = 2 * constTB; //2 TB
	else if (Current_File_System == "f2fs")
		maxFileSize = 3.94 * constTB; //3.94 TB
	else
		maxFileSize = 100000000L;
	return maxFileSize - 1;
}

bool TWPartition::Flash_Image(PartitionSettings *part_settings) {
	string Restore_File_System, full_filename;

	full_filename = part_settings->Backup_Folder + "/" + Backup_FileName;

	LOGINFO("Image filename is: %s\n", Backup_FileName.c_str());

	if (Backup_Method == BM_FILES) {
		LOGERR("Cannot flash images to file systems\n");
		return false;
	} else if (!Can_Flash_Img) {
		LOGERR("Cannot flash images to partitions %s\n", Display_Name.c_str());
		return false;
	} else {
		if (!Find_Partition_Size()) {
			LOGERR("Unable to find partition size for '%s'\n", Mount_Point.c_str());
			return false;
		}
		unsigned long long image_size = TWFunc::Get_File_Size(full_filename);
		if (image_size > Size) {
			LOGINFO("Size (%llu bytes) of image '%s' is larger than target device '%s' (%llu bytes)\n",
				image_size, Backup_FileName.c_str(), Actual_Block_Device.c_str(), Size);
			gui_err("img_size_err=Size of image is larger than target device");
			return false;
		}
		if (Backup_Method == BM_DD) {
			if (!part_settings->adbbackup) {
				if (Is_Sparse_Image(full_filename)) {
					return Flash_Sparse_Image(full_filename);
				}
			}
			return Raw_Read_Write(part_settings);
		} else if (Backup_Method == BM_FLASH_UTILS) {
			return Flash_Image_FI(full_filename, NULL);
		}
	}

	LOGERR("Unknown flash method for '%s'\n", Mount_Point.c_str());
	return false;
}

bool TWPartition::Is_Sparse_Image(const string& Filename) {
	uint32_t magic = 0;
	int fd = open(Filename.c_str(), O_RDONLY);
	if (fd < 0) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(Filename)(strerror(errno)));
		return false;
	}

	if (read(fd, &magic, sizeof(magic)) != sizeof(magic)) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(Filename)(strerror(errno)));
		close(fd);
		return false;
	}
	close(fd);
	if (magic == SPARSE_HEADER_MAGIC)
		return true;
	return false;
}

bool TWPartition::Flash_Sparse_Image(const string& Filename) {
	string Command;

#ifdef TW_ENABLE_BLKDISCARD
	BlkDiscard();
#endif

	gui_msg(Msg("flashing=Flashing {1}...")(Display_Name));

	Command = "simg2img '" + Filename + "' '" + Actual_Block_Device + "'";
	LOGINFO("Flash command: '%s'\n", Command.c_str());
	TWFunc::Exec_Cmd(Command);
	return true;
}

bool TWPartition::Flash_Image_FI(const string& Filename, ProgressTracking *progress) {
	string Command;
	unsigned long long file_size;

	gui_msg(Msg("flashing=Flashing {1}...")(Display_Name));
	if (progress) {
		file_size = (unsigned long long)(TWFunc::Get_File_Size(Filename));
		progress->SetPartitionSize(file_size);
	}
	// Sometimes flash image doesn't like to flash due to the first 2KB matching, so we erase first to ensure that it flashes
	Command = "erase_image " + MTD_Name;
	LOGINFO("Erase command: '%s'\n", Command.c_str());
	TWFunc::Exec_Cmd(Command);
	Command = "flash_image " + MTD_Name + " '" + Filename + "'";
	LOGINFO("Flash command: '%s'\n", Command.c_str());
	TWFunc::Exec_Cmd(Command);
	if (progress)
		progress->UpdateSize(file_size);
	return true;
}

void TWPartition::Change_Mount_Read_Only(bool new_value) {
	Mount_Read_Only = new_value;
}

bool TWPartition::Is_Read_Only() {
	return Mount_Read_Only;
}

int TWPartition::Check_Lifetime_Writes() {
	bool original_read_only = Mount_Read_Only;
	int ret = 1;

	Mount_Read_Only = true;
	if (Mount(false)) {
		Find_Actual_Block_Device();
		string temp = Actual_Block_Device;
		Find_Real_Block_Device(temp, false);
		string block = basename(temp.c_str());
		string file = "/sys/fs/" + Current_File_System + "/" + block + "/lifetime_write_kbytes";
		string result;
		if (TWFunc::Path_Exists(file)) {
			if (TWFunc::read_file(file, result) != 0) {
				LOGINFO("Check_Lifetime_Writes of '%s' failed to read_file\n", file.c_str());
			} else {
				LOGINFO("Check_Lifetime_Writes result: '%s'\n", result.c_str());
				if (result == "0") {
					ret = 0;
				}
			}
		} else {
			LOGINFO("Check_Lifetime_Writes file does not exist '%s'\n", file.c_str());
		}
		UnMount(true);
	} else {
		LOGINFO("Check_Lifetime_Writes failed to mount '%s'\n", Mount_Point.c_str());
	}
	Mount_Read_Only = original_read_only;
	return ret;
}

int TWPartition::Decrypt_Adopted() {
#ifdef TW_INCLUDE_CRYPTO
	int ret = 1;
	Is_Adopted_Storage = false;
	string Adopted_Key_File = "";

	if (!Removable)
		return ret;

	int fd = open(Alternate_Block_Device.c_str(), O_RDONLY);
	if (fd < 0) {
		LOGINFO("failed to open '%s'\n", Alternate_Block_Device.c_str());
		return ret;
	}
	char type_guid[80];
	char part_guid[80];

	uint32_t p_num;
	size_t last_digit = Primary_Block_Device.find_last_not_of("0123456789");
	if ((last_digit != string::npos) && (last_digit != Primary_Block_Device.length()-1))
		p_num = atoi(Primary_Block_Device.substr(last_digit + 1).c_str()) + 1;
	else
		p_num = 2;

	if (gpt_disk_get_partition_info(fd, p_num, type_guid, part_guid) == 0) {
		LOGINFO("type: '%s'\n", type_guid);
		LOGINFO("part: '%s'\n", part_guid);
		Adopted_GUID = part_guid;
		LOGINFO("Adopted_GUID '%s'\n", Adopted_GUID.c_str());
		if (strcmp(type_guid, TWGptAndroidExpand) == 0) {
			LOGINFO("android_expand found\n");
			Adopted_Key_File = "/data/misc/vold/expand_";
			Adopted_Key_File += part_guid;
			Adopted_Key_File += ".key";
			if (TWFunc::Path_Exists(Adopted_Key_File)) {
				Is_Adopted_Storage = true;
				/* Until we find a use case for this, I think it is safe
				 * to disable USB Mass Storage whenever adopted storage
				 * is present.
				 */
				if (p_num == 2) {
					// TODO: Properly detect mixed vs fully adopted storage. Maybe this
					// should be moved to partitionmanager instead, and disable after
					// checking all partitions. Also the presence of adopted storage does
					// not necessarily mean it's being used as Internal Storage
					LOGINFO("Detected adopted storage, disabling USB mass storage mode\n");
					DataManager::SetValue("tw_has_usb_storage", 0);
				}
			}
		}
	}

	if (Is_Adopted_Storage) {
		string Adopted_Block_Device = Alternate_Block_Device + "p" + TWFunc::to_string(p_num);
		if (!TWFunc::Path_Exists(Adopted_Block_Device)) {
			Adopted_Block_Device = Alternate_Block_Device + TWFunc::to_string(p_num);
			if (!TWFunc::Path_Exists(Adopted_Block_Device)) {
				LOGINFO("Adopted block device does not exist\n");
				goto exit;
			}
		}
		LOGINFO("key file is '%s', block device '%s'\n", Adopted_Key_File.c_str(), Adopted_Block_Device.c_str());
		char crypto_blkdev[MAXPATHLEN];
		std::string thekey;
		int fdkey = open(Adopted_Key_File.c_str(), O_RDONLY);
		if (fdkey < 0) {
			LOGINFO("failed to open key file\n");
			goto exit;
		}
		char buf[512];
		ssize_t n;
		while ((n = read(fdkey, &buf[0], sizeof(buf))) > 0) {
			thekey.append(buf, n);
		}
		close(fdkey);
		unsigned char* key = (unsigned char*) thekey.data();
		cryptfs_revert_ext_volume(part_guid);

		ret = cryptfs_setup_ext_volume(part_guid, Adopted_Block_Device.c_str(), key, thekey.size(), crypto_blkdev);
		if (ret == 0) {
			LOGINFO("adopted storage new block device: '%s'\n", crypto_blkdev);
			Decrypted_Block_Device = crypto_blkdev;
			Is_Decrypted = true;
			Is_Encrypted = true;
			Find_Actual_Block_Device();
			if (!Mount_Storage_Retry(false)) {
				LOGERR("Failed to mount decrypted adopted storage device\n");
				Is_Decrypted = false;
				Is_Encrypted = false;
				cryptfs_revert_ext_volume(part_guid);
				ret = 1;
			} else {
				UnMount(false);
				Has_Android_Secure = false;
				Symlink_Path = "";
				Symlink_Mount_Point = "";
				Backup_Name = Mount_Point.substr(1);
				Backup_Path = Mount_Point;
				TWPartition* sdext = PartitionManager.Find_Partition_By_Path("/sd-ext");
				if (sdext && sdext->Actual_Block_Device == Adopted_Block_Device) {
					LOGINFO("Removing /sd-ext from partition list due to adopted storage\n");
					PartitionManager.Remove_Partition_By_Path("/sd-ext");
				}
				Setup_Data_Media();
				Wipe_Available_in_GUI = true;
				Wipe_During_Factory_Reset = true;
				Can_Be_Backed_Up = true;
				Can_Encrypt_Backup = true;
				Use_Userdata_Encryption = true;
				Is_Storage = true;
				Storage_Name = "Adopted Storage";
				Is_SubPartition = true;
				SubPartition_Of = "/data";
				PartitionManager.Add_MTP_Storage(MTP_Storage_ID);
				DataManager::SetValue("tw_has_adopted_storage", 1);
			}
		} else {
			LOGERR("Failed to setup adopted storage decryption\n");
		}
	}
exit:
	close(fd);
	return ret;
#else
	LOGINFO("Decrypt_Adopted: no crypto support\n");
	return 1;
#endif
}

void TWPartition::Revert_Adopted() {
#ifdef TW_INCLUDE_CRYPTO
	if (!Adopted_GUID.empty()) {
		PartitionManager.Remove_MTP_Storage(Mount_Point);
		UnMount(false);
		cryptfs_revert_ext_volume(Adopted_GUID.c_str());
		Is_Adopted_Storage = false;
		Is_Encrypted = false;
		Is_Decrypted = false;
		Decrypted_Block_Device = "";
		Find_Actual_Block_Device();
		Wipe_During_Factory_Reset = false;
		Can_Be_Backed_Up = false;
		Can_Encrypt_Backup = false;
		Use_Userdata_Encryption = false;
		Is_SubPartition = false;
		SubPartition_Of = "";
		Has_Data_Media = false;
		Storage_Path = Mount_Point;
		if (!Symlink_Mount_Point.empty()) {
			TWPartition* Dat = PartitionManager.Find_Partition_By_Path("/data");
			if (Dat) {
				Dat->UnMount(false);
				Dat->Symlink_Mount_Point = Symlink_Mount_Point;
			}
			Symlink_Mount_Point = "";
		}
	}
#else
	LOGINFO("Revert_Adopted: no crypto support\n");
#endif
}

void TWPartition::Set_Backup_FileName(string fname) {
	Backup_FileName = fname;
}

string TWPartition::Get_Backup_Name() {
	return Backup_Name;
}

string TWPartition::Get_Mount_Point() {
	return Mount_Point;
}

void TWPartition::Set_Block_Device(std::string block_device) {
	Primary_Block_Device = Actual_Block_Device = block_device;
}

bool TWPartition::Get_Super_Status() {
	return Is_Super;
}

void TWPartition::Set_Can_Be_Backed_Up(bool val) {
	Can_Be_Backed_Up = val;
}

void TWPartition::Set_Can_Be_Wiped(bool val) {
	Can_Be_Wiped = val;
	Wipe_Available_in_GUI = val;
}

std::string TWPartition::Get_Backup_FileName() {
	return Backup_FileName;
}

std::string TWPartition::Get_Display_Name() {
	return Display_Name;
}

bool TWPartition::Is_SlotSelect() {
	return SlotSelect;
}

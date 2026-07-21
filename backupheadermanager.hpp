/*
	Copyright 2026 TeamWin
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

#ifndef _BACKUPHEADERMANAGER_HPP_HEADER
#define _BACKUPHEADERMANAGER_HPP_HEADER

#include <string>
#include <map>
#include "twrp-functions.hpp"   // Archive_Type / DetectResult / TWFunc::is_legacy_type

using namespace std;

// Reads the TWRP.* PAX g-header values from a backup's first segment
// (in-process: decrypt 5/7 + zstd decompress 6/7 + parse). Counterpart to
// InfoManager: Info reads the .info FILE, BackupHeaderManager reads the
// g-header INSIDE the archive. Compiled into both recovery and twrpTarMain.
// Clockwork principle like InfoManager: one peel (layer removal) + one generic
// parse (all TWRP.* records -> map) -> any number of getters. A future g-key
// only needs a typed getter, not a new peek.
class BackupHeaderManager
{
public:
	BackupHeaderManager();

	// Peeks ONE known segment (exact path) and parses all TWRP.* records into
	// mHeader. password is only needed for types 5/7 (encrypted) — callers
	// guarantee it is never empty on the encrypted branch (after password
	// validation). false = not peekable / error.
	bool Load(const string& segment, const string& password);

	// Generic getter (like InfoManager). GetValue: 0 = ok, -1 = key missing.
	int    GetValue(const string& key, string& value) const;

	// Typed convenience getters
	int                GetEad() const;         // TWRP.ead:         1/0, -1 = no marker
	unsigned long long GetBackupSize() const;  // TWRP.backup_size: 0  = no marker
	unsigned long long GetExtAppDataSize() const; // TWRP.ext_app_data_size: 0 = no marker

	// Detection result (consolidated via TWFunc::detect_archive_type in Load).
	Archive_Type GetType() const;              // detected archive type (outer type even on reject)
	DetectResult GetStatus() const;            // DET_OK / reject reason (for TWFunc::emit_detect_reject)
	bool         IsLegacy() const;             // is_legacy_type(GetType()): legacy (0-3) vs this build (4-7)

	// Outer archive type from the magic (outer only, NO decrypt) — for callers
	// that only need "which type?" (Set_Restore_Files / uncompressedSize /
	// Try_Decrypting_Backup outer check).
	static Archive_Type GetFileType(const string& fn);

private:
	// Detection internals; called from Load/detect_archive_type/GetFileType.
	static Archive_Type Get_File_Type(string fn);                         // outer sniff: 4-byte magic
	// Partition type: scans ALL segments of the partition (glob from the first
	// segment) and calls Get_File_Type per segment -> detects heterogeneous
	// legacy OpenAES (gzip OR plain-tar lead + "OA" only in later segments win100..;
	// plain-tar lead = compression off). MUST stay an all-segment scan for BOTH lead
	// types — a first-segment-only probe would let OpenAES archives through as
	// plain gzip/plain tar. Used by detect_archive_type + Load (outer type per
	// partition).
	static Archive_Type Get_Archive_Type_From_Segments(string fn);
	static int          Try_Decrypting_File(string fn, const string& password,
	                        Archive_Type *out_archive_type = nullptr, string *out_plaintext = nullptr); // inner BAES sniff
	static DetectResult detect_archive_type(const string& probe, const string& password,
	                        Archive_Type *out, string *out_plaintext = nullptr);                        // orchestration

	map<string, string> mHeader;
	bool mLoaded;
	Archive_Type mType;     // set by Load (always, outer type even on reject)
	DetectResult mStatus;   // set by Load (DET_OK / reject reason)

	// Peels the plaintext tar head for the (already detected) DFP type; plain =
	// the first chunk decrypted by TWFunc::detect_archive_type via
	// Try_Decrypting_File (only set for 5/7).
	bool decode_head(const string& segment, Archive_Type t, const string& plain, string& tarhead);
	static bool zstd_head(const char* src, size_t src_len, string& out, size_t out_cap); // zstd-decode the first KBs
	void parse(const string& tarhead);                                                   // scans ALL "TWRP.*=" -> mHeader
};

#endif // _BACKUPHEADERMANAGER_HPP_HEADER

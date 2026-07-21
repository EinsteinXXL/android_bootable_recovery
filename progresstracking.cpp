/*
        Copyright 2016 bigbiff/Dees_Troy TeamWin
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

// Progress tracking class for tracking backup progess and updating the progress bar as appropriate


#include "progresstracking.hpp"
#include "twcommon.h"
#ifndef BUILD_TWRPTAR_MAIN
#include "gui/gui.hpp"
#include "data.hpp"
#endif
#include "twrp-functions.hpp"
#include <time.h>

const int32_t update_interval_ms = 200; // Update interval in ms

ProgressTracking::ProgressTracking(const unsigned long long backup_size) {
	total_size = backup_size;
	partition_size = 0;
	file_count = 0;
	current_size = 0;
	current_count = 0;
	previous_partitions_size = 0;
	display_file_count = false;
	clock_gettime(CLOCK_MONOTONIC, &last_update);
}

void ProgressTracking::SetPartitionSize(const unsigned long long part_size) {
	previous_partitions_size += partition_size;
	// Reset current_size on the partition roll — otherwise, until the new
	// partition's first UpdateSize(), the counter is previous(new) + current(stale
	// from the old partition), briefly spiking the bar (e.g. to 100% for two
	// equally sized dd-image partitions) before falling back. Affects GUI and ADB
	// backup alike (shared Raw_Read_Write path).
	current_size = 0;
	partition_size = part_size;
	UpdateDisplayDetails(true);
}

void ProgressTracking::SetSizeCount(const unsigned long long part_size, unsigned long long f_count) {
	previous_partitions_size += partition_size;
	current_size = 0;   // see SetPartitionSize: avoid the stale-current_size spike on partition roll
	partition_size = part_size;
	file_count = f_count;
	display_file_count = (file_count != 0);
	UpdateDisplayDetails(true);
}

// The denominator total_size is seeded in the ctor from the Backup_Size estimate
// (Get_Folder_Size overcounts hardlink instances and symlink lengths), before the
// walk that yields the exact content sum. Correct it per partition by the exact
// delta (exact - Total_Backup_Size, usually negative) so the data bar ends at
// exactly 100% instead of 99%. Clamped at 0.
void ProgressTracking::CorrectTotalSize(long long delta) {
	long long corrected = (long long)total_size + delta;
	total_size = (corrected > 0) ? (unsigned long long)corrected : 0;
	UpdateDisplayDetails(true);
}

// ADB restore only: the stream announces ESTIMATES (twfilehdr.size = backup-time
// Backup_Size estimate; the stream-header total is their sum), while the actually
// extracted content bytes (current_size, reported via UpdateSize — hardlinks and
// symlinks count 0, same accounting as exact_backup_size) are only known at the
// end of a partition. Reconcile both: correct the total by (exact - announced)
// AND set partition_size to the exact value, so the next partition's
// SetPartitionSize roll carries the exact amount into previous_partitions_size —
// bar and MB counter end byte-exact at 100%. The caller (twrpAdbBuFifo restore
// loop) zeroes current_size via UpdateSize(0) before each partition so no stale
// value from the previous partition leaks in.
void ProgressTracking::Finish_Partition_Exact() {
	CorrectTotalSize((long long)current_size - (long long)partition_size);
	partition_size = current_size;
}

void ProgressTracking::UpdateSize(const unsigned long long size) {
	current_size = size;
	UpdateDisplayDetails(false);
}

void ProgressTracking::UpdateSizeCount(const unsigned long long size, const unsigned long long count) {
	current_size = size;
	current_count = count;
	UpdateDisplayDetails(false);
}

void ProgressTracking::DisplayFileCount(const bool display) {
	display_file_count = display;
	UpdateDisplayDetails(true);
}

void ProgressTracking::UpdateDisplayDetails(const bool force) {
#ifndef BUILD_TWRPTAR_MAIN
	if (!force) {
		// Do something to check the time frame and only update periodically to reduce the total number of GUI updates
		timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);

		int32_t diff = TWFunc::timespec_diff_ms(last_update, now);
		if (diff < update_interval_ms)
			return;
	}
	clock_gettime(CLOCK_MONOTONIC, &last_update);
	double display_percent = 0.0, progress_percent;
	string size_prog = gui_lookup("size_progress", "%lluMB of %lluMB, %i%%");
	if (size_prog.find("%n") != string::npos)
		size_prog = "%lluMB of %lluMB, %i%%";
	char size_progress[1024];

	if (total_size != 0) // prevent division by 0
		display_percent = (double)(current_size + previous_partitions_size) / (double)(total_size) * 100;
	snprintf(size_progress, sizeof(size_progress), size_prog.c_str(), (current_size + previous_partitions_size) / 1048576, total_size / 1048576, (int)(display_percent));
	DataManager::SetValue("tw_size_progress", size_progress);
	progress_percent = (display_percent / 100);
	DataManager::SetProgress((float)(progress_percent));

	if (!display_file_count || file_count == 0) {
		DataManager::SetValue("tw_file_progress", "");
	} else {
		string file_prog = gui_lookup("file_progress", "%llu of %llu files, %i%%");
		if (file_prog.find("%n") != string::npos)
			file_prog = "%llu of %llu files, %i%%";
		char file_progress[1024];

		display_percent = (double)(current_count) / (double)(file_count) * 100;
		snprintf(file_progress, sizeof(file_progress), file_prog.c_str(), current_count, file_count, (int)(display_percent));
		DataManager::SetValue("tw_file_progress", file_progress);
	}
#endif
}

/*
		Copyright 2013 to 2016 TeamWin
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
#include <dirent.h>
#include <errno.h>
#include <string>
#include <vector>
#include "exclude.hpp"
#include "twrp-functions.hpp"
#include "gui/gui.hpp"
#include "twcommon.h"

using namespace std;

extern bool datamedia;

TWExclude::TWExclude() {
	add_relative_dir(".");
	add_relative_dir("..");
	add_relative_dir("lost+found");
}

void TWExclude::add_relative_dir(const string& dir) {
	relativedir.push_back(dir);
}

void TWExclude::clear_relative_dir(string dir) {
	vector<string>::iterator iter = relativedir.begin();
	while (iter != relativedir.end()) {
		if (*iter == dir)
			iter = relativedir.erase(iter);
		else
			iter++;
	}
}

void TWExclude::add_absolute_dir(const string& dir) {
	absolutedir.push_back(TWFunc::Remove_Trailing_Slashes(dir));
}

uint64_t TWExclude::Get_Folder_Size(const string& Path) {
	DIR* d;
	struct dirent* de;
	struct stat st;
	uint64_t dusize = 0;
	string FullPath;

	d = opendir(Path.c_str());
	if (d == NULL) {
		gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(Path)(strerror(errno)));
		return 0;
	}

	while ((de = readdir(d)) != NULL) {
		FullPath = Path + "/" + de->d_name;
		if (lstat(FullPath.c_str(), &st)) {
			gui_msg(Msg(msg::kError, "error_opening_strerr=Error opening: '{1}' ({2})")(FullPath)(strerror(errno)));
			LOGINFO("Real error: Unable to stat '%s'\n", FullPath.c_str());
			continue;
		}
		if (check_skip_dirs(FullPath))
			continue;
		if (S_ISDIR(st.st_mode) && de->d_type != DT_SOCK) {
			dusize += Get_Folder_Size(FullPath);
		} else if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
			dusize += (uint64_t)(st.st_size);
		}
	}
	closedir(d);
	return dusize;
}

bool TWExclude::check_relative_skip_dirs(const string& dir) {
	return std::find(relativedir.begin(), relativedir.end(), dir) != relativedir.end();
}

	bool TWExclude::check_absolute_skip_dirs(const string& path) {
		if (std::find(absolutedir.begin(), absolutedir.end(), path) != absolutedir.end())
			return true;
		// Prefix match: path lies below an excluded directory. The boundary check
		// path[excl.size()] == '/' prevents false positives like "/data/media2"
		// matching "/data/media".
		for (const auto& excl : absolutedir) {
			if (path.size() > excl.size() &&
			    path.compare(0, excl.size(), excl) == 0 &&
			    path[excl.size()] == '/')
				return true;
		}
		return false;
	}

void TWExclude::Add_External_App_Data_Inclusion(const string& path) {
	external_app_data_inclusion.push_back(TWFunc::Remove_Trailing_Slashes(path));
}

void TWExclude::Clear_External_App_Data_Inclusion() {
	external_app_data_inclusion.clear();
}

bool TWExclude::Check_External_App_Data_Inclusion(const string& path) {
	for (const auto& inc : external_app_data_inclusion) {
		// Path equals the inclusion
		if (path == inc)
			return true;
		// Path lies below the inclusion
		if (path.size() > inc.size() &&
			path.compare(0, inc.size(), inc) == 0 &&
			path[inc.size()] == '/')
			return true;
		// Path is an ancestor of the inclusion — must not be skipped, or the walk
		// could never descend into /data/media to reach /data/media/0/Android.
		if (inc.size() > path.size() &&
			inc.compare(0, path.size(), path) == 0 &&
			inc[path.size()] == '/')
			return true;
	}
	return false;
}

// Strict variant of Check_External_App_Data_Inclusion for the exact ext-app-data
// size accounting in the backup walk (g-header TWRP.ext_app_data_size): only paths
// equal to or below an inclusion entry count — ancestors (e.g. "/data/media") do not.
bool TWExclude::Is_External_App_Data_Path(const string& path) {
	string normalized = TWFunc::Remove_Trailing_Slashes(path);
	for (const auto& inc : external_app_data_inclusion) {
		if (normalized == inc)
			return true;
		if (normalized.size() > inc.size() &&
			normalized.compare(0, inc.size(), inc) == 0 &&
			normalized[inc.size()] == '/')
			return true;
	}
	return false;
}

bool TWExclude::check_skip_dirs(const string& path) {
	string normalized = TWFunc::Remove_Trailing_Slashes(path);

	// Relative exclusions (".", "..", "lost+found") MUST be checked before the
	// inclusion check: otherwise "." and ".." count as "below an inclusion" and
	// the walk recurses endlessly into /data/media/0/Android/./././... until FD
	// exhaustion ("too many open files") or SIGSEGV.
	size_t slashIdx = normalized.find_last_of('/');
	if (slashIdx != std::string::npos && slashIdx+1 < normalized.size()) {
		if (check_relative_skip_dirs(normalized.substr(slashIdx+1)))
			return true;
	}

	// Inclusions override absolute exclusions: never skip a path that is (or has
	// an ancestor) in the external-app-data inclusion list.
	if (Check_External_App_Data_Inclusion(normalized))
		return false;

	return check_absolute_skip_dirs(normalized);
}

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

#ifndef TWRPADBFIFO_HPP
#define TWRPADBFIFO_HPP

#include <string>
#include <pthread.h>
#include <sys/types.h>
#include <atomic>

#define TW_ADB_FIFO "/tmp/twadbfifo"

// twadbd mode state (file-scope atomics in twrpAdbBuFifo.cpp). Free functions so
// the GUI action "adbbucancel" (gui/action.cpp, action_page button) can also end
// the mode -- the twrpAdbBuFifo instance lives only locally in twrp.cpp::main.
bool twrp_adbbu_mode_active(void);	// true while twadbd is running (pid > 0)
void twrp_adbbu_cancel_mode(void);	// SIGTERM to twadbd; the lifecycle waitpid does the reap/cleanup

class twrpAdbBuFifo {
	public:
		twrpAdbBuFifo(void);
		pthread_t threadAdbBuFifo(void);
	private:
		bool start(void);
		bool Backup_ADB_Command(std::string Options);
		void Check_Adb_Fifo_For_Events(void);
		// gui_stream=false (PC adb restore): the engine owns the GUI completion
		// (run page + ADB_Bu_Operation_Start/_End). gui_stream=true (GUI .ab restore
		// via bu --twrp stream): the GUI action thread owns start+completion; the
		// engine only reports the real status in tw_adbbu_stream_status (via bu exit
		// the action knows only "streamed" -- wrongly 0 on cancel/engine error).
		bool Restore_ADB_Backup(bool gui_stream = false);
		// PTY-free ADB backup mode (twadbd), triggered via `adb shell adbbu start`
		bool Start_ADB_Bu_Mode(void);
		bool Cancel_ADB_Bu_Mode(void);
		void ADB_Bu_Mode_Lifecycle(void);
		void Show_ADB_Bu_Notice(void);	// bu refused a stock-adbd PTY -> notify the user in the GUI log (red, overlay)
		// GUI parity mimic of GUIAction::operation_start/_end for the FIFO-driven
		// ADB ops (they do NOT run in the GUI action thread but enter the same run
		// pages backup_run/restore_run). Details in the .cpp.
		static void ADB_Bu_Operation_Start(const std::string& operation_name);
		static void ADB_Bu_Operation_End(int status);
		typedef bool (twrpAdbBuFifo::*ThreadPtr)(void);
		typedef void* (*PThreadPtr)(void *);
		int adb_fifo_fd;
};
#endif

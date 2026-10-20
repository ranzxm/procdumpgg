#pragma once

#include "dump_runner.h"
#include <array>
#include <future>

namespace pd_gui
{
	class app
	{
		HWND window_;
		dump_runner runner_;
		std::vector<process_info> processes_;
		std::array<char, 128> filter_{};
		std::array<char, 24> pid_{};
		std::array<char, 2048> output_{};
		std::array<char, 128> module_filter_{};
		int scope_ = 0;
		int selected_module_ = -1;
		module_snapshot modules_;
		std::future<module_snapshot> module_query_;
		ULONGLONG module_generation_ = 0;
		ULONGLONG query_generation_ = 0;
		bool module_reload_ = false;
		std::string module_error_;
		ULONGLONG selected_creation_ = 0;
		std::string selected_name_;
		std::string error_;
		bool imports_ = true;
		bool loose_code_ = true;
		bool entrypoints_ = true;
		bool force_entrypoint_ = false;
		bool verbose_ = false;
		bool auto_scroll_ = true;
		bool close_requested_ = false;
		bool stop_requested_ = false;
		bool close_after_stop_ = false;
		bool waiting_to_close_ = false;
		bool admin_ = false;
		ULONGLONG previous_log_revision_ = 0;
		void refresh();
		DWORD target_pid() const;
		void reset_modules(bool reload);
		void update_modules(bool running);
		bool selected_module_valid() const;
		void module_selection();
		void browse();
		void start();
		void open_output();
		void processes(bool running);
		void options(const dump_snapshot& state);
		void log(const dump_snapshot& state);

	public:
		explicit app(HWND window);
		void request_close() { if (!waiting_to_close_) close_requested_ = true; }
		bool ready_to_close() const { return (waiting_to_close_ || close_requested_) && !runner_.snapshot().running; }
		bool render();
	};
}

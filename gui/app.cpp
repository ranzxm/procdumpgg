#include "app.h"
#include "imgui.h"
#include "../pd/version.h"
#include <shobjidl.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <wrl/client.h>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace pd_gui
{
	namespace
	{
		bool is_admin()
		{
			SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
			PSID administrators = nullptr;
			BOOL member = FALSE;
			if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
				DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators))
			{
				CheckTokenMembership(nullptr, administrators, &member);
				FreeSid(administrators);
			}
			return member != FALSE;
		}

		void section_title(const char* title, const char* description)
		{
			ImGui::TextUnformatted(title);
			ImGui::TextDisabled("%s", description);
			ImGui::Spacing();
		}
	}

	app::app(HWND window) : window_(window), admin_(is_admin())
	{
		const auto path = to_utf8((executable_directory() / L"dumps").wstring());
		if (path.size() < output_.size())
			std::copy(path.begin(), path.end(), output_.begin());
		else
			error_ = "Default output path is too long. Choose a shorter folder.";
		refresh();
	}

	void app::refresh()
	{
		try
		{
			processes_ = list_processes();
			std::sort(processes_.begin(), processes_.end(), [](const process_info& first, const process_info& second) {
				const int name = _stricmp(first.name.c_str(), second.name.c_str());
				return name == 0 ? first.pid < second.pid : name < 0;
			});
			reset_modules(true);
			error_.clear();
		}
		catch (const std::exception& error) { error_ = error.what(); }
	}

	DWORD app::target_pid() const
	{
		DWORD pid = 0;
		const char* end = pid_.data() + strlen(pid_.data());
		const auto parsed = std::from_chars(pid_.data(), end, pid);
		return parsed.ec == std::errc() && parsed.ptr == end ? pid : 0;
	}

	void app::reset_modules(bool reload)
	{
		++module_generation_;
		modules_ = {};
		selected_module_ = -1;
		module_filter_.fill(0);
		module_error_.clear();
		module_reload_ = reload && scope_ == 2 && target_pid() != 0;
	}

	void app::update_modules(bool running)
	{
		if (module_query_.valid() && module_query_.wait_for(std::chrono::seconds(0)) == std::future_status::ready)
		{
			try
			{
				auto snapshot = module_query_.get();
				// A PID/mode change invalidates old results without waiting on the UI thread.
				if (query_generation_ == module_generation_ && scope_ == 2 && snapshot.pid == target_pid())
				{
					std::sort(snapshot.modules.begin(), snapshot.modules.end(), [](const module_info& first, const module_info& second) {
						if (first.main_image != second.main_image) return first.main_image;
						const int name = _stricmp(first.name.c_str(), second.name.c_str());
						return name == 0 ? first.base < second.base : name < 0;
					});
					modules_ = std::move(snapshot);
				}
			}
			catch (const std::exception& error)
			{
				if (query_generation_ == module_generation_) module_error_ = error.what();
			}
			catch (...)
			{
				if (query_generation_ == module_generation_) module_error_ = "Unexpected module enumeration failure.";
			}
		}
		if (!running && module_reload_ && !module_query_.valid())
		{
			module_reload_ = false;
			const DWORD pid = target_pid();
			if (!pid || scope_ != 2) return;
			const ULONGLONG created = selected_creation_;
			query_generation_ = module_generation_;
			try
			{
				module_query_ = std::async(std::launch::async, [pid, created] { return list_modules(pid, created); });
			}
			catch (const std::exception& error) { module_error_ = error.what(); }
		}
	}

	bool app::selected_module_valid() const
	{
		return modules_.pid == target_pid() && modules_.creation_time != 0 &&
			(!selected_creation_ || modules_.creation_time == selected_creation_) &&
			selected_module_ >= 0 && static_cast<size_t>(selected_module_) < modules_.modules.size();
	}

	void app::module_selection()
	{
		ImGui::TextUnformatted("Dump scope");
		ImGui::SetNextItemWidth(-1);
		if (ImGui::Combo("##scope", &scope_, "All modules\0Main EXE only\0Specific module\0")) reset_modules(true);
		if (scope_ != 2) return;
		ImGui::BeginDisabled(!target_pid() || module_query_.valid());
		if (ImGui::Button("Load modules")) reset_modules(true);
		ImGui::EndDisabled();
		ImGui::SameLine();
		if (module_query_.valid()) ImGui::TextDisabled("Loading modules...");
		else ImGui::TextDisabled("%zu loaded modules", modules_.modules.size());
		const auto label = [](const module_info& module) {
			char address[32];
			sprintf_s(address, sizeof(address), "0x%llX", module.base);
			return std::string(address) + " - " + module.name + (module.main_image ? " (main EXE)" : "");
		};
		const std::string preview = selected_module_valid() ? label(modules_.modules[selected_module_]) : "Choose a module...";
		ImGui::SetNextItemWidth(-1);
		if (ImGui::BeginCombo("##module", preview.c_str(), ImGuiComboFlags_HeightLarge))
		{
			ImGui::InputTextWithHint("##module_filter", "Search module name or base", module_filter_.data(), module_filter_.size());
			for (size_t i = 0; i < modules_.modules.size(); ++i)
			{
				const auto text = label(modules_.modules[i]);
				if (module_filter_[0] && !StrStrIA(text.c_str(), module_filter_.data())) continue;
				ImGui::PushID(static_cast<int>(i));
				if (ImGui::Selectable(text.c_str(), selected_module_ == static_cast<int>(i))) selected_module_ = static_cast<int>(i);
				ImGui::PopID();
			}
			ImGui::EndCombo();
		}
		if (selected_module_valid())
		{
			ImGui::TextDisabled("Module path (hover to view)");
			if (ImGui::IsItemHovered())
			{
				ImGui::BeginTooltip();
				ImGui::TextUnformatted(modules_.modules[selected_module_].path.c_str());
				ImGui::EndTooltip();
			}
		}
		if (!module_error_.empty())
		{
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.55f, 0.45f, 1));
			ImGui::TextWrapped("%s", module_error_.c_str());
			ImGui::PopStyleColor();
		}
	}

	void app::browse()
	{
		Microsoft::WRL::ComPtr<IFileOpenDialog> dialog;
		if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
			IID_PPV_ARGS(dialog.GetAddressOf()))))
		{
			error_ = "Cannot open the Windows folder picker. Enter a folder path instead.";
			return;
		}
		if (FAILED(dialog->SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST)) ||
			FAILED(dialog->SetTitle(L"Choose a private dump output folder")))
		{
			error_ = "Cannot configure the Windows folder picker.";
			return;
		}
		const HRESULT shown = dialog->Show(window_);
		if (shown == HRESULT_FROM_WIN32(ERROR_CANCELLED)) return;
		Microsoft::WRL::ComPtr<IShellItem> item;
		PWSTR path = nullptr;
		if (FAILED(shown) || FAILED(dialog->GetResult(item.GetAddressOf())) ||
			FAILED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)))
		{
			error_ = "Cannot read the selected folder.";
			return;
		}
		try
		{
			const auto text = to_utf8(path);
			if (text.size() >= output_.size())
				throw std::runtime_error("Selected folder path is too long.");
			output_.fill(0);
			std::copy(text.begin(), text.end(), output_.begin());
			error_.clear();
		}
		catch (const std::exception& error) { error_ = error.what(); }
		CoTaskMemFree(path);
	}

	void app::start()
	{
		try
		{
			const DWORD pid = target_pid();
			if (!pid)
				throw std::runtime_error("Select a process or enter a valid decimal PID.");
			if (!output_[0]) throw std::runtime_error("Choose an output folder first.");
			dump_request request;
			request.pid = pid;
			request.creation_time = selected_creation_;
			request.scope = static_cast<dump_scope>(scope_);
			if (request.scope == dump_scope::selected_module)
			{
				if (!selected_module_valid()) throw std::runtime_error("Load and select a module for the current PID first.");
				request.module = modules_.modules[selected_module_];
				request.creation_time = modules_.creation_time;
			}
			request.output = std::filesystem::absolute(to_wide(output_.data()));
			request.create_output = true;
			request.imports = imports_;
			request.loose_code = scope_ == 0 && loose_code_;
			request.entrypoints = entrypoints_;
			request.force_entrypoint = entrypoints_ && force_entrypoint_;
			request.verbose = verbose_;
			error_.clear();
			previous_log_revision_ = 0;
			if (!runner_.start(request)) error_ = runner_.snapshot().error;
		}
		catch (const std::exception& error) { error_ = error.what(); }
	}

	void app::open_output()
	{
		try
		{
			const auto path = std::filesystem::absolute(to_wide(output_.data()));
			if (!std::filesystem::is_directory(path))
				throw std::runtime_error("The output folder does not exist yet.");
			if (reinterpret_cast<INT_PTR>(ShellExecuteW(window_, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL)) <= 32)
				throw std::runtime_error("Windows could not open the output folder.");
		}
		catch (const std::exception& error) { error_ = error.what(); }
	}

	void app::processes(bool running)
	{
		section_title("TARGET PROCESS", "Select a process or enter a PID.");
		ImGui::BeginDisabled(running);
		ImGui::SetNextItemWidth(-6.5f * ImGui::GetFontSize());
		ImGui::InputTextWithHint("##search", "Search process name or PID", filter_.data(), filter_.size());
		ImGui::SameLine();
		if (ImGui::Button("Refresh")) refresh();
		ImGui::Spacing();
		const float list_height = (std::max)(120.0f, ImGui::GetContentRegionAvail().y - 95.0f);
		if (ImGui::BeginTable("processes", 2, ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg |
			ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable, ImVec2(0, list_height)))
		{
			ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 75.0f);
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableHeadersRow();
			for (const auto& process : processes_)
			{
				if (process.pid == 0 || process.pid == GetCurrentProcessId()) continue;
				const auto pid = std::to_string(process.pid);
				if (filter_[0] && !StrStrIA(process.name.c_str(), filter_.data()) &&
					pid.find(filter_.data()) == std::string::npos) continue;
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0);
				ImGui::PushID(static_cast<int>(process.pid));
				if (ImGui::Selectable(process.name.c_str(), pid == pid_.data(), ImGuiSelectableFlags_SpanAllColumns))
				{
					sprintf_s(pid_.data(), pid_.size(), "%lu", process.pid);
					selected_creation_ = process.creation_time;
					selected_name_ = process.name;
					reset_modules(true);
				}
				ImGui::PopID();
				ImGui::TableSetColumnIndex(1);
				ImGui::TextUnformatted(pid.c_str());
			}
			ImGui::EndTable();
		}
		ImGui::SetNextItemWidth(150.0f);
		if (ImGui::InputText("PID", pid_.data(), pid_.size(), ImGuiInputTextFlags_CharsDecimal))
		{
			selected_creation_ = 0;
			selected_name_.clear();
			reset_modules(false);
		}
		ImGui::TextDisabled("%s", selected_name_.empty() ? "Manual PID: refresh selection if the process restarts." : selected_name_.c_str());
		ImGui::EndDisabled();
	}

	void app::options(const dump_snapshot& state)
	{
		section_title("DUMP CONFIGURATION", "Uses pd.exe beside this application.");
		const float footer_height = ImGui::GetFontSize() * (state.running ? 9.0f : state.finished ? 11.0f : 5.5f);
		ImGui::BeginChild("settings", ImVec2(0, -footer_height));
		ImGui::BeginDisabled(state.running);
		module_selection();
		ImGui::Spacing();
		ImGui::TextUnformatted("Output folder");
		ImGui::SetNextItemWidth(-1);
		ImGui::InputText("##output", output_.data(), output_.size());
		if (ImGui::Button("Browse...")) browse();
		ImGui::SameLine();
		if (ImGui::Button("Open folder")) open_output();
		ImGui::TextWrapped("New folders are created when dumping. Use an ASCII path.");
		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();
		ImGui::Checkbox("Reconstruct imports", &imports_);
		ImGui::BeginDisabled(scope_ != 0);
		ImGui::Checkbox("Include loose executable code", &loose_code_);
		ImGui::EndDisabled();
		if (scope_ != 0) ImGui::TextDisabled("Loose code applies only to All modules.");
		ImGui::Checkbox("Recover missing entrypoints", &entrypoints_);
		ImGui::BeginDisabled(!entrypoints_);
		ImGui::Checkbox("Force entrypoint recovery", &force_entrypoint_);
		ImGui::EndDisabled();
		ImGui::Checkbox("Verbose diagnostics", &verbose_);
		ImGui::Spacing();
		ImGui::TextWrapped(scope_ == 0 ?
			"All modules also scans for hidden images. Clean-hash matches may be skipped. Entrypoint recovery is heuristic." :
			"Only the requested image base is dumped. Import analysis may read other modules. Clean-hash matches may be skipped.");
		ImGui::EndDisabled();
		ImGui::EndChild();
		ImGui::TextWrapped("Target PID: %s | %s", pid_[0] ? pid_.data() : "none", selected_name_.empty() ? "manual selection" : selected_name_.c_str());
		ImGui::BeginDisabled(state.running || !target_pid() || (scope_ == 2 && !selected_module_valid()));
		const char* action = scope_ == 1 ? "Dump main EXE" : scope_ == 2 ? "Dump selected module" : "Dump all modules";
		if (ImGui::Button(action, ImVec2(-1, 36.0f))) start();
		ImGui::EndDisabled();
		if (state.running)
		{
			ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.77f, 1), "%s",
				state.cancelled ? "Stopping dumper..." : state.preparing ? "Preparing dump..." : "Dump running...");
			if (ImGui::Button("Stop dump...")) stop_requested_ = true;
		}
		else if (state.finished)
		{
			if (!state.error.empty()) ImGui::TextWrapped("Dump could not complete. See the error above.");
			else if (state.cancelled) ImGui::TextWrapped("Dump stopped. Incomplete output files may remain.");
			else ImGui::Text("Dumper exited with code %lu.", state.exit_code);
			ImGui::TextWrapped("Check diagnostics and output files. Exit code 0 does not guarantee a complete dump.");
		}
	}

	void app::log(const dump_snapshot& state)
	{
		ImGui::Separator();
		ImGui::TextUnformatted("DIAGNOSTICS");
		ImGui::SameLine();
		ImGui::Checkbox("Auto-scroll", &auto_scroll_);
		ImGui::SameLine();
		if (ImGui::Button("Copy log")) ImGui::SetClipboardText(state.log.c_str());
		ImGui::TextDisabled("Last 1 MiB retained. CLI output may arrive in batches; copy diagnostics before the next dump.");
		ImGui::BeginChild("log", ImVec2(0, 0), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
		if (state.log.empty()) ImGui::TextDisabled("Dumper output will appear here.");
		else ImGui::TextUnformatted(state.log.data(), state.log.data() + state.log.size());
		if (auto_scroll_ && state.log_revision != previous_log_revision_) ImGui::SetScrollHereY(1.0f);
		previous_log_revision_ = state.log_revision;
		ImGui::EndChild();
	}

	bool app::render()
	{
		const auto state = runner_.snapshot();
		update_modules(state.running);
		if (waiting_to_close_ && !state.running) return false;
		const auto* viewport = ImGui::GetMainViewport();
		ImGui::SetNextWindowPos(viewport->WorkPos);
		ImGui::SetNextWindowSize(viewport->WorkSize);
		ImGui::Begin("Process Dump", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoSavedSettings);
		ImGui::Text("PROCESS DUMP  %s", PD_VERSION_STRING);
		ImGui::SameLine();
		ImGui::TextDisabled("/ Dear ImGui / %s", admin_ ? "Administrator" : "Standard user");
		if (!admin_) ImGui::TextWrapped("Some processes require Administrator access. Reopen this app elevated only when needed.");
		ImGui::TextDisabled("Dump only processes you own or are authorized to analyze. Memory dumps may contain secrets.");
		const auto& error = error_.empty() ? state.error : error_;
		if (!error.empty())
		{
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.55f, 0.45f, 1));
			ImGui::TextWrapped("%s", error.c_str());
			ImGui::PopStyleColor();
		}
		ImGui::Spacing();
		const float top_height = (std::max)(310.0f, ImGui::GetContentRegionAvail().y * 0.63f);
		const float left_width = ImGui::GetContentRegionAvail().x * 0.46f;
		ImGui::BeginChild("targets", ImVec2(left_width, top_height), ImGuiChildFlags_Borders);
		processes(state.running);
		ImGui::EndChild();
		ImGui::SameLine();
		ImGui::BeginChild("options", ImVec2(0, top_height), ImGuiChildFlags_Borders);
		options(state);
		ImGui::EndChild();
		log(state);
		if (close_requested_ && !state.running)
		{
			ImGui::End();
			return false;
		}
		if (close_requested_ && state.running)
		{
			close_after_stop_ = true;
			close_requested_ = false;
			stop_requested_ = true;
		}
		if (stop_requested_)
		{
			ImGui::OpenPopup("Stop dump?");
			stop_requested_ = false;
		}
		if (ImGui::BeginPopupModal("Stop dump?", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
		{
			ImGui::TextUnformatted("Stop only the dumper subprocess? The target will not be terminated.");
			ImGui::TextUnformatted("Partially written files may remain. Inspect or remove them before retrying.");
			ImGui::TextUnformatted("Buffered CLI output may be lost. Preparation cancellation may take time.");
			if (ImGui::Button("Stop dumper"))
			{
				runner_.cancel();
				waiting_to_close_ = close_after_stop_;
				close_after_stop_ = false;
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (ImGui::Button("Keep running"))
			{
				close_after_stop_ = false;
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		}
		ImGui::End();
		return true;
	}
}

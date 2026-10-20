#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace pd_gui
{
struct process_info
{
    DWORD pid = 0;
    ULONGLONG creation_time = 0; // Zero when query access is unavailable.
    std::string name;
};

enum class dump_scope { all_modules, main_image, selected_module };

struct module_info
{
    ULONGLONG base = 0;
    DWORD size = 0;
    std::string name;
    std::string path;
    bool main_image = false;
};

struct module_snapshot
{
    DWORD pid = 0;
    ULONGLONG creation_time = 0;
    std::vector<module_info> modules;
};

struct dump_request
{
    DWORD pid = 0;
    ULONGLONG creation_time = 0;
    std::filesystem::path output;
    bool create_output = false;
    bool imports = true;
    bool loose_code = true;
    bool entrypoints = true;
    bool force_entrypoint = false;
    bool verbose = false;
    dump_scope scope = dump_scope::all_modules;
    std::optional<module_info> module;
};

struct dump_snapshot
{
    bool running = false; // Active request, including preparation.
    bool preparing = false;
    bool finished = false;
    bool cancelled = false;
    DWORD exit_code = 0;
    std::string log; // Combined stdout/stderr, newest 1 MiB of raw bytes.
    ULONGLONG log_revision = 0; // Monotonic across requests; incremented on append.
    std::string error;
};

std::wstring quote_argument(const std::wstring& argument);
std::wstring to_wide(const std::string& text);
std::string to_utf8(const std::wstring& text);
std::filesystem::path executable_directory();
std::vector<process_info> list_processes();
module_snapshot list_modules(DWORD pid, ULONGLONG expected_creation_time = 0);

class dump_runner
{
public:
    explicit dump_runner(std::filesystem::path executable = {});
    ~dump_runner();
    dump_runner(const dump_runner&) = delete;
    dump_runner& operator=(const dump_runner&) = delete;
    // Accepts and queues a request. Native/filesystem errors arrive in snapshot.
    // False means busy, lexical validation failed, or thread creation failed.
    bool start(const dump_request& request);
    dump_snapshot snapshot() const;
    void cancel();
private:
    struct implementation;
    std::unique_ptr<implementation> impl_;
};
}

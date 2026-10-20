#include "dump_runner.h"
#include <TlHelp32.h>
#include <algorithm>
#include <cstdio>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>

namespace pd_gui
{
namespace
{
constexpr size_t log_limit = 1024 * 1024;
struct handle
{
    HANDLE value = nullptr;
    handle() = default;
    explicit handle(HANDLE h) : value(h) {}
    ~handle() { reset(); }
    handle(const handle&) = delete;
    handle& operator=(const handle&) = delete;
    void reset(HANDLE h = nullptr)
    {
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
        value = h;
    }
    HANDLE release() { HANDLE h = value; value = nullptr; return h; }
};

std::runtime_error windows_error(const char* operation)
{
    const DWORD code = GetLastError();
    return std::runtime_error(std::string(operation) + " (Windows error " + std::to_string(code) + ")");
}

ULONGLONG creation_time(HANDLE process)
{
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user))
        throw windows_error("Cannot query process creation time");
    return (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}

std::wstring normalized_module_path(std::wstring path)
{
    std::replace(path.begin(), path.end(), L'/', L'\\');
    if (path.compare(0, 8, L"\\\\?\\UNC\\") == 0) path = L"\\\\" + path.substr(8);
    else if (path.compare(0, 4, L"\\\\?\\") == 0 || path.compare(0, 4, L"\\??\\") == 0) path.erase(0, 4);
    return std::filesystem::path(path).lexically_normal().native();
}

bool same_module_path(const std::wstring& left, const std::wstring& right)
{
    const auto a = normalized_module_path(left), b = normalized_module_path(right);
    return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_EQUAL;
}

template<class Checkpoint>
ULONGLONG check_target(HANDLE process, ULONGLONG expected, Checkpoint checkpoint)
{
    checkpoint();
    FILETIME created_time{}, exited{}, kernel{}, user{};
    const BOOL timed = GetProcessTimes(process, &created_time, &exited, &kernel, &user);
    const DWORD time_error = GetLastError();
    checkpoint();
    if (!timed)
        throw std::runtime_error("Cannot query process creation time (Windows error " + std::to_string(time_error) + ")");
    const ULONGLONG created = (static_cast<ULONGLONG>(created_time.dwHighDateTime) << 32) | created_time.dwLowDateTime;
    if (expected && created != expected)
        throw std::runtime_error("Selected process has exited or its PID was reused; refresh the process list");
    DWORD code = 0;
    const BOOL queried = GetExitCodeProcess(process, &code);
    const DWORD error = GetLastError();
    checkpoint();
    if (!queried)
        throw std::runtime_error("Cannot query selected target state (Windows error " + std::to_string(error) + ")");
    if (code != STILL_ACTIVE) throw std::runtime_error("Selected process has already exited");
    return created;
}

template<class Checkpoint>
module_snapshot snapshot_modules(DWORD pid, ULONGLONG expected, Checkpoint checkpoint)
{
    if (!pid) throw std::runtime_error("Select a nonzero target PID");
    checkpoint();
    handle target(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    const DWORD open_error = GetLastError();
    checkpoint();
    if (!target.value)
        throw std::runtime_error("Cannot open selected target for module enumeration (Windows error " + std::to_string(open_error) + ")");
    module_snapshot result;
    result.pid = pid;
    result.creation_time = check_target(target.value, expected, checkpoint);

    std::vector<wchar_t> image(512);
    std::wstring image_path;
    for (;;)
    {
        checkpoint();
        DWORD length = static_cast<DWORD>(image.size());
        const BOOL queried = QueryFullProcessImageNameW(target.value, 0, image.data(), &length);
        const DWORD error = GetLastError();
        checkpoint();
        if (queried) { image_path.assign(image.data(), length); break; }
        if (error != ERROR_INSUFFICIENT_BUFFER || image.size() >= 32768)
            throw std::runtime_error("Cannot identify target main image (Windows error " + std::to_string(error) + ")");
        image.resize((std::min)(image.size() * 2, size_t(32768)));
    }

    handle modules;
    for (unsigned attempt = 0; attempt != 8; ++attempt)
    {
        checkpoint();
        modules.reset(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
        const DWORD error = GetLastError();
        checkpoint();
        if (modules.value != INVALID_HANDLE_VALUE) break;
        if (error == ERROR_PARTIAL_COPY)
            throw std::runtime_error("Cannot enumerate target modules (Windows error 299 / ERROR_PARTIAL_COPY); use the x64 GUI for a 64-bit target");
        if (error != ERROR_BAD_LENGTH || attempt == 7)
            throw std::runtime_error("Cannot snapshot target modules (Windows error " + std::to_string(error) + ")");
    }
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    checkpoint();
    BOOL available = Module32FirstW(modules.value, &entry);
    DWORD error = GetLastError();
    checkpoint();
    size_t main_count = 0;
    std::unordered_map<ULONGLONG, size_t> by_base;
    while (available)
    {
        module_info info;
        info.base = static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(entry.modBaseAddr));
        info.size = entry.modBaseSize;
        info.name = to_utf8(entry.szModule);
        info.path = to_utf8(entry.szExePath);
        info.main_image = same_module_path(entry.szExePath, image_path);
        const auto duplicate = by_base.find(info.base);
        if (duplicate != by_base.end())
        {
            // Combined native/WOW64 snapshots can list the same main image twice.
            const auto& previous = result.modules[duplicate->second];
            if (previous.size != info.size || !same_module_path(to_wide(previous.path), to_wide(info.path)))
                throw std::runtime_error("Module identity changed within the snapshot; refresh the module list");
        }
        else
        {
            by_base.emplace(info.base, result.modules.size());
            if (info.main_image) ++main_count;
            result.modules.push_back(std::move(info));
        }
        checkpoint();
        available = Module32NextW(modules.value, &entry);
        error = GetLastError();
        checkpoint();
    }
    if (error != ERROR_NO_MORE_FILES)
        throw std::runtime_error("Cannot read target module list (Windows error " + std::to_string(error) + ")");
    check_target(target.value, result.creation_time, checkpoint);
    if (main_count != 1)
        throw std::runtime_error("Cannot identify target main image unambiguously in the module snapshot; refresh the module list");
    return result;
}

struct attribute_list
{
    std::vector<unsigned char> bytes;
    LPPROC_THREAD_ATTRIBUTE_LIST value = nullptr;
    attribute_list()
    {
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        bytes.resize(size);
        value = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(bytes.data());
        if (!InitializeProcThreadAttributeList(value, 1, 0, &size))
        {
            value = nullptr;
            throw windows_error("Cannot initialize child handle list");
        }
    }
    ~attribute_list() { if (value) DeleteProcThreadAttributeList(value); }
};
}

std::wstring quote_argument(const std::wstring& argument)
{
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (wchar_t ch : argument)
    {
        if (ch == L'\\') { ++slashes; continue; }
        result.append(ch == L'"' ? slashes * 2 + 1 : slashes, L'\\');
        result += ch;
        slashes = 0;
    }
    result.append(slashes * 2, L'\\');
    result += L'"';
    return result;
}

std::wstring to_wide(const std::string& text)
{
    if (text.empty()) return {};
    if (text.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
        throw std::runtime_error("UTF-8 string is too large");
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!size) throw windows_error("Invalid UTF-8 text");
    std::wstring result(size, L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size))
        throw windows_error("Cannot convert UTF-8 text");
    return result;
}

std::string to_utf8(const std::wstring& text)
{
    if (text.empty()) return {};
    if (text.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
        throw std::runtime_error("Unicode string is too large");
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!size) throw windows_error("Invalid Unicode text");
    std::string result(size, '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size, nullptr, nullptr))
        throw windows_error("Cannot convert Unicode text");
    return result;
}

std::filesystem::path executable_directory()
{
    std::vector<wchar_t> buffer(512);
    for (;;)
    {
        const DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (!size) throw windows_error("Cannot locate current executable");
        if (size < buffer.size()) return std::filesystem::path(std::wstring(buffer.data(), size)).parent_path();
        if (buffer.size() >= 32768) throw std::runtime_error("Executable path is too long");
        buffer.resize(buffer.size() * 2);
    }
}

std::vector<process_info> list_processes()
{
    handle processes(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (processes.value == INVALID_HANDLE_VALUE) throw windows_error("Cannot enumerate processes");
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::vector<process_info> result;
    if (!Process32FirstW(processes.value, &entry))
    {
        if (GetLastError() == ERROR_NO_MORE_FILES) return result;
        throw windows_error("Cannot read process list");
    }
    do
    {
        if (!entry.th32ProcessID) continue;
        process_info info;
        info.pid = entry.th32ProcessID;
        info.name = to_utf8(entry.szExeFile);
        handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.pid));
        if (process.value)
        {
            try { info.creation_time = creation_time(process.value); }
            catch (const std::runtime_error&) {} // Inaccessible/exiting entries remain visible.
        }
        result.push_back(std::move(info));
    } while (Process32NextW(processes.value, &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) throw windows_error("Cannot finish process enumeration");
    return result;
}

module_snapshot list_modules(DWORD pid, ULONGLONG expected_creation_time)
{
    return snapshot_modules(pid, expected_creation_time, [] {});
}

struct dump_runner::implementation
{
    std::filesystem::path executable;
    std::mutex operations;
    mutable std::mutex mutex;
    dump_snapshot state;
    // Borrowed from worker-local RAII owners, published/withdrawn under mutex.
    HANDLE child = nullptr;
    HANDLE job = nullptr;
    std::thread worker;

    explicit implementation(std::filesystem::path path) : executable(std::move(path)) {}

    struct cancelled_request {};

    void checkpoint()
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (state.cancelled) throw cancelled_request{};
    }

    void set_error(const char* message) noexcept
    {
        // state.error has reserved capacity before the worker starts. A short
        // fallback remains reportable even if copying a detailed error fails.
        try { state.error = message; }
        catch (...)
        {
            try { state.error = "Backend error (details unavailable)"; }
            catch (...) { OutputDebugStringW(L"pd_gui: cannot store backend error\n"); }
        }
    }

    void set_windows_error(const char* operation, DWORD code) noexcept
    {
        char message[256];
        _snprintf_s(message, sizeof(message), _TRUNCATE, "%s (Windows error %lu)", operation, code);
        set_error(message);
    }

    void check_output(const std::filesystem::path& output, bool allow_missing)
    {
        // Check existing ancestors as well as the leaf before creating folders.
        // The CLI independently enforces its own race-resistant output policy.
        auto part = output.root_path();
        auto check = [&]
        {
            checkpoint();
            const DWORD attributes = GetFileAttributesW(part.c_str());
            const DWORD error = GetLastError();
            checkpoint();
            if (attributes == INVALID_FILE_ATTRIBUTES)
            {
                if (allow_missing && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)) return;
                throw std::runtime_error("Output must be an accessible existing ordinary directory (Windows error " + std::to_string(error) + ")");
            }
            if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
                throw std::runtime_error("Output must be an ordinary directory; reparse points in the output path are rejected");
        };
        const auto root_name = output.root_name().native();
        // A conventional UNC root_path is just \\server\, not an accessible
        // directory. Start querying at its share component instead.
        const bool unc_host = root_name.size() > 2 && root_name[0] == L'\\' && root_name[1] == L'\\' &&
            root_name != L"\\\\?" && root_name != L"\\\\.";
        if (!unc_host || output.relative_path().empty()) check();
        for (const auto& component : output.relative_path())
        {
            part /= component;
            check();
        }
    }

    DWORD read_output(HANDLE process, HANDLE output, HANDLE owned_job)
    {
        bool pipe_open = true;
        bool exited = false;
        for (;;)
        {
            DWORD available = 0;
            if (pipe_open && !PeekNamedPipe(output, nullptr, 0, nullptr, &available, nullptr))
            {
                if (GetLastError() != ERROR_BROKEN_PIPE) throw windows_error("Cannot inspect dumper output");
                pipe_open = false;
            }
            if (pipe_open && available)
            {
                char buffer[16384];
                DWORD count = 0;
                if (!ReadFile(output, buffer, (std::min)(available, static_cast<DWORD>(sizeof(buffer))), &count, nullptr))
                    throw windows_error("Cannot read dumper output");
                std::lock_guard<std::mutex> lock(mutex);
                state.log.append(buffer, count);
                ++state.log_revision;
                if (state.log.size() > log_limit) state.log.erase(0, state.log.size() - log_limit);
            }
            else if (exited) break;

            if (!exited)
            {
                const DWORD wait = WaitForSingleObject(process, available ? 0 : 20);
                if (wait == WAIT_FAILED) throw windows_error("Cannot wait for dumper");
                if (wait == WAIT_OBJECT_0)
                {
                    exited = true;
                    // Descendants must not retain the output writer after exit.
                    if (!TerminateJobObject(owned_job, ERROR_PROCESS_ABORTED))
                        throw windows_error("Cannot clean up dumper descendants");
                }
            }
        }
        DWORD code = 0;
        if (!GetExitCodeProcess(process, &code)) throw windows_error("Cannot query dumper exit code");
        return code;
    }

    DWORD launch_and_read(const dump_request& request)
    {
        checkpoint();
        const auto output = request.output.lexically_normal();
        check_output(output, request.create_output);
        if (request.create_output)
        {
            checkpoint();
            std::error_code error;
            std::filesystem::create_directories(output, error);
            checkpoint();
            if (error) throw std::runtime_error("Cannot create output directory: " + error.message());
            check_output(output, false);
        }
        checkpoint();
        const auto executable_path = std::filesystem::absolute(executable).lexically_normal();
        checkpoint();
        const DWORD exe_attributes = GetFileAttributesW(executable_path.c_str());
        checkpoint();
        if (exe_attributes == INVALID_FILE_ATTRIBUTES || (exe_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
            throw std::runtime_error("Dumper executable is missing or is not an ordinary file: " + to_utf8(executable_path.native()));
        checkpoint();
        handle target(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, request.pid));
        checkpoint();
        if (!target.value) throw windows_error("Cannot open selected target for identity verification");
        const auto target_created = check_target(target.value, request.creation_time, [this] { checkpoint(); });
        std::optional<module_info> selected;
        if (request.scope != dump_scope::all_modules)
        {
            const auto modules = snapshot_modules(request.pid, target_created, [this] { checkpoint(); });
            for (const auto& module : modules.modules)
            {
                const bool matches = request.scope == dump_scope::main_image ? module.main_image :
                    module.base == request.module->base && module.size == request.module->size &&
                    same_module_path(to_wide(module.path), to_wide(request.module->path));
                if (matches) { selected = module; break; }
            }
            if (!selected || !selected->base || !selected->size)
                throw std::runtime_error("Selected module is no longer loaded or has changed; refresh the module list");
        }

        checkpoint();
        std::wstring command = quote_argument(executable_path.native()) + L" -pid " + std::to_wstring(request.pid) + L" -o " + quote_argument(output.native());
        if (selected)
        {
            wchar_t address[32];
            _snwprintf_s(address, _countof(address), _TRUNCATE, L"0x%llx", selected->base);
            command += L" -a ";
            command += address;
        }
        if (!request.imports) command += L" -ni";
        if (!request.loose_code || selected) command += L" -nc";
        if (!request.entrypoints) command += L" -nep";
        if (request.force_entrypoint) command += L" -eprec";
        if (request.verbose) command += L" -v";
        SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
        handle reader, writer;
        if (!CreatePipe(&reader.value, &writer.value, &security, 0)) throw windows_error("Cannot create dumper output pipe");
        if (!SetHandleInformation(reader.value, HANDLE_FLAG_INHERIT, 0)) throw windows_error("Cannot protect output reader");
        handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        checkpoint();
        if (input.value == INVALID_HANDLE_VALUE) throw windows_error("Cannot open NUL stdin");
        attribute_list attributes_list;
        HANDLE inherited[] = {writer.value, input.value};
        if (!UpdateProcThreadAttribute(attributes_list.value, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr))
            throw windows_error("Cannot restrict inherited child handles");
        handle owned_job(CreateJobObjectW(nullptr, nullptr));
        if (!owned_job.value) throw windows_error("Cannot create dumper job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(owned_job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
            throw windows_error("Cannot configure dumper job");
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = input.value;
        startup.StartupInfo.hStdOutput = startup.StartupInfo.hStdError = writer.value;
        startup.lpAttributeList = attributes_list.value;
        PROCESS_INFORMATION process{};
        checkpoint();
        if (!CreateProcessW(executable_path.c_str(), command.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr,
            executable_path.parent_path().c_str(), &startup.StartupInfo, &process))
        {
            const auto error = windows_error("Cannot launch dumper");
            checkpoint();
            throw error;
        }
        handle owned_child(process.hProcess), thread(process.hThread);
        if (!AssignProcessToJobObject(owned_job.value, owned_child.value))
        {
            const auto error = windows_error("Cannot assign dumper to its private job");
            if (!TerminateProcess(owned_child.value, ERROR_PROCESS_ABORTED))
                throw windows_error("Cannot terminate unassigned suspended dumper");
            throw error;
        }
        writer.reset(); // Parent must not retain a writer.
        // Serialize publication and resume with cancellation. Until assignment,
        // the suspended process is local; job RAII kills it on any exception.
        // Withdraw pointers before their local owners close on every exit path.
        struct publication
        {
            implementation& owner;
            ~publication()
            {
                std::lock_guard<std::mutex> lock(owner.mutex);
                owner.child = nullptr;
                owner.job = nullptr;
            }
        } published{*this};
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (state.cancelled) throw cancelled_request{};
            child = owned_child.value;
            job = owned_job.value;
            if (ResumeThread(thread.value) == static_cast<DWORD>(-1)) throw windows_error("Cannot resume dumper");
            state.preparing = false;
        }
        return read_output(owned_child.value, reader.value, owned_job.value);
    }

    void run(const dump_request& request) noexcept
    {
        try
        {
            const DWORD code = launch_and_read(request);
            std::lock_guard<std::mutex> lock(mutex);
            state.exit_code = code;
        }
        catch (const cancelled_request&)
        {
            std::lock_guard<std::mutex> lock(mutex);
            state.exit_code = ERROR_CANCELLED;
        }
        catch (const std::exception& error)
        {
            std::lock_guard<std::mutex> lock(mutex);
            set_error(error.what());
        }
        catch (...)
        {
            std::lock_guard<std::mutex> lock(mutex);
            set_error("Unexpected GUI backend failure");
        }
        // All local native resources have been closed before finished is visible.
        std::lock_guard<std::mutex> lock(mutex);
        state.preparing = false;
        state.running = false;
        state.finished = true;
    }
};

dump_runner::dump_runner(std::filesystem::path executable)
    : impl_(std::make_unique<implementation>(executable.empty() ? executable_directory() / L"pd.exe" : std::move(executable))) {}

dump_runner::~dump_runner()
{
    cancel();
    if (impl_->worker.joinable())
    {
        // Retry cancellation to cover the gap between a checkpoint and entering
        // synchronous I/O. Windows cancellation is advisory: some filesystem
        // drivers/launch operations can still require their own timeout.
        while (WaitForSingleObject(impl_->worker.native_handle(), 20) == WAIT_TIMEOUT) cancel();
        impl_->worker.join();
    }
}

bool dump_runner::start(const dump_request& request)
{
    std::lock_guard<std::mutex> operation(impl_->operations);
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->state.running) return false;
    }
    // A previous worker publishes finished only after releasing its native
    // resources. Never hold the state mutex while joining it.
    if (impl_->worker.joinable()) impl_->worker.join();
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        const ULONGLONG revision = impl_->state.log_revision;
        impl_->state = {};
        impl_->state.log_revision = revision;
    }
    try
    {
        // Lexical checks only. No filesystem queries, target access, or native
        // launch calls are permitted on the caller/UI thread.
        if (!request.pid) throw std::runtime_error("Select a nonzero target PID");
        switch (request.scope)
        {
        case dump_scope::all_modules:
        case dump_scope::main_image:
            break;
        case dump_scope::selected_module:
            if (!request.creation_time)
                throw std::runtime_error("Selected module requires process creation time from its module snapshot; refresh the module list");
            if (!request.module || !request.module->base || !request.module->size || request.module->path.empty())
                throw std::runtime_error("Select a module with a nonzero base, size, and nonempty path");
            if (request.module->path.find('\0') != std::string::npos)
                throw std::runtime_error("Selected module path contains a null character");
            to_wide(request.module->path); // Lexical UTF-8 validation only.
            break;
        default:
            throw std::runtime_error("Invalid dump scope");
        }
        if (request.output.empty() || !request.output.is_absolute())
            throw std::runtime_error("Output must be an absolute directory path");
        for (wchar_t ch : request.output.native())
            if (!ch || ch > 127)
                throw std::runtime_error("Output path must contain ASCII characters only: pd.exe uses legacy ANSI path conversion and cannot reliably handle Unicode output paths");
        if (impl_->executable.native().find(L'\0') != std::wstring::npos)
            throw std::runtime_error("Dumper executable path contains a null character");
        to_utf8(impl_->executable.native()); // Validate Unicode without touching disk.
        {
            std::lock_guard<std::mutex> lock(impl_->mutex);
            impl_->state.error.reserve(256);
            impl_->state.running = true;
            impl_->state.preparing = true;
        }
        impl_->worker = std::thread([this, request] { impl_->run(request); });
        return true;
    }
    catch (const std::exception& error)
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->set_error(error.what());
        impl_->state.running = false;
        impl_->state.preparing = false;
        impl_->state.finished = true;
        return false;
    }
    catch (...)
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->set_error("Unexpected failure accepting dump request");
        impl_->state.running = false;
        impl_->state.preparing = false;
        impl_->state.finished = true;
        return false;
    }
}

dump_snapshot dump_runner::snapshot() const
{
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->state;
}

void dump_runner::cancel()
{
    std::lock_guard<std::mutex> operation(impl_->operations);
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->state.running) return;
    // Record cancellation even before a child exists. Publication/resume and
    // this flag share the same mutex, so a cancelled request cannot resume.
    impl_->state.cancelled = true;
    if (impl_->state.preparing && impl_->worker.joinable())
    {
        if (!CancelSynchronousIo(impl_->worker.native_handle()) && GetLastError() != ERROR_NOT_FOUND)
            impl_->set_windows_error("Cannot interrupt dumper preparation", GetLastError());
    }
    if (impl_->job)
    {
        if (!TerminateJobObject(impl_->job, ERROR_CANCELLED))
        {
            const DWORD error = GetLastError();
            if (!impl_->child || !TerminateProcess(impl_->child, ERROR_CANCELLED))
                impl_->set_windows_error("Cannot cancel dumper job", error);
        }
    }
}
}

#include "../gui/dump_runner.h"
#include "test_support.h"
#include <shellapi.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <winioctl.h>

namespace
{
std::filesystem::path self_executable()
{
    wchar_t path[32768];
    const DWORD size = GetModuleFileNameW(nullptr, path, 32768);
    require(size && size < 32768, "cannot locate fixture executable");
    return std::filesystem::path(std::wstring(path, size));
}

class fixture_directory
{
public:
    std::filesystem::path path;
    explicit fixture_directory(const wchar_t* mode = L"normal")
    {
        wchar_t temp[32768];
        require(GetTempPathW(32768, temp) != 0, "cannot locate temporary directory");
        path = std::filesystem::path(temp) / (L"pd gui runner " + std::to_wstring(GetCurrentProcessId()) + L" " +
            std::to_wstring(GetTickCount64()) + L" " + mode);
        require(CreateDirectoryW(path.c_str(), nullptr) != 0, "cannot create fixture directory");
    }
    ~fixture_directory() { RemoveDirectoryW(path.c_str()); }
};

pd_gui::dump_request self_request(const std::filesystem::path& output)
{
    pd_gui::dump_request request;
    request.pid = GetCurrentProcessId();
    request.output = output;
    for (const auto& process : pd_gui::list_processes())
        if (process.pid == request.pid) request.creation_time = process.creation_time;
    require(request.creation_time != 0, "own process creation time missing");
    return request;
}

pd_gui::dump_snapshot wait_finished(pd_gui::dump_runner& runner)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    for (;;)
    {
        auto state = runner.snapshot();
        if (state.finished) return state;
        require(std::chrono::steady_clock::now() < deadline, "fixture child timed out");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void require_async_error(pd_gui::dump_runner& runner, const pd_gui::dump_request& request,
    const char* message, const char* error_fragment = "")
{
    require(runner.start(request), "asynchronous invalid request was not queued");
    const auto state = wait_finished(runner);
    require(!state.running && !state.preparing && !state.cancelled && !state.error.empty(), message);
    require(state.error.find(error_fragment) != std::string::npos, "asynchronous error lacks expected explanation");
    require(state.log.empty(), "invalid request launched the fixture child");
}

// Junctions do not require symbolic-link privileges. Use only owned temp paths.
class fixture_junction
{
public:
    std::filesystem::path path;
    fixture_junction(const std::filesystem::path& link, const std::filesystem::path& destination) : path(link)
    {
        require(CreateDirectoryW(path.c_str(), nullptr) != 0, "cannot create junction directory");
        const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            RemoveDirectoryW(path.c_str());
            throw std::runtime_error("cannot open owned junction directory");
        }
        struct junction_header
        {
            DWORD tag;
            WORD data_length, reserved;
            WORD substitute_offset, substitute_length, print_offset, print_length;
        };
        const std::wstring substitute = L"\\??\\" + destination.native();
        const std::wstring printed = destination.native();
        const size_t substitute_bytes = substitute.size() * sizeof(wchar_t);
        const size_t print_bytes = printed.size() * sizeof(wchar_t);
        std::vector<unsigned char> bytes(sizeof(junction_header) + substitute_bytes + print_bytes + 2 * sizeof(wchar_t), 0);
        auto* header = reinterpret_cast<junction_header*>(bytes.data());
        header->tag = IO_REPARSE_TAG_MOUNT_POINT;
        header->data_length = static_cast<WORD>(bytes.size() - 8);
        header->substitute_length = static_cast<WORD>(substitute_bytes);
        header->print_offset = static_cast<WORD>(substitute_bytes + sizeof(wchar_t));
        header->print_length = static_cast<WORD>(print_bytes);
        memcpy(bytes.data() + sizeof(junction_header), substitute.data(), substitute_bytes);
        memcpy(bytes.data() + sizeof(junction_header) + header->print_offset, printed.data(), print_bytes);
        DWORD returned = 0;
        const BOOL success = DeviceIoControl(file, FSCTL_SET_REPARSE_POINT, bytes.data(), static_cast<DWORD>(bytes.size()), nullptr, 0, &returned, nullptr);
        CloseHandle(file);
        if (!success)
        {
            RemoveDirectoryW(path.c_str());
            throw std::runtime_error("cannot set owned junction reparse point");
        }
    }
    ~fixture_junction() { RemoveDirectoryW(path.c_str()); }
};

void quoting()
{
    const std::vector<std::wstring> arguments = {
        L"", L"simple", L"a b", L"tab\there", L"\"", L"a\\\"b", L"C:\\space dir\\",
        L"\\\\server\\share\\", L"trail\\\\", L"\u03bb\u4e2d", L"a & b | c > d"
    };
    std::wstring command = L"fixture.exe";
    for (const auto& argument : arguments) command += L" " + pd_gui::quote_argument(argument);
    int count = 0;
    wchar_t** parsed = CommandLineToArgvW(command.c_str(), &count);
    require(parsed != nullptr, "CommandLineToArgvW failed");
    bool equal = count == static_cast<int>(arguments.size() + 1);
    if (equal)
        for (size_t i = 0; i < arguments.size(); ++i) equal = equal && arguments[i] == parsed[i + 1];
    LocalFree(parsed);
    require(equal, "Windows argument quoting failed roundtrip");
    const std::wstring unicode = L"Unicode \u03bb \u4e2d \xd83d\xde00";
    require(pd_gui::to_wide(pd_gui::to_utf8(unicode)) == unicode, "Unicode conversion failed roundtrip");
    require(pd_gui::to_wide("").empty() && pd_gui::to_utf8(L"").empty(), "empty conversion failed");
    bool rejected = false;
    try { pd_gui::to_wide(std::string("\xff", 1)); } catch (const std::runtime_error&) { rejected = true; }
    require(rejected, "invalid UTF-8 accepted");
    rejected = false;
    try { pd_gui::to_utf8(std::wstring(1, static_cast<wchar_t>(0xd800))); } catch (const std::runtime_error&) { rejected = true; }
    require(rejected, "invalid UTF-16 accepted");
}

void enumeration()
{
    bool found = false;
    for (const auto& process : pd_gui::list_processes())
        if (process.pid == GetCurrentProcessId())
        {
            require(process.creation_time != 0 && !process.name.empty(), "own process identity incomplete");
            found = true;
        }
    require(found, "own PID missing from enumeration");
    require(pd_gui::executable_directory() == self_executable().parent_path(), "wrong executable directory");
}

void module_enumeration()
{
    const auto request = self_request(self_executable().parent_path());
    const auto snapshot = pd_gui::list_modules(request.pid, request.creation_time);
    require(snapshot.pid == request.pid && snapshot.creation_time == request.creation_time, "module snapshot identity incorrect");
    const auto main_base = static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(GetModuleHandleW(nullptr)));
    const auto kernel_base = static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(GetModuleHandleW(L"kernel32.dll")));
    require(kernel_base != 0, "kernel32 is not loaded");
    unsigned main_count = 0;
    std::unordered_set<ULONGLONG> bases;
    bool kernel_found = false;
    for (const auto& module : snapshot.modules)
    {
        require(module.base && module.size && !module.name.empty() && !module.path.empty(), "incomplete module entry");
        require(bases.insert(module.base).second, "combined module snapshot contains duplicate image bases");
        require(pd_gui::to_utf8(pd_gui::to_wide(module.path)) == module.path, "module path is not lossless UTF-8");
        if (module.main_image)
        {
            ++main_count;
            require(module.base == main_base, "DLL incorrectly identified as main image");
            const auto path = pd_gui::to_wide(module.path);
            require(CompareStringOrdinal(path.c_str(), -1, self_executable().c_str(), -1, TRUE) == CSTR_EQUAL,
                "main image path incorrect");
        }
        if (module.base == kernel_base)
        {
            kernel_found = true;
            require(!module.main_image, "kernel32 marked as main image");
        }
    }
    require(main_count == 1 && kernel_found, "main image or kernel32 missing from module snapshot");
    bool rejected = false;
    try { pd_gui::list_modules(request.pid, request.creation_time + 1); }
    catch (const std::runtime_error&) { rejected = true; }
    require(rejected, "module snapshot accepted mismatched process creation time");
    rejected = false;
    try { pd_gui::list_modules(0); }
    catch (const std::runtime_error&) { rejected = true; }
    require(rejected, "module snapshot accepted zero PID");
}

std::string address_argument(ULONGLONG base)
{
    std::ostringstream text;
    text << "0x" << std::hex << base;
    return text.str();
}

void selective_modules()
{
    fixture_directory directory;
    pd_gui::dump_runner runner(self_executable()); // Only prints argv; never dumps memory.
    auto request = self_request(directory.path);
    const auto snapshot = pd_gui::list_modules(request.pid, request.creation_time);
    pd_gui::module_info main, kernel;
    const auto kernel_base = static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(GetModuleHandleW(L"kernel32.dll")));
    for (const auto& module : snapshot.modules)
    {
        if (module.main_image) main = module;
        if (module.base == kernel_base) kernel = module;
    }
    require(main.base && kernel.base, "selective test modules missing");
    for (const auto scope : {pd_gui::dump_scope::main_image, pd_gui::dump_scope::selected_module})
    {
        request.scope = scope;
        request.module = scope == pd_gui::dump_scope::main_image ? std::optional<pd_gui::module_info>{} : kernel;
        require(request.loose_code, "test must exercise forced -nc");
        require(runner.start(request), "single-module request not queued");
        const auto state = wait_finished(runner);
        require(state.error.empty() && state.exit_code == 23, "single-module fixture launch failed");
        auto log = state.log;
        log.erase(std::remove(log.begin(), log.end(), '\r'), log.end());
        const auto base = scope == pd_gui::dump_scope::main_image ? main.base : kernel.base;
        require(log.find(" -a " + address_argument(base) + " -nc\n") != std::string::npos,
            "single-module CLI base truncated or flags incorrect");
        require(log.find("arg[2]=" + std::to_string(request.pid) + "\n") != std::string::npos, "wrong selected PID argument");
        require(log.find("arg[4]=" + pd_gui::to_utf8(directory.path.native()) + "\n") != std::string::npos,
            "output argument with spaces was not preserved");
        require(log.find("arg[6]=" + address_argument(base) + "\n") != std::string::npos,
            "module address was not a single full-width argument");
    }

    request.scope = pd_gui::dump_scope::selected_module;
    request.module.reset();
    require(!runner.start(request), "missing selected module accepted");
    request.module = kernel;
    request.module->base = 0;
    require(!runner.start(request), "zero module base accepted");
    request.module = kernel;
    request.module->size = 0;
    require(!runner.start(request), "zero module size accepted");
    request.module = kernel;
    request.module->path.clear();
    require(!runner.start(request), "missing module path accepted");
    request.module->path = std::string("bad\0path", 8);
    require(!runner.start(request), "embedded null module path accepted");
    request.module->path = std::string("\xff", 1);
    require(!runner.start(request), "invalid UTF-8 module path accepted");
    request.module = kernel;
    request.creation_time = 0;
    require(!runner.start(request), "selected module without snapshot identity accepted");
    request.creation_time = snapshot.creation_time;
    ++request.module->size;
    require_async_error(runner, request, "stale module size accepted", "module");
    request.module = kernel;
    request.module->path += ".stale";
    require_async_error(runner, request, "stale module path accepted", "module");
    request.module = kernel;
    ++request.module->base;
    require_async_error(runner, request, "unloaded module base accepted", "module");
    request.module = kernel;
    ++request.creation_time;
    require_async_error(runner, request, "selected module accepted stale PID identity", "PID");
    request.scope = pd_gui::dump_scope::main_image;
    require_async_error(runner, request, "main image accepted stale PID identity", "PID");
    request = self_request(directory.path);
    request.scope = static_cast<pd_gui::dump_scope>(-1);
    require(!runner.start(request), "invalid scope accepted");

    request = self_request(directory.path);
    request.module = kernel; // An unused selection must not change all-module mode.
    require(runner.start(request), "default all-module request not queued");
    const auto state = wait_finished(runner);
    require(state.error.empty() && state.exit_code == 23, "default all-module fixture failed");
    require(state.log.find(" -a ") == std::string::npos && state.log.find(" -nc") == std::string::npos,
        "default all-module arguments changed");
}

void invalid_requests()
{
    fixture_directory directory;
    auto request = self_request(directory.path);
    pd_gui::dump_runner runner(self_executable());
    request.output = L"relative";
    require(!runner.start(request) && !runner.snapshot().error.empty(), "relative output accepted");
    request.output = directory.path / L"missing";
    require_async_error(runner, request, "missing output accepted");
    request.output = directory.path / L"\u03bb";
    require(!runner.start(request) && runner.snapshot().error.find("ASCII") != std::string::npos, "Unicode path not explained");
    request.output = self_executable();
    require_async_error(runner, request, "output file accepted as directory");
    request.output = directory.path;
    ++request.creation_time;
    require_async_error(runner, request, "stale PID identity accepted", "PID");
    request = self_request(directory.path);
    request.pid = 0;
    require(!runner.start(request), "zero PID accepted");
    pd_gui::dump_runner missing(directory.path / L"missing.exe");
    require_async_error(missing, self_request(directory.path), "missing executable accepted", "executable");
    pd_gui::dump_runner not_file(directory.path);
    require_async_error(not_file, self_request(directory.path), "directory executable accepted");
    request = self_request(directory.path);
    request.output = std::filesystem::path(directory.path.native() + std::wstring(1, L'\0') + L"suffix");
    require(!runner.start(request), "embedded null output accepted");
    pd_gui::dump_runner null_executable(std::filesystem::path(self_executable().native() + std::wstring(1, L'\0') + L"suffix"));
    require(!null_executable.start(self_request(directory.path)), "embedded null executable accepted");
    fixture_junction junction(directory.path / L"junction", directory.path);
    request = self_request(junction.path);
    require_async_error(runner, request, "reparse output accepted", "reparse");
    request.output = junction.path / L"new child";
    request.create_output = true;
    require_async_error(runner, request, "reparse ancestor accepted when creating output", "reparse");
}

void output_and_restart()
{
    fixture_directory directory;
    pd_gui::dump_runner runner(self_executable());
    auto request = self_request(directory.path);
    request.imports = request.loose_code = request.entrypoints = false;
    request.force_entrypoint = request.verbose = true;
    ULONGLONG revision = 0;
    for (int i = 0; i != 2; ++i)
    {
        require(runner.start(request), "fixture launch/restart failed");
        auto state = wait_finished(runner);
        require(!state.running && !state.preparing && !state.cancelled && state.error.empty() && state.exit_code == 23, "fixture completion incorrect");
        require(state.log_revision > revision, "log revision did not advance across restart");
        revision = state.log_revision;
        require(state.log.find("fixture stdout") != std::string::npos && state.log.find("fixture stderr") != std::string::npos,
            "combined output incomplete");
        require(state.log.find("-ni -nc -nep -eprec -v") != std::string::npos, "CLI options incorrect");
        require(state.log.find(" -a ") == std::string::npos, "all-module mode supplied a module address");
    }
}

void cancellation()
{
    fixture_directory directory(L"hold");
    pd_gui::dump_runner runner(self_executable());
    auto request = self_request(directory.path);
    require(runner.start(request), "hold fixture launch failed");
    require(!runner.start(request), "active runner allowed second launch");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (runner.snapshot().log.find("fixture stdout") == std::string::npos)
    {
        require(std::chrono::steady_clock::now() < deadline, "hold fixture never became active");
        require(!runner.snapshot().finished, "hold fixture failed during preparation");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    require(!runner.snapshot().preparing, "launched fixture still preparing");
    runner.cancel();
    runner.cancel();
    const auto state = wait_finished(runner);
    require(state.cancelled && !state.running && !state.preparing && state.error.empty(), "cancellation state incorrect");
    DWORD exit_code = 0;
    require(GetExitCodeProcess(GetCurrentProcess(), &exit_code) && exit_code == STILL_ACTIVE, "target was terminated");
    fixture_directory normal;
    require(runner.start(self_request(normal.path)), "restart after cancellation failed");
    const auto restarted = wait_finished(runner);
    require(!restarted.cancelled && restarted.error.empty() && restarted.exit_code == 23, "cancel state leaked into restart");
    const auto before = std::chrono::steady_clock::now();
    {
        pd_gui::dump_runner scoped(self_executable());
        require(scoped.start(request), "destructor fixture launch failed");
    }
    require(std::chrono::steady_clock::now() - before < std::chrono::seconds(5), "destructor blocked on child output");
}

void create_output()
{
    fixture_directory directory;
    struct cleanup
    {
        std::filesystem::path parent, leaf;
        ~cleanup() { RemoveDirectoryW(leaf.c_str()); RemoveDirectoryW(parent.c_str()); }
    } folders{directory.path / L"new parent", directory.path / L"new parent" / L"new leaf"};
    auto request = self_request(folders.leaf);
    request.create_output = true;
    pd_gui::dump_runner runner(self_executable());
    require(runner.start(request), "directory creation request not queued");
    const auto state = wait_finished(runner);
    require(!state.running && !state.preparing && state.error.empty() && state.exit_code == 23, "directory creation/launch failed");
    require(std::filesystem::is_directory(folders.leaf), "worker did not create nested output directory");
}

void preparation_cancellation()
{
    fixture_directory directory(L"hold");
    auto request = self_request(directory.path);
    pd_gui::dump_runner runner(self_executable());
    // No artificial network stalls: race immediate cancellation against the
    // local preparation/launch path repeatedly. Either side may win publication.
    for (int i = 0; i < 12; ++i)
    {
        require(runner.start(request), "preparation cancellation request not queued");
        const auto accepted = runner.snapshot();
        require(accepted.running && !accepted.finished, "queued hold request not active");
        runner.cancel();
        const auto state = wait_finished(runner);
        require(state.cancelled && !state.running && !state.preparing && state.error.empty(), "preparation cancellation did not finish safely");
        DWORD code = 0;
        require(GetExitCodeProcess(GetCurrentProcess(), &code) && code == STILL_ACTIVE, "preparation cancellation killed target");
    }
}

void capped_output()
{
    fixture_directory directory(L"large");
    pd_gui::dump_runner runner(self_executable());
    require(runner.start(self_request(directory.path)), "large fixture launch failed");
    const auto state = wait_finished(runner);
    require(state.error.empty() && state.exit_code == 23, "large fixture failed");
    require(state.log.size() == 1024 * 1024, "log cap not enforced");
    require(state.log_revision > 64, "log revision did not advance after reaching cap");
    require(state.log.find("fixture tail") != std::string::npos, "newest log bytes not retained");
    require(state.log.find("fixture stdout") == std::string::npos, "old log bytes retained");
}
}

// Only used when the tests executable itself is explicitly supplied as the child.
int run_gui_runner_fixture(int argc, char** argv)
{
    std::string output;
    for (int i = 1; i + 1 < argc; ++i)
        if (strcmp(argv[i], "-o") == 0) output = argv[i + 1];
    if (output.find("pd gui runner ") == std::string::npos) return 91;
    printf("fixture stdout\n");
    fprintf(stderr, "fixture stderr\n");
    for (int i = 1; i < argc; ++i) printf("%s%s", argv[i], i + 1 == argc ? "\n" : " ");
    for (int i = 1; i < argc; ++i) printf("arg[%d]=%s\n", i, argv[i]);
    if (output.size() >= 4 && output.compare(output.size() - 4, 4, "hold") == 0)
        Sleep(INFINITE);
    if (output.size() >= 5 && output.compare(output.size() - 5, 5, "large") == 0)
    {
        const std::string block(16384, 'x');
        for (int i = 0; i < 160; ++i) fwrite(block.data(), 1, block.size(), stdout);
        printf("fixture tail\n");
    }
    return 23;
}

void append_gui_runner_tests(std::vector<test_case>& tests)
{
    tests.push_back({"gui-runner-quoting", quoting});
    tests.push_back({"gui-runner-enumeration", enumeration});
    tests.push_back({"gui-runner-module-enumeration", module_enumeration});
    tests.push_back({"gui-runner-selective-modules", selective_modules});
    tests.push_back({"gui-runner-invalid-requests", invalid_requests});
    tests.push_back({"gui-runner-output-restart", output_and_restart});
    tests.push_back({"gui-runner-cancellation", cancellation});
    tests.push_back({"gui-runner-log-cap", capped_output});
    tests.push_back({"gui-runner-create-output", create_output});
    tests.push_back({"gui-runner-preparation-cancellation", preparation_cancellation});
}

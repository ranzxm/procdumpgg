#include "test_support.h"

class virtual_buffer
{
public:
	unsigned char* bytes;
	SIZE_T size;
	explicit virtual_buffer(SIZE_T length, DWORD allocation = MEM_RESERVE | MEM_COMMIT) : size(length)
	{
		bytes = static_cast<unsigned char*>(VirtualAlloc(NULL, size, allocation, PAGE_READWRITE));
		require(bytes != NULL, "test VirtualAlloc failed");
	}
	~virtual_buffer() { VirtualFree(bytes, 0, MEM_RELEASE); }
	virtual_buffer(const virtual_buffer&) = delete;
	virtual_buffer& operator=(const virtual_buffer&) = delete;
};

static void interior_region_read()
{
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	const SIZE_T page = info.dwPageSize;
	virtual_buffer source(page);
	memset(source.bytes, 0x5a, source.size);
	std::vector<unsigned char> destination(32, 0);
	process_stream stream(GetCurrentProcess(), source.bytes + 17);
	SIZE_T read = 0;
	require(stream.read(0, destination.size(), destination.data(), &read) && read == destination.size(), "small region read failed");
	for (SIZE_T i = 0; i < destination.size(); ++i)
		require(destination[i] == 0x5a, "interior region contents changed");
	require(stream.block_size(0) == page - 17, "block_size includes bytes before base");
	require(stream.estimate_section_size(0) == page - 17, "section estimate includes bytes before base");
}

static void sparse_region_read()
{
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	const SIZE_T page = info.dwPageSize;
	virtual_buffer source(3 * page);
	memset(source.bytes, 0x5a, source.size);
	DWORD previous;
	require(VirtualProtect(source.bytes + page, page, PAGE_NOACCESS, &previous) != 0, "test noaccess setup failed");
	process_stream stream(GetCurrentProcess(), source.bytes);
	std::vector<unsigned char> destination(source.size, 0xcc);
	SIZE_T read = 0;
	require(!stream.read(0, destination.size(), destination.data(), &read), "sparse read falsely reported complete");
	require(read == 2 * page, "sparse read count changed");
	require(stream.unread_ranges.size() == 1 && stream.unread_ranges[0].offset == page &&
		stream.unread_ranges[0].size == page, "sparse read did not locate the missing page");
	require(stream.unread_ranges[0].reason == stream_wrapper::unread_reason::no_access &&
		stream.unread_ranges[0].memory_state == MEM_COMMIT && stream.unread_ranges[0].protection == PAGE_NOACCESS,
		"noaccess reason or protection was lost");
	for (SIZE_T i = 0; i < destination.size(); ++i)
		require(destination[i] == (i >= page && i < 2 * page ? 0xcc : 0x5a), "sparse read overwrote skipped bytes");
	require(stream.read(0, page, destination.data(), &read) && stream.unread_ranges.empty(),
		"successful read retained stale unread ranges");
}

static void stream_failure_reasons()
{
	using reason = stream_wrapper::unread_reason;
	virtual_buffer source(0x1000), reserved(0x1000, MEM_RESERVE);
	unsigned char value = 0xcc;
	SIZE_T read = 99;
	process_stream reserve_stream(GetCurrentProcess(), reserved.bytes);
	require(!reserve_stream.read(0, 1, &value, &read) && read == 0 && value == 0xcc &&
		reserve_stream.unread_ranges[0].reason == reason::uncommitted &&
		reserve_stream.unread_ranges[0].memory_state == MEM_RESERVE, "reserved page reason incorrect");
	DWORD previous;
	require(VirtualProtect(source.bytes, source.size, PAGE_READWRITE | PAGE_GUARD, &previous) != 0, "protect guard page");
	process_stream guarded(GetCurrentProcess(), source.bytes);
	require(!guarded.read(0, 1, &value, &read) && read == 0 && value == 0xcc &&
		guarded.unread_ranges[0].reason == reason::guard_page, "guard page reason incorrect");
	MEMORY_BASIC_INFORMATION region = {};
	require(VirtualQuery(source.bytes, &region, sizeof(region)) == sizeof(region) &&
		(region.Protect & PAGE_GUARD), "diagnostics accessed or cleared a guard page");
	require(VirtualProtect(source.bytes, source.size, PAGE_READWRITE, &previous) != 0, "restore guard page");
	struct owned_handle
	{
		HANDLE value;
		explicit owned_handle(DWORD access) : value(OpenProcess(access, FALSE, GetCurrentProcessId()))
		{ require(value != NULL, "open restricted test handle"); }
		~owned_handle() { CloseHandle(value); }
	};
	owned_handle query_only(PROCESS_QUERY_INFORMATION), read_only(PROCESS_VM_READ);
	process_stream denied_read(query_only.value, source.bytes), denied_query(read_only.value, source.bytes);
	require(!denied_read.read(0, 1, &value, &read) && read == 0 &&
		denied_read.unread_ranges[0].reason == reason::read_failed &&
		denied_read.unread_ranges[0].error == ERROR_ACCESS_DENIED, "ReadProcessMemory error was not preserved");
	require(!denied_query.read(0, 1, &value, &read) && read == 0 &&
		denied_query.unread_ranges[0].reason == reason::query_failed &&
		denied_query.unread_ranges[0].error == ERROR_ACCESS_DENIED, "VirtualQueryEx error was not preserved");
	require(!guarded.read(-1, 1, &value, &read) && read == 0 &&
		guarded.unread_ranges[0].reason == reason::invalid_request, "invalid read reason incorrect");
}

static void capture_accounting(const image_capture_report& report)
{
	const auto classified = report.unread_header_bytes + report.unread_executable_bytes + report.unread_data_bytes +
		report.unread_directory_bytes + report.unread_outside_layout_bytes + report.unread_synthetic_header_bytes + report.unread_unknown_bytes;
	unsigned __int64 raw = 0, split = 0;
	for (const auto& range : report.unread_ranges) raw += range.size;
	for (const auto& detail : report.classified_ranges) split += detail.unread.size;
	require(raw == split && raw == classified && raw == report.requested_bytes - report.read_bytes,
		"capture classification lost or duplicated unread bytes");
}

template<typename NT>
static void capture_layout(bool win64)
{
	virtual_buffer source(0x5000);
	const auto fixture = pe_fixture(win64);
	memcpy(source.bytes, fixture.data(), 0x200);
	auto& nt = *reinterpret_cast<NT*>(source.bytes + 0x80);
	nt.FileHeader.NumberOfSections = 2;
	nt.OptionalHeader.SizeOfImage = 0x5000;
	auto* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(&nt + 1);
	sections[0].VirtualAddress = 0x2000;
	sections[0].Misc.VirtualSize = sections[0].SizeOfRawData = 0x800;
	sections[1] = {};
	memcpy(sections[1].Name, ".data", 5);
	sections[1].VirtualAddress = 0x4000;
	sections[1].Misc.VirtualSize = sections[1].SizeOfRawData = 0x1000;
	sections[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	test_options options;
	pe_header header(GetCurrentProcess(), source.bytes, NULL, &options);
	require(header.process_pe_header(), "layout fixture header rejected");
	DWORD previous;
	require(VirtualProtect(source.bytes + 0x1000, 0x1000, PAGE_NOACCESS, &previous) != 0, "protect alignment gap");
	require(header.process_sections(), "gap-only partial capture rejected");
	const auto& gap = header.capture_report();
	require(gap.status == image_capture_status::partial && gap.memory_source &&
		gap.base_address == reinterpret_cast<uintptr_t>(source.bytes) && !gap.generated_layout && !gap.adjusted_layout &&
		gap.unread_outside_layout_bytes == 0x1000 && gap.unread_header_bytes == 0 &&
		gap.unread_executable_bytes == 0 && gap.unread_data_bytes == 0 && gap.unread_unknown_bytes == 0 &&
		gap.classified_ranges.size() == 1 && gap.classified_ranges[0].area == image_capture_area::outside_layout,
		"alignment gap was misreported as lost header/section bytes");
	capture_accounting(gap);
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE] = {0x1800, 0x100};
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = {0x1200, 0x100};
	require(header.process_pe_header() && header.process_sections(), "directory-gap fixture rejected");
	require(header.capture_report().unread_directory_bytes == 0x100 &&
		header.capture_report().unread_outside_layout_bytes == 0xf00 &&
		header.capture_report().classified_ranges.size() == 3,
		"directory data was treated as a gap or certificate file offsets as RVAs");
	capture_accounting(header.capture_report());
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE] = {};
	nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = {};
	require(header.process_pe_header(), "refresh layout header");
	require(VirtualProtect(source.bytes + 0x1000, 0x4000, PAGE_NOACCESS, &previous) != 0, "protect mixed layout span");
	require(header.process_sections(), "mixed partial capture rejected");
	const auto& mixed = header.capture_report();
	require(mixed.unread_ranges.size() == 1 && mixed.classified_ranges.size() == 4 &&
		mixed.unread_executable_bytes == 0x800 && mixed.unread_data_bytes == 0x1000 &&
		mixed.unread_outside_layout_bytes == 0x2800 && mixed.unread_header_bytes == 0 &&
		mixed.classified_ranges[1].section_index == 0 && mixed.classified_ranges[1].section_name == ".text" &&
		mixed.classified_ranges[3].section_index == 1 && mixed.classified_ranges[3].section_name == ".data",
		"mixed span was not split at section boundaries");
	for (const auto& detail : mixed.classified_ranges)
		require(detail.unread.reason == stream_wrapper::unread_reason::no_access &&
			detail.unread.protection == PAGE_NOACCESS, "classification lost read-failure details");
	capture_accounting(mixed);
	require(VirtualProtect(source.bytes, source.size, PAGE_READWRITE, &previous) != 0 &&
		VirtualProtect(source.bytes, 0x1000, PAGE_NOACCESS, &previous) != 0, "protect original header");
	require(header.process_sections() && header.capture_report().unread_header_bytes == 0x200 &&
		header.capture_report().unread_outside_layout_bytes == 0xe00 &&
		header.capture_report().classified_ranges[0].area == image_capture_area::headers,
		"original header loss was not distinguished from page padding");
	capture_accounting(header.capture_report());
	require(VirtualProtect(source.bytes, source.size, PAGE_READWRITE, &previous) != 0, "restore layout fixture");
	sections[1].VirtualAddress = 0x2000;
	require(header.process_pe_header(), "overlapping fixture header rejected");
	require(VirtualProtect(source.bytes + 0x2000, 0x1000, PAGE_NOACCESS, &previous) != 0, "protect overlapping sections");
	require(header.process_sections() && header.capture_report().unread_unknown_bytes == 0x800 &&
		header.capture_report().unread_data_bytes == 0x800 && header.capture_report().unread_executable_bytes == 0 &&
		header.capture_report().classified_ranges[0].area == image_capture_area::ambiguous_layout,
		"overlapping sections were assigned an unjustified unique category");
	capture_accounting(header.capture_report());
	require(VirtualProtect(source.bytes, source.size, PAGE_READWRITE, &previous) != 0, "restore overlapping fixture");
	sections[1].VirtualAddress = 0x4000;
	nt.OptionalHeader.SizeOfHeaders = 0x180;
	require(header.process_pe_header() && header.process_sections() &&
		header.capture_report().status == image_capture_status::complete && header.capture_report().adjusted_layout,
		"complete reads concealed a header/section-table layout anomaly");
	require(VirtualProtect(source.bytes + 0x1000, 0x1000, PAGE_NOACCESS, &previous) != 0 &&
		header.process_sections() && header.capture_report().adjusted_layout &&
		header.capture_report().unread_unknown_bytes == 0x1000 && header.capture_report().unread_outside_layout_bytes == 0,
		"header layout anomaly classification changed between complete and partial captures");
	capture_accounting(header.capture_report());
	nt.OptionalHeader.SizeOfHeaders = 0x200;
	require(VirtualProtect(source.bytes, source.size, PAGE_READWRITE, &previous) != 0 &&
		VirtualProtect(source.bytes + 0x1000, 0x1000, PAGE_NOACCESS, &previous) != 0, "protect adjusted-layout gap");
	nt.FileHeader.NumberOfSections = 300;
	require(header.process_pe_header() && header.process_sections() && header.capture_report().adjusted_layout &&
		header.capture_report().unread_unknown_bytes == 0x1000 && header.capture_report().unread_outside_layout_bytes == 0,
		"a truncated section table reassured about unknown gaps");
	capture_accounting(header.capture_report());
}

static void generated_capture_layout(bool win64)
{
	virtual_buffer source(0x3000);
	DWORD previous;
	require(VirtualProtect(source.bytes, 0x2000, PAGE_NOACCESS, &previous) != 0, "protect synthetic header location");
	test_options options;
	pe_header header(GetCurrentProcess(), source.bytes + 0x2000, NULL, &options);
	require(header.build_pe_header(0x1000, win64, 1) && header.process_sections(), "generated fixture rejected");
	const auto& report = header.capture_report();
	require(report.status == image_capture_status::partial && report.generated_layout &&
		report.base_address == reinterpret_cast<uintptr_t>(source.bytes) &&
		report.unread_synthetic_header_bytes == 0x2000 && report.unread_header_bytes == 0 &&
		report.unread_executable_bytes == 0 && report.classified_ranges.size() == 1 &&
		report.classified_ranges[0].area == image_capture_area::synthetic_headers,
		"synthesized PE headers were misreported as lost original headers");
	capture_accounting(report);
}

static void file_capture_layout(bool win64)
{
	temporary_file source;
	auto bytes = pe_fixture(win64);
	bytes.resize(0x600);
	source.write(bytes);
	test_options options;
	pe_header header(source.path, &options);
	require(header.process_pe_header() && header.process_sections(), "truncated file fixture rejected");
	const auto& report = header.capture_report();
	require(report.status == image_capture_status::partial && !report.memory_source && report.base_address == 0 &&
		report.unread_executable_bytes == 0xc00 && report.classified_ranges.size() == 1 &&
		report.classified_ranges[0].unread.offset == 0x1400 &&
		report.classified_ranges[0].unread.reason == stream_wrapper::unread_reason::end_of_file,
		"file EOF was not translated from raw offsets into section RVAs");
	capture_accounting(report);
}

template<typename NT>
static void image_capture(bool win64)
{
	virtual_buffer source(0x3000);
	const auto fixture = pe_fixture(win64);
	memcpy(source.bytes, fixture.data(), 0x200);
	auto& nt = *reinterpret_cast<NT*>(source.bytes + 0x80);
	nt.OptionalHeader.SizeOfImage = 0x3000;
	auto& section = *reinterpret_cast<IMAGE_SECTION_HEADER*>(&nt + 1);
	section.Misc.VirtualSize = section.SizeOfRawData = 0x2000;
	memset(source.bytes + 0x1000, 0x5a, 0x2000);
	test_options options;
	pe_header header(GetCurrentProcess(), source.bytes, NULL, &options);
	require(header.capture_report().status == image_capture_status::not_captured, "new image already captured");
	require(header.process_pe_header() && header.process_sections(), "complete fixture rejected");
	require(header.capture_report().status == image_capture_status::complete &&
		header.capture_report().read_bytes == 0x3000 && header.capture_report().unread_ranges.empty(),
		"complete image capture misreported");
	DWORD previous;
	require(VirtualProtect(source.bytes + 0x1000, 0x1000, PAGE_NOACCESS, &previous) != 0, "protect image page");
	require(header.process_sections(), "useful partial capture discarded");
	const auto& report = header.capture_report();
	require(report.status == image_capture_status::partial && report.requested_bytes == 0x3000 &&
		report.read_bytes == 0x2000 && report.unread_ranges.size() == 1 &&
		report.unread_ranges[0].offset == 0x1000 && report.unread_ranges[0].size == 0x1000,
		"partial image capture coverage incorrect");
	export_list exports;
	require(header.process_disk_image(&exports, NULL), "partial image reconstruction rejected");
	temporary_file output;
	require(DeleteFileA(output.path) && header.write_image(output.path), "partial image write failed");
	const auto bytes = output.read();
	const auto& output_nt = *reinterpret_cast<const NT*>(bytes.data() + 0x80);
	const auto& output_section = *reinterpret_cast<const IMAGE_SECTION_HEADER*>(&output_nt + 1);
	const SIZE_T raw = output_section.PointerToRawData;
	require(range_fits(bytes.size(), raw, 0x2000), "partial output truncated");
	for (SIZE_T i = 0; i < 0x2000; ++i)
		require(bytes[raw + i] == (i < 0x1000 ? 0 : 0x5a), "partial output lost readable bytes or fabricated missing data");
	require(VirtualProtect(source.bytes, source.size, PAGE_NOACCESS, &previous) != 0, "protect full image");
	require(!header.process_sections() && header.capture_report().status == image_capture_status::failed &&
		header.capture_report().read_bytes == 0, "empty capture reported success");
	require(!header.process_disk_image(&exports, NULL), "failed capture was reconstructed");
	require(VirtualProtect(source.bytes, source.size, PAGE_READWRITE, &previous) != 0, "restore full image");
	require(header.process_sections() && header.capture_report().status == image_capture_status::complete &&
		header.capture_report().unread_ranges.empty(), "retry retained stale partial status");
}

static void file_stream_bounds()
{
	temporary_file file;
	file.write(std::vector<unsigned char>{1, 2, 3});
	file_stream stream(file.path);
	require(stream.block_size(4) == 0 && stream.block_size(-1) == 0, "file block size underflow");
	unsigned char value = 0xcc;
	SIZE_T read = 99;
	require(!stream.read(-1, 1, &value, &read) && read == 0 && value == 0xcc, "negative file offset accepted");
	char name = 'x';
	require(stream.get_short_name(&name, 0) == 0 && name == 'x', "zero-capacity name write");
	require(stream.get_long_name(&name, 0) == 0 && name == 'x', "zero-capacity path write");
}

static void borrowed_process_handle()
{
	HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
	require(handle != NULL, "test OpenProcess failed");
	{
		unsigned char value = 42;
		process_stream stream(handle, &value);
		unsigned char out = 0;
		SIZE_T read = 0;
		require(stream.read(0, 1, &out, &read) && out == 42, "borrowed process read failed");
	}
	DWORD exit_code = 0;
	const BOOL valid = GetExitCodeProcess(handle, &exit_code);
	CloseHandle(handle);
	require(valid != 0, "stream closed borrowed handle");
}

void append_stream_tests(std::vector<test_case>& tests)
{
	tests.emplace_back("stream-interior-region", interior_region_read);
	tests.emplace_back("stream-sparse-regions", sparse_region_read);
	tests.emplace_back("stream-file-bounds", file_stream_bounds);
	tests.emplace_back("stream-borrowed-handle", borrowed_process_handle);
	tests.emplace_back("pe32-image-capture-status", [] { image_capture<IMAGE_NT_HEADERS32>(false); });
	tests.emplace_back("pe64-image-capture-status", [] { image_capture<IMAGE_NT_HEADERS64>(true); });
	tests.emplace_back("stream-read-failure-reasons", stream_failure_reasons);
	tests.emplace_back("pe32-capture-layout", [] { capture_layout<IMAGE_NT_HEADERS32>(false); });
	tests.emplace_back("pe64-capture-layout", [] { capture_layout<IMAGE_NT_HEADERS64>(true); });
	tests.emplace_back("pe32-generated-capture-layout", [] { generated_capture_layout(false); });
	tests.emplace_back("pe64-generated-capture-layout", [] { generated_capture_layout(true); });
	tests.emplace_back("pe32-file-capture-layout", [] { file_capture_layout(false); });
	tests.emplace_back("pe64-file-capture-layout", [] { file_capture_layout(true); });
}

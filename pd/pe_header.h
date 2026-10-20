#pragma once

#include "nmd_assembly.h"
#include "stdafx.h"
#include <stdio.h>
#include "windows.h"
#include "stream_wrapper.h"
#include <stdlib.h>
#include "module_list.h"
#include "export_list.h"
#include <unordered_map>
#include <unordered_set>
#include "string.h"
#include "pe_imports.h"
#include <functional>
#include "pe_hash_database.h"

using namespace std;
using namespace std::tr1;


#define FILEPATH_SIZE 265

#define EP_HASH_OPCODES_MIN 30
#define EP_HASH_OPCODES_MAX 100

class pe_hash_database;

static bool static_zero_init = false;
static char static_zero [100];

enum ALIGNMENT
{
	PHYSICAL,
	VIRTUAL
};

struct IMPORT_SUMMARY
{
	size_t COUNT_UNIQUE_IMPORT_ADDRESSES;
	size_t COUNT_UNIQUE_IMPORT_LIBRARIES;
	unsigned __int64 HASH_GENERIC;
	unsigned __int64 HASH_SPECIFIC;
};

enum class image_capture_status { not_captured, complete, partial, failed };

enum class image_capture_area
{
	headers, executable_section, data_section, directory_data, outside_layout,
	synthetic_headers, ambiguous_layout, unknown_layout
};

struct image_unread_range
{
	stream_wrapper::unread_range unread;
	image_capture_area area = image_capture_area::unknown_layout;
	int section_index = -1;
	std::string section_name;
};

struct image_capture_report
{
	image_capture_status status = image_capture_status::not_captured;
	// Read-attempt totals; malformed overlapping file sections can count an RVA more than once.
	unsigned __int64 requested_bytes = 0;
	unsigned __int64 read_bytes = 0;
	unsigned __int64 base_address = 0;
	bool memory_source = false;
	bool generated_layout = false;
	bool adjusted_layout = false;
	unsigned __int64 unread_header_bytes = 0;
	unsigned __int64 unread_executable_bytes = 0;
	unsigned __int64 unread_data_bytes = 0;
	unsigned __int64 unread_directory_bytes = 0;
	unsigned __int64 unread_outside_layout_bytes = 0;
	unsigned __int64 unread_synthetic_header_bytes = 0;
	unsigned __int64 unread_unknown_bytes = 0;
	// Missing spans use image RVAs, not input file offsets.
	std::vector<stream_wrapper::unread_range> unread_ranges;
	// Splits spans at parsed header/section/directory boundaries; not a PE validity verdict.
	std::vector<image_unread_range> classified_ranges;
};

class pe_header
{
	friend struct entrypoint_benchmark;
	
	unsigned __int64 _unique_hash;
	unsigned __int64 _unique_hash_ep;
	unsigned __int64 _unique_hash_ep_short;

	PD_OPTIONS* _options = NULL;

	stream_wrapper* _stream = NULL;
	void* _original_base = NULL;


	SIZE_T _raw_header_size = 0;
	unsigned char* _raw_header = NULL;
	SIZE_T _image_size = 0;
	unsigned char* _image = NULL;
	SIZE_T _disk_image_size = 0;
	unsigned char* _disk_image = NULL;
	

	// Extracted current and original filename information about this module
	SIZE_T _name_filepath_short_size;
	char* _name_filepath_short = NULL;
	SIZE_T _name_filepath_long_size;
	char* _name_filepath_long = NULL;
	SIZE_T _name_original_exports_size;
	char* _name_original_exports = NULL;
	SIZE_T _name_original_manifest_size;
	char* _name_original_manifest = NULL;
	SIZE_T _name_symbols_path_size;
	char* _name_symbols_path = NULL;


	bool _parsed_dos;
	IMAGE_DOS_HEADER* _header_dos = NULL;

	bool _parsed_pe_32;
	IMAGE_NT_HEADERS32* _header_pe32 = NULL;
	bool _parsed_pe_64;
	IMAGE_NT_HEADERS64* _header_pe64 = NULL;
	int _correction_offset = 0;

	// Import table
	int _header_import_descriptors_count = 0;
	IMAGE_IMPORT_DESCRIPTOR* _header_import_descriptors = NULL;

	// Export table
	IMAGE_EXPORT_DIRECTORY* _header_export_directory = NULL;
	export_list* _export_list = NULL;
	
	bool _parsed_sections;
	bool _generated_header = false;
	bool _section_layout_adjusted = false;
	image_capture_report _capture;
	bool _read_image(long offset, SIZE_T size, unsigned char* output, SIZE_T* read, SIZE_T rva);
	bool _finish_capture();
	void _classify_capture();
	int _num_sections = 0;
	IMAGE_SECTION_HEADER* _header_sections = NULL;
	DWORD* _header_section_sizes = NULL;

	bool _test_read( unsigned char* buffer, SIZE_T length, unsigned char* read_ptr, SIZE_T read_length );
	void _clear_images();
	void _clear_header();
	bool _reject_size();
	bool _append_import_section(DWORD rva, DWORD size);
	bool _pack_disk_image(const unsigned char* image, SIZE_T size, SIZE_T cookie_rva);
	bool _writable_data_range(SIZE_T rva, SIZE_T width) const;
	bool _reexecution_import_ranges(std::vector<std::pair<SIZE_T, SIZE_T>>& ranges) const;
	bool _reexecution_cookie_rva(SIZE_T& rva) const;
	bool _executable_range(SIZE_T rva, SIZE_T length) const;
	void _recover_entrypoint(pe_hash_database* database);
	
	unsigned __int64 _hash_asm(SIZE_T offset);
	unsigned __int64 _hash_short_asm(SIZE_T offset);
	
	
	DWORD _section_align( DWORD address, DWORD alignment);
	__int64 _section_align( __int64 address, DWORD alignment);

public:
	pe_header( char* filename, PD_OPTIONS* options );
	pe_header( DWORD pid, void* base, module_list* modules, PD_OPTIONS* options );
	pe_header( DWORD pid, module_list* modules, PD_OPTIONS* options );
	pe_header( HANDLE ph, void* base, module_list* modules, PD_OPTIONS* options );
	
	bool build_pe_header( __int64 size, bool amd64 );
	bool build_pe_header( __int64 size, bool amd64, int num_sections_limit );
	
	bool process_pe_header( );
	bool process_import_directory( );
	bool process_export_directory( );
	bool process_relocation_directory();
	// A usable partial capture returns true; consult capture_report() for completeness.
	bool process_sections( );
	const image_capture_report& capture_report() const { return _capture; }
	bool process_disk_image(export_list* exports, pe_hash_database* hash_database);
	bool process_hash( );
	bool process_hash_ep( );

	bool somewhat_parsed();

	unsigned __int64 get_hash();
	unsigned __int64 get_hash_ep();
	unsigned __int64 get_hash_ep_short();

	IMPORT_SUMMARY get_imports_information( export_list* exports );
	IMPORT_SUMMARY get_imports_information( export_list* exports, __int64 size_limit );

	bool write_image( char* filename );

	export_list* get_exports();
	unsigned __int64 get_virtual_size();

	bool is_64();
	bool is_dll();
	bool is_exe();
	bool is_sys();
	char* get_name();
	void set_name(char* new_name);

	void print_report( FILE* stream );

	__int64 get_export_addresses();
	
	~pe_header(void);
};

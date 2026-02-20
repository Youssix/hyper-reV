#include "system.h"

#include <algorithm>
#include <filesystem>
#include <fstream>

#include "../hypercall/hypercall.h"
#include "../hook/hook.h"
#include "../pdb/pdb.hpp"

#include <portable_executable/image.hpp>

#include <print>
#include <vector>
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(std::uint32_t privilege, std::uint8_t enable, std::uint8_t current_thread, std::uint8_t* previous_enabled_state);

std::vector<std::uint8_t> dump_kernel_module(std::uint64_t module_base_address)
{
	constexpr std::uint64_t headers_size = 0x1000;

	std::vector<std::uint8_t> headers(headers_size);

	std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(headers.data(), module_base_address, sys::current_cr3, headers_size);

	if (bytes_read != headers_size)
	{
		return { };
	}

	std::uint16_t magic = *reinterpret_cast<std::uint16_t*>(headers.data());

	if (magic != 0x5a4d)
	{
		return { };
	}

	const portable_executable::image_t* image = reinterpret_cast<portable_executable::image_t*>(headers.data());

	std::vector<std::uint8_t> image_buffer(image->nt_headers()->optional_header.size_of_image);

	memcpy(image_buffer.data(), headers.data(), 0x1000);

	for (const auto& current_section : image->sections())
	{
		std::uint64_t read_offset = current_section.virtual_address;
		std::uint64_t read_size = current_section.virtual_size;

		hypercall::read_guest_virtual_memory(image_buffer.data() + read_offset, module_base_address + read_offset, sys::current_cr3, read_size);
	}

	return image_buffer;
}

std::uint64_t find_kernel_detour_holder_base_address(portable_executable::image_t* ntoskrnl, std::uint64_t ntoskrnl_base_address)
{
	for (const auto& current_section : ntoskrnl->sections())
	{
		std::string_view current_section_name(current_section.name);

		if (current_section_name.contains("Pad") == true && current_section.characteristics.mem_execute == 1)
		{
			return ntoskrnl_base_address + current_section.virtual_address;
		}
	}

	return 0;
}

std::unordered_map<std::string, std::uint64_t> parse_module_exports(const portable_executable::image_t* image, const std::string& module_name, const std::uint64_t module_base_address)
{
	std::unordered_map<std::string, std::uint64_t> exports = { };

	for (const auto& current_export : image->exports())
	{
		std::string current_export_name = module_name + "!" + current_export.name;

		std::uint64_t delta = reinterpret_cast<std::uint64_t>(current_export.address) - image->as<std::uint64_t>();

		exports[current_export_name] = module_base_address + delta;
	}

	return exports;
}

void add_module_to_list(const std::string& module_name, const std::vector<std::uint8_t>& module_dump, const std::uint64_t module_base_address, const std::uint32_t module_size)
{
	sys::kernel_module_t kernel_module = { };

	const portable_executable::image_t* image = reinterpret_cast<const portable_executable::image_t*>(module_dump.data());

	kernel_module.exports = parse_module_exports(image, module_name, module_base_address);
	kernel_module.base_address = module_base_address;
	kernel_module.size = module_size;

	sys::kernel::modules_list[module_name] = kernel_module;
}

void erase_unused_modules(const std::unordered_map<std::string, sys::kernel_module_t>& modules_not_found)
{
	for (const auto& [module_name, module_info] : modules_not_found)
	{
		sys::kernel::modules_list.erase(module_name);
	}
}

// requires SeDebugPriviledge, use PsLoadedModulesList instead unless if using before ntoskrnl.exe is parsed
std::vector<rtl_process_module_information_t> get_loaded_modules_priviledged()
{
	std::uint32_t size_of_information = 0;

	sys::user::query_system_information(11, nullptr, 0, &size_of_information);

	if (size_of_information == 0)
	{
		return { };
	}

	std::vector<std::uint8_t> buffer(size_of_information);

	std::uint32_t status = sys::user::query_system_information(11, buffer.data(), size_of_information, &size_of_information);

	if (NT_SUCCESS(status) == false)
	{
		return { };
	}

	rtl_process_modules_t* process_modules = reinterpret_cast<rtl_process_modules_t*>(buffer.data());

	rtl_process_module_information_t* start = &process_modules->modules[0];
	rtl_process_module_information_t* end = start + process_modules->module_count;

	return { start, end };
}

template <class t>
t read_kernel_virtual_memory(std::uint64_t address)
{
	t buffer = t();

	hypercall::read_guest_virtual_memory(&buffer, address, sys::current_cr3, sizeof(t));

	return buffer;
}

std::wstring read_unicode_string(std::uint64_t address)
{
	std::uint16_t length = read_kernel_virtual_memory<std::uint16_t>(address);

	if (length == 0)
	{
		return { };
	}

	std::uint64_t buffer_address = read_kernel_virtual_memory<std::uint64_t>(address + 8);

	std::wstring string(length / 2, L'\0');

	hypercall::read_guest_virtual_memory(string.data(), buffer_address, sys::current_cr3, length);

	return string;
}

std::uint64_t get_ps_loaded_module_list()
{
	const std::string ntoskrnl_name = "ntoskrnl.exe";

	if (sys::kernel::modules_list.contains(ntoskrnl_name) == 0)
	{
		return 0;
	}

	sys::kernel_module_t& ntoskrnl = sys::kernel::modules_list[ntoskrnl_name];

	const std::string ps_loaded_module_list_name = "ntoskrnl.exe!PsLoadedModuleList";

	return ntoskrnl.exports[ps_loaded_module_list_name];
}

std::uint8_t sys::kernel::parse_modules()
{
	const std::uint64_t ps_loaded_module_list = get_ps_loaded_module_list();

	if (ps_loaded_module_list == 0)
	{
		std::println("can't locate PsLoadedModuleList");

		return 0;
	}

	std::unordered_map<std::string, kernel_module_t> modules_not_found = modules_list;

	const std::uint64_t start_entry = ps_loaded_module_list;

	std::uint64_t current_entry = read_kernel_virtual_memory<std::uint64_t>(start_entry); // flink

	while (current_entry != start_entry)
	{
		kernel_module_t kernel_module = { };

		std::uint64_t module_base_address = read_kernel_virtual_memory<std::uint64_t>(current_entry + 0x30); // DllBase
		std::uint32_t module_size = read_kernel_virtual_memory<std::uint32_t>(current_entry + 0x40); // SizeOfImage
		std::string module_name = user::to_string(read_unicode_string(current_entry + 0x58)); // BaseDllName

		// current_entry must not be accessed after this point in this iteration
		current_entry = read_kernel_virtual_memory<std::uint64_t>(current_entry); // flink

		if (modules_list.contains(module_name) == true)
		{
			modules_not_found.erase(module_name);

			const kernel_module_t already_present_module = modules_list[module_name];

			if (already_present_module.base_address == module_base_address && already_present_module.size == module_size)
			{
				continue;
			}
		}

		std::vector<std::uint8_t> module_dump = dump_kernel_module(module_base_address);

		if (module_dump.empty() == true)
		{
			continue;
		}

		add_module_to_list(module_name, module_dump, module_base_address, module_size);
	}

	erase_unused_modules(modules_not_found);

	return 1;
}

void fix_dump(std::vector<std::uint8_t>& buffer)
{
	portable_executable::image_t* image = reinterpret_cast<portable_executable::image_t*>(buffer.data());

	for (auto& current_section : image->sections())
	{
		current_section.pointer_to_raw_data = current_section.virtual_address;
		current_section.size_of_raw_data = current_section.virtual_size;
	}
}

std::uint8_t sys::kernel::dump_module_to_disk(const std::string_view target_module_name, const std::string_view output_directory)
{
	const auto module_info = modules_list[target_module_name.data()];

	const std::uint64_t module_base_address = module_info.base_address;

	if (module_base_address == 0)
	{
		return 0;
	}

	std::vector<std::uint8_t> buffer = dump_kernel_module(module_base_address);

	if (buffer.empty() == 1)
	{
		return 0;
	}

	fix_dump(buffer);

	std::string output_path = std::string(output_directory) + "\\" + "dump_" + std::string(target_module_name);

	return fs::write_to_disk(output_path, buffer);
}

struct ntoskrnl_information_t
{
	std::uint64_t base_address;
	std::uint32_t size;

	std::vector<std::uint8_t> dump;
};

std::optional<ntoskrnl_information_t> load_ntoskrnl_information()
{
	std::uint8_t desired_privilege_state = 1;
	std::uint8_t previous_privilege_state = 0;

	if (sys::user::set_debug_privilege(desired_privilege_state, &previous_privilege_state) == 0)
	{
		std::println("unable to acquire necessary privilege");

		return std::nullopt;
	}

	const std::vector<rtl_process_module_information_t> loaded_modules = get_loaded_modules_priviledged();

	sys::user::set_debug_privilege(previous_privilege_state, &desired_privilege_state);

	for (const rtl_process_module_information_t& current_module : loaded_modules)
	{
		std::string_view current_module_name = reinterpret_cast<const char*>(current_module.full_path_name + current_module.offset_to_file_name);

		if (current_module_name == "ntoskrnl.exe")
		{
			std::vector<std::uint8_t> ntoskrnl_dump = dump_kernel_module(current_module.image_base);

			if (ntoskrnl_dump.empty() == true)
			{
				std::println("unable to dump ntoskrnl.exe");

				return std::nullopt;
			}

			ntoskrnl_information_t ntoskrnl_info = { };

			ntoskrnl_info.base_address = current_module.image_base;
			ntoskrnl_info.size = current_module.image_size;
			ntoskrnl_info.dump = ntoskrnl_dump;

			return ntoskrnl_info;
		}
	}

	return std::nullopt;
}

std::uint64_t scan_pattern_in_module(const std::vector<std::uint8_t>& module_dump,
	const std::uint8_t* pattern, const char* mask, std::size_t pattern_size)
{
	const auto* image = reinterpret_cast<const portable_executable::image_t*>(module_dump.data());

	for (const auto& section : image->sections())
	{
		if (section.characteristics.mem_execute == 0) continue;

		std::uint64_t section_start = section.virtual_address;
		std::uint64_t section_end = section_start + section.virtual_size;

		if (section_end > module_dump.size())
			section_end = module_dump.size();

		if (section_start + pattern_size > section_end) continue;

		for (std::uint64_t i = section_start; i <= section_end - pattern_size; i++)
		{
			bool found = true;
			for (std::size_t j = 0; j < pattern_size; j++)
			{
				if (mask[j] == '?') continue;
				if (module_dump[i + j] != pattern[j]) { found = false; break; }
			}
			if (found) return i;
		}
	}
	return 0;
}

std::uint8_t parse_ntoskrnl()
{
	std::optional<ntoskrnl_information_t> ntoskrnl_info = load_ntoskrnl_information();

	if (ntoskrnl_info.has_value() == 0)
	{
		std::println("unable to load ntoskrnl.exe's information");

		return 0;
	}

	std::vector<std::uint8_t>& ntoskrnl_dump = ntoskrnl_info->dump;

	portable_executable::image_t* ntoskrnl_image = reinterpret_cast<portable_executable::image_t*>(ntoskrnl_dump.data());

	add_module_to_list("ntoskrnl.exe", ntoskrnl_dump, ntoskrnl_info->base_address, ntoskrnl_info->size);

	hook::kernel_detour_holder_base = find_kernel_detour_holder_base_address(ntoskrnl_image, ntoskrnl_info->base_address);

	if (hook::kernel_detour_holder_base == 0)
	{
		std::println("unable to locate kernel hook holder");

		return 0;
	}

	// Pattern scan for KiSystemCall64 instrumentation callback exit point
	// Signature: mov r10, [rbp+0xE8] ; mov [rbp+0xE8], rax
	// 4C 8B 95 E8 ?? ?? ?? 48 89 85 E8
	{
		const std::uint8_t pattern[] = { 0x4C, 0x8B, 0x95, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x85, 0xE8 };
		const char mask[] = "xxxx???xxxx";

		std::uint64_t rva = scan_pattern_in_module(ntoskrnl_dump, pattern, mask, sizeof(pattern));
		if (rva != 0)
		{
			sys::offsets::ki_system_call64_service_exit_rva = rva;
			std::int32_t disp = *reinterpret_cast<const std::int32_t*>(&ntoskrnl_dump[rva + 3]);
			sys::offsets::ki_system_call64_service_exit_disp = disp;
			std::println("[+] KiSystemCall64 service exit hook point: RVA=0x{:X}, [rbp+0x{:X}]", rva, disp);
		}
		else
		{
			std::println("[!] WARNING: KiSystemCall64 service exit pattern not found");
		}
	}

	return 1;
}

// EPROCESS offsets resolved dynamically via PDB (see resolve_offsets_from_pdb)
// Fallback values for Windows 11 22H2+ if PDB download fails
namespace eprocess_offsets_fallback
{
	constexpr std::uint64_t active_process_links = 0x448;
	constexpr std::uint64_t unique_process_id = 0x440;
	constexpr std::uint64_t directory_table_base = 0x28;
	constexpr std::uint64_t image_file_name = 0x5A8;
	constexpr std::uint64_t section_base_address = 0x520;
	constexpr std::uint64_t peb = 0x550;
	constexpr std::uint64_t peb_kernel_callback_table = 0x58;

	// thread offsets (Win11 22H2+)
	constexpr std::uint64_t eprocess_thread_list_head = 0x5E0;
	constexpr std::uint64_t ethread_thread_list_entry = 0x538;
	constexpr std::uint64_t kthread_trap_frame = 0x90;
	constexpr std::uint64_t kthread_state = 0x184;
	constexpr std::uint64_t kthread_process = 0x220;
}

std::uint8_t resolve_offsets_from_pdb()
{
	std::println("[pdb] resolving EPROCESS/PEB offsets from ntoskrnl.pdb...");

	std::string pdb_path = pdb_download("C:\\Windows\\System32\\ntoskrnl.exe");

	if (pdb_path.empty())
	{
		std::println("[pdb] failed to download PDB, using fallback offsets");
		return 0;
	}

	pdb_context pdb_ctx = {};

	if (!pdb_load(pdb_path, &pdb_ctx))
	{
		std::println("[pdb] failed to load PDB, using fallback offsets");
		return 0;
	}

	auto resolve = [&](const std::string& struct_name, const std::wstring& property_name) -> std::uint64_t {
		ULONG offset = pdb_get_struct_property_offset(&pdb_ctx, struct_name, property_name);
		if (offset == static_cast<ULONG>(-1))
		{
			std::println("[pdb] WARNING: failed to resolve {}.{}", struct_name, sys::user::to_string(std::wstring(property_name)));
			return 0;
		}
		return static_cast<std::uint64_t>(offset);
	};

	sys::offsets::eprocess_active_process_links = resolve("_EPROCESS", L"ActiveProcessLinks");
	sys::offsets::eprocess_unique_process_id = resolve("_EPROCESS", L"UniqueProcessId");
	// DirectoryTableBase is in _KPROCESS (first member of _EPROCESS at offset 0)
	sys::offsets::eprocess_directory_table_base = resolve("_KPROCESS", L"DirectoryTableBase");
	sys::offsets::eprocess_image_file_name = resolve("_EPROCESS", L"ImageFileName");
	sys::offsets::eprocess_section_base_address = resolve("_EPROCESS", L"SectionBaseAddress");
	sys::offsets::eprocess_peb = resolve("_EPROCESS", L"Peb");
	sys::offsets::peb_kernel_callback_table = resolve("_PEB", L"KernelCallbackTable");

	std::println("[pdb] EPROCESS offsets: APL=0x{:X} PID=0x{:X} DTB=0x{:X} IFN=0x{:X} SBA=0x{:X} PEB=0x{:X}",
		sys::offsets::eprocess_active_process_links,
		sys::offsets::eprocess_unique_process_id,
		sys::offsets::eprocess_directory_table_base,
		sys::offsets::eprocess_image_file_name,
		sys::offsets::eprocess_section_base_address,
		sys::offsets::eprocess_peb);
	std::println("[pdb] PEB offsets: KCT=0x{:X}", sys::offsets::peb_kernel_callback_table);

	// thread offsets for syscall hijack
	sys::offsets::eprocess_thread_list_head = resolve("_EPROCESS", L"ThreadListHead");
	sys::offsets::ethread_thread_list_entry = resolve("_ETHREAD", L"ThreadListEntry");
	sys::offsets::kthread_trap_frame = resolve("_KTHREAD", L"TrapFrame");
	sys::offsets::kthread_state = resolve("_KTHREAD", L"State");
	sys::offsets::kthread_process = resolve("_KTHREAD", L"Process");

	std::println("[pdb] Thread offsets: TLH=0x{:X} TLE=0x{:X} TF=0x{:X} KS=0x{:X} KP=0x{:X}",
		sys::offsets::eprocess_thread_list_head,
		sys::offsets::ethread_thread_list_entry,
		sys::offsets::kthread_trap_frame,
		sys::offsets::kthread_state,
		sys::offsets::kthread_process);

	// resolve MmAccessFault RVA for EPT hook
	ULONG mmaf_rva = pdb_get_rva(&pdb_ctx, "MmAccessFault");
	if (mmaf_rva != 0 && mmaf_rva != static_cast<ULONG>(-1))
	{
		sys::offsets::mm_access_fault_rva = static_cast<std::uint64_t>(mmaf_rva);
		std::println("[pdb] MmAccessFault RVA: 0x{:X}", sys::offsets::mm_access_fault_rva);
	}
	else
	{
		std::println("[pdb] WARNING: failed to resolve MmAccessFault RVA");
	}

	// resolve KiSystemServiceExit RVA for syscall return EPT hook
	ULONG ksse_rva = pdb_get_rva(&pdb_ctx, "KiSystemServiceExit");
	if (ksse_rva != 0 && ksse_rva != static_cast<ULONG>(-1))
	{
		sys::offsets::ki_system_service_exit_rva = static_cast<std::uint64_t>(ksse_rva);
		std::println("[pdb] KiSystemServiceExit RVA: 0x{:X}", sys::offsets::ki_system_service_exit_rva);
	}
	else
	{
		std::println("[pdb] WARNING: KiSystemServiceExit not found, trying KiSystemCall64Shadow...");
		// fallback: try to find via KiSystemCall64Shadow
		ULONG ksc64_rva = pdb_get_rva(&pdb_ctx, "KiSystemCall64Shadow");
		if (ksc64_rva == 0 || ksc64_rva == static_cast<ULONG>(-1))
			ksc64_rva = pdb_get_rva(&pdb_ctx, "KiSystemCall64");
		if (ksc64_rva != 0 && ksc64_rva != static_cast<ULONG>(-1))
			std::println("[pdb] KiSystemCall64 RVA: 0x{:X} (will need signature scan for exit point)", ksc64_rva);
	}

	pdb_unload(pdb_path, &pdb_ctx);

	return 1;
}

void apply_fallback_offsets()
{
	sys::offsets::eprocess_active_process_links = eprocess_offsets_fallback::active_process_links;
	sys::offsets::eprocess_unique_process_id = eprocess_offsets_fallback::unique_process_id;
	sys::offsets::eprocess_directory_table_base = eprocess_offsets_fallback::directory_table_base;
	sys::offsets::eprocess_image_file_name = eprocess_offsets_fallback::image_file_name;
	sys::offsets::eprocess_section_base_address = eprocess_offsets_fallback::section_base_address;
	sys::offsets::eprocess_peb = eprocess_offsets_fallback::peb;
	sys::offsets::peb_kernel_callback_table = eprocess_offsets_fallback::peb_kernel_callback_table;

	// thread offsets
	sys::offsets::eprocess_thread_list_head = eprocess_offsets_fallback::eprocess_thread_list_head;
	sys::offsets::ethread_thread_list_entry = eprocess_offsets_fallback::ethread_thread_list_entry;
	sys::offsets::kthread_trap_frame = eprocess_offsets_fallback::kthread_trap_frame;
	sys::offsets::kthread_state = eprocess_offsets_fallback::kthread_state;
	sys::offsets::kthread_process = eprocess_offsets_fallback::kthread_process;
}

std::uint8_t sys::set_up()
{
	current_cr3 = hypercall::read_guest_cr3();

	if (current_cr3 == 0)
	{
		std::println("hyperv-attachment doesn't seem to be loaded");

		return 0;
	}

	// resolve EPROCESS/PEB offsets from PDB (fallback to hardcoded if fails)
	if (resolve_offsets_from_pdb() == 0)
	{
		std::println("using fallback hardcoded offsets");
		apply_fallback_offsets();
	}

	if (parse_ntoskrnl() == 0)
	{
		std::println("unable to parse ntoskrnl.exe");

		return 0;
	}

	if (kernel::parse_modules() == 0)
	{
		std::println("unable to parse kernel modules");

		return 0;
	}

	if (hook::set_up() == 0)
	{
		std::println("unable to set up kernel hook helper");

		return 0;
	}

	return 1;
}

void sys::clean_up()
{
	hook::clean_up();
}

std::uint32_t sys::user::query_system_information(std::int32_t information_class, void* information_out, std::uint32_t information_size, std::uint32_t* returned_size)
{
	return NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(information_class), information_out, information_size, reinterpret_cast<ULONG*>(returned_size));
}

std::uint32_t sys::user::adjust_privilege(std::uint32_t privilege, std::uint8_t enable, std::uint8_t current_thread_only, std::uint8_t* previous_enabled_state)
{
	return RtlAdjustPrivilege(privilege, enable, current_thread_only, previous_enabled_state);
}

std::uint8_t sys::user::set_debug_privilege(const std::uint8_t state, std::uint8_t* previous_state)
{
	constexpr std::uint32_t debug_privilege_id = 20;

	std::uint32_t status = adjust_privilege(debug_privilege_id, state, 0, previous_state);

	return NT_SUCCESS(status);
}

void* sys::user::allocate_locked_memory(std::uint64_t size, std::uint32_t protection)
{
	void* allocation_base = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);

	if (allocation_base == nullptr)
	{
		return nullptr;
	}

	std::int32_t lock_status = VirtualLock(allocation_base, size);

	if (lock_status == 0)
	{
		free_memory(allocation_base);

		return nullptr;
	}

	return allocation_base;
}

std::uint8_t sys::user::free_memory(void* address)
{
	std::int32_t free_status = VirtualFree(address, 0, MEM_RELEASE);

	return free_status != 0;
}

std::string sys::user::to_string(const std::wstring& wstring)
{
	if (wstring.empty() == 1)
	{
		return { };
	}

	std::string converted_string = { };

	std::ranges::transform(wstring,
		std::back_inserter(converted_string), [](wchar_t character)
		{
			return static_cast<char>(character);
		});

	return converted_string;
}

std::uint8_t sys::fs::exists(std::string_view path)
{
	return std::filesystem::exists(path);
}

std::uint8_t sys::fs::write_to_disk(const std::string_view full_path, const std::vector<std::uint8_t>& buffer)
{
	std::ofstream file(full_path.data(),std::ios::binary);

	if (file.is_open() == 0)
	{
		return 0;
	}

	file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());

	return file.good();
}

std::vector<sys::process_info_t> sys::process::enumerate_processes()
{
	std::vector<process_info_t> processes;

	const std::string ntoskrnl_name = "ntoskrnl.exe";

	if (kernel::modules_list.contains(ntoskrnl_name) == false)
	{
		return processes;
	}

	const kernel_module_t& ntoskrnl = kernel::modules_list[ntoskrnl_name];

	const std::string ps_initial_system_process_name = "ntoskrnl.exe!PsInitialSystemProcess";

	if (ntoskrnl.exports.contains(ps_initial_system_process_name) == false)
	{
		return processes;
	}

	const std::uint64_t ps_initial_system_process_ptr = ntoskrnl.exports.at(ps_initial_system_process_name);

	// Read the pointer to System EPROCESS
	const std::uint64_t system_eprocess = read_kernel_virtual_memory<std::uint64_t>(ps_initial_system_process_ptr);

	if (system_eprocess == 0)
	{
		return processes;
	}

	std::uint64_t current_eprocess = system_eprocess;

	do
	{
		process_info_t process = { };

		process.eprocess = current_eprocess;

		// Read PID
		process.pid = read_kernel_virtual_memory<std::uint64_t>(current_eprocess + sys::offsets::eprocess_unique_process_id);

		// Read CR3 (DirectoryTableBase)
		process.cr3 = read_kernel_virtual_memory<std::uint64_t>(current_eprocess + sys::offsets::eprocess_directory_table_base);

		// Read ImageFileName (15 chars max)
		char image_file_name[16] = { 0 };
		hypercall::read_guest_virtual_memory(image_file_name, current_eprocess + sys::offsets::eprocess_image_file_name, current_cr3, 15);
		process.name = std::string(image_file_name);

		// Read SectionBaseAddress (image base)
		process.base_address = read_kernel_virtual_memory<std::uint64_t>(current_eprocess + sys::offsets::eprocess_section_base_address);

		processes.push_back(process);

		// Get next process via ActiveProcessLinks.Flink
		std::uint64_t flink = read_kernel_virtual_memory<std::uint64_t>(current_eprocess + sys::offsets::eprocess_active_process_links);

		// flink points to ActiveProcessLinks of next process, subtract offset to get EPROCESS base
		current_eprocess = flink - sys::offsets::eprocess_active_process_links;

	} while (current_eprocess != system_eprocess && current_eprocess != 0);

	return processes;
}

std::optional<sys::process_info_t> sys::process::find_process_by_name(const std::string& name)
{
	const std::vector<process_info_t> processes = enumerate_processes();

	for (const auto& process : processes)
	{
		// Case-insensitive comparison
		std::string process_name_lower = process.name;
		std::string search_name_lower = name;

		std::transform(process_name_lower.begin(), process_name_lower.end(), process_name_lower.begin(), ::tolower);
		std::transform(search_name_lower.begin(), search_name_lower.end(), search_name_lower.begin(), ::tolower);

		if (process_name_lower.find(search_name_lower) != std::string::npos)
		{
			return process;
		}
	}

	return std::nullopt;
}

std::optional<sys::thread_info_t> sys::thread::find_hijackable_thread(
	std::uint64_t eprocess, std::uint64_t cr3)
{
	// read ThreadListHead (LIST_ENTRY) from EPROCESS
	std::uint64_t list_head_flink = read_kernel_virtual_memory<std::uint64_t>(
		eprocess + offsets::eprocess_thread_list_head);

	if (list_head_flink == 0)
	{
		std::println("[-] ThreadListHead.Flink is NULL");
		return std::nullopt;
	}

	std::uint64_t list_head_addr = eprocess + offsets::eprocess_thread_list_head;
	std::uint64_t current_entry = list_head_flink;
	int threads_checked = 0;

	while (current_entry != list_head_addr && current_entry != 0)
	{
		threads_checked++;

		// LIST_ENTRY points into ETHREAD at ThreadListEntry offset
		// ETHREAD base = current_entry - ethread_thread_list_entry offset
		std::uint64_t ethread = current_entry - offsets::ethread_thread_list_entry;

		// KTHREAD is at offset 0 of ETHREAD (first member)
		// Read KTHREAD.State (UCHAR)
		std::uint8_t thread_state = read_kernel_virtual_memory<std::uint8_t>(
			ethread + offsets::kthread_state);

		// Read KTHREAD.TrapFrame pointer for diagnostics
		std::uint64_t trap_frame_ptr = read_kernel_virtual_memory<std::uint64_t>(
			ethread + offsets::kthread_trap_frame);

		std::uint64_t saved_rip = 0;
		std::uint64_t saved_rsp = 0;
		if (trap_frame_ptr != 0)
		{
			saved_rip = read_kernel_virtual_memory<std::uint64_t>(
				trap_frame_ptr + offsets::ktrap_frame_rip);
			saved_rsp = read_kernel_virtual_memory<std::uint64_t>(
				trap_frame_ptr + offsets::ktrap_frame_rsp);
		}

		std::println("[*] Thread #{}: ETHREAD=0x{:X}, State={}, TrapFrame=0x{:X}, RIP=0x{:X}, RSP=0x{:X} {}",
			threads_checked, ethread, thread_state, trap_frame_ptr, saved_rip, saved_rsp,
			(thread_state == 5 && saved_rip != 0 && saved_rip < 0xFFFF800000000000ull) ? "<-- CANDIDATE" : "");

		// State 5 = Waiting (kernel wait state — thread is blocked in syscall)
		if (thread_state == 5)
		{
			if (trap_frame_ptr != 0)
			{
				// Saved RIP should be in usermode (< 0xFFFF800000000000)
				// This means the thread entered kernel from user mode via syscall
				if (saved_rip != 0 && saved_rip < 0xFFFF800000000000ull)
				{
					std::println("[+] Selected thread #{} for hijack", threads_checked);

					thread_info_t info = {};
					info.ethread = ethread;
					info.trap_frame_ptr = trap_frame_ptr;
					info.saved_rip = saved_rip;
					info.saved_rsp = saved_rsp;
					return info;
				}
			}
		}

		// Follow linked list: read Flink of current LIST_ENTRY
		current_entry = read_kernel_virtual_memory<std::uint64_t>(current_entry);

		if (threads_checked > 256) break; // safety limit
	}

	std::println("[-] No hijackable thread found (checked {} threads)", threads_checked);
	return std::nullopt;
}

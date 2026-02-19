#pragma once
#include <unordered_map>
#include <optional>
#include <string>
#include "system_def.h"

namespace sys
{
	struct kernel_module_t;

	std::uint8_t set_up();
	void clean_up();

	namespace kernel
	{
		std::uint8_t parse_modules();
		std::uint8_t dump_module_to_disk(std::string_view target_module_name, const std::string_view output_directory);

		inline std::unordered_map<std::string, kernel_module_t> modules_list = { };
	}

	namespace user
	{
		std::uint32_t query_system_information(std::int32_t information_class, void* information_out, std::uint32_t information_size, std::uint32_t* returned_size);

		std::uint32_t adjust_privilege(std::uint32_t privilege, std::uint8_t enable, std::uint8_t current_thread_only, std::uint8_t* previous_enabled_state);
		std::uint8_t set_debug_privilege(std::uint8_t state, std::uint8_t* previous_state);

		void* allocate_locked_memory(std::uint64_t size, std::uint32_t protection);
		std::uint8_t free_memory(void* address);

		std::string to_string(const std::wstring& wstring);
	}

	namespace fs
	{
		std::uint8_t exists(std::string_view path);

		std::uint8_t write_to_disk(std::string_view full_path, const std::vector<std::uint8_t>& buffer);
	}

	struct kernel_module_t
	{
		std::unordered_map<std::string, std::uint64_t> exports;

		std::uint64_t base_address;
		std::uint32_t size;
	};

	struct process_info_t
	{
		std::string name;
		std::uint64_t eprocess;
		std::uint64_t pid;
		std::uint64_t cr3;
		std::uint64_t base_address;
	};

	namespace process
	{
		std::vector<process_info_t> enumerate_processes();
		std::optional<process_info_t> find_process_by_name(const std::string& name);
	}

	// dynamic EPROCESS/PEB offsets (resolved from PDB at startup)
	namespace offsets
	{
		inline std::uint64_t eprocess_active_process_links = 0;
		inline std::uint64_t eprocess_unique_process_id = 0;
		inline std::uint64_t eprocess_directory_table_base = 0;
		inline std::uint64_t eprocess_image_file_name = 0;
		inline std::uint64_t eprocess_section_base_address = 0;
		inline std::uint64_t eprocess_peb = 0;
		inline std::uint64_t peb_kernel_callback_table = 0;
		inline std::uint64_t mm_access_fault_rva = 0;

		// thread offsets for syscall hijack
		inline std::uint64_t eprocess_thread_list_head = 0;
		inline std::uint64_t ethread_thread_list_entry = 0;
		inline std::uint64_t kthread_trap_frame = 0;
		inline std::uint64_t kthread_state = 0;
		inline std::uint64_t kthread_process = 0; // _KTHREAD.Process → EPROCESS ptr

		// KiSystemServiceExit RVA (resolved from PDB, for EPT hook)
		inline std::uint64_t ki_system_service_exit_rva = 0;

		// KTRAP_FRAME offsets (stable across Win10/11)
		constexpr std::uint64_t ktrap_frame_rip = 0x168;
		constexpr std::uint64_t ktrap_frame_rsp = 0x180;
		constexpr std::uint64_t ktrap_frame_cs  = 0x170;
	}

	struct thread_info_t {
		std::uint64_t ethread;
		std::uint64_t trap_frame_ptr;
		std::uint64_t saved_rip;
		std::uint64_t saved_rsp;
	};

	namespace thread
	{
		std::optional<thread_info_t> find_hijackable_thread(
			std::uint64_t eprocess, std::uint64_t cr3);
	}

	inline std::uint64_t current_cr3 = 0;
}

#pragma once
#include <cstdint>
#include <vector>
#include <structures/trap_frame.h>

namespace hypercall
{
	std::uint64_t read_guest_physical_memory(void* guest_destination_buffer, std::uint64_t guest_source_physical_address, std::uint64_t size);
	std::uint64_t write_guest_physical_memory(void* guest_source_buffer, std::uint64_t guest_destination_physical_address, std::uint64_t size);

	std::uint64_t read_guest_virtual_memory(void* guest_destination_buffer, std::uint64_t guest_source_virtual_address, std::uint64_t source_cr3, std::uint64_t size);
	std::uint64_t write_guest_virtual_memory(void* guest_source_buffer, std::uint64_t guest_destination_virtual_address, std::uint64_t destination_cr3, std::uint64_t size);

	std::uint64_t translate_guest_virtual_address(std::uint64_t guest_virtual_address, std::uint64_t guest_cr3);

	std::uint64_t read_guest_cr3();
	std::uint64_t read_cr3_exit_count();
	std::uint64_t read_cr3_swap_count();
	std::uint64_t read_cr3_last_seen();
	std::uint64_t write_guest_cr3(std::uint64_t new_cr3);
	std::uint64_t clone_guest_cr3(std::uint64_t target_cr3);
	std::uint64_t setup_hidden_region(std::uint64_t pml4_index);
	std::uint64_t map_hidden_page(std::uint64_t page_index);
	std::uint64_t set_user_cr3(std::uint64_t user_cr3);
	std::uint64_t clear_user_cr3();
	std::uint64_t enable_cr3_intercept(std::uint64_t target_cr3, std::uint64_t cloned_cr3);
	std::uint64_t disable_cr3_intercept();
	std::uint64_t enable_cr3_enforce();
	std::uint64_t disable_cr3_enforce();
	std::uint64_t read_mmaf_hit_count();
	std::uint64_t read_slat_violation_count();
	std::uint64_t arm_syscall_hijack(std::uint64_t shellcode_va, std::uint64_t rip_offset);
	std::uint64_t disarm_syscall_hijack();
	std::uint64_t read_hijack_cpuid_count();
	std::uint64_t read_hijack_claimed_count();
	std::uint64_t read_hijack_armed_state();

	std::uint64_t set_diag_watch_pfn(std::uint64_t pfn);
	std::uint64_t read_diag_watch_exec_count();
	std::uint64_t read_diag_watch_rw_count();
	std::uint64_t read_ept_pte(std::uint64_t guest_physical_address, std::uint64_t ept_index); // 0=hyperv_cr3, 1=hook_cr3

	std::uint64_t shadow_guest_page(std::uint64_t target_va);
	std::uint64_t unshadow_guest_page(std::uint64_t target_va);

	std::uint64_t add_slat_code_hook(std::uint64_t target_guest_physical_address, std::uint64_t shadow_page_guest_physical_address);
	std::uint64_t remove_slat_code_hook(std::uint64_t target_guest_physical_address);
	std::uint64_t hide_guest_physical_page(std::uint64_t target_guest_physical_address);

	std::uint64_t monitor_physical_page(std::uint64_t target_guest_physical_address);
	std::uint64_t unmonitor_physical_page(std::uint64_t target_guest_physical_address);

	std::uint64_t flush_logs(std::vector<trap_frame_log_t>& logs);

	std::uint64_t get_heap_free_page_count();
}

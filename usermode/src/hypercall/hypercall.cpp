#include "hypercall.h"
#include <hypercall/hypercall_def.h>

extern "C" std::uint64_t launch_raw_hypercall(hypercall_info_t rcx, std::uint64_t rdx, std::uint64_t r8, std::uint64_t r9);

std::uint64_t make_hypercall(hypercall_type_t call_type, std::uint64_t call_reserved_data, std::uint64_t rdx, std::uint64_t r8, std::uint64_t r9)
{
	hypercall_info_t hypercall_info = { };

	hypercall_info.primary_key = hypercall_primary_key;
	hypercall_info.secondary_key = hypercall_secondary_key;
	hypercall_info.call_type = call_type;
	hypercall_info.call_reserved_data = call_reserved_data;

	return launch_raw_hypercall(hypercall_info, rdx, r8, r9);
}

std::uint64_t hypercall::read_guest_physical_memory(void* guest_destination_buffer, std::uint64_t guest_source_physical_address, std::uint64_t size)
{
	hypercall_type_t call_type = hypercall_type_t::guest_physical_memory_operation;

	std::uint64_t call_data = static_cast<std::uint64_t>(memory_operation_t::read_operation);

	std::uint64_t guest_destination_virtual_address = reinterpret_cast<std::uint64_t>(guest_destination_buffer);

	return make_hypercall(call_type, call_data, guest_source_physical_address, guest_destination_virtual_address, size);
}

std::uint64_t hypercall::write_guest_physical_memory(void* guest_source_buffer, std::uint64_t guest_destination_physical_address, std::uint64_t size)
{
	hypercall_type_t call_type = hypercall_type_t::guest_physical_memory_operation;

	std::uint64_t call_data = static_cast<std::uint64_t>(memory_operation_t::write_operation);

	std::uint64_t guest_source_virtual_address = reinterpret_cast<std::uint64_t>(guest_source_buffer);

	return make_hypercall(call_type, call_data, guest_destination_physical_address, guest_source_virtual_address, size);
}

std::uint64_t hypercall::read_guest_virtual_memory(void* guest_destination_buffer, std::uint64_t guest_source_virtual_address, std::uint64_t source_cr3, std::uint64_t size)
{
	virt_memory_op_hypercall_info_t memory_op_call = { };

	memory_op_call.call_type = hypercall_type_t::guest_virtual_memory_operation;
	memory_op_call.memory_operation = memory_operation_t::read_operation;
	memory_op_call.address_of_page_directory = source_cr3 >> 12;

	hypercall_info_t hypercall_info = { .value = memory_op_call.value };

	std::uint64_t guest_destination_virtual_address = reinterpret_cast<std::uint64_t>(guest_destination_buffer);

	return make_hypercall(hypercall_info.call_type, hypercall_info.call_reserved_data, guest_destination_virtual_address, guest_source_virtual_address, size);
}

std::uint64_t hypercall::write_guest_virtual_memory(void* guest_source_buffer, std::uint64_t guest_destination_virtual_address, std::uint64_t destination_cr3, std::uint64_t size)
{
	virt_memory_op_hypercall_info_t memory_op_call = { };

	memory_op_call.call_type = hypercall_type_t::guest_virtual_memory_operation;
	memory_op_call.memory_operation = memory_operation_t::write_operation;
	memory_op_call.address_of_page_directory = destination_cr3 >> 12;

	hypercall_info_t hypercall_info = { .value = memory_op_call.value };

	std::uint64_t guest_source_virtual_address = reinterpret_cast<std::uint64_t>(guest_source_buffer);

	return make_hypercall(hypercall_info.call_type, hypercall_info.call_reserved_data, guest_source_virtual_address, guest_destination_virtual_address, size);
}

std::uint64_t hypercall::translate_guest_virtual_address(std::uint64_t guest_virtual_address, std::uint64_t guest_cr3)
{
	hypercall_type_t call_type = hypercall_type_t::translate_guest_virtual_address;

	return make_hypercall(call_type, 0, guest_virtual_address, guest_cr3, 0);
}

std::uint64_t hypercall::read_guest_cr3()
{
	hypercall_type_t call_type = hypercall_type_t::read_guest_cr3;

	return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::read_cr3_exit_count()
{
	hypercall_type_t call_type = hypercall_type_t::read_guest_cr3;

	return make_hypercall(call_type, 1, 0, 0, 0);
}

std::uint64_t hypercall::read_cr3_swap_count()
{
	hypercall_type_t call_type = hypercall_type_t::read_guest_cr3;

	return make_hypercall(call_type, 2, 0, 0, 0);
}

std::uint64_t hypercall::read_cr3_last_seen()
{
	hypercall_type_t call_type = hypercall_type_t::read_guest_cr3;

	return make_hypercall(call_type, 3, 0, 0, 0);
}

std::uint64_t hypercall::write_guest_cr3(std::uint64_t new_cr3)
{
	hypercall_type_t call_type = hypercall_type_t::write_guest_cr3;

	return make_hypercall(call_type, 0, new_cr3, 0, 0);
}

std::uint64_t hypercall::clone_guest_cr3(std::uint64_t target_cr3)
{
	hypercall_type_t call_type = hypercall_type_t::clone_guest_cr3;

	return make_hypercall(call_type, 0, target_cr3, 0, 0);
}

std::uint64_t hypercall::setup_hidden_region(std::uint64_t pml4_index)
{
	return make_hypercall(hypercall_type_t::clone_guest_cr3, 1, pml4_index, 0, 0);
}

std::uint64_t hypercall::map_hidden_page(std::uint64_t page_index)
{
	return make_hypercall(hypercall_type_t::clone_guest_cr3, 2, page_index, 0, 0);
}

std::uint64_t hypercall::set_user_cr3(std::uint64_t user_cr3)
{
	return make_hypercall(hypercall_type_t::clone_guest_cr3, 3, user_cr3, 0, 0);
}

std::uint64_t hypercall::clear_user_cr3()
{
	return make_hypercall(hypercall_type_t::clone_guest_cr3, 4, 0, 0, 0);
}

std::uint64_t hypercall::enable_cr3_intercept(std::uint64_t target_cr3, std::uint64_t cloned_cr3)
{
	hypercall_type_t call_type = hypercall_type_t::enable_cr3_intercept;

	return make_hypercall(call_type, 0, target_cr3, cloned_cr3, 0);
}

std::uint64_t hypercall::disable_cr3_intercept()
{
	hypercall_type_t call_type = hypercall_type_t::disable_cr3_intercept;

	return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::enable_cr3_enforce()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 4, 0, 0, 0);
}

std::uint64_t hypercall::disable_cr3_enforce()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 5, 0, 0, 0);
}

std::uint64_t hypercall::read_mmaf_hit_count()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 6, 0, 0, 0);
}

std::uint64_t hypercall::read_slat_violation_count()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 11, 0, 0, 0);
}

std::uint64_t hypercall::arm_syscall_hijack(std::uint64_t shellcode_va, std::uint64_t rip_offset)
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 8, shellcode_va, rip_offset, 0);
}

std::uint64_t hypercall::disarm_syscall_hijack()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 9, 0, 0, 0);
}

std::uint64_t hypercall::read_hijack_cpuid_count()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 12, 0, 0, 0);
}

std::uint64_t hypercall::read_hijack_claimed_count()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 13, 0, 0, 0);
}

std::uint64_t hypercall::read_hijack_armed_state()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 14, 0, 0, 0);
}

std::uint64_t hypercall::set_diag_watch_pfn(std::uint64_t pfn)
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 15, pfn, 0, 0);
}

std::uint64_t hypercall::read_diag_watch_exec_count()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 16, 0, 0, 0);
}

std::uint64_t hypercall::read_diag_watch_rw_count()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 17, 0, 0, 0);
}

std::uint64_t hypercall::read_ept_pte(std::uint64_t guest_physical_address, std::uint64_t ept_index)
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 18, guest_physical_address, ept_index, 0);
}

std::uint64_t hypercall::shadow_guest_page(std::uint64_t target_va)
{
	return make_hypercall(hypercall_type_t::clone_guest_cr3, 5, target_va, 0, 0);
}

std::uint64_t hypercall::unshadow_guest_page(std::uint64_t target_va)
{
	return make_hypercall(hypercall_type_t::clone_guest_cr3, 6, target_va, 0, 0);
}

std::uint64_t hypercall::add_slat_code_hook(std::uint64_t target_guest_physical_address, std::uint64_t shadow_page_guest_physical_address)
{
	hypercall_type_t call_type = hypercall_type_t::add_slat_code_hook;

	return make_hypercall(call_type, 0, target_guest_physical_address, shadow_page_guest_physical_address, 0);
}

std::uint64_t hypercall::remove_slat_code_hook(std::uint64_t target_guest_physical_address)
{
	hypercall_type_t call_type = hypercall_type_t::remove_slat_code_hook;

	return make_hypercall(call_type, 0, target_guest_physical_address, 0, 0);
}

std::uint64_t hypercall::hide_guest_physical_page(std::uint64_t target_guest_physical_address)
{
	hypercall_type_t call_type = hypercall_type_t::hide_guest_physical_page;

	return make_hypercall(call_type, 0, target_guest_physical_address, 0, 0);
}

std::uint64_t hypercall::monitor_physical_page(std::uint64_t target_guest_physical_address)
{
	hypercall_type_t call_type = hypercall_type_t::monitor_physical_page;

	return make_hypercall(call_type, 0, target_guest_physical_address, 0, 0);
}

std::uint64_t hypercall::unmonitor_physical_page(std::uint64_t target_guest_physical_address)
{
	hypercall_type_t call_type = hypercall_type_t::unmonitor_physical_page;

	return make_hypercall(call_type, 0, target_guest_physical_address, 0, 0);
}

std::uint64_t hypercall::flush_logs(std::vector<trap_frame_log_t>& logs)
{
	hypercall_type_t call_type = hypercall_type_t::flush_logs;

	return make_hypercall(call_type, 0, reinterpret_cast<std::uint64_t>(logs.data()), logs.size(), 0);
}

std::uint64_t hypercall::get_heap_free_page_count()
{
	hypercall_type_t call_type = hypercall_type_t::get_heap_free_page_count;

	return make_hypercall(call_type, 0, 0, 0, 0);
}

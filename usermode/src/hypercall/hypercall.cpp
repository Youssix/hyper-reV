#include "hypercall.h"
#include "../system/system.h"
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
	return make_hypercall(hypercall_type_t::write_guest_cr3, 0, new_cr3, 0, 0);
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

std::uint64_t hypercall::arm_process_cleanup(std::uint64_t target_eprocess,
                                              std::uint64_t ntoskrnl_base,
                                              const char* process_name)
{
	// R8 = ntoskrnl base (hypervisor resolves PsGetProcessImageFileName via PE export walk)
	// R9 = guest VA of name string on stack
	return make_hypercall(hypercall_type_t::read_guest_cr3, 23,
	                      target_eprocess,
	                      ntoskrnl_base,
	                      reinterpret_cast<std::uint64_t>(process_name));
}

std::uint64_t hypercall::read_cleanup_count()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 28, 0, 0, 0);
}

std::uint64_t hypercall::read_boot_hook_diag(std::uint64_t field)
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 35, field, 0, 0);
}

std::uint64_t hypercall::setup_exception_handler(std::uint64_t ki_dispatch_exception_va,
                                                  std::uint32_t displaced_byte_count)
{
	// Pack offsets: (displaced_count & 0xFF) | (ktf_r10_offset << 8) | (ktf_rax_offset << 24)
	const std::uint32_t ktf_r10 = static_cast<std::uint32_t>(sys::offsets::ktrap_frame_r10);
	const std::uint32_t ktf_rax = static_cast<std::uint32_t>(sys::offsets::ktrap_frame_rax);
	const std::uint64_t packed_offsets = (displaced_byte_count & 0xFF)
		| (static_cast<std::uint64_t>(ktf_r10) << 8)
		| (static_cast<std::uint64_t>(ktf_rax) << 24);

	// Direct hypercall (reserved_data=24): RDX = full kde_va, R8 = packed_offsets
	// Avoids relay encoding which truncates kernel VAs (top byte lost by va<<8)
	return make_hypercall(hypercall_type_t::read_guest_cr3, 24, ki_dispatch_exception_va, packed_offsets, 0);
}

std::uint64_t hypercall::store_probe_stub_vas(std::uint64_t copy_va, std::uint64_t write_va)
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 25, copy_va, write_va, 0);
}

std::uint64_t hypercall::setup_ki_page_fault_hook(std::uint64_t ki_page_fault_va,
                                                   std::uint32_t displaced_byte_count,
                                                   std::uint8_t hidden_pml4_index)
{
	// Pack: bits [7:0] = hidden_pml4_index, bits [15:8] = displaced_byte_count
	const std::uint64_t packed_args = (hidden_pml4_index & 0xFF)
		| (static_cast<std::uint64_t>(displaced_byte_count & 0xFF) << 8);

	return make_hypercall(hypercall_type_t::read_guest_cr3, 26, ki_page_fault_va, packed_args, 0);
}

std::uint64_t hypercall::read_idt_handler(std::uint8_t vector)
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 27, vector, 0, 0);
}

std::uint64_t hypercall::setup_mmclean_inline_hook(std::uint64_t mmclean_va,
                                                    std::uint64_t target_eprocess,
                                                    std::uint32_t displaced_byte_count)
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 29, mmclean_va, target_eprocess, displaced_byte_count);
}

std::uint64_t hypercall::remove_mmclean_inline_hook()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 31, 0, 0, 0);
}

std::uint64_t hypercall::setup_mmaf_inline_hook(std::uint64_t mmaf_va,
                                                 std::uint64_t clone_cr3,
                                                 std::uint32_t displaced_byte_count,
                                                 std::uint8_t hidden_pml4_index)
{
	// Pack: bits [15:0] = displaced_byte_count, bits [23:16] = hidden_pml4_index
	const std::uint64_t packed = (displaced_byte_count & 0xFFFF)
		| (static_cast<std::uint64_t>(hidden_pml4_index) << 16);
	return make_hypercall(hypercall_type_t::read_guest_cr3, 36, mmaf_va, clone_cr3, packed);
}

std::uint64_t hypercall::sig_scan_kernel(std::uint64_t scan_base, std::uint64_t scan_size,
                                          const std::uint8_t* pattern, const char* mask,
                                          std::uint32_t pattern_len, bool resolve_call)
{
	sig_scan_request_t request{};
	request.scan_base_va = scan_base;
	request.scan_size = scan_size;
	request.pattern_len = pattern_len;
	request.resolve_call = resolve_call ? 1 : 0;
	memcpy(request.pattern, pattern, pattern_len);
	memcpy(request.mask, mask, pattern_len);

	return make_hypercall(hypercall_type_t::read_guest_cr3, 33,
		reinterpret_cast<std::uint64_t>(&request), 0, 0);
}

std::uint64_t hypercall::read_mmaf_hit_count()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 6, 0, 0, 0);
}

std::uint64_t hypercall::screenshot_enable()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 30, 4, 0, 0);
}

std::uint64_t hypercall::screenshot_disable()
{
	return make_hypercall(hypercall_type_t::read_guest_cr3, 30, 5, 0, 0);
}

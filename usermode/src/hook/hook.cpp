#include "hook.h"
#include "kernel_detour_holder.h"
#include "../system/system.h"
#include "../hypercall/hypercall.h"

#include <Windows.h>
#include <print>
#include <vector>
#include <array>
#include <memory_resource>

#include "hook_disassembly.h"

hook::kernel_hook_info_t* hook::find_hook_on_same_page(std::uint64_t target_pfn, std::uint64_t excluding_va)
{
	for (auto& [va, info] : kernel_hook_list)
	{
		if (va != excluding_va && info.original_page_pfn == target_pfn)
		{
			return &info;
		}
	}

	return nullptr;
}

std::uint8_t hook::set_up()
{
	kernel_detour_holder_shadow_page_mapped = static_cast<std::uint8_t*>(sys::user::allocate_locked_memory(0x1000, PAGE_READWRITE));

	if (kernel_detour_holder_shadow_page_mapped == nullptr)
	{
		return 0;
	}

	std::uint64_t shadow_page_physical = hypercall::translate_guest_virtual_address(reinterpret_cast<std::uint64_t>(kernel_detour_holder_shadow_page_mapped), sys::current_cr3);

	if (shadow_page_physical == 0)
	{
		return 0;
	}

	kernel_detour_holder_physical_page = hypercall::translate_guest_virtual_address(kernel_detour_holder_base, sys::current_cr3);

	if (kernel_detour_holder_physical_page == 0)
	{
		return 0;
	}

	// in case of a previously wrongfully ended session which would've left the hook still applied
	hypercall::remove_slat_code_hook(kernel_detour_holder_physical_page);

	hypercall::read_guest_physical_memory(kernel_detour_holder_shadow_page_mapped, kernel_detour_holder_physical_page, 0x1000);

	std::uint64_t hook_status = hypercall::add_slat_code_hook(kernel_detour_holder_physical_page, shadow_page_physical);

	if (hook_status == 0)
	{
		return 0;
	}

	kernel_detour_holder::set_up(reinterpret_cast<std::uint64_t>(kernel_detour_holder_shadow_page_mapped), 0x1000);

	return 1;
}

void hook::clean_up()
{
	while (kernel_hook_list.empty() == false)
	{
		remove_kernel_hook(kernel_hook_list.begin()->first, 1);
	}

	saved_shadow_bytes.clear();

	if (kernel_detour_holder_physical_page != 0)
	{
		hypercall::remove_slat_code_hook(kernel_detour_holder_physical_page);
	}
}

#define d_inline_hook_bytes_size 14

std::pair<std::vector<std::uint8_t>, std::uint64_t> load_original_bytes_into_shadow_page(std::uint8_t* shadow_page_virtual, const std::uint64_t routine_to_hook_virtual, const std::uint8_t is_overflow_hook, const std::uint64_t extra_asm_byte_count)
{
	const std::uint64_t page_offset = routine_to_hook_virtual & 0xFFF;

	hypercall::read_guest_virtual_memory(shadow_page_virtual, routine_to_hook_virtual - page_offset, sys::current_cr3, is_overflow_hook == 1 ? 0x2000 : 0x1000);

	return hook_disasm::get_routine_aligned_bytes(shadow_page_virtual + page_offset, d_inline_hook_bytes_size + extra_asm_byte_count, routine_to_hook_virtual);
}

std::uint8_t set_up_inline_hook(std::uint8_t* shadow_page_virtual, std::uint64_t routine_to_hook_virtual, std::uint64_t routine_to_hook_physical, std::uint64_t detour_address, const std::pair<std::vector<std::uint8_t>, std::uint64_t>& original_bytes, const std::vector<std::uint8_t>& extra_assembled_bytes, const std::vector<uint8_t>& post_original_assembled_bytes, const std::uint8_t is_overflow_hook, std::uint64_t& overflow_shadow_page_physical_address, std::uint64_t& overflow_original_page_physical_address)
{
	std::array<std::uint8_t, d_inline_hook_bytes_size> jmp_to_detour_bytes = {
		0x68, 0x21, 0x43, 0x65, 0x87, // push   0xffffffff87654321
		0xC7, 0x44, 0x24, 0x04, 0x78, 0x56, 0x34, 0x12, // mov    DWORD PTR [rsp+0x4],0x12345678
		0xC3 // ret
	};

	parted_address_t parted_subroutine_to_jmp_to = { .value = detour_address };

	*reinterpret_cast<std::uint32_t*>(&jmp_to_detour_bytes[1]) = parted_subroutine_to_jmp_to.u.low_part;
	*reinterpret_cast<std::uint32_t*>(&jmp_to_detour_bytes[9]) = parted_subroutine_to_jmp_to.u.high_part;

	std::vector<std::uint8_t> inline_hook_bytes = extra_assembled_bytes;

	inline_hook_bytes.insert(inline_hook_bytes.end(), jmp_to_detour_bytes.begin(), jmp_to_detour_bytes.end());

	if (post_original_assembled_bytes.empty() == 0)
	{
		inline_hook_bytes.insert(inline_hook_bytes.end(), post_original_assembled_bytes.begin(), post_original_assembled_bytes.end());

		std::uint64_t nop_bytes_needed = original_bytes.second - inline_hook_bytes.size();

		inline_hook_bytes.insert(inline_hook_bytes.end(), nop_bytes_needed, 0x90); // nop padding until next actual instruction
	}

	const std::uint64_t page_offset = routine_to_hook_physical & 0xFFF;

	if (is_overflow_hook == 1)
	{
		std::uint8_t* overflow_shadow_page_virtual = shadow_page_virtual + 0x1000;

		overflow_shadow_page_physical_address = hypercall::translate_guest_virtual_address(reinterpret_cast<std::uint64_t>(overflow_shadow_page_virtual), sys::current_cr3);

		if (overflow_shadow_page_physical_address == 0)
		{
			return 0;
		}

		const std::uint64_t overflow_page_virtual_address = routine_to_hook_virtual + 0x1000;

		overflow_original_page_physical_address = hypercall::translate_guest_virtual_address(overflow_page_virtual_address, sys::current_cr3);

		if (overflow_original_page_physical_address == 0)
		{
			return 0;
		}

		const std::uint64_t hook_end = page_offset + inline_hook_bytes.size();
		const std::uint64_t bytes_overflowed = hook_end - 0x1000;

		const std::uint64_t prior_page_copy_size = inline_hook_bytes.size() - bytes_overflowed;

		memcpy(shadow_page_virtual + page_offset, inline_hook_bytes.data(), prior_page_copy_size);
		memcpy(overflow_shadow_page_virtual, inline_hook_bytes.data() + prior_page_copy_size, bytes_overflowed);
	}
	else
	{
		memcpy(shadow_page_virtual + page_offset, inline_hook_bytes.data(), inline_hook_bytes.size());
	}

	return 1;
}

std::uint8_t set_up_hook_handler(std::uint64_t routine_to_hook_virtual, std::uint16_t& detour_holder_shadow_offset, const std::pair<std::vector<std::uint8_t>, std::uint64_t>& original_bytes, const std::vector<uint8_t>& extra_assembled_bytes, const std::vector<uint8_t>& post_original_assembled_bytes)
{
	std::array<std::uint8_t, 14> return_to_original_bytes = {
		0x68, 0x21, 0x43, 0x65, 0x87, // push   0xffffffff87654321
		0xC7, 0x44, 0x24, 0x04, 0x78, 0x56, 0x34, 0x12, // mov    DWORD PTR [rsp+0x4],0x12345678
		0xC3 // ret
	};

	parted_address_t parted_subroutine_to_jmp_to = { };

	if (post_original_assembled_bytes.empty() == 0)
	{
		parted_subroutine_to_jmp_to.value = routine_to_hook_virtual + extra_assembled_bytes.size() + d_inline_hook_bytes_size;
	}
	else
	{
		parted_subroutine_to_jmp_to.value = routine_to_hook_virtual + original_bytes.second;
	}

	*reinterpret_cast<std::uint32_t*>(&return_to_original_bytes[1]) = parted_subroutine_to_jmp_to.u.low_part;
	*reinterpret_cast<std::uint32_t*>(&return_to_original_bytes[9]) = parted_subroutine_to_jmp_to.u.high_part;

	std::vector<std::uint8_t> hook_handler_bytes = original_bytes.first;

	hook_handler_bytes.insert(hook_handler_bytes.end(), return_to_original_bytes.begin(), return_to_original_bytes.end());

	void* bytes_buffer = kernel_detour_holder::allocate_memory(static_cast<std::uint16_t>(hook_handler_bytes.size()));

	if (bytes_buffer == nullptr)
	{
		return 0;
	}

	detour_holder_shadow_offset = kernel_detour_holder::get_allocation_offset(bytes_buffer);

	memcpy(bytes_buffer, hook_handler_bytes.data(), hook_handler_bytes.size());

	return 1;
}

std::uint8_t hook::add_kernel_hook(std::uint64_t routine_to_hook_virtual, const std::vector<std::uint8_t>& extra_assembled_bytes, const std::vector<uint8_t>& post_original_assembled_bytes)
{
	if (kernel_hook_list.contains(routine_to_hook_virtual) == true)
	{
		return 0;
	}

	std::uint64_t routine_to_hook_physical = hypercall::translate_guest_virtual_address(routine_to_hook_virtual, sys::current_cr3);

	if (routine_to_hook_physical == 0)
	{
		return 0;
	}

	const std::uint64_t page_offset = routine_to_hook_physical & 0xFFF;
	const std::uint64_t hook_end = page_offset + d_inline_hook_bytes_size + extra_assembled_bytes.size();

	const std::uint8_t is_overflow_hook = 0x1000 < hook_end;

	const std::uint64_t target_pfn = routine_to_hook_physical >> 12;
	kernel_hook_info_t* existing_hook = find_hook_on_same_page(target_pfn);

	// === Same-page path: reuse existing shadow page ===
	if (existing_hook != nullptr)
	{
		if (is_overflow_hook == 1 || existing_hook->overflow_original_page_pfn != 0)
		{
			return 0; // overflow hooks can't share pages
		}

		std::uint8_t* shadow_page_virtual = static_cast<std::uint8_t*>(existing_hook->get_mapped_shadow_page());

		// Shadow already has original bytes at our offset (only the other hook's offset is patched)
		std::pair<std::vector<std::uint8_t>, std::uint64_t> original_bytes = hook_disasm::get_routine_aligned_bytes(
			shadow_page_virtual + page_offset,
			d_inline_hook_bytes_size + extra_assembled_bytes.size() + post_original_assembled_bytes.size(),
			routine_to_hook_virtual);

		if (original_bytes.first.empty() == true)
		{
			return 0;
		}

		std::uint16_t detour_holder_shadow_offset = 0;

		std::uint8_t status = set_up_hook_handler(routine_to_hook_virtual, detour_holder_shadow_offset, original_bytes, extra_assembled_bytes, post_original_assembled_bytes);

		if (status == 0)
		{
			return 0;
		}

		std::uint64_t detour_address = kernel_detour_holder_base + detour_holder_shadow_offset;

		// Compute patch size and save original shadow bytes before patching
		std::uint64_t patch_size = post_original_assembled_bytes.empty()
			? extra_assembled_bytes.size() + d_inline_hook_bytes_size
			: original_bytes.second;

		saved_shadow_bytes[routine_to_hook_virtual] = std::vector<std::uint8_t>(
			shadow_page_virtual + page_offset,
			shadow_page_virtual + page_offset + patch_size);

		// Write inline hook onto existing shadow page
		std::uint64_t overflow_shadow = 0, overflow_original = 0;

		std::uint64_t hook_status = set_up_inline_hook(shadow_page_virtual, routine_to_hook_virtual, routine_to_hook_physical, detour_address, original_bytes, extra_assembled_bytes, post_original_assembled_bytes, 0, overflow_shadow, overflow_original);

		if (hook_status == 0)
		{
			saved_shadow_bytes.erase(routine_to_hook_virtual);
			return 0;
		}

		// Skip add_slat_code_hook — EPT already registered by the page owner

		kernel_hook_info_t hook_info = { };

		hook_info.set_mapped_shadow_page(shadow_page_virtual);
		hook_info.original_page_pfn = target_pfn;
		hook_info.overflow_original_page_pfn = 0;
		hook_info.detour_holder_shadow_offset = detour_holder_shadow_offset;
		hook_info.is_shadow_page_owner = 0;
		hook_info.patched_byte_count = static_cast<std::uint64_t>(patch_size);

		kernel_hook_list[routine_to_hook_virtual] = hook_info;

		return 1;
	}

	// === Normal path: allocate new shadow page ===

	void* shadow_page_virtual = sys::user::allocate_locked_memory(is_overflow_hook == 1 ? 0x2000 : 0x1000, PAGE_READWRITE);

	if (shadow_page_virtual == nullptr)
	{
		return 0;
	}

	std::uint64_t shadow_page_physical = hypercall::translate_guest_virtual_address(reinterpret_cast<std::uint64_t>(shadow_page_virtual), sys::current_cr3);

	if (shadow_page_physical == 0)
	{
		return 0;
	}

	std::pair<std::vector<std::uint8_t>, std::uint64_t> original_bytes = load_original_bytes_into_shadow_page(static_cast<std::uint8_t*>(shadow_page_virtual), routine_to_hook_virtual, is_overflow_hook, extra_assembled_bytes.size() + post_original_assembled_bytes.size());

	if (original_bytes.first.empty() == true)
	{
		return 0;
	}

	std::uint16_t detour_holder_shadow_offset = 0;

	std::uint8_t status = set_up_hook_handler(routine_to_hook_virtual, detour_holder_shadow_offset, original_bytes, extra_assembled_bytes, post_original_assembled_bytes);

	if (status == 0)
	{
		return 0;
	}

	std::uint64_t detour_address = kernel_detour_holder_base + detour_holder_shadow_offset;

	// Compute patch size and save original shadow bytes before patching
	std::uint64_t patch_size = post_original_assembled_bytes.empty()
		? extra_assembled_bytes.size() + d_inline_hook_bytes_size
		: original_bytes.second;

	saved_shadow_bytes[routine_to_hook_virtual] = std::vector<std::uint8_t>(
		static_cast<std::uint8_t*>(shadow_page_virtual) + page_offset,
		static_cast<std::uint8_t*>(shadow_page_virtual) + page_offset + patch_size);

	std::uint64_t overflow_shadow_page_physical_address = 0;
	std::uint64_t overflow_original_page_physical_address = 0;

	std::uint64_t hook_status = set_up_inline_hook(static_cast<std::uint8_t*>(shadow_page_virtual), routine_to_hook_virtual, routine_to_hook_physical, detour_address, original_bytes, extra_assembled_bytes, post_original_assembled_bytes, is_overflow_hook, overflow_shadow_page_physical_address, overflow_original_page_physical_address);

	if (hook_status == 0)
	{
		saved_shadow_bytes.erase(routine_to_hook_virtual);
		return 0;
	}

	hook_status = hypercall::add_slat_code_hook(routine_to_hook_physical, shadow_page_physical);

	if (hook_status == 0)
	{
		saved_shadow_bytes.erase(routine_to_hook_virtual);
		return 0;
	}

	if (overflow_shadow_page_physical_address != 0)
	{
		hook_status = hypercall::add_slat_code_hook(overflow_original_page_physical_address, overflow_shadow_page_physical_address);

		if (hook_status == 0)
		{
			saved_shadow_bytes.erase(routine_to_hook_virtual);
			return 0;
		}
	}

	kernel_hook_info_t hook_info = { };

	hook_info.set_mapped_shadow_page(shadow_page_virtual);
	hook_info.original_page_pfn = target_pfn;
	hook_info.overflow_original_page_pfn = overflow_original_page_physical_address >> 12;
	hook_info.detour_holder_shadow_offset = detour_holder_shadow_offset;
	hook_info.is_shadow_page_owner = 1;
	hook_info.patched_byte_count = static_cast<std::uint64_t>(patch_size);

	kernel_hook_list[routine_to_hook_virtual] = hook_info;

	return 1;
}

std::uint8_t hook::remove_kernel_hook(std::uint64_t hooked_routine_virtual, std::uint8_t do_list_erase)
{
	if (kernel_hook_list.contains(hooked_routine_virtual) == false)
	{
		std::println("unable to find kernel hook");

		return 0;
	}

	kernel_hook_info_t hook_info = kernel_hook_list[hooked_routine_virtual];

	// Check if another hook shares this physical page
	kernel_hook_info_t* other_hook = find_hook_on_same_page(hook_info.original_page_pfn, hooked_routine_virtual);

	if (other_hook != nullptr)
	{
		// Shared page: restore original bytes on shadow, skip EPT removal and shadow free
		auto saved_it = saved_shadow_bytes.find(hooked_routine_virtual);

		if (saved_it != saved_shadow_bytes.end())
		{
			const std::uint64_t page_offset = hooked_routine_virtual & 0xFFF;
			std::uint8_t* shadow = static_cast<std::uint8_t*>(hook_info.get_mapped_shadow_page());
			memcpy(shadow + page_offset, saved_it->second.data(), saved_it->second.size());
			saved_shadow_bytes.erase(saved_it);
		}

		// Transfer shadow page ownership if needed
		if (hook_info.is_shadow_page_owner == 1)
		{
			other_hook->is_shadow_page_owner = 1;
		}
	}
	else
	{
		// Sole hook on page: remove EPT and free shadow page
		if (hypercall::remove_slat_code_hook(hook_info.original_page_pfn << 12) == 0)
		{
			std::println("unable to remove slat counterpart of kernel hook");

			return 0;
		}

		if (hook_info.overflow_original_page_pfn != 0 && hypercall::remove_slat_code_hook(hook_info.overflow_original_page_pfn << 12) == 0)
		{
			std::println("unable to remove slat counterpart of kernel hook (2)");

			return 0;
		}

		if (sys::user::free_memory(hook_info.get_mapped_shadow_page()) == 0)
		{
			std::println("unable to deallocate mapped shadow page");

			return 0;
		}

		saved_shadow_bytes.erase(hooked_routine_virtual);
	}

	if (do_list_erase == 1)
	{
		kernel_hook_list.erase(hooked_routine_virtual);
	}

	// Free detour holder allocation (if this hook has one)
	if (hook_info.detour_holder_shadow_offset != 0)
	{
		void* detour_holder_allocation = kernel_detour_holder::get_allocation_from_offset(hook_info.detour_holder_shadow_offset);
		kernel_detour_holder::free_memory(detour_holder_allocation);
	}

	return 1;
}

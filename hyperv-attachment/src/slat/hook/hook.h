#pragma once
#include <cstdint>

union virtual_address_t;

namespace slat::hook
{
	void set_up_entries();

	std::uint64_t add(virtual_address_t target_guest_physical_address, virtual_address_t shadow_guest_physical_address, std::uint64_t hook_byte_length = 0);
	std::uint64_t add_to_same_page(virtual_address_t target_gpa, std::uint64_t hook_byte_length);
	std::uint64_t remove(virtual_address_t guest_physical_address);
	void remove_all();
}

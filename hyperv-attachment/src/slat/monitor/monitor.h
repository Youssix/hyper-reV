#pragma once
#include <cstdint>

union virtual_address_t;

namespace slat::monitor
{
	void set_up_entries();

	std::uint64_t add(virtual_address_t guest_physical_address);
	std::uint64_t remove(virtual_address_t guest_physical_address);
}

#pragma once
#include <cstdint>

namespace slat::violation
{
	std::uint8_t process();

#ifdef _INTELMACHINE
	extern std::uint64_t fork_sync_pending_gpa[];
#endif
}

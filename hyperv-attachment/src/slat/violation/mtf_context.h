#pragma once
#include <cstdint>
#include "../slat_def.h"

namespace slat::mtf
{
	constexpr std::uint64_t max_contexts = 128;

	struct context_t
	{
		std::uint64_t pending_gpa;
		slat_pte* hook_pte;
		std::uint64_t saved_pte_flags;
		std::uint8_t active;
		std::uint8_t is_write;
	};

	void set_up();

	void arm(std::uint16_t vpid, std::uint64_t gpa, slat_pte* hook_pte, std::uint64_t saved_flags, std::uint8_t is_write = 0);

	// Returns 1 if this was our MTF, 0 if not
	std::uint8_t process();
}

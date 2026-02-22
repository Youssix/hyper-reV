#pragma once
#include <cstdint>
#include <unordered_map>
#include <imgui.h>

namespace memory
{
	void set_context(uint64_t cr3, uint64_t eprocess);
	uint64_t get_cr3();
	uint64_t get_eprocess();

	bool read(void* dest, uint64_t address, size_t size);
	bool write(const void* src, uint64_t address, size_t size);
	uint64_t translate(uint64_t virtual_address);

	struct cached_page_t
	{
		uint64_t base_address = 0;
		uint8_t data[0x1000] = {};
		uint8_t prev_data[0x1000] = {};
		float last_read_time = 0.0f;
		bool valid = false;
		bool has_changes = false;
	};

	cached_page_t* cache_read_page(uint64_t page_aligned_addr, float refresh_interval = 0.5f);
	void invalidate_cache();
	void set_refresh_interval(float seconds);

	// check if a byte changed recently (for highlight)
	bool did_byte_change(uint64_t address);
	float byte_change_time(uint64_t address);
}

#include "memory_reader.h"
#include "hypercall/hypercall.h"
#include <cstring>
#include <unordered_map>

namespace memory
{
	static uint64_t s_cr3 = 0;
	static uint64_t s_eprocess = 0;
	static float s_refresh_interval = 0.5f;

	static std::unordered_map<uint64_t, cached_page_t> s_cache;
	static std::unordered_map<uint64_t, float> s_change_times;

	void set_context(uint64_t cr3, uint64_t eprocess)
	{
		s_cr3 = cr3;
		s_eprocess = eprocess;
		invalidate_cache();
	}

	uint64_t get_cr3() { return s_cr3; }
	uint64_t get_eprocess() { return s_eprocess; }

	bool read(void* dest, uint64_t address, size_t size)
	{
		if (s_cr3 == 0 || size == 0)
			return false;

		uint64_t result = hypercall::read_guest_virtual_memory(dest, address, s_cr3, size);
		return result == size;
	}

	bool write(const void* src, uint64_t address, size_t size)
	{
		if (s_cr3 == 0 || size == 0)
			return false;

		uint64_t result = hypercall::write_guest_virtual_memory(
			const_cast<void*>(src), address, s_cr3, size);

		// invalidate affected cache pages
		uint64_t start_page = address & ~0xFFFull;
		uint64_t end_page = (address + size - 1) & ~0xFFFull;
		for (uint64_t page = start_page; page <= end_page; page += 0x1000)
			s_cache.erase(page);

		return result == size;
	}

	uint64_t translate(uint64_t virtual_address)
	{
		if (s_cr3 == 0)
			return 0;

		return hypercall::translate_guest_virtual_address(virtual_address, s_cr3);
	}

	cached_page_t* cache_read_page(uint64_t page_aligned_addr, float refresh_interval)
	{
		if (s_cr3 == 0)
			return nullptr;

		page_aligned_addr &= ~0xFFFull;

		float now = (float)ImGui::GetTime();
		auto it = s_cache.find(page_aligned_addr);

		if (it != s_cache.end())
		{
			cached_page_t& page = it->second;

			if (page.valid && (now - page.last_read_time) < refresh_interval)
				return &page;

			// refresh: save old data for change detection
			memcpy(page.prev_data, page.data, 0x1000);

			uint64_t result = hypercall::read_guest_virtual_memory(
				page.data, page_aligned_addr, s_cr3, 0x1000);

			page.valid = (result == 0x1000);
			page.last_read_time = now;

			// detect changes
			page.has_changes = false;
			if (page.valid)
			{
				for (int i = 0; i < 0x1000; i++)
				{
					if (page.data[i] != page.prev_data[i])
					{
						page.has_changes = true;
						s_change_times[page_aligned_addr + i] = now;
					}
				}
			}

			return page.valid ? &page : nullptr;
		}

		// new page
		cached_page_t page = {};
		page.base_address = page_aligned_addr;

		uint64_t result = hypercall::read_guest_virtual_memory(
			page.data, page_aligned_addr, s_cr3, 0x1000);

		page.valid = (result == 0x1000);
		page.last_read_time = now;
		memcpy(page.prev_data, page.data, 0x1000);

		if (!page.valid)
			return nullptr;

		auto [inserted_it, _] = s_cache.emplace(page_aligned_addr, page);
		return &inserted_it->second;
	}

	void invalidate_cache()
	{
		s_cache.clear();
		s_change_times.clear();
	}

	void set_refresh_interval(float seconds)
	{
		s_refresh_interval = seconds;
	}

	bool did_byte_change(uint64_t address)
	{
		auto it = s_change_times.find(address);
		if (it == s_change_times.end())
			return false;

		float elapsed = (float)ImGui::GetTime() - it->second;
		return elapsed < 2.0f;
	}

	float byte_change_time(uint64_t address)
	{
		auto it = s_change_times.find(address);
		if (it == s_change_times.end())
			return -1.0f;
		return it->second;
	}
}

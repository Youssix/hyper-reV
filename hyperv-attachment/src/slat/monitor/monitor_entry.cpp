#include "monitor_entry.h"

slat::monitor::entry_t* slat::monitor::entry_t::next() const
{
	return reinterpret_cast<entry_t*>(next_);
}

void slat::monitor::entry_t::set_next(entry_t* const next_entry)
{
	next_ = reinterpret_cast<std::uint64_t>(next_entry);
}

std::uint64_t slat::monitor::entry_t::original_pfn() const
{
	return original_pfn_;
}

void slat::monitor::entry_t::set_original_pfn(const std::uint64_t original_pfn)
{
	original_pfn_ = original_pfn;
}

std::uint64_t slat::monitor::entry_t::original_read_access() const
{
	return original_read_access_;
}

std::uint64_t slat::monitor::entry_t::original_write_access() const
{
	return original_write_access_;
}

std::uint64_t slat::monitor::entry_t::original_execute_access() const
{
	return original_execute_access_;
}

std::uint64_t slat::monitor::entry_t::paging_split_state() const
{
	return paging_split_state_;
}

void slat::monitor::entry_t::set_original_read_access(const std::uint64_t original_read_access)
{
	original_read_access_ = original_read_access;
}

void slat::monitor::entry_t::set_original_write_access(const std::uint64_t original_write_access)
{
	original_write_access_ = original_write_access;
}

void slat::monitor::entry_t::set_original_execute_access(const std::uint64_t original_execute_access)
{
	original_execute_access_ = original_execute_access;
}

void slat::monitor::entry_t::set_paging_split_state(const std::uint64_t paging_split_state)
{
	paging_split_state_ = paging_split_state;
}

std::uint64_t slat::monitor::entry_t::access_count() const
{
	return access_count_;
}

void slat::monitor::entry_t::increment_access_count()
{
	if (access_count_ < 0xFFFFFF)
	{
		access_count_++;
	}
}

void slat::monitor::entry_t::reset_access_count()
{
	access_count_ = 0;
}

slat::monitor::entry_t* slat::monitor::entry_t::find(const std::uint64_t target_original_4kb_pfn, entry_t** const previous_entry_out)
{
	entry_t* current_entry = used_monitor_list_head;
	entry_t* previous_entry = nullptr;

	while (current_entry != nullptr)
	{
		if (current_entry->original_pfn() == target_original_4kb_pfn)
		{
			if (previous_entry_out != nullptr)
			{
				*previous_entry_out = previous_entry;
			}

			return current_entry;
		}

		previous_entry = current_entry;
		current_entry = current_entry->next();
	}

	return nullptr;
}

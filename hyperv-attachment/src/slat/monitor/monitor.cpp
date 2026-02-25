#include "monitor.h"
#include "monitor_entry.h"

#include "../cr3/cr3.h"
#include "../cr3/pte.h"
#include "../slat_def.h"
#include "../slat.h"

#include "../../memory_manager/heap_manager.h"
#include "../../structures/virtual_address.h"
#include "../../crt/crt.h"

namespace
{
	crt::mutex_t monitor_mutex = { };
}

void slat::monitor::set_up_entries()
{
	constexpr std::uint64_t monitor_entries_wanted = 0x1000 / sizeof(entry_t);

	void* const monitor_entries_allocation = heap_manager::allocate_page();

	available_monitor_list_head = static_cast<entry_t*>(monitor_entries_allocation);

	entry_t* current_entry = available_monitor_list_head;

	for (std::uint64_t i = 0; i < monitor_entries_wanted - 1; i++)
	{
		current_entry->set_next(current_entry + 1);
		current_entry->set_original_pfn(0);
		current_entry->reset_access_count();

		current_entry = current_entry->next();
	}

	current_entry->set_original_pfn(0);
	current_entry->reset_access_count();
	current_entry->set_next(nullptr);
}

std::uint64_t slat::monitor::add(const virtual_address_t guest_physical_address)
{
	monitor_mutex.lock();

	const entry_t* const already_present_entry = entry_t::find(guest_physical_address.address >> 12);

	if (already_present_entry != nullptr)
	{
		monitor_mutex.release();
		return 0;
	}

	std::uint8_t paging_split_state = 0;

#ifdef _INTELMACHINE
	slat_pte* const target_pte = fork_get_pte(hook_cr3(), hyperv_cr3(), guest_physical_address, 1, &paging_split_state);
#else
	slat_pte* const target_pte = get_pte(hook_cr3(), guest_physical_address, 1, &paging_split_state);
#endif

	if (target_pte == nullptr)
	{
		monitor_mutex.release();
		return 0;
	}

	entry_t* const monitor_entry = available_monitor_list_head;

	if (monitor_entry == nullptr)
	{
		monitor_mutex.release();
		return 0;
	}

	available_monitor_list_head = monitor_entry->next();

	monitor_entry->set_next(used_monitor_list_head);
	monitor_entry->set_original_pfn(target_pte->page_frame_number);
	monitor_entry->set_paging_split_state(paging_split_state);
	monitor_entry->reset_access_count();

	used_monitor_list_head = monitor_entry;

#ifdef _INTELMACHINE
	monitor_entry->set_original_read_access(target_pte->read_access);
	monitor_entry->set_original_write_access(target_pte->write_access);
	monitor_entry->set_original_execute_access(target_pte->execute_access);

	// Remove read access to trigger EPT violation on read
	target_pte->read_access = 0;
#else
	// AMD: We can't easily remove just read access with NPT
	// For now, we'll use a different approach - mark as not present
	// This is a simplification; a full implementation would need more work
	monitor_entry->set_original_read_access(1);
	monitor_entry->set_original_write_access(1);
	monitor_entry->set_original_execute_access(!target_pte->execute_disable);
#endif

	monitor_mutex.release();

	flush_all_logical_processors_cache();

	return 1;
}

std::uint64_t slat::monitor::remove(const virtual_address_t guest_physical_address)
{
	monitor_mutex.lock();

	entry_t* previous_entry = nullptr;
	entry_t* const monitor_entry = entry_t::find(guest_physical_address.address >> 12, &previous_entry);

	if (monitor_entry == nullptr)
	{
		monitor_mutex.release();
		return 0;
	}

	slat_pte* const target_pte = get_pte(hook_cr3(), guest_physical_address);

	if (target_pte == nullptr)
	{
		monitor_mutex.release();
		return 0;
	}

#ifdef _INTELMACHINE
	// Restore original permissions
	target_pte->read_access = monitor_entry->original_read_access();
	target_pte->write_access = monitor_entry->original_write_access();
	target_pte->execute_access = monitor_entry->original_execute_access();
#else
	target_pte->execute_disable = !monitor_entry->original_execute_access();
#endif

	// Remove from used list
	if (previous_entry == nullptr)
	{
		used_monitor_list_head = monitor_entry->next();
	}
	else
	{
		previous_entry->set_next(monitor_entry->next());
	}

	// Add back to available list
	monitor_entry->set_next(available_monitor_list_head);
	available_monitor_list_head = monitor_entry;

	monitor_mutex.release();

	flush_all_logical_processors_cache();

	return 1;
}

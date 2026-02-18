#include "hypercall.h"
#include "../memory_manager/memory_manager.h"
#include "../memory_manager/heap_manager.h"

#include "../slat/slat.h"
#include "../slat/cr3/cr3.h"
#include "../slat/cr3/pte.h"
#include "../slat/hook/hook.h"
#include "../slat/monitor/monitor.h"

#include "../arch/arch.h"
#include "../logs/logs.h"
#include "../crt/crt.h"
#include "../cr3_intercept.h"
#include "../interrupts/interrupts.h"

#include <ia32-doc/ia32.hpp>
#include <hypercall/hypercall_def.h>

std::uint64_t operate_on_guest_physical_memory(const trap_frame_t* const trap_frame, const memory_operation_t operation)
{
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t guest_buffer_virtual_address = trap_frame->r8;
    const std::uint64_t guest_physical_address = trap_frame->rdx;

    std::uint64_t size_left_to_copy = trap_frame->r9;

    std::uint64_t bytes_copied = 0;

    while (size_left_to_copy != 0)
    {
        std::uint64_t size_left_of_destination_slat_page = UINT64_MAX;
        std::uint64_t size_left_of_source_slat_page = UINT64_MAX;

        const std::uint64_t guest_buffer_physical_address = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = guest_buffer_virtual_address + bytes_copied });

        void* host_destination = memory_manager::map_guest_physical(slat_cr3, guest_buffer_physical_address, &size_left_of_destination_slat_page);
        void* host_source = memory_manager::map_guest_physical(slat_cr3, guest_physical_address + bytes_copied, &size_left_of_source_slat_page);

        if (size_left_of_destination_slat_page == UINT64_MAX || size_left_of_source_slat_page == UINT64_MAX)
        {
            break;
        }

        if (operation == memory_operation_t::write_operation)
        {
            crt::swap(host_source, host_destination);
        }

        const std::uint64_t size_left_of_slat_pages = crt::min(size_left_of_source_slat_page, size_left_of_destination_slat_page);

        const std::uint64_t copy_size = crt::min(size_left_to_copy, size_left_of_slat_pages);

        if (copy_size == 0)
        {
            break;
        }

        crt::copy_memory(host_destination, host_source, copy_size);

        size_left_to_copy -= copy_size;
        bytes_copied += copy_size;
    }

    return bytes_copied;
}

std::uint64_t operate_on_guest_virtual_memory(const trap_frame_t* const trap_frame, const memory_operation_t operation, const std::uint64_t address_of_page_directory)
{
    const cr3 guest_source_cr3 = { .address_of_page_directory = address_of_page_directory };

    const cr3 guest_destination_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t guest_destination_virtual_address = trap_frame->rdx;
    const  std::uint64_t guest_source_virtual_address = trap_frame->r8;

    std::uint64_t size_left_to_read = trap_frame->r9;

    std::uint64_t bytes_copied = 0;

    while (size_left_to_read != 0)
    {
        std::uint64_t size_left_of_destination_virtual_page = UINT64_MAX;
        std::uint64_t size_left_of_destination_slat_page = UINT64_MAX;

        std::uint64_t size_left_of_source_virtual_page = UINT64_MAX;
        std::uint64_t size_left_of_source_slat_page = UINT64_MAX;

        const std::uint64_t guest_source_physical_address = memory_manager::translate_guest_virtual_address(guest_source_cr3, slat_cr3, { .address = guest_source_virtual_address + bytes_copied }, &size_left_of_source_virtual_page);
        const std::uint64_t guest_destination_physical_address = memory_manager::translate_guest_virtual_address(guest_destination_cr3, slat_cr3, { .address = guest_destination_virtual_address + bytes_copied }, &size_left_of_destination_virtual_page);

        if (size_left_of_destination_virtual_page == UINT64_MAX || size_left_of_source_virtual_page == UINT64_MAX)
        {
            break;
        }

        void* host_destination = memory_manager::map_guest_physical(slat_cr3, guest_destination_physical_address, &size_left_of_destination_slat_page);
        void* host_source = memory_manager::map_guest_physical(slat_cr3, guest_source_physical_address, &size_left_of_source_slat_page);

    	if (size_left_of_destination_slat_page == UINT64_MAX || size_left_of_source_slat_page == UINT64_MAX)
        {
            break;
        }

        if (operation == memory_operation_t::write_operation)
        {
            crt::swap(host_source, host_destination);
        }

        const std::uint64_t size_left_of_slat_pages = crt::min(size_left_of_source_slat_page, size_left_of_destination_slat_page);
        const std::uint64_t size_left_of_virtual_pages = crt::min(size_left_of_source_virtual_page, size_left_of_destination_virtual_page);

        const std::uint64_t size_left_of_pages = crt::min(size_left_of_slat_pages, size_left_of_virtual_pages);

        const std::uint64_t copy_size = crt::min(size_left_to_read, size_left_of_pages);

        if (copy_size == 0)
        {
            break;
        }

        crt::copy_memory(host_destination, host_source, copy_size);

        size_left_to_read -= copy_size;
        bytes_copied += copy_size;
    }

    return bytes_copied;
}

std::uint8_t copy_stack_data_from_log_exit(std::uint64_t* const stack_data, const std::uint64_t stack_data_count, const cr3 guest_cr3, const std::uint64_t rsp)
{
    if (rsp == 0)
    {
        return 0;
    }

    const cr3 slat_cr3 = slat::hyperv_cr3();

    std::uint64_t bytes_read = 0;
    std::uint64_t bytes_remaining = stack_data_count * sizeof(std::uint64_t);

    while (bytes_remaining != 0)
    {
        std::uint64_t virtual_size_left = 0;

        const std::uint64_t rsp_guest_physical_address = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = rsp + bytes_read }, &virtual_size_left);

        if (rsp_guest_physical_address == 0)
        {
            return 0;
        }

        std::uint64_t physical_size_left = 0;

        // rcx has just been pushed onto stack
        const auto rsp_mapped = static_cast<const std::uint64_t*>(memory_manager::map_guest_physical(slat_cr3, rsp_guest_physical_address, &physical_size_left));

        const std::uint64_t size_left_of_page = crt::min(physical_size_left, virtual_size_left);
        const std::uint64_t size_to_read = crt::min(bytes_remaining, size_left_of_page);

        if (size_to_read == 0)
        {
            return 0;
        }

        crt::copy_memory(reinterpret_cast<std::uint8_t*>(stack_data) + bytes_read, reinterpret_cast<const std::uint8_t*>(rsp_mapped) + bytes_read, size_to_read);

        bytes_remaining -= size_to_read;
        bytes_read += size_to_read;
    }

    return 1;
}

void do_stack_data_copy(trap_frame_log_t& trap_frame, const cr3 guest_cr3)
{
    constexpr std::uint64_t stack_data_count = trap_frame_log_stack_data_count + 1;

    std::uint64_t stack_data[stack_data_count] = { };

    copy_stack_data_from_log_exit(&stack_data[0], stack_data_count, guest_cr3, trap_frame.rsp);

    crt::copy_memory(&trap_frame.stack_data, &stack_data[1], sizeof(trap_frame.stack_data));

    trap_frame.rcx = stack_data[0];
    trap_frame.rsp += 8; // get rid of the rcx value we push onto stack ourselves
}

void log_current_state(trap_frame_log_t trap_frame)
{
    cr3 guest_cr3 = arch::get_guest_cr3();

    do_stack_data_copy(trap_frame, guest_cr3);

    trap_frame.cr3 = guest_cr3.flags;
    trap_frame.rip = arch::get_guest_rip();

    logs::add_log(trap_frame);
}

std::uint64_t flush_logs(const trap_frame_t* const trap_frame)
{
    std::uint64_t stored_logs_count = logs::stored_log_index;

    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t guest_virtual_address = trap_frame->rdx;
    const std::uint16_t count = static_cast<std::uint16_t>(trap_frame->r8);

    if (logs::flush(slat_cr3, guest_virtual_address, guest_cr3, count) == 0)
    {
        return -1;
    }

    return stored_logs_count;
}

void hypercall::process(const hypercall_info_t hypercall_info, trap_frame_t* const trap_frame)
{
    switch (hypercall_info.call_type)
    {
    case hypercall_type_t::guest_physical_memory_operation:
    {
        const auto memory_operation = static_cast<memory_operation_t>(hypercall_info.call_reserved_data);

        trap_frame->rax = operate_on_guest_physical_memory(trap_frame, memory_operation);

        break;
    }
    case hypercall_type_t::guest_virtual_memory_operation:
    {
        const virt_memory_op_hypercall_info_t virt_memory_op_info = { .value = hypercall_info.value };

        const memory_operation_t memory_operation = virt_memory_op_info.memory_operation;
        const std::uint64_t address_of_page_directory = virt_memory_op_info.address_of_page_directory;

        trap_frame->rax = operate_on_guest_virtual_memory(trap_frame, memory_operation, address_of_page_directory);

        break;
    }
    case hypercall_type_t::translate_guest_virtual_address:
    {
        const virtual_address_t guest_virtual_address = { .address = trap_frame->rdx };

        const cr3 target_guest_cr3 = { .flags = trap_frame->r8 };
        const cr3 slat_cr3 = slat::hyperv_cr3();

        trap_frame->rax = memory_manager::translate_guest_virtual_address(target_guest_cr3, slat_cr3, guest_virtual_address);

        break;
    }
    case hypercall_type_t::read_guest_cr3:
    {
        if (hypercall_info.call_reserved_data == 1)
        {
            trap_frame->rax = cr3_intercept::cr3_exit_count;
        }
        else if (hypercall_info.call_reserved_data == 2)
        {
            trap_frame->rax = cr3_intercept::cr3_swap_count;
        }
        else if (hypercall_info.call_reserved_data == 3)
        {
            trap_frame->rax = cr3_intercept::cr3_last_seen;
        }
        else if (hypercall_info.call_reserved_data == 4)
        {
            // enable enforce: force clone CR3 at every VM exit
            cr3_intercept::enforce_active = 1;

            // immediately swap if needed
            const cr3 current = arch::get_guest_cr3();
            if ((current.flags & cr3_intercept::cr3_pfn_mask) == (cr3_intercept::target_original_cr3 & cr3_intercept::cr3_pfn_mask))
            {
                arch::set_guest_cr3({ .flags = cr3_intercept::cloned_cr3_value });
                arch::invalidate_vpid_current();
            }

            trap_frame->rax = 1;
        }
        else if (hypercall_info.call_reserved_data == 5)
        {
            // disable enforce
            cr3_intercept::enforce_active = 0;
            trap_frame->rax = 1;
        }
        else
        {
            const cr3 guest_cr3 = arch::get_guest_cr3();
            trap_frame->rax = guest_cr3.flags;
        }

        break;
    }
    case hypercall_type_t::add_slat_code_hook:
    {
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };
        const virtual_address_t shadow_page_guest_physical_address = { .address = trap_frame->r8 };

        trap_frame->rax = slat::hook::add(target_guest_physical_address, shadow_page_guest_physical_address);

        break;
    }
    case hypercall_type_t::remove_slat_code_hook:
    {
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };

        trap_frame->rax = slat::hook::remove(target_guest_physical_address);

        break;
    }
    case hypercall_type_t::hide_guest_physical_page:
    {
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };

        trap_frame->rax = slat::hide_physical_page_from_guest(target_guest_physical_address);

        break;
    }
    case hypercall_type_t::log_current_state:
    {
        trap_frame_log_t trap_frame_log;

        crt::copy_memory(&trap_frame_log, trap_frame, sizeof(trap_frame_t));

        log_current_state(trap_frame_log);

        break;
    }
    case hypercall_type_t::flush_logs:
    {
        trap_frame->rax = flush_logs(trap_frame);

        break;
    }
    case hypercall_type_t::get_heap_free_page_count:
    {
        trap_frame->rax = heap_manager::get_free_page_count();

        break;
    }
    case hypercall_type_t::monitor_physical_page:
    {
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };

        trap_frame->rax = slat::monitor::add(target_guest_physical_address);

        break;
    }
    case hypercall_type_t::unmonitor_physical_page:
    {
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };

        trap_frame->rax = slat::monitor::remove(target_guest_physical_address);

        break;
    }
    case hypercall_type_t::write_guest_cr3:
    {
        const cr3 new_guest_cr3 = { .flags = trap_frame->rdx };

        arch::set_guest_cr3(new_guest_cr3);
        arch::invalidate_vpid_current();

        trap_frame->rax = 1;

        break;
    }
    case hypercall_type_t::clone_guest_cr3:
    {
        if (hypercall_info.call_reserved_data == 1)
        {
            // setup_hidden_region: allocate PDPT + PD + PT, build hierarchy, insert into clone PML4
            const std::uint64_t pml4_index = trap_frame->rdx;

            if (pml4_index >= 512 || cr3_intercept::cloned_pml4_host_va == nullptr || cr3_intercept::hidden_pt_host_va != nullptr)
            {
                trap_frame->rax = 0;
                break;
            }

            const cr3 slat_cr3 = slat::hyperv_cr3();
            const cr3 hook = slat::hook_cr3();

            // allocate 3 pages: PDPT, PD, PT
            void* const pdpt_va = heap_manager::allocate_page();
            void* const pd_va = heap_manager::allocate_page();
            void* const pt_va = heap_manager::allocate_page();

            if (pdpt_va == nullptr || pd_va == nullptr || pt_va == nullptr)
            {
                if (pdpt_va) heap_manager::free_page(pdpt_va);
                if (pd_va) heap_manager::free_page(pd_va);
                if (pt_va) heap_manager::free_page(pt_va);
                trap_frame->rax = 0;
                break;
            }

            // zero all 3 pages
            crt::set_memory(pdpt_va, 0, 0x1000);
            crt::set_memory(pd_va, 0, 0x1000);
            crt::set_memory(pt_va, 0, 0x1000);

            // get physical addresses
            const std::uint64_t pdpt_pa = memory_manager::unmap_host_physical(pdpt_va);
            const std::uint64_t pd_pa = memory_manager::unmap_host_physical(pd_va);
            const std::uint64_t pt_pa = memory_manager::unmap_host_physical(pt_va);

            // un-hide all 3 pages in EPT
            auto unhide = [&](std::uint64_t pa)
            {
                slat_pte* const pte = slat::get_pte(slat_cr3, { .address = pa }, 1);
                if (pte != nullptr)
                    pte->page_frame_number = pa >> 12;

                if (hook.flags != 0)
                {
                    slat_pte* const pte_hook = slat::get_pte(hook, { .address = pa }, 1);
                    if (pte_hook != nullptr)
                        pte_hook->page_frame_number = pa >> 12;
                }
            };

            unhide(pdpt_pa);
            unhide(pd_pa);
            unhide(pt_pa);

            // build page table hierarchy: PDPT[0] -> PD, PD[0] -> PT
            // flags: present=1, write=1, supervisor=1 (usermode accessible) = 0x7
            auto* const pdpt = static_cast<pdpte_64*>(pdpt_va);
            pdpt[0].flags = (pd_pa & 0xFFFFFFFFF000ull) | 0x7;

            auto* const pd = static_cast<pde_64*>(pd_va);
            pd[0].flags = (pt_pa & 0xFFFFFFFFF000ull) | 0x7;

            // store state — set reserved index BEFORE writing PML4E to prevent
            // sync_page_tables on another VCPU from overwriting our entry
            cr3_intercept::reserved_pml4e_index = pml4_index;
            cr3_intercept::hidden_pt_host_va = pt_va;

            // set clone PML4[pml4_index] -> PDPT
            auto* const cloned_pml4 = static_cast<pml4e_64*>(cr3_intercept::cloned_pml4_host_va);
            cloned_pml4[pml4_index].flags = (pdpt_pa & 0xFFFFFFFFF000ull) | 0x7;

            slat::flush_all_logical_processors_cache();

            // return the base VA for this PML4 index
            trap_frame->rax = pml4_index << 39;

            break;
        }
        else if (hypercall_info.call_reserved_data == 2)
        {
            // map_hidden_page: allocate a data page, insert into PT[page_index]
            const std::uint64_t page_index = trap_frame->rdx;

            if (page_index >= 512 || cr3_intercept::hidden_pt_host_va == nullptr)
            {
                trap_frame->rax = 0;
                break;
            }

            // check if this PT slot is already mapped
            const auto* const pt_check = static_cast<const pte_64*>(cr3_intercept::hidden_pt_host_va);
            if (pt_check[page_index].present)
            {
                trap_frame->rax = 0;
                break;
            }

            const cr3 slat_cr3 = slat::hyperv_cr3();
            const cr3 hook = slat::hook_cr3();

            void* const data_page_va = heap_manager::allocate_page();

            if (data_page_va == nullptr)
            {
                trap_frame->rax = 0;
                break;
            }

            crt::set_memory(data_page_va, 0, 0x1000);

            const std::uint64_t data_pa = memory_manager::unmap_host_physical(data_page_va);

            // un-hide in EPT
            slat_pte* const pte_hyperv = slat::get_pte(slat_cr3, { .address = data_pa }, 1);
            if (pte_hyperv != nullptr)
                pte_hyperv->page_frame_number = data_pa >> 12;

            if (hook.flags != 0)
            {
                slat_pte* const pte_hook = slat::get_pte(hook, { .address = data_pa }, 1);
                if (pte_hook != nullptr)
                    pte_hook->page_frame_number = data_pa >> 12;
            }

            // set PT[page_index] -> data page
            // flags: present=1, write=1, supervisor=1 (usermode accessible) = 0x7
            auto* const pt = static_cast<pte_64*>(cr3_intercept::hidden_pt_host_va);
            pt[page_index].flags = (data_pa & 0xFFFFFFFFF000ull) | 0x7;

            slat::flush_all_logical_processors_cache();

            // return the physical address of the data page
            trap_frame->rax = data_pa;

            break;
        }

        // call_reserved_data == 0: existing clone behavior
        const cr3 target_cr3 = { .flags = trap_frame->rdx };
        const cr3 slat_cr3 = slat::hyperv_cr3();

        // allocate a page from heap for the cloned PML4
        void* const new_pml4_page = heap_manager::allocate_page();

        if (new_pml4_page == nullptr)
        {
            trap_frame->rax = 0;
            break;
        }

        const std::uint64_t new_pml4_hpa = memory_manager::unmap_host_physical(new_pml4_page);

        // map the target CR3's PML4 via guest physical memory
        const auto target_pml4 = static_cast<const std::uint8_t*>(
            memory_manager::map_guest_physical(slat_cr3, target_cr3.address_of_page_directory << 12));

        if (target_pml4 == nullptr)
        {
            heap_manager::free_page(new_pml4_page);
            trap_frame->rax = 0;
            break;
        }

        // copy all 512 PML4 entries
        crt::copy_memory(new_pml4_page, target_pml4, 0x1000);

        // un-hide this page in the hyperv EPT so the CPU page walker can access it
        // heap pages are identity-mapped (GPA == HPA) but hidden after init
        slat_pte* const pte_hyperv = slat::get_pte(slat_cr3, { .address = new_pml4_hpa }, 1);

        if (pte_hyperv != nullptr)
        {
            pte_hyperv->page_frame_number = new_pml4_hpa >> 12;
        }

        // also un-hide in hook EPT if it's been initialized
        const cr3 hook = slat::hook_cr3();

        if (hook.flags != 0)
        {
            slat_pte* const pte_hook = slat::get_pte(hook, { .address = new_pml4_hpa }, 1);

            if (pte_hook != nullptr)
            {
                pte_hook->page_frame_number = new_pml4_hpa >> 12;
            }
        }

        slat::flush_all_logical_processors_cache();

        // return the cloned CR3: same flags as target but with our new PML4 PFN
        cr3 cloned_cr3 = target_cr3;
        cloned_cr3.address_of_page_directory = new_pml4_hpa >> 12;

        trap_frame->rax = cloned_cr3.flags;

        break;
    }
    case hypercall_type_t::enable_cr3_intercept:
    {
        const std::uint64_t target_cr3_value = trap_frame->rdx;
        const std::uint64_t cloned_cr3_value = trap_frame->r8;

        const cr3 cloned = { .flags = cloned_cr3_value };
        const std::uint64_t cloned_pml4_hpa = cloned.address_of_page_directory << 12;

        cr3_intercept::cloned_pml4_host_va = memory_manager::map_host_physical(cloned_pml4_hpa);
        cr3_intercept::target_original_cr3 = target_cr3_value;
        cr3_intercept::cloned_cr3_value = cloned_cr3_value;

        // preserve reserved_pml4e_index if hidden region was already setup
        if (cr3_intercept::hidden_pt_host_va == nullptr)
            cr3_intercept::reserved_pml4e_index = 512;

        // initial sync of page tables
        cr3_intercept::sync_page_tables(target_cr3_value);

        // enable CR3 exiting on this VCPU
        arch::enable_cr3_exiting();

        // set enabled before NMI so other VCPUs see it
        cr3_intercept::enabled = 1;

        // propagate CR3 exiting to all other VCPUs via NMI
        interrupts::set_all_nmi_ready();
        interrupts::send_nmi_all_but_self();

        // if current guest CR3 matches target, swap immediately
        const cr3 current_guest_cr3 = arch::get_guest_cr3();

        if ((current_guest_cr3.flags & cr3_intercept::cr3_pfn_mask) == (target_cr3_value & cr3_intercept::cr3_pfn_mask))
        {
            arch::set_guest_cr3({ .flags = cloned_cr3_value });
            arch::invalidate_vpid_current();
        }

        trap_frame->rax = 1;

        break;
    }
    case hypercall_type_t::disable_cr3_intercept:
    {
        if (cr3_intercept::enabled == 0)
        {
            trap_frame->rax = 0;
            break;
        }

        // disable intercept flag first (other VCPUs will see this immediately)
        cr3_intercept::enabled = 0;

        // if current guest CR3 is the clone, restore original
        const cr3 current_guest_cr3 = arch::get_guest_cr3();

        if ((current_guest_cr3.flags & cr3_intercept::cr3_pfn_mask) == (cr3_intercept::cloned_cr3_value & cr3_intercept::cr3_pfn_mask))
        {
            arch::set_guest_cr3({ .flags = cr3_intercept::target_original_cr3 });
            arch::invalidate_vpid_current();
        }

        // disable CR3 exiting on this VCPU
        arch::disable_cr3_exiting();

        // propagate disable to all other VCPUs via NMI
        interrupts::set_all_nmi_ready();
        interrupts::send_nmi_all_but_self();

        // clear state
        cr3_intercept::target_original_cr3 = 0;
        cr3_intercept::cloned_cr3_value = 0;
        cr3_intercept::cloned_pml4_host_va = nullptr;
        cr3_intercept::hidden_pt_host_va = nullptr;
        cr3_intercept::reserved_pml4e_index = 512;

        trap_frame->rax = 1;

        break;
    }
    default:
        break;
    }
}

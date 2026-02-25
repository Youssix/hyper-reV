#include "commands.h"
#include <CLI/CLI.hpp>
#include <hypercall/hypercall_def.h>
#include "../hook/hook.h"
#include "../hypercall/hypercall.h"
#include "../system/system.h"
#include "../inject/inject.h"

#include <print>
#include <array>

#define d_invoke_command_processor(command) process_##command(##command)
#define d_initial_process_command(command) if (*##command) d_invoke_command_processor(command)
#define d_process_command(command) else if (*##command) d_invoke_command_processor(command)

template <class t>
t get_command_option(CLI::App* app, std::string option_name)
{
	auto option = app->get_option(option_name);

	return option->empty() == false ? option->as<t>() : t{};
}

CLI::Option* add_command_option(CLI::App* app, std::string option_name)
{
	return app->add_option(option_name);
}

CLI::Option* add_transformed_command_option(CLI::App* app, std::string option_name, CLI::Transformer& transformer)
{
	CLI::Option* option = add_command_option(app, option_name);

	return option->transform(transformer);
}

std::uint8_t get_command_flag(CLI::App* app, std::string flag_name)
{
	auto option = app->get_option(flag_name);

	return !option->empty();
}

CLI::Option* add_command_flag(CLI::App* app, std::string flag_name)
{
	return app->add_flag(flag_name);
}

CLI::App* init_rgpm(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* rgpm = app.add_subcommand("rgpm", "reads memory from a given guest physical address")->ignore_case();

	add_transformed_command_option(rgpm, "physical_address", aliases_transformer)->required();
	add_command_option(rgpm, "size")->check(CLI::Range(0, 8))->required();

	return rgpm;
}

void process_rgpm(CLI::App* rgpm)
{
	const std::uint64_t guest_physical_address = get_command_option<std::uint64_t>(rgpm, "physical_address");
	const std::uint64_t size = get_command_option<std::uint64_t>(rgpm, "size");

	std::uint64_t value = 0;

	const std::uint64_t bytes_read = hypercall::read_guest_physical_memory(&value, guest_physical_address, size);

	if (bytes_read == size)
	{
		std::println("value: 0x{:x}", value);
	}
	else
	{
		std::println("failed to read");
	}
}

CLI::App* init_wgpm(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* wgpm = app.add_subcommand("wgpm", "writes memory to a given guest physical address")->ignore_case();

	add_transformed_command_option(wgpm, "physical_address", aliases_transformer)->required();
	add_command_option(wgpm, "value")->required();
	add_command_option(wgpm, "size")->check(CLI::Range(0, 8))->required();

	return wgpm;
}

void process_wgpm(CLI::App* wgpm)
{
	const std::uint64_t guest_physical_address = get_command_option<std::uint64_t>(wgpm, "physical_address");
	const std::uint64_t size = get_command_option<std::uint64_t>(wgpm, "size");

	std::uint64_t value = get_command_option<std::uint64_t>(wgpm, "value");

	const std::uint64_t bytes_written = hypercall::write_guest_physical_memory(&value, guest_physical_address, size);

	if (bytes_written == size)
	{
		std::println("success in write");
	}
	else
	{
		std::println("failed to write");
	}
}

CLI::App* init_cgpm(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* cgpm = app.add_subcommand("cgpm", "copies memory from a given source to a destination (guest physical addresses)")->ignore_case();

	add_transformed_command_option(cgpm, "destination_physical_address", aliases_transformer)->required();
	add_transformed_command_option(cgpm, "source_physical_address", aliases_transformer)->required();
	add_command_option(cgpm, "size")->required();

	return cgpm;
}

void process_cgpm(CLI::App* cgpm)
{
	const std::uint64_t guest_destination_physical_address = get_command_option<std::uint64_t>(cgpm, "destination_physical_address");
	const std::uint64_t guest_source_physical_address = get_command_option<std::uint64_t>(cgpm, "source_physical_address");
	const std::uint64_t size = get_command_option<std::uint64_t>(cgpm, "size");

	std::vector<std::uint8_t> buffer(size);

	const std::uint64_t bytes_read = hypercall::read_guest_physical_memory(buffer.data(), guest_source_physical_address, size);
	const std::uint64_t bytes_written = hypercall::write_guest_physical_memory(buffer.data(), guest_destination_physical_address, size);

	if ((bytes_read == size) && (bytes_written == size))
	{
		std::println("success in copy");
	}
	else
	{
		std::println("failed to copy");
	}
}

CLI::App* init_gvat(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* gvat = app.add_subcommand("gvat", "translates a guest virtual address to its corresponding guest physical address, with the given guest cr3 value")->ignore_case();

	add_transformed_command_option(gvat, "virtual_address", aliases_transformer)->required();
	add_transformed_command_option(gvat, "cr3", aliases_transformer)->required();

	return gvat;
}

void process_gvat(CLI::App* gvat)
{
	const std::uint64_t virtual_address = get_command_option<std::uint64_t>(gvat, "virtual_address");
	const std::uint64_t cr3 = get_command_option<std::uint64_t>(gvat, "cr3");

	const std::uint64_t physical_address = hypercall::translate_guest_virtual_address(virtual_address, cr3);

	std::println("physical address: 0x{:x}", physical_address);
}

CLI::App* init_rgvm(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* rgvm = app.add_subcommand("rgvm", "reads memory from a given guest virtual address (when given the corresponding guest cr3 value)")->ignore_case();

	add_transformed_command_option(rgvm, "virtual_address", aliases_transformer)->required();
	add_transformed_command_option(rgvm, "cr3", aliases_transformer)->required();
	add_command_option(rgvm, "size")->check(CLI::Range(0, 8))->required();

	return rgvm;
}

void process_rgvm(CLI::App* rgvm)
{
	const std::uint64_t guest_virtual_address = get_command_option<std::uint64_t>(rgvm, "virtual_address");
	const std::uint64_t cr3 = get_command_option<std::uint64_t>(rgvm, "cr3");
	const std::uint64_t size = get_command_option<std::uint64_t>(rgvm, "size");

	std::uint64_t value = 0;

	const std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(&value, guest_virtual_address, cr3, size);

	if (bytes_read == size)
	{
		std::println("value: 0x{:x}", value);
	}
	else
	{
		std::println("failed to read");
	}
}

CLI::App* init_wgvm(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* wgvm = app.add_subcommand("wgvm", "writes memory from a given guest virtual address (when given the corresponding guest cr3 value)")->ignore_case();

	add_transformed_command_option(wgvm, "virtual_address", aliases_transformer)->required();
	add_transformed_command_option(wgvm, "cr3", aliases_transformer)->required();
	add_command_option(wgvm, "value")->required();
	add_command_option(wgvm, "size")->check(CLI::Range(0, 8))->required();

	return wgvm;
}

void process_wgvm(CLI::App* wgvm)
{
	const std::uint64_t guest_virtual_address = get_command_option<std::uint64_t>(wgvm, "virtual_address");
	const std::uint64_t cr3 = get_command_option<std::uint64_t>(wgvm, "cr3");
	const std::uint64_t size = get_command_option<std::uint64_t>(wgvm, "size");

	std::uint64_t value = get_command_option<std::uint64_t>(wgvm, "value");

	const std::uint64_t bytes_written = hypercall::write_guest_virtual_memory(&value, guest_virtual_address, cr3, size);

	if (bytes_written == size)
	{
		std::println("success in write at given address");
	}
	else
	{
		std::println("failed to write at given address");
	}
}

CLI::App* init_cgvm(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* cgvm = app.add_subcommand("cgvm", "copies memory from a given source to a destination (guest virtual addresses) (when given the corresponding guest cr3 values)")->ignore_case();

	add_transformed_command_option(cgvm, "destination_virtual_address", aliases_transformer)->required();
	add_transformed_command_option(cgvm, "destination_cr3", aliases_transformer)->required();
	add_transformed_command_option(cgvm, "source_virtual_address", aliases_transformer)->required();
	add_transformed_command_option(cgvm, "source_cr3", aliases_transformer)->required();
	add_command_option(cgvm, "size")->required();

	return cgvm;
}

void process_cgvm(CLI::App* wgvm)
{
	const std::uint64_t guest_destination_virtual_address = get_command_option<std::uint64_t>(wgvm, "destination_virtual_address");
	const std::uint64_t guest_destination_cr3 = get_command_option<std::uint64_t>(wgvm, "destination_cr3");

	const std::uint64_t guest_source_virtual_address = get_command_option<std::uint64_t>(wgvm, "source_virtual_address");
	const std::uint64_t guest_source_cr3 = get_command_option<std::uint64_t>(wgvm, "source_cr3");

	const std::uint64_t size = get_command_option<std::uint64_t>(wgvm, "size");

	std::vector<std::uint8_t> buffer(size);

	const std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(buffer.data(), guest_source_virtual_address, guest_source_cr3, size);
	const std::uint64_t bytes_written = hypercall::write_guest_virtual_memory(buffer.data(), guest_destination_virtual_address, guest_destination_cr3, size);

	if ((bytes_read == size) && (bytes_written == size))
	{
		std::println("success in copy");
	}
	else
	{
		std::println("failed to copy");
	}
}

CLI::App* init_akh(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* akh = app.add_subcommand("akh", "add a hook on specified kernel code (given the guest virtual address) (asmbytes in form: 0xE8 0x12 0x23 0x34 0x45)")->ignore_case();

	add_transformed_command_option(akh, "virtual_address", aliases_transformer)->required();
	add_command_option(akh, "--asmbytes")->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)->expected(-1);
	add_command_option(akh, "--post_original_asmbytes")->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)->expected(-1);
	add_command_flag(akh, "--monitor");

	return akh;
}

void process_akh(CLI::App* akh)
{
	const std::uint64_t virtual_address = get_command_option<std::uint64_t>(akh, "virtual_address");

	std::vector<uint8_t> asm_bytes = get_command_option<std::vector<uint8_t>>(akh, "--asmbytes");
	const std::vector<uint8_t> post_original_asm_bytes = get_command_option<std::vector<uint8_t>>(akh, "--post_original_asmbytes");

	const std::uint8_t monitor = get_command_flag(akh, "--monitor");

	if (monitor == 1)
	{
		std::array<std::uint8_t, 9> monitor_bytes = {
			0x51, // push rcx
			0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, 0
			0x0F, 0xA2, // cpuid
			0x59 // pop rcx
		};

		hypercall_info_t call_info = { };

		call_info.primary_key = hypercall_primary_key;
		call_info.secondary_key = hypercall_secondary_key;
		call_info.call_type = hypercall_type_t::log_current_state;

		*reinterpret_cast<std::uint32_t*>(&monitor_bytes[2]) = static_cast<std::uint32_t>(call_info.value);

		asm_bytes.insert(asm_bytes.end(), monitor_bytes.begin(), monitor_bytes.end());
	}

	const std::uint8_t hook_status = hook::add_kernel_hook(virtual_address, asm_bytes, post_original_asm_bytes);

	if (hook_status == 1)
	{
		std::println("success in hook");
	}
	else
	{
		std::println("failed to hook");
	}
}

CLI::App* init_rkh(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* rkh = app.add_subcommand("rkh", "remove a previously placed hook on specified kernel code (given the guest virtual address)")->ignore_case();

	add_transformed_command_option(rkh, "virtual_address", aliases_transformer)->required();

	return rkh;
}

void process_rkh(CLI::App* rkh)
{
	const std::uint64_t virtual_address = get_command_option<std::uint64_t>(rkh, "virtual_address");

	const std::uint8_t hook_removal_status = hook::remove_kernel_hook(virtual_address, 1);

	if (hook_removal_status == 1)
	{
		std::println("success in hook removal");
	}
	else
	{
		std::println("failed to remove hook");
	}
}

CLI::App* init_hgpp(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* hgpp = app.add_subcommand("hgpp", "hide a physical page's real contents from the guest")->ignore_case();

	add_transformed_command_option(hgpp, "physical_address", aliases_transformer)->required();

	return hgpp;
}

void process_hgpp(CLI::App* hgpp)
{
	const std::uint64_t physical_address = get_command_option<std::uint64_t>(hgpp, "physical_address");

	const std::uint64_t hide_status = hypercall::hide_guest_physical_page(physical_address);

	if (hide_status == 1)
	{
		std::println("success in hiding page");
	}
	else
	{
		std::println("failed to hide page");
	}
}

CLI::App* init_mpp(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* mpp = app.add_subcommand("mpp", "monitor read access to a physical page (EPT violation logging)")->ignore_case();

	add_transformed_command_option(mpp, "physical_address", aliases_transformer)->required();

	return mpp;
}

void process_mpp(CLI::App* mpp)
{
	const std::uint64_t physical_address = get_command_option<std::uint64_t>(mpp, "physical_address");

	const std::uint64_t monitor_status = hypercall::monitor_physical_page(physical_address);

	if (monitor_status == 1)
	{
		std::println("success in monitoring page 0x{:X}", physical_address & ~0xFFFull);
		std::println("use 'fl' to flush and view access logs");
	}
	else
	{
		std::println("failed to monitor page (already monitored or no entries available)");
	}
}

CLI::App* init_umpp(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* umpp = app.add_subcommand("umpp", "remove monitoring from a physical page")->ignore_case();

	add_transformed_command_option(umpp, "physical_address", aliases_transformer)->required();

	return umpp;
}

void process_umpp(CLI::App* umpp)
{
	const std::uint64_t physical_address = get_command_option<std::uint64_t>(umpp, "physical_address");

	const std::uint64_t unmonitor_status = hypercall::unmonitor_physical_page(physical_address);

	if (unmonitor_status == 1)
	{
		std::println("success in removing monitor from page 0x{:X}", physical_address & ~0xFFFull);
	}
	else
	{
		std::println("failed to remove monitor (page not monitored)");
	}
}

CLI::App* init_fl(CLI::App& app)
{
	CLI::App* fl = app.add_subcommand("fl", "flush trap frame logs from hooks")->ignore_case();

	return fl;
}

void process_fl(CLI::App* fl)
{
	constexpr std::uint64_t log_count = 100;
	constexpr std::uint64_t failed_log_count = -1;

	std::vector<trap_frame_log_t> logs(log_count);

	const std::uint64_t logs_flushed = hypercall::flush_logs(logs);

	if (logs_flushed == failed_log_count)
	{
		std::println("failed to flush logs");
	}
	else if (logs_flushed == 0)
	{
		std::println("there are no logs to flush");
	}
	else
	{
		std::println("success in flushing logs ({}), outputting logs now:\n\n", logs_flushed);

		for (std::uint64_t i = 0; i < logs_flushed; i++)
		{
			const trap_frame_log_t& log = logs[i];

			if (log.rip == 0)
			{
				break;
			}

			std::println("{}. rip=0x{:X} rax=0x{:X} rcx=0x{:X}\nrdx=0x{:X} rbx=0x{:X} rsp=0x{:X} rbp=0x{:X}\nrsi=0x{:X} rdi=0x{:X} r8=0x{:X} r9=0x{:X}\nr10=0x{:X} r11=0x{:X} r12=0x{:X} r13=0x{:X} r14=0x{:X}\nr15=0x{:X} cr3=0x{:X}\n"
				,i, log.rip, log.rax, log.rcx, log.rdx, log.rbx, log.rsp, log.rbp, log.rsi, log.rdi, log.r8, log.r9, log.r10, log.r11, log.r12, log.r13, log.r14, log.r15, log.cr3);

			std::println("stack data:");
			
			for (const std::uint64_t stack_value : log.stack_data)
			{
				std::println("  0x{:X}", stack_value);
			}

			std::println();
		}
	}
}

CLI::App* init_hfpc(CLI::App& app)
{
	CLI::App* hfpc = app.add_subcommand("hfpc", "get hyperv-attachment's heap free page count")->ignore_case();

	return hfpc;
}

void process_hfpc(CLI::App* hfpc)
{
	const std::uint64_t heap_free_page_count = hypercall::get_heap_free_page_count();

	std::println("heap free page count: {}", heap_free_page_count);
}

CLI::App* init_lkm(CLI::App& app)
{
	CLI::App* lkm = app.add_subcommand("lkm", "print list of loaded kernel modules")->ignore_case();

	return lkm;
}

void process_lkm(CLI::App* lkm)
{
	for (const auto& [module_name, module_info] : sys::kernel::modules_list)
	{
		std::println("'{}' has a base address of: 0x{:x}, and a size of: 0x{:X}", module_name, module_info.base_address, module_info.size);
	}
}

CLI::App* init_kme(CLI::App& app)
{
	CLI::App* kme = app.add_subcommand("kme", "list the exports of a loaded kernel module (when given the name)")->ignore_case();

	add_command_option(kme, "module_name")->required();

	return kme;
}

void process_kme(CLI::App* kme)
{
	const std::string module_name = get_command_option<std::string>(kme, "module_name");

	if (sys::kernel::modules_list.contains(module_name) == false)
	{
		std::println("module not found");

		return;
	}

	const sys::kernel_module_t module = sys::kernel::modules_list[module_name];

	for (auto& [export_name, export_address] : module.exports)
	{
		std::println("{} = 0x{:X}", export_name, export_address);
	}
}

CLI::App* init_dkm(CLI::App& app)
{
	CLI::App* dkm = app.add_subcommand("dkm", "dump kernel module to a file on disk")->ignore_case();

	add_command_option(dkm, "module_name")->required();
	add_command_option(dkm, "output_directory")->required();

	return dkm;
}

void process_dkm(CLI::App* dkm)
{
	const std::string module_name = get_command_option<std::string>(dkm, "module_name");

	if (sys::kernel::modules_list.contains(module_name) == false)
	{
		std::println("module not found");

		return;
	}

	const std::string output_directory = get_command_option<std::string>(dkm, "output_directory");

	const std::uint8_t status = sys::kernel::dump_module_to_disk(module_name, output_directory);

	if (status == 1)
	{
		std::println("success in dumping module");
	}
	else
	{
		std::println("failed to dump module");
	}
}

CLI::App* init_gva(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* gva = app.add_subcommand("gva", "get the numerical value of an alias")->ignore_case();

	add_transformed_command_option(gva, "alias_name", aliases_transformer)->required();

	return gva;
}

void process_gva(CLI::App* gva)
{
	const std::uint64_t alias_value = get_command_option<std::uint64_t>(gva, "alias_name");

	std::println("alias value: 0x{:X}", alias_value);
}

CLI::App* init_lp(CLI::App& app)
{
	CLI::App* lp = app.add_subcommand("lp", "list all running guest processes")->ignore_case();

	return lp;
}

void process_lp(CLI::App* lp)
{
	const std::vector<sys::process_info_t> processes = sys::process::enumerate_processes();

	if (processes.empty())
	{
		std::println("failed to enumerate processes");
		return;
	}

	std::println("{:<6} {:<20} {:<18} {:<18} {:<18}", "PID", "Name", "EPROCESS", "CR3", "ImageBase");
	std::println("{}", std::string(90, '-'));

	for (const auto& process : processes)
	{
		std::println("{:<6} {:<20} 0x{:<16X} 0x{:<16X} 0x{:<16X}",
			process.pid,
			process.name,
			process.eprocess,
			process.cr3,
			process.base_address);
	}

	std::println("\nTotal processes: {}", processes.size());
}

CLI::App* init_fp(CLI::App& app)
{
	CLI::App* fp = app.add_subcommand("fp", "find a process by name")->ignore_case();

	add_command_option(fp, "process_name")->required();

	return fp;
}

void process_fp(CLI::App* fp)
{
	const std::string process_name = get_command_option<std::string>(fp, "process_name");

	const std::optional<sys::process_info_t> process = sys::process::find_process_by_name(process_name);

	if (process.has_value() == false)
	{
		std::println("process '{}' not found", process_name);
		return;
	}

	std::println("Process found: {}", process->name);
	std::println("  PID:        {}", process->pid);
	std::println("  EPROCESS:   0x{:X}", process->eprocess);
	std::println("  CR3:        0x{:X}", process->cr3);
	std::println("  ImageBase:  0x{:X}", process->base_address);
}

CLI::App* init_wcr3(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* wcr3 = app.add_subcommand("wcr3", "write a new CR3 value to the guest VMCS")->ignore_case();

	add_transformed_command_option(wcr3, "cr3_value", aliases_transformer)->required();

	return wcr3;
}

void process_wcr3(CLI::App* wcr3)
{
	const std::uint64_t cr3_value = get_command_option<std::uint64_t>(wcr3, "cr3_value");

	const std::uint64_t result = hypercall::write_guest_cr3(cr3_value);

	if (result == 1)
	{
		std::println("guest CR3 written: 0x{:X}", cr3_value);
	}
	else
	{
		std::println("failed to write guest CR3");
	}
}

CLI::App* init_rcr3(CLI::App& app)
{
	CLI::App* rcr3 = app.add_subcommand("rcr3", "read the current guest CR3 value from VMCS")->ignore_case();

	return rcr3;
}

void process_rcr3(CLI::App* rcr3)
{
	const std::uint64_t cr3_value = hypercall::read_guest_cr3();

	std::println("guest CR3: 0x{:X}", cr3_value);
}

CLI::App* init_ccr3(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* ccr3 = app.add_subcommand("ccr3", "clone a guest CR3 (copy PML4, return new CR3 value)")->ignore_case();

	add_transformed_command_option(ccr3, "target_cr3", aliases_transformer)->required();

	return ccr3;
}

void process_ccr3(CLI::App* ccr3)
{
	const std::uint64_t target_cr3 = get_command_option<std::uint64_t>(ccr3, "target_cr3");

	const std::uint64_t cloned_cr3 = hypercall::clone_guest_cr3(target_cr3);

	if (cloned_cr3 != 0)
	{
		std::println("cloned CR3: 0x{:X} (from target 0x{:X})", cloned_cr3, target_cr3);
	}
	else
	{
		std::println("failed to clone CR3 (heap full or invalid target)");
	}
}

CLI::App* init_icr3(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* icr3 = app.add_subcommand("icr3", "enable CR3 intercept (swap target CR3 with clone on context switch)")->ignore_case();

	add_transformed_command_option(icr3, "target_cr3", aliases_transformer)->required();
	add_transformed_command_option(icr3, "cloned_cr3", aliases_transformer)->required();

	return icr3;
}

void process_icr3(CLI::App* icr3)
{
	const std::uint64_t target_cr3 = get_command_option<std::uint64_t>(icr3, "target_cr3");
	const std::uint64_t cloned_cr3 = get_command_option<std::uint64_t>(icr3, "cloned_cr3");

	const std::uint64_t result = hypercall::enable_cr3_intercept(target_cr3, cloned_cr3);

	if (result == 1)
	{
		std::println("CR3 intercept enabled: target=0x{:X} clone=0x{:X}", target_cr3, cloned_cr3);
		std::println("all context switches to target CR3 will now use the clone");
	}
	else
	{
		std::println("failed to enable CR3 intercept");
	}
}

CLI::App* init_dcr3(CLI::App& app)
{
	CLI::App* dcr3 = app.add_subcommand("dcr3", "disable CR3 intercept and restore original CR3")->ignore_case();

	return dcr3;
}

void process_dcr3(CLI::App* dcr3)
{
	const std::uint64_t result = hypercall::disable_cr3_intercept();

	if (result == 1)
	{
		std::println("CR3 intercept disabled, original CR3 restored");
	}
	else
	{
		std::println("failed to disable CR3 intercept (not active?)");
	}
}

CLI::App* init_cr3stat(CLI::App& app)
{
	CLI::App* cr3stat = app.add_subcommand("cr3stat", "show CR3 intercept statistics (MOV CR3 exit count)")->ignore_case();

	return cr3stat;
}

void process_cr3stat(CLI::App* cr3stat)
{
	const std::uint64_t exit_count = hypercall::read_cr3_exit_count();
	const std::uint64_t swap_count = hypercall::read_cr3_swap_count();
	const std::uint64_t last_seen = hypercall::read_cr3_last_seen();

	std::println("CR3 exit count: {}", exit_count);
	std::println("CR3 swap count: {}", swap_count);
	std::println("CR3 last seen:  0x{:X}", last_seen);
}

// hidden memory state
static std::uint64_t hidden_base_va = 0;
static std::uint64_t hidden_clone_cr3 = 0;
static std::uint64_t hidden_original_cr3 = 0;

CLI::App* init_mkhidden(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* mkhidden = app.add_subcommand("mkhidden", "setup hidden memory region in clone CR3 (allocates PDPT/PD/PT at given PML4 index)")->ignore_case();

	add_command_option(mkhidden, "pml4_index")->required();

	return mkhidden;
}

void process_mkhidden(CLI::App* mkhidden)
{
	const std::uint64_t pml4_index = get_command_option<std::uint64_t>(mkhidden, "pml4_index");

	const std::uint64_t base_va = hypercall::setup_hidden_region(pml4_index);

	if (base_va != 0)
	{
		hidden_base_va = base_va;
		std::println("hidden region at VA 0x{:X} (PML4[{}], PDPT/PD/PT allocated)", base_va, pml4_index);
	}
	else
	{
		std::println("failed to setup hidden region (clone CR3 not active or heap full)");
	}
}

CLI::App* init_maphidden(CLI::App& app)
{
	CLI::App* maphidden = app.add_subcommand("maphidden", "map a data page into the hidden region at given PT index (0-511)")->ignore_case();

	add_command_option(maphidden, "page_index")->required();

	return maphidden;
}

void process_maphidden(CLI::App* maphidden)
{
	const std::uint64_t page_index = get_command_option<std::uint64_t>(maphidden, "page_index");

	const std::uint64_t data_pa = hypercall::map_hidden_page(page_index);

	if (data_pa != 0)
	{
		const std::uint64_t page_va = hidden_base_va + (page_index * 0x1000);
		std::println("page {} mapped at VA 0x{:X}, PA=0x{:X}", page_index, page_va, data_pa);
	}
	else
	{
		std::println("failed to map hidden page (region not setup or heap full)");
	}
}

CLI::App* init_testhidden(CLI::App& app)
{
	CLI::App* testhidden = app.add_subcommand("testhidden", "test hidden memory: write via clone CR3, verify invisible via original CR3")->ignore_case();

	return testhidden;
}

void process_testhidden(CLI::App* testhidden)
{
	if (hidden_base_va == 0)
	{
		std::println("no hidden region setup (use mkhidden first)");
		return;
	}

	// read current CR3s from intercept state
	const std::uint64_t clone_cr3 = hypercall::read_guest_cr3();

	if (hidden_original_cr3 == 0 || hidden_clone_cr3 == 0)
	{
		std::println("set clone/original CR3 first:");
		std::println("  use 'sethidden <original_cr3> <clone_cr3>' or run ccr3/icr3 sequence");
		std::println("  current guest CR3 (should be clone): 0x{:X}", clone_cr3);
		return;
	}

	const std::uint64_t test_va = hidden_base_va;
	std::uint64_t write_value = 0xDEADBEEFCAFEBABE;
	std::uint64_t read_value = 0;

	// write via clone CR3
	std::println("writing 0x{:X} to clone:0x{:X}...", write_value, test_va);
	const std::uint64_t bytes_written = hypercall::write_guest_virtual_memory(&write_value, test_va, hidden_clone_cr3, 8);

	if (bytes_written != 8)
	{
		std::println("FAILED to write via clone CR3 (wrote {} bytes)", bytes_written);
		return;
	}

	std::println("write OK");

	// read back via clone CR3
	const std::uint64_t bytes_read_clone = hypercall::read_guest_virtual_memory(&read_value, test_va, hidden_clone_cr3, 8);

	if (bytes_read_clone == 8 && read_value == write_value)
	{
		std::println("read from clone:0x{:X} = 0x{:X} OK", test_va, read_value);
	}
	else
	{
		std::println("FAILED read from clone (read {} bytes, value=0x{:X})", bytes_read_clone, read_value);
		return;
	}

	// read via original CR3 — should fail (not mapped)
	read_value = 0;
	const std::uint64_t bytes_read_orig = hypercall::read_guest_virtual_memory(&read_value, test_va, hidden_original_cr3, 8);

	if (bytes_read_orig == 0)
	{
		std::println("read from original:0x{:X} = FAILED (not mapped) OK", test_va);
		std::println("hidden memory works!");
	}
	else
	{
		std::println("WARNING: read from original:0x{:X} returned {} bytes, value=0x{:X}", test_va, bytes_read_orig, read_value);
		std::println("hidden memory may not be properly isolated");
	}
}

CLI::App* init_sethidden(CLI::App& app, CLI::Transformer& aliases_transformer)
{
	CLI::App* sethidden = app.add_subcommand("sethidden", "store original and clone CR3 values for testhidden command")->ignore_case();

	add_transformed_command_option(sethidden, "original_cr3", aliases_transformer)->required();
	add_transformed_command_option(sethidden, "clone_cr3", aliases_transformer)->required();

	return sethidden;
}

void process_sethidden(CLI::App* sethidden)
{
	hidden_original_cr3 = get_command_option<std::uint64_t>(sethidden, "original_cr3");
	hidden_clone_cr3 = get_command_option<std::uint64_t>(sethidden, "clone_cr3");

	std::println("hidden test CR3s set: original=0x{:X} clone=0x{:X}", hidden_original_cr3, hidden_clone_cr3);
}

CLI::App* init_hookcb(CLI::App& app)
{
	CLI::App* hookcb = app.add_subcommand("hookcb", "install InstrumentationCallback bypass hook on KiSystemCall64 (protects PML4[70] syscalls from callback redirection)")->ignore_case();

	return hookcb;
}

void process_hookcb(CLI::App* hookcb)
{
	if (inject::ki_sc64se_target_eprocess == 0)
	{
		std::println("no target EPROCESS set — inject a DLL first");
		return;
	}

	if (inject::install_ki_syscall64_service_exit_hook(inject::ki_sc64se_target_eprocess))
	{
		std::println("InstrumentationCallback bypass hook installed (EPROCESS: 0x{:X})", inject::ki_sc64se_target_eprocess);
	}
	else
	{
		std::println("failed to install InstrumentationCallback bypass hook");
	}
}

CLI::App* init_unhookcb(CLI::App& app)
{
	CLI::App* unhookcb = app.add_subcommand("unhookcb", "remove InstrumentationCallback bypass hook")->ignore_case();

	return unhookcb;
}

void process_unhookcb(CLI::App* unhookcb)
{
	if (inject::remove_ki_syscall64_service_exit_hook())
	{
		std::println("InstrumentationCallback bypass hook removed");
	}
	else
	{
		std::println("failed to remove InstrumentationCallback bypass hook");
	}
}

CLI::App* init_hookblt(CLI::App& app)
{
	return app.add_subcommand("hookblt", "install screenshot hooks on NtGdiBitBlt / NtGdiStretchBlt (anti-cheat capture interception)")->ignore_case();
}

void process_hookblt(CLI::App* hookblt)
{
	if (inject::install_blt_hooks())
	{
		// Enable the screenshot hook feature via CPUID(30, sub_cmd=4)
		std::uint64_t result = hypercall::screenshot_enable();
		std::println("[+] Screenshot hooks installed and enabled (result: {})", result);
	}
	else
	{
		std::println("[-] Failed to install screenshot hooks");
	}
}

CLI::App* init_unhookblt(CLI::App& app)
{
	return app.add_subcommand("unhookblt", "remove screenshot hooks from NtGdiBitBlt / NtGdiStretchBlt")->ignore_case();
}

void process_unhookblt(CLI::App* unhookblt)
{
	// Disable the screenshot hook feature via CPUID(30, sub_cmd=5)
	hypercall::screenshot_disable();

	if (inject::remove_blt_hooks())
	{
		std::println("[+] Screenshot hooks disabled and removed");
	}
	else
	{
		std::println("[-] Failed to remove screenshot hooks (may not be installed)");
	}
}

CLI::App* init_hookws(CLI::App& app)
{
	return app.add_subcommand("hookws", "install PsWatchWorkingSet hook (suppress working set monitoring for hidden memory)")->ignore_case();
}

void process_hookws(CLI::App* hookws)
{
	if (inject::install_pswatch_hook())
	{
		std::println("[+] PsWatchWorkingSet hook installed");
	}
	else
	{
		std::println("[-] Failed to install PsWatchWorkingSet hook");
	}
}

CLI::App* init_unhookws(CLI::App& app)
{
	return app.add_subcommand("unhookws", "remove PsWatchWorkingSet hook")->ignore_case();
}

void process_unhookws(CLI::App* unhookws)
{
	if (inject::remove_pswatch_hook())
	{
		std::println("[+] PsWatchWorkingSet hook removed");
	}
	else
	{
		std::println("[-] Failed to remove PsWatchWorkingSet hook");
	}
}

CLI::App* init_injectdll(CLI::App& app)
{
	CLI::App* injectdll = app.add_subcommand("injectdll", "inject a DLL into a process using hidden memory (PE manual map + syscall exit EPT hook)")->ignore_case();

	add_command_option(injectdll, "dll_path")->required();
	add_command_option(injectdll, "process_name")->required();

	return injectdll;
}

void process_injectdll(CLI::App* injectdll)
{
	const std::string dll_path = get_command_option<std::string>(injectdll, "dll_path");
	const std::string process_name = get_command_option<std::string>(injectdll, "process_name");

	std::println("[*] Injecting {} into {}...", dll_path, process_name);

	bool result = inject::inject_dll(dll_path, process_name);

	if (result)
	{
		std::println("[+] Injection successful!");
	}
	else
	{
		std::println("[-] Injection failed");
	}
}

CLI::App* init_uninject(CLI::App& app)
{
	return app.add_subcommand("uninject", "tear down all injection hooks and restore clean state")->ignore_case();
}

void process_uninject(CLI::App* uninject)
{
	if (!uninject->parsed()) return;
	inject::uninject();
}

CLI::App* init_hookstatus(CLI::App& app)
{
	return app.add_subcommand("hookstatus", "show EPT hook and cleanup diagnostics")->ignore_case();
}

void process_hookstatus(CLI::App* hookstatus)
{
	if (!hookstatus->parsed()) return;
	std::println("[+] Diagnostics:");
	std::println("    cr3_exits:        {}", hypercall::read_cr3_exit_count());
	std::println("    cr3_swaps:        {}", hypercall::read_cr3_swap_count());
	std::println("    ept_violations:   {}", hypercall::read_slat_violation_count());
	std::println("    mmaf_hits:        {}", hypercall::read_mmaf_hit_count());
	std::println("    cleanup_count:    {}", hypercall::read_cleanup_count());
	std::println("    hijack_cpuid:     {}", hypercall::read_hijack_cpuid_count());
	std::println("    hijack_claimed:   {}", hypercall::read_hijack_claimed_count());
	std::println("    hijack_armed:     {}", hypercall::read_hijack_armed_state());
}

CLI::App* init_boothook(CLI::App& app)
{
	return app.add_subcommand("boothook", "show boot-time hook installation status")->ignore_case();
}

void process_boothook(CLI::App* boothook)
{
	if (!boothook->parsed()) return;

	const std::uint64_t flags = hypercall::read_boot_hook_diag(0);
	const std::uint64_t ntos_base = hypercall::read_boot_hook_diag(1);
	const std::uint64_t psgetprocname = hypercall::read_boot_hook_diag(2);

	// extract target name from packed flags (7 chars in bits 8..63)
	char name[8] = {};
	for (int i = 0; i < 7; i++)
		name[i] = static_cast<char>((flags >> (8 + i * 8)) & 0xFF);
	name[7] = '\0';

	const std::uint64_t hit_count = hypercall::read_boot_hook_diag(3);
	const std::uint64_t match_count = hypercall::read_boot_hook_diag(4);
	const std::uint64_t entry_count = hypercall::read_boot_hook_diag(5);

	std::println("[+] Boot Hook Status:");
	std::println("    mmclean_active:   {}", (flags & 1) ? "YES" : "NO");
	std::println("    armed:            {}", (flags & 2) ? "YES" : "NO");
	std::println("    PsGetProcName:    {}", (flags & 4) ? "YES" : "NO");
	std::println("    hidden_pt:        {}", (flags & 8) ? "YES" : "NO");
	std::println("    hidden_pml4e:     {}", (flags & 16) ? "YES" : "NO");
	std::println("    target_name:      \"{}\"", name);
	std::println("    ntoskrnl_base:    0x{:X}", ntos_base);
	std::println("    PsGetProcNameVA:  0x{:X}", psgetprocname);
	std::println("    hook_entries:     {} (unconditional)", entry_count);
	std::println("    hook_hits:        {} (armed+fn ok)", hit_count);
	std::println("    hook_matches:     {} (name match)", match_count);
	std::println("    cleanup_count:    {}", hypercall::read_cleanup_count());
}

CLI::App* init_testmm(CLI::App& app)
{
	auto* cmd = app.add_subcommand("testmm", "minimal MmClean hook test: attach + install + arm (no DLL)")->ignore_case();
	cmd->add_option("process_name", "target process name")->required();
	return cmd;
}

void process_testmm(CLI::App* testmm)
{
	if (!testmm->parsed()) return;

	const std::string process_name = testmm->get_option("process_name")->as<std::string>();

	// 1. Cleanup stale state
	hypercall::disable_cr3_intercept();

	// 2. Find process
	auto process = sys::process::find_process_by_name(process_name);
	if (!process.has_value())
	{
		std::println("[-] Process '{}' not found", process_name);
		return;
	}
	std::println("[+] Found {} (PID: {}, CR3: 0x{:X}, EPROCESS: 0x{:X})",
		process->name, process->pid, process->cr3, process->eprocess);

	// 3. Clone CR3
	std::uint64_t cloned_cr3 = hypercall::clone_guest_cr3(process->cr3);
	if (cloned_cr3 == 0)
	{
		std::println("[-] Failed to clone CR3");
		return;
	}
	std::println("[+] Cloned CR3: 0x{:X}", cloned_cr3);

	// 4. Enable CR3 intercept
	if (hypercall::enable_cr3_intercept(process->cr3, cloned_cr3) == 0)
	{
		std::println("[-] Failed to enable CR3 intercept");
		return;
	}
	std::println("[+] CR3 intercept enabled");

	// 5. Setup hidden region (uses pre-existing from boot)
	std::uint64_t hidden_base = hypercall::setup_hidden_region(70);
	if (hidden_base == 0)
	{
		std::println("[-] Failed to setup hidden region");
		hypercall::disable_cr3_intercept();
		return;
	}
	std::println("[+] Hidden region at 0x{:X}", hidden_base);

	// 5b. Initialize hook infrastructure (kernel detour holder + EPT split)
	// Required for MMAF shellcode allocation — inject_dll calls this but testmm didn't
	if (hook::set_up() == 0)
	{
		std::println("[-] hook::set_up() failed — cannot install MMAF safety net");
		hypercall::disable_cr3_intercept();
		return;
	}
	std::println("[+] Hook infrastructure initialized");

	// 6. MmAccessFault C++ EPT hook — safety net for hidden memory #PFs
	if (inject::install_mmaf_cpp_hook(cloned_cr3, 70))
		std::println("[+] MmAccessFault safety net active");
	else
		std::println("[!] WARNING: MmAccessFault hook failed — hidden memory faults will BSOD");

	// 7. Install MmClean EPT hook (RVA from PDB)
	if (!inject::install_mmclean_hook(process->eprocess))
	{
		std::println("[-] MmClean hook install failed");
		hypercall::disable_cr3_intercept();
		return;
	}

	// 8. Arm with process name
	char target_name_buf[16] = {};
	for (size_t i = 0; i < process->name.size() && i < 15; i++)
		target_name_buf[i] = process->name[i];

	const auto& ntoskrnl = sys::kernel::modules_list["ntoskrnl.exe"];
	std::uint64_t arm_result = hypercall::arm_process_cleanup(process->eprocess, ntoskrnl.base_address, target_name_buf);

	if (arm_result == 0)
		std::println("[!] WARNING: arm_process_cleanup returned 0 — PsGetProcessImageFileName resolution FAILED");
	else
		std::println("[+] MmClean armed for '{}' (PsGetProcessImageFileName resolved)", process->name);

	std::println("[+] testmm active — kill {} and run 'boothook' to check counters", process->name);
}

std::unordered_map<std::string, std::uint64_t> form_aliases()
{
	std::unordered_map<std::string, std::uint64_t> aliases = { { "current_cr3", sys::current_cr3 } };

	for (auto& [module_name, module_info] : sys::kernel::modules_list)
	{
		aliases.insert({ module_name, module_info.base_address });
		aliases.insert(module_info.exports.begin(), module_info.exports.end());
	}

	return aliases;
}

void commands::process(const std::string command)
{
	if (command.empty() == true)
	{
		return;
	}

	CLI::App app;
	app.require_subcommand();

	sys::kernel::parse_modules();

	const std::unordered_map<std::string, std::uint64_t> aliases = form_aliases();

	CLI::Transformer aliases_transformer = CLI::Transformer(aliases, CLI::ignore_case);

	aliases_transformer.description(" can_use_aliases");

	CLI::App* rgpm = init_rgpm(app, aliases_transformer);
	CLI::App* wgpm = init_wgpm(app, aliases_transformer);
	CLI::App* cgpm = init_cgpm(app, aliases_transformer);
	CLI::App* gvat = init_gvat(app, aliases_transformer);
	CLI::App* rgvm = init_rgvm(app, aliases_transformer);
	CLI::App* wgvm = init_wgvm(app, aliases_transformer);
	CLI::App* cgvm = init_cgvm(app, aliases_transformer);
	CLI::App* akh = init_akh(app, aliases_transformer);
	CLI::App* rkh = init_rkh(app, aliases_transformer);
	CLI::App* gva = init_gva(app, aliases_transformer);
	CLI::App* hgpp = init_hgpp(app, aliases_transformer);
	CLI::App* mpp = init_mpp(app, aliases_transformer);
	CLI::App* umpp = init_umpp(app, aliases_transformer);
	CLI::App* fl = init_fl(app);
	CLI::App* hfpc = init_hfpc(app);
	CLI::App* lkm = init_lkm(app);
	CLI::App* kme = init_kme(app);
	CLI::App* dkm = init_dkm(app);
	CLI::App* lp = init_lp(app);
	CLI::App* fp = init_fp(app);
	CLI::App* wcr3 = init_wcr3(app, aliases_transformer);
	CLI::App* rcr3 = init_rcr3(app);
	CLI::App* ccr3 = init_ccr3(app, aliases_transformer);
	CLI::App* icr3 = init_icr3(app, aliases_transformer);
	CLI::App* dcr3 = init_dcr3(app);
	CLI::App* cr3stat = init_cr3stat(app);
	CLI::App* mkhidden = init_mkhidden(app, aliases_transformer);
	CLI::App* maphidden = init_maphidden(app);
	CLI::App* testhidden = init_testhidden(app);
	CLI::App* sethidden = init_sethidden(app, aliases_transformer);
	CLI::App* hookcb = init_hookcb(app);
	CLI::App* unhookcb = init_unhookcb(app);
	CLI::App* hookblt = init_hookblt(app);
	CLI::App* unhookblt = init_unhookblt(app);
	CLI::App* hookws = init_hookws(app);
	CLI::App* unhookws = init_unhookws(app);
	CLI::App* injectdll = init_injectdll(app);
	CLI::App* uninject = init_uninject(app);
	CLI::App* hookstatus = init_hookstatus(app);
	CLI::App* boothook = init_boothook(app);
	CLI::App* testmm = init_testmm(app);

	try
	{
		app.parse(command);

		d_initial_process_command(rgpm);
		d_process_command(wgpm);
		d_process_command(cgpm);
		d_process_command(gvat);
		d_process_command(rgvm);
		d_process_command(wgvm);
		d_process_command(cgvm);
		d_process_command(akh);
		d_process_command(rkh);
		d_process_command(gva);
		d_process_command(hgpp);
		d_process_command(mpp);
		d_process_command(umpp);
		d_process_command(fl);
		d_process_command(hfpc);
		d_process_command(lkm);
		d_process_command(kme);
		d_process_command(dkm);
		d_process_command(lp);
		d_process_command(fp);
		d_process_command(wcr3);
		d_process_command(rcr3);
		d_process_command(ccr3);
		d_process_command(icr3);
		d_process_command(dcr3);
		d_process_command(cr3stat);
		d_process_command(mkhidden);
		d_process_command(maphidden);
		d_process_command(testhidden);
		d_process_command(sethidden);
		d_process_command(hookcb);
		d_process_command(unhookcb);
		d_process_command(hookblt);
		d_process_command(unhookblt);
		d_process_command(hookws);
		d_process_command(unhookws);
		d_process_command(injectdll);
		d_process_command(uninject);
		d_process_command(hookstatus);
		d_process_command(boothook);
		d_process_command(testmm);
	}
	catch (const CLI::ParseError& error)
	{
		app.exit(error);
	}
}


#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>
#include "../memory/memory_reader.h"

namespace widgets
{
	struct module_info_t
	{
		std::string name;
		uint64_t base;
		uint32_t size;
	};

	// global module list — populated by ModulesPanel, used by all panels
	inline std::vector<module_info_t> g_modules;
	inline bool g_modules_valid = false;

	// resolve address to "module.dll+0x1234" or "0x..." if not in any module
	inline std::string format_address_module(uint64_t address)
	{
		for (auto& mod : g_modules)
		{
			if (address >= mod.base && address < mod.base + mod.size)
			{
				char buf[256];
				snprintf(buf, sizeof(buf), "%s+%llX", mod.name.c_str(), address - mod.base);
				return buf;
			}
		}

		char buf[32];
		snprintf(buf, sizeof(buf), "%016llX", address);
		return buf;
	}

	// resolve address, return module name and offset separately
	inline bool resolve_module(uint64_t address, std::string& out_name, uint64_t& out_offset)
	{
		for (auto& mod : g_modules)
		{
			if (address >= mod.base && address < mod.base + mod.size)
			{
				out_name = mod.name;
				out_offset = address - mod.base;
				return true;
			}
		}
		return false;
	}

	// short format: "module+0x1234" or "0x..."
	inline std::string format_address_short(uint64_t address)
	{
		std::string name;
		uint64_t offset;
		if (resolve_module(address, name, offset))
		{
			char buf[256];
			snprintf(buf, sizeof(buf), "%s+0x%llX", name.c_str(), offset);
			return buf;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "0x%llX", address);
		return buf;
	}

	// resolve address to export name if it's at the start of an exported function
	// uses PE export directory walk in guest memory
	inline std::string resolve_export_name(uint64_t address)
	{
		for (auto& mod : g_modules)
		{
			if (address < mod.base || address >= mod.base + mod.size)
				continue;

			// read DOS header
			uint16_t e_magic = 0;
			memory::read(&e_magic, mod.base, 2);
			if (e_magic != 0x5A4D) continue;

			uint32_t e_lfanew = 0;
			memory::read(&e_lfanew, mod.base + 0x3C, 4);
			if (e_lfanew == 0 || e_lfanew > 0x1000) continue;

			// PE signature check
			uint32_t pe_sig = 0;
			memory::read(&pe_sig, mod.base + e_lfanew, 4);
			if (pe_sig != 0x00004550) continue; // "PE\0\0"

			// read export directory RVA from optional header
			// offset: e_lfanew + 4 (sig) + 20 (file header) + 112 (export dir in optional header)
			uint32_t export_rva = 0, export_size = 0;
			memory::read(&export_rva, mod.base + e_lfanew + 0x88, 4);
			memory::read(&export_size, mod.base + e_lfanew + 0x8C, 4);
			if (export_rva == 0 || export_size == 0) continue;

			uint64_t export_dir = mod.base + export_rva;

			uint32_t num_functions = 0, num_names = 0;
			uint32_t addr_table_rva = 0, name_table_rva = 0, ordinal_table_rva = 0;
			memory::read(&num_functions, export_dir + 0x14, 4);
			memory::read(&num_names, export_dir + 0x18, 4);
			memory::read(&addr_table_rva, export_dir + 0x1C, 4);
			memory::read(&name_table_rva, export_dir + 0x20, 4);
			memory::read(&ordinal_table_rva, export_dir + 0x24, 4);

			if (num_names == 0 || num_names > 20000) continue;

			uint32_t target_rva = (uint32_t)(address - mod.base);

			// scan export address table for matching RVA
			// read ordinals + name pointers in bulk for speed
			int batch = (int)(num_names < 4096 ? num_names : 4096);
			std::vector<uint32_t> name_rvas(batch);
			std::vector<uint16_t> ordinals(batch);
			memory::read(name_rvas.data(), mod.base + name_table_rva, batch * 4);
			memory::read(ordinals.data(), mod.base + ordinal_table_rva, batch * 2);

			for (int i = 0; i < batch; i++)
			{
				if (ordinals[i] >= num_functions) continue;

				uint32_t func_rva = 0;
				memory::read(&func_rva, mod.base + addr_table_rva + ordinals[i] * 4, 4);

				if (func_rva == target_rva)
				{
					// read the name
					char name_buf[128] = {};
					memory::read(name_buf, mod.base + name_rvas[i], sizeof(name_buf) - 1);
					name_buf[sizeof(name_buf) - 1] = '\0';
					if (name_buf[0])
						return std::string(name_buf);
				}
			}
		}
		return {};
	}

	// clipboard copy helper
	inline void copy_to_clipboard(const char* text)
	{
		ImGui::SetClipboardText(text);
	}

	// standard right-click context menu for any address
	inline void address_context_menu(const char* id, uint64_t address)
	{
		if (ImGui::BeginPopupContextItem(id))
		{
			std::string mod_str = format_address_short(address);

			if (ImGui::MenuItem("Copy Address"))
			{
				char buf[32];
				snprintf(buf, sizeof(buf), "0x%llX", address);
				copy_to_clipboard(buf);
			}
			if (ImGui::MenuItem("Copy Module+Offset"))
				copy_to_clipboard(mod_str.c_str());

			ImGui::Separator();

			// these use app::navigate_to_address which must be declared
			// callers handle navigation themselves via return value
			ImGui::EndPopup();
		}
	}
}

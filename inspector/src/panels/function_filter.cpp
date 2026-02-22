#include "function_filter.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../renderer/anim.h"
#include "../memory/memory_reader.h"
#include "../widgets/module_resolver.h"
#include "../widgets/ui_helpers.h"
#include "hypercall/hypercall.h"
#include <Zydis/Zydis.h>
#include <structures/trap_frame.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <print>

FunctionFilterPanel::~FunctionFilterPanel()
{
	if (m_monitoring)
		stop_monitoring();
	if (m_tracing)
		stop_trace();
	if (m_load_thread.joinable())
		m_load_thread.join();
}

// ---- PE helpers ----

// [I6 fix] Find ALL code sections in a module, not just the first
std::vector<FunctionFilterPanel::code_section_t> FunctionFilterPanel::find_code_sections(uint64_t base)
{
	std::vector<code_section_t> sections;

	uint32_t e_lfanew = 0;
	memory::read(&e_lfanew, base + 0x3C, 4);
	if (e_lfanew == 0 || e_lfanew > 0x1000) return sections;

	uint16_t num_sections = 0, opt_hdr_size = 0;
	memory::read(&num_sections, base + e_lfanew + 6, 2);
	memory::read(&opt_hdr_size, base + e_lfanew + 20, 2);
	if (num_sections == 0 || num_sections > 96) return sections;

	uint64_t section_hdr_offset = e_lfanew + 24 + opt_hdr_size;

	for (int i = 0; i < num_sections; i++)
	{
		uint8_t sec[40] = {};
		memory::read(sec, base + section_hdr_offset + i * 40, 40);

		uint32_t characteristics = *(uint32_t*)(sec + 36);
		if (characteristics & 0x20) // IMAGE_SCN_CNT_CODE
		{
			uint32_t rva  = *(uint32_t*)(sec + 12);
			uint32_t size = *(uint32_t*)(sec + 8);
			if (rva && size)
				sections.push_back({ rva, size });
		}
	}

	return sections;
}

void FunctionFilterPanel::rebuild_va_set()
{
	m_va_set.clear();
	m_va_set.reserve(m_functions.size());
	for (auto& fn : m_functions)
		m_va_set.insert(fn.va);
}

// ---- Source 1: Unwind Info (.pdata) ----

void FunctionFilterPanel::load_from_pdata(const widgets::module_info_t& mod)
{
	m_functions.clear();

	// read e_lfanew
	uint32_t e_lfanew = 0;
	memory::read(&e_lfanew, mod.base + 0x3C, 4);
	if (e_lfanew == 0 || e_lfanew > 0x1000) return;

	// exception directory = DataDirectory[3] at e_lfanew + 0xA0
	uint32_t exc_rva = 0, exc_size = 0;
	memory::read(&exc_rva, mod.base + e_lfanew + 0xA0, 4);
	memory::read(&exc_size, mod.base + e_lfanew + 0xA4, 4);
	if (exc_rva == 0 || exc_size == 0) return;

	// each RUNTIME_FUNCTION is 12 bytes: BeginAddress(4), EndAddress(4), UnwindInfoAddress(4)
	int count = exc_size / 12;
	if (count <= 0 || count > 500000) return;

	// batch read all RUNTIME_FUNCTION entries
	std::vector<uint8_t> pdata_buf(count * 12);
	if (!memory::read(pdata_buf.data(), mod.base + exc_rva, pdata_buf.size()))
		return;

	uint64_t cr3 = memory::get_cr3();
	m_functions.reserve(count);

	for (int i = 0; i < count; i++)
	{
		uint32_t begin_addr = *(uint32_t*)(pdata_buf.data() + i * 12);
		uint32_t end_addr   = *(uint32_t*)(pdata_buf.data() + i * 12 + 4);
		if (begin_addr == 0) continue;

		uint64_t va = mod.base + begin_addr;

		function_entry_t fn;
		fn.va = va;
		fn.size = (end_addr > begin_addr) ? (end_addr - begin_addr) : 0;
		fn.name = widgets::format_address_short(va);

		// try to resolve export name
		std::string ename = widgets::resolve_export_name(va);
		if (!ename.empty())
			fn.name = ename;

		// translate to GPA (page-aligned)
		if (cr3)
		{
			uint64_t gpa = hypercall::translate_guest_virtual_address(va, cr3);
			fn.gpa = gpa ? (gpa & ~0xFFFull) : 0;
		}

		m_functions.push_back(std::move(fn));
	}

	rebuild_va_set();
	std::println("[FuncFilter] Loaded {} functions from .pdata of {}", m_functions.size(), mod.name);
	m_phase = fn_phase_t::loaded;
}

// ---- Source 2: CALL Scan ----

void FunctionFilterPanel::load_from_call_scan(const widgets::module_info_t& mod)
{
	m_phase = fn_phase_t::loading;
	m_load_done = false;

	// [C2 fix] join previous thread BEFORE clearing shared state
	if (m_load_thread.joinable())
		m_load_thread.join();
	m_load_result.clear();

	// capture values for thread
	uint64_t base = mod.base;
	uint32_t mod_size = mod.size;
	std::string mod_name = mod.name;

	// [I6 fix] find ALL code sections on main thread (uses memory::read which is safe)
	auto code_sections = find_code_sections(base);
	if (code_sections.empty())
	{
		m_load_done = true;
		return;
	}

	m_load_thread = std::thread([this, base, mod_size, mod_name, code_sections]() {
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		std::unordered_set<uint64_t> call_targets;

		// [I6 fix] scan ALL code sections
		for (auto& sec : code_sections)
		{
			uint32_t text_rva = sec.rva;
			uint32_t text_size = sec.size;
			if (text_size > 0x2000000) text_size = 0x2000000; // 32MB max per section

			call_targets.insert(base + text_rva); // section entry

			// [I4 fix] read chunks with 15-byte overlap to handle instructions at boundaries
			constexpr int CHUNK = 4096;
			constexpr int OVERLAP = 15; // max x86-64 instruction length
			std::vector<uint8_t> chunk(CHUNK + OVERLAP);

			for (uint32_t off = 0; off < text_size; )
			{
				uint32_t read_sz = std::min((uint32_t)(CHUNK + OVERLAP), text_size - off);
				if (!memory::read(chunk.data(), base + text_rva + off, read_sz))
				{
					off += CHUNK;
					continue;
				}

				// only decode up to CHUNK bytes (or remainder), overlap is buffer headroom
				uint32_t decode_limit = std::min((uint32_t)CHUNK, text_size - off);
				uint32_t pos = 0;
				while (pos < decode_limit)
				{
					ZydisDecodedInstruction instr;
					ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

					uint32_t avail = read_sz - pos;
					if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
						chunk.data() + pos, avail, &instr, operands)))
					{
						pos++;
						continue;
					}

					uint64_t rip = base + text_rva + off + pos;

					if (instr.mnemonic == ZYDIS_MNEMONIC_CALL)
					{
						uint64_t target = 0;
						if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &operands[0], rip, &target)))
						{
							if (target >= base && target < base + mod_size)
								call_targets.insert(target);
						}
					}

					pos += instr.length;
				}

				off += decode_limit; // advance by actual decoded range, not by read_sz
			}
		}

		// build result vector — resolve names on background thread
		// (widgets::g_modules is read-only after attach, widgets::format_address_short and
		//  resolve_export_name only read from cached data, safe for concurrent reads)
		uint64_t cr3 = memory::get_cr3();
		std::vector<function_entry_t> result;
		result.reserve(call_targets.size());

		for (uint64_t va : call_targets)
		{
			function_entry_t fn;
			fn.va = va;
			fn.name = widgets::format_address_short(va);

			std::string ename = widgets::resolve_export_name(va);
			if (!ename.empty())
				fn.name = ename;

			if (cr3)
			{
				uint64_t gpa = hypercall::translate_guest_virtual_address(va, cr3);
				fn.gpa = gpa ? (gpa & ~0xFFFull) : 0;
			}

			result.push_back(std::move(fn));
		}

		// sort by VA
		std::sort(result.begin(), result.end(),
			[](const function_entry_t& a, const function_entry_t& b) { return a.va < b.va; });

		m_load_result = std::move(result);
		std::println("[FuncFilter] CALL scan found {} targets in {}", m_load_result.size(), mod_name);
		m_load_done = true;
	});
}

// ---- Source 4: Combined (pdata + CALL scan) ----

void FunctionFilterPanel::load_combined(const widgets::module_info_t& mod)
{
	// step 1: load pdata synchronously (fast, gives sizes)
	load_from_pdata(mod);
	// pdata sets m_phase = loaded, but we'll override to loading for the background scan

	// step 2: kick off CALL scan in background — when done, merge_call_scan_results() merges
	m_phase = fn_phase_t::loading;
	m_load_done = false;

	// [C2 fix] join previous thread BEFORE clearing shared state
	if (m_load_thread.joinable())
		m_load_thread.join();
	m_load_result.clear();

	uint64_t base = mod.base;
	uint32_t mod_size = mod.size;
	std::string mod_name = mod.name;

	// [I6 fix] find ALL code sections on main thread
	auto code_sections = find_code_sections(base);
	if (code_sections.empty())
	{
		m_load_done = true;
		return;
	}

	m_load_thread = std::thread([this, base, mod_size, mod_name, code_sections]() {
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		std::unordered_set<uint64_t> call_targets;

		// [I6 fix] scan ALL code sections
		for (auto& sec : code_sections)
		{
			uint32_t text_rva = sec.rva;
			uint32_t text_size = sec.size;
			if (text_size > 0x2000000) text_size = 0x2000000;

			// [I4 fix] read chunks with overlap
			constexpr int CHUNK = 4096;
			constexpr int OVERLAP = 15;
			std::vector<uint8_t> chunk(CHUNK + OVERLAP);

			for (uint32_t off = 0; off < text_size; )
			{
				uint32_t read_sz = std::min((uint32_t)(CHUNK + OVERLAP), text_size - off);
				if (!memory::read(chunk.data(), base + text_rva + off, read_sz))
				{
					off += CHUNK;
					continue;
				}

				uint32_t decode_limit = std::min((uint32_t)CHUNK, text_size - off);
				uint32_t pos = 0;
				while (pos < decode_limit)
				{
					ZydisDecodedInstruction instr;
					ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

					uint32_t avail = read_sz - pos;
					if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
						chunk.data() + pos, avail, &instr, operands)))
					{
						pos++;
						continue;
					}

					uint64_t rip = base + text_rva + off + pos;

					if (instr.mnemonic == ZYDIS_MNEMONIC_CALL)
					{
						uint64_t target = 0;
						if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &operands[0], rip, &target)))
						{
							if (target >= base && target < base + mod_size)
								call_targets.insert(target);
						}
					}

					pos += instr.length;
				}

				off += decode_limit;
			}
		}

		// build result — only targets NOT already in pdata
		uint64_t cr3 = memory::get_cr3();
		std::vector<function_entry_t> result;

		for (uint64_t va : call_targets)
		{
			function_entry_t fn;
			fn.va = va;
			fn.name = widgets::format_address_short(va);

			std::string ename = widgets::resolve_export_name(va);
			if (!ename.empty())
				fn.name = ename;

			if (cr3)
			{
				uint64_t gpa = hypercall::translate_guest_virtual_address(va, cr3);
				fn.gpa = gpa ? (gpa & ~0xFFFull) : 0;
			}

			result.push_back(std::move(fn));
		}

		m_load_result = std::move(result);
		std::println("[FuncFilter] Combined CALL scan found {} additional targets in {}", m_load_result.size(), mod_name);
		m_load_done = true;
	});
}

void FunctionFilterPanel::merge_call_scan_results()
{
	if (m_load_result.empty())
	{
		m_load_result.clear();
		m_load_done = false;
		m_phase = fn_phase_t::loaded;
		return;
	}

	int added = 0;
	for (auto& fn : m_load_result)
	{
		// [I3 fix] O(1) dedup via m_va_set
		if (m_va_set.find(fn.va) == m_va_set.end())
		{
			m_va_set.insert(fn.va);
			m_functions.push_back(std::move(fn));
			added++;
		}
	}

	m_load_result.clear();
	m_load_done = false;

	// sort by VA
	std::sort(m_functions.begin(), m_functions.end(),
		[](const function_entry_t& a, const function_entry_t& b) { return a.va < b.va; });

	m_phase = fn_phase_t::loaded;
	std::println("[FuncFilter] Combined: merged {} new CALL targets, total {} functions", added, m_functions.size());
}

// ---- Source 3: Trace ----

void FunctionFilterPanel::load_from_trace(const widgets::module_info_t& mod)
{
	// [I6 fix] find ALL code sections
	auto code_sections = find_code_sections(mod.base);
	if (code_sections.empty()) return;

	uint64_t cr3 = memory::get_cr3();
	if (!cr3) return;

	m_trace_rips.clear();
	m_trace_gpas.clear();
	m_trace_monitor_ids.clear();
	m_trace_hit_pages.clear();
	m_trace_pending_unmonitor.clear();
	m_tracing = true;

	// [I6 fix] monitor ALL code sections' pages
	std::unordered_set<uint64_t> seen_gpas;

	for (auto& sec : code_sections)
	{
		uint64_t va_start = mod.base + sec.rva;
		uint64_t va_end = va_start + sec.size;

		for (uint64_t va = va_start & ~0xFFFull; va < va_end; va += 0x1000)
		{
			uint64_t gpa = hypercall::translate_guest_virtual_address(va, cr3);
			if (!gpa) continue;

			uint64_t page_gpa = gpa & ~0xFFFull;
			if (seen_gpas.count(page_gpa)) continue;
			seen_gpas.insert(page_gpa);

			uint32_t mid = app::register_page_monitor(page_gpa, [this, page_gpa](const trap_frame_log_t& log) {
				// filter by attached process CR3
				auto& st = app::state();
				if (st.process_attached && log.cr3 != st.attached_process.cr3)
					return;

				m_trace_rips.insert(log.rip);

				// one-shot: mark page for deferred unmonitor after first hit
				if (m_trace_hit_pages.find(page_gpa) == m_trace_hit_pages.end())
				{
					m_trace_hit_pages.insert(page_gpa);
					m_trace_pending_unmonitor.push_back(page_gpa);
				}
			});
			hypercall::monitor_physical_page(page_gpa);
			m_trace_gpas.push_back(page_gpa);
			m_trace_monitor_ids.push_back(mid);
		}
	}

	std::println("[FuncFilter] Trace: monitoring {} pages for {}", m_trace_gpas.size(), mod.name);
	m_phase = fn_phase_t::loading;
}

void FunctionFilterPanel::stop_trace()
{
	if (!m_tracing) return;

	for (size_t i = 0; i < m_trace_gpas.size(); i++)
	{
		hypercall::unmonitor_physical_page(m_trace_gpas[i]);
		if (i < m_trace_monitor_ids.size())
			app::unregister_page_monitor(m_trace_monitor_ids[i]);
	}

	// [I5 fix] try to snap RIPs to .pdata function starts
	// find the module for the collected RIPs
	uint64_t cr3 = memory::get_cr3();
	m_functions.clear();

	// sort RIPs
	std::vector<uint64_t> rips(m_trace_rips.begin(), m_trace_rips.end());
	std::sort(rips.begin(), rips.end());

	if (!rips.empty())
	{
		// try to load pdata to snap RIPs to function starts
		std::string mod_name;
		uint64_t mod_offset;
		const widgets::module_info_t* found_mod = nullptr;

		if (widgets::resolve_module(rips[0], mod_name, mod_offset))
		{
			for (auto& m : widgets::g_modules)
			{
				if (m.name == mod_name)
				{
					found_mod = &m;
					break;
				}
			}
		}

		// build pdata lookup table for snapping
		struct pdata_fn_t { uint64_t va; uint64_t end_va; std::string name; };
		std::vector<pdata_fn_t> pdata_fns;

		if (found_mod)
		{
			uint32_t e_lfanew = 0;
			memory::read(&e_lfanew, found_mod->base + 0x3C, 4);
			if (e_lfanew && e_lfanew <= 0x1000)
			{
				uint32_t exc_rva = 0, exc_size = 0;
				memory::read(&exc_rva, found_mod->base + e_lfanew + 0xA0, 4);
				memory::read(&exc_size, found_mod->base + e_lfanew + 0xA4, 4);
				if (exc_rva && exc_size)
				{
					int count = exc_size / 12;
					if (count > 0 && count <= 500000)
					{
						std::vector<uint8_t> pdata_buf(count * 12);
						if (memory::read(pdata_buf.data(), found_mod->base + exc_rva, pdata_buf.size()))
						{
							pdata_fns.reserve(count);
							for (int i = 0; i < count; i++)
							{
								uint32_t begin = *(uint32_t*)(pdata_buf.data() + i * 12);
								uint32_t end   = *(uint32_t*)(pdata_buf.data() + i * 12 + 4);
								if (begin == 0) continue;
								pdata_fns.push_back({
									found_mod->base + begin,
									found_mod->base + end,
									""
								});
							}
							std::sort(pdata_fns.begin(), pdata_fns.end(),
								[](const pdata_fn_t& a, const pdata_fn_t& b) { return a.va < b.va; });
						}
					}
				}
			}
		}

		// snap each RIP to its containing pdata function (if any)
		std::unordered_set<uint64_t> added_vas;

		for (uint64_t rip : rips)
		{
			uint64_t fn_va = rip; // default: use raw RIP

			if (!pdata_fns.empty())
			{
				// binary search: find largest va <= rip
				auto it = std::upper_bound(pdata_fns.begin(), pdata_fns.end(), rip,
					[](uint64_t v, const pdata_fn_t& f) { return v < f.va; });

				if (it != pdata_fns.begin())
				{
					--it;
					if (rip >= it->va && rip < it->end_va)
						fn_va = it->va; // snap to function start
				}
			}

			if (added_vas.count(fn_va)) continue;
			added_vas.insert(fn_va);

			function_entry_t fn;
			fn.va = fn_va;
			fn.name = widgets::format_address_short(fn_va);

			std::string ename = widgets::resolve_export_name(fn_va);
			if (!ename.empty())
				fn.name = ename;

			// set size from pdata if snapped
			if (fn_va != rip && !pdata_fns.empty())
			{
				for (auto& pf : pdata_fns)
				{
					if (pf.va == fn_va)
					{
						fn.size = (uint32_t)(pf.end_va - pf.va);
						break;
					}
				}
			}

			if (cr3)
			{
				uint64_t gpa = hypercall::translate_guest_virtual_address(fn_va, cr3);
				fn.gpa = gpa ? (gpa & ~0xFFFull) : 0;
			}

			m_functions.push_back(std::move(fn));
		}
	}

	m_trace_gpas.clear();
	m_trace_monitor_ids.clear();
	m_trace_rips.clear();
	m_trace_hit_pages.clear();
	m_trace_pending_unmonitor.clear();
	m_tracing = false;

	rebuild_va_set();
	std::println("[FuncFilter] Trace collected {} unique functions (snapped to pdata)", m_functions.size());
	m_phase = fn_phase_t::loaded;
}

// ---- Deferred page unmonitor (called from render/tick, safe outside callback) ----

void FunctionFilterPanel::process_pending_unmonitor()
{
	if (m_trace_pending_unmonitor.empty()) return;

	for (auto gpa : m_trace_pending_unmonitor)
	{
		hypercall::unmonitor_physical_page(gpa);

		// find and unregister the specific monitor ID for this GPA
		for (size_t i = 0; i < m_trace_gpas.size(); i++)
		{
			if (m_trace_gpas[i] == gpa && i < m_trace_monitor_ids.size())
			{
				app::unregister_page_monitor(m_trace_monitor_ids[i]);
				m_trace_monitor_ids[i] = 0; // mark as unregistered
				break;
			}
		}
	}

	m_trace_pending_unmonitor.clear();

	// remove hit pages from trace_gpas
	std::vector<uint64_t> remaining_gpas;
	std::vector<uint32_t> remaining_ids;
	for (size_t i = 0; i < m_trace_gpas.size(); i++)
	{
		if (m_trace_hit_pages.count(m_trace_gpas[i]) == 0)
		{
			remaining_gpas.push_back(m_trace_gpas[i]);
			if (i < m_trace_monitor_ids.size())
				remaining_ids.push_back(m_trace_monitor_ids[i]);
		}
	}
	m_trace_gpas = std::move(remaining_gpas);
	m_trace_monitor_ids = std::move(remaining_ids);

	// auto-stop when all pages have been hit
	if (m_trace_gpas.empty() && m_tracing)
	{
		std::println("[FuncFilter] Trace: all pages hit, auto-stopping");

		// build functions from collected RIPs (same logic as stop_trace but pages already unregistered)
		uint64_t cr3 = memory::get_cr3();
		m_functions.clear();

		std::vector<uint64_t> rips(m_trace_rips.begin(), m_trace_rips.end());
		std::sort(rips.begin(), rips.end());

		for (uint64_t rip : rips)
		{
			function_entry_t fn;
			fn.va = rip;
			fn.name = widgets::format_address_short(rip);

			if (cr3)
			{
				uint64_t gpa = hypercall::translate_guest_virtual_address(rip, cr3);
				fn.gpa = gpa ? (gpa & ~0xFFFull) : 0;
			}

			m_functions.push_back(std::move(fn));
		}

		m_trace_rips.clear();
		m_trace_hit_pages.clear();
		m_tracing = false;

		rebuild_va_set();
		m_phase = fn_phase_t::loaded;

		std::println("[FuncFilter] Trace auto-completed: {} unique RIPs as functions", m_functions.size());
	}
}

// ---- Register value extraction from trap frame ----

uint64_t FunctionFilterPanel::get_register_value(const trap_frame_log_t& log, int zydis_reg) const
{
	switch (zydis_reg)
	{
	case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_AX: return log.rax;
	case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_CX: return log.rcx;
	case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_DX: return log.rdx;
	case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_BX: return log.rbx;
	case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_SP: return log.rsp;
	case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_BP: return log.rbp;
	case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_SI: return log.rsi;
	case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_DI: return log.rdi;
	case ZYDIS_REGISTER_R8:  case ZYDIS_REGISTER_R8D:  return log.r8;
	case ZYDIS_REGISTER_R9:  case ZYDIS_REGISTER_R9D:  return log.r9;
	case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D: return log.r10;
	case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D: return log.r11;
	case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D: return log.r12;
	case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D: return log.r13;
	case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D: return log.r14;
	case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D: return log.r15;
	case ZYDIS_REGISTER_RIP: return log.rip;
	default: return 0;
	}
}

// ---- Indirect CALL target resolution from trap frame ----

uint64_t FunctionFilterPanel::resolve_indirect_call_target(const trap_frame_log_t& log)
{
	uint8_t code[15] = {};
	if (!memory::read(code, log.rip, sizeof(code)))
		return 0;

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	ZydisDecodedInstruction instr;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

	if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code, sizeof(code), &instr, operands)))
		return 0;

	if (instr.mnemonic != ZYDIS_MNEMONIC_CALL)
		return 0;

	auto& op = operands[0];

	// CALL reg (e.g. call rax)
	if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
		return get_register_value(log, op.reg.value);

	// CALL [mem] (e.g. call [rax+0x18], call [rip+0x1234])
	if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
	{
		uint64_t addr = 0;

		// base register
		if (op.mem.base != ZYDIS_REGISTER_NONE)
		{
			if (op.mem.base == ZYDIS_REGISTER_RIP)
				addr = log.rip + instr.length; // RIP-relative uses next-instruction RIP
			else
				addr = get_register_value(log, op.mem.base);
		}

		// index * scale
		if (op.mem.index != ZYDIS_REGISTER_NONE)
			addr += get_register_value(log, op.mem.index) * op.mem.scale;

		// displacement
		if (op.mem.disp.has_displacement)
			addr += (uint64_t)(int64_t)op.mem.disp.value;

		// read the pointer at computed address -> actual call target
		uint64_t target = 0;
		uint64_t cr3 = memory::get_cr3();
		if (cr3 && addr)
			hypercall::read_guest_virtual_memory(&target, addr, cr3, 8);

		return target;
	}

	// CALL rel32 -- direct call
	if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
	{
		uint64_t target = 0;
		if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &op, log.rip, &target)))
			return target;
	}

	return 0;
}

// ---- EPT Monitoring ----

void FunctionFilterPanel::build_page_map()
{
	m_page_map.clear();
	uint64_t cr3 = memory::get_cr3();

	for (auto& fn : m_functions)
	{
		// ensure GPA is resolved
		if (fn.gpa == 0 && cr3)
		{
			uint64_t gpa = hypercall::translate_guest_virtual_address(fn.va, cr3);
			fn.gpa = gpa ? (gpa & ~0xFFFull) : 0;
		}

		if (fn.gpa == 0) continue;

		// [C1 fix] store VAs instead of indices — stable across sorts
		auto& page = m_page_map[fn.gpa];
		page.gpa = fn.gpa;
		page.fn_vas.push_back(fn.va);
	}
}

void FunctionFilterPanel::start_monitoring()
{
	if (m_monitoring) return;
	if (m_functions.empty()) return;

	build_page_map();
	m_monitoring = true;

	for (auto& [gpa, page] : m_page_map)
	{
		// [C3 fix] store registration ID per page
		page.monitor_id = app::register_page_monitor(gpa, [this](const trap_frame_log_t& log) {
			on_page_hit(log);
		});
		hypercall::monitor_physical_page(gpa);
		page.registered = true;
	}

	m_phase = fn_phase_t::monitoring;
	std::println("[FuncFilter] Started monitoring {} pages for {} functions",
		m_page_map.size(), m_functions.size());
}

void FunctionFilterPanel::stop_monitoring()
{
	if (!m_monitoring) return;

	for (auto& [gpa, page] : m_page_map)
	{
		if (page.registered)
		{
			hypercall::unmonitor_physical_page(gpa);
			// [C3 fix] unregister by ID, not by GPA
			app::unregister_page_monitor(page.monitor_id);
			page.registered = false;
			page.monitor_id = 0;
		}
	}

	m_monitoring = false;
	m_phase = fn_phase_t::loaded;
	std::println("[FuncFilter] Stopped monitoring");
}

void FunctionFilterPanel::on_page_hit(const trap_frame_log_t& log)
{
	// filter by CR3 (only our attached process)
	auto& st = app::state();
	if (st.process_attached && log.cr3 != st.attached_process.cr3)
		return;

	uint64_t cr3 = memory::get_cr3();
	if (!cr3) return;

	uint64_t gpa = hypercall::translate_guest_virtual_address(log.rip, log.cr3);
	if (!gpa) return;

	uint64_t page_gpa = gpa & ~0xFFFull;

	auto it = m_page_map.find(page_gpa);
	if (it == m_page_map.end()) return;

	// [C1 fix] look up functions by VA instead of index
	for (uint64_t fn_va : it->second.fn_vas)
	{
		// find the function entry
		for (auto& fn : m_functions)
		{
			if (fn.va != fn_va) continue;

			if (fn.size > 0)
			{
				// precise: RIP must be within [fn.va, fn.va + fn.size)
				if (log.rip >= fn.va && log.rip < fn.va + fn.size)
					fn.executed = true;
			}
			else
			{
				// no size info: fall back to page-level (mark all)
				fn.executed = true;
			}
			break;
		}
	}

	// resolve indirect CALL targets (vtable calls, call reg, etc.)
	uint64_t call_target = resolve_indirect_call_target(log);
	if (call_target)
	{
		// [I2+I3 fix] O(1) lookup + dedup via m_va_set
		if (m_va_set.count(call_target))
		{
			// already tracked — just mark as executed
			for (auto& fn : m_functions)
			{
				if (fn.va == call_target)
				{
					fn.executed = true;
					break;
				}
			}
		}
		else
		{
			// new target — check if it's in any loaded module
			std::string name;
			uint64_t offset;
			if (widgets::resolve_module(call_target, name, offset))
			{
				uint64_t target_gpa_translated = hypercall::translate_guest_virtual_address(call_target, cr3);
				uint64_t target_page = target_gpa_translated ? (target_gpa_translated & ~0xFFFull) : 0;

				function_entry_t new_fn;
				new_fn.va = call_target;
				new_fn.gpa = target_page;
				new_fn.executed = true;

				std::string ename = widgets::resolve_export_name(call_target);
				new_fn.name = ename.empty() ? widgets::format_address_short(call_target) : ename;

				m_va_set.insert(call_target);
				m_functions.push_back(std::move(new_fn));

				// add to page map if the page is already monitored
				if (target_page)
				{
					auto page_it = m_page_map.find(target_page);
					if (page_it != m_page_map.end())
						page_it->second.fn_vas.push_back(call_target);
				}
			}
		}
	}
}

// ---- Filtering ----

void FunctionFilterPanel::keep_executed()
{
	if (m_monitoring) stop_monitoring();

	m_functions.erase(
		std::remove_if(m_functions.begin(), m_functions.end(),
			[](const function_entry_t& fn) { return !fn.executed; }),
		m_functions.end());

	reset_flags();
	rebuild_va_set();
	std::println("[FuncFilter] Keep executed: {} functions remaining", m_functions.size());
}

void FunctionFilterPanel::remove_executed()
{
	if (m_monitoring) stop_monitoring();

	m_functions.erase(
		std::remove_if(m_functions.begin(), m_functions.end(),
			[](const function_entry_t& fn) { return fn.executed; }),
		m_functions.end());

	reset_flags();
	rebuild_va_set();
	std::println("[FuncFilter] Remove executed: {} functions remaining", m_functions.size());
}

void FunctionFilterPanel::reset_flags()
{
	for (auto& fn : m_functions)
		fn.executed = false;
}

void FunctionFilterPanel::clear_all()
{
	if (m_monitoring) stop_monitoring();
	if (m_tracing) stop_trace();

	m_functions.clear();
	m_page_map.clear();
	m_va_set.clear();
	m_phase = fn_phase_t::idle;
}

int FunctionFilterPanel::count_executed() const
{
	int count = 0;
	for (auto& fn : m_functions)
		if (fn.executed) count++;
	return count;
}

// ---- MCP API ----

void FunctionFilterPanel::api_load(const std::string& module_name, fn_source_t source)
{
	clear_all();

	// find module
	const widgets::module_info_t* found = nullptr;
	std::string target = module_name;
	std::transform(target.begin(), target.end(), target.begin(), ::tolower);

	for (auto& mod : widgets::g_modules)
	{
		std::string mname = mod.name;
		std::transform(mname.begin(), mname.end(), mname.begin(), ::tolower);
		if (mname.find(target) != std::string::npos)
		{
			found = &mod;
			break;
		}
	}

	if (!found) return;

	m_module_name = found->name;
	m_current_source = source;

	switch (source)
	{
	case fn_source_t::pdata:     load_from_pdata(*found); break;
	case fn_source_t::call_scan: load_from_call_scan(*found); break;
	case fn_source_t::trace:     load_from_trace(*found); break;
	case fn_source_t::combined:  load_combined(*found); break;
	}
}

void FunctionFilterPanel::api_start_monitoring()
{
	// if background loading is done, pick up results
	if (m_load_done && !m_load_result.empty())
	{
		if (m_current_source == fn_source_t::combined)
			merge_call_scan_results();
		else
		{
			m_functions = std::move(m_load_result);
			m_load_result.clear();
			m_load_done = false;
			rebuild_va_set();
			m_phase = fn_phase_t::loaded;
		}
	}

	if (m_phase == fn_phase_t::loaded)
		start_monitoring();
}

void FunctionFilterPanel::api_stop_monitoring()
{
	if (m_tracing)
		stop_trace();
	else
		stop_monitoring();
}

void FunctionFilterPanel::api_keep_executed()
{
	keep_executed();
}

void FunctionFilterPanel::api_remove_executed()
{
	remove_executed();
}

std::string FunctionFilterPanel::api_status() const
{
	const char* phase_str = "idle";
	switch (m_phase)
	{
	case fn_phase_t::idle:       phase_str = "idle"; break;
	case fn_phase_t::loading:    phase_str = "loading"; break;
	case fn_phase_t::loaded:     phase_str = "loaded"; break;
	case fn_phase_t::monitoring: phase_str = "monitoring"; break;
	}

	const char* source_str = "combined";
	switch (m_current_source)
	{
	case fn_source_t::pdata:     source_str = "pdata"; break;
	case fn_source_t::call_scan: source_str = "call_scan"; break;
	case fn_source_t::trace:     source_str = "trace"; break;
	case fn_source_t::combined:  source_str = "combined"; break;
	}

	char buf[512];
	snprintf(buf, sizeof(buf),
		"phase=%s, source=%s, module=%s, functions=%d, executed=%d, pages=%d, monitoring=%s, tracing=%s",
		phase_str, source_str, m_module_name.c_str(),
		(int)m_functions.size(), count_executed(), (int)m_page_map.size(),
		m_monitoring ? "true" : "false",
		m_tracing ? "true" : "false");
	return buf;
}

std::vector<function_entry_t> FunctionFilterPanel::api_get_functions(int limit) const
{
	if (limit <= 0 || limit >= (int)m_functions.size())
		return m_functions;
	return std::vector<function_entry_t>(m_functions.begin(), m_functions.begin() + limit);
}

// ---- Render ----

void FunctionFilterPanel::render()
{
	auto& st = app::state();

	if (!st.process_attached)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Attach a process to use Function Filter.");
		return;
	}

	// check if background load finished
	if (m_load_done && !m_load_result.empty())
	{
		if (m_current_source == fn_source_t::combined)
		{
			// combined mode: merge CALL scan results into existing pdata functions
			merge_call_scan_results();
		}
		else
		{
			// standalone call_scan: replace function list
			m_functions = std::move(m_load_result);
			m_load_result.clear();
			m_load_done = false;
			rebuild_va_set();
			m_phase = fn_phase_t::loaded;
		}
	}

	// process deferred unmonitor for trace one-shot pages
	if (m_tracing)
		process_pending_unmonitor();

	// ---- Toolbar row 1: Module + Source + Load ----
	ImGui::Text("Module:");
	ImGui::SameLine();
	ImGui::PushItemWidth(200);
	if (ImGui::BeginCombo("##ff_module",
		(m_selected_module >= 0 && m_selected_module < (int)widgets::g_modules.size())
		? widgets::g_modules[m_selected_module].name.c_str() : "<select>"))
	{
		for (int i = 0; i < (int)widgets::g_modules.size(); i++)
		{
			bool selected = (i == m_selected_module);
			if (ImGui::Selectable(widgets::g_modules[i].name.c_str(), selected))
				m_selected_module = i;
		}
		ImGui::EndCombo();
	}
	ImGui::PopItemWidth();

	ImGui::SameLine(0, 16);
	ImGui::Text("Source:");
	ImGui::SameLine();
	ImGui::RadioButton("Combined", &m_source_radio, 3);
	ImGui::SameLine();
	ImGui::RadioButton("Unwind (.pdata)", &m_source_radio, 0);
	ImGui::SameLine();
	ImGui::RadioButton("CALL Scan", &m_source_radio, 1);
	ImGui::SameLine();
	ImGui::RadioButton("Trace", &m_source_radio, 2);

	ImGui::SameLine(0, 16);

	bool can_load = (m_selected_module >= 0 && m_selected_module < (int)widgets::g_modules.size())
		&& m_phase != fn_phase_t::loading && !m_tracing;

	if (!can_load) ImGui::BeginDisabled();
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.4f, 0.1f, 0.8f));
	if (ImGui::Button("Load Functions", ImVec2(120, 28)))
	{
		clear_all();
		auto& mod = widgets::g_modules[m_selected_module];
		m_module_name = mod.name;
		m_current_source = (fn_source_t)m_source_radio;

		switch (m_current_source)
		{
		case fn_source_t::pdata:     load_from_pdata(mod); break;
		case fn_source_t::call_scan: load_from_call_scan(mod); break;
		case fn_source_t::trace:     load_from_trace(mod); break;
		case fn_source_t::combined:  load_combined(mod); break;
		}
	}
	ImGui::PopStyleColor();
	if (!can_load) ImGui::EndDisabled();

	// ---- Stats row ----
	ImGui::Spacing();

	int exec_count = count_executed();

	ImGui::PushFont(renderer::font_small());
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Functions");
	ImGui::PopFont();
	ImGui::SameLine(0, 6);
	ImGui::Text("%d", (int)m_functions.size());

	ImGui::SameLine(0, 14);
	ImGui::PushFont(renderer::font_small());
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Executed");
	ImGui::PopFont();
	ImGui::SameLine(0, 6);
	if (exec_count > 0)
		ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "%d", exec_count);
	else
		ImGui::Text("0");

	ImGui::SameLine(0, 14);
	ImGui::PushFont(renderer::font_small());
	ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Pages");
	ImGui::PopFont();
	ImGui::SameLine(0, 6);
	ImGui::Text("%d", (int)m_page_map.size());

	if (m_phase == fn_phase_t::loading)
	{
		ImGui::SameLine(0, 14);
		ui::badge("Loading", IM_COL32(40, 100, 180, 200));
	}
	if (m_monitoring)
	{
		ImGui::SameLine(0, 14);
		ui::status_dot(true);
		ImGui::SameLine(0, 2);
		ui::badge("Monitoring", IM_COL32(20, 130, 50, 200));
	}
	if (m_tracing)
	{
		ImGui::SameLine(0, 14);
		ui::status_dot(true);
		ImGui::SameLine(0, 2);
		ui::badge("Tracing", IM_COL32(130, 80, 20, 200));
	}

	// ---- Toolbar row 2: Actions ----
	bool has_functions = !m_functions.empty() && m_phase >= fn_phase_t::loaded;

	if (!m_monitoring && !m_tracing)
	{
		if (!has_functions) ImGui::BeginDisabled();
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.4f, 0.1f, 0.8f));
		if (ImGui::Button("Start Monitoring", ImVec2(130, 28)))
			start_monitoring();
		ImGui::PopStyleColor();
		if (!has_functions) ImGui::EndDisabled();
	}
	else
	{
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.15f, 0.1f, 0.8f));
		if (ImGui::Button("Stop", ImVec2(60, 28)))
		{
			if (m_tracing)
				stop_trace();
			else
				stop_monitoring();
		}
		ImGui::PopStyleColor();
	}

	ImGui::SameLine(0, 8);

	if (!has_functions || exec_count == 0) ImGui::BeginDisabled();
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.15f, 0.35f, 0.55f, 0.9f));
	if (ImGui::Button("Keep Executed", ImVec2(110, 28)))
		keep_executed();
	ImGui::PopStyleColor();
	if (!has_functions || exec_count == 0) ImGui::EndDisabled();

	ImGui::SameLine(0, 4);

	if (!has_functions || exec_count == 0) ImGui::BeginDisabled();
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.55f, 0.35f, 0.15f, 0.9f));
	if (ImGui::Button("Remove Executed", ImVec2(120, 28)))
		remove_executed();
	ImGui::PopStyleColor();
	if (!has_functions || exec_count == 0) ImGui::EndDisabled();

	ImGui::SameLine(0, 4);

	if (!has_functions) ImGui::BeginDisabled();
	if (ImGui::Button("Reset", ImVec2(55, 28)))
		reset_flags();
	if (!has_functions) ImGui::EndDisabled();

	ImGui::SameLine(0, 4);
	if (ImGui::Button("Clear All", ImVec2(70, 28)))
		clear_all();

	ImGui::SameLine(0, 16);
	widgets::filter_bar("##ff_filter", m_filter, 200.0f);

	ImGui::Spacing();

	// ---- Function table ----
	ImGui::PushFont(renderer::font_mono());

	if (ImGui::BeginTable("##ff_table", 3,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable,
		ImVec2(-1, -1)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 180.0f);
		ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Executed", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort, 70.0f);
		ImGui::TableHeadersRow();

		// [C1 fix] build visible indices, then sort the INDICES (not m_functions)
		// This prevents invalidating page_map VA references
		std::vector<int> visible_indices;
		visible_indices.reserve(m_functions.size());
		for (int i = 0; i < (int)m_functions.size(); i++)
		{
			if (m_filter.passes(m_functions[i].name.c_str()))
				visible_indices.push_back(i);
		}

		// sort visible_indices based on sort spec
		if (ImGuiTableSortSpecs* sorts = ImGui::TableGetSortSpecs())
		{
			if (sorts->SpecsDirty && sorts->SpecsCount > 0)
			{
				auto spec = sorts->Specs[0];
				bool asc = (spec.SortDirection == ImGuiSortDirection_Ascending);
				auto& fns = m_functions; // capture ref for lambda
				std::sort(visible_indices.begin(), visible_indices.end(),
					[&fns, &spec, asc](int ia, int ib) {
						auto& a = fns[ia];
						auto& b = fns[ib];
						switch (spec.ColumnIndex)
						{
						case 0: return asc ? (a.va < b.va) : (a.va > b.va);
						case 1: return asc ? (a.name < b.name) : (a.name > b.name);
						case 2: return asc ? (a.executed < b.executed) : (a.executed > b.executed);
						default: return false;
						}
					});
				sorts->SpecsDirty = false;
			}
		}

		ImGuiListClipper clipper;
		clipper.Begin((int)visible_indices.size());
		while (clipper.Step())
		{
			for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++)
			{
				int i = visible_indices[row];
				auto& fn = m_functions[i];

				ImGui::TableNextRow();

				// address
				ImGui::TableNextColumn();
				char addr_buf[32];
				snprintf(addr_buf, sizeof(addr_buf), "0x%llX##ff%d", fn.va, i);

				if (fn.executed)
					ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(255, 107, 0, 25));

				ImGui::Selectable(addr_buf, false, ImGuiSelectableFlags_SpanAllColumns);

				if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0))
					app::navigate_to_address(fn.va, tab_id::disassembler);

				if (ImGui::BeginPopupContextItem())
				{
					if (ImGui::MenuItem("View in Disasm"))
						app::navigate_to_address(fn.va, tab_id::disassembler);
					if (ImGui::MenuItem("View in Memory"))
						app::navigate_to_address(fn.va, tab_id::memory_viewer);
					if (ImGui::MenuItem("Add Breakpoint"))
						app::add_breakpoint_from_disasm(fn.va);
					ImGui::Separator();
					if (ImGui::MenuItem("Copy Address"))
					{
						char buf[32];
						snprintf(buf, sizeof(buf), "0x%llX", fn.va);
						ui::clipboard(buf, "Address copied");
					}
					ImGui::EndPopup();
				}

				// name
				ImGui::TableNextColumn();
				ImGui::Text("%s", fn.name.c_str());

				// executed
				ImGui::TableNextColumn();
				if (fn.executed)
					ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "*");
			}
		}

		ImGui::EndTable();
	}

	ImGui::PopFont();
}

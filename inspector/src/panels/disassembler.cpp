#include "disassembler.h"
#include "../app.h"
#include "../renderer/renderer.h"
#include "../memory/memory_reader.h"
#include "../widgets/address_input.h"
#include "../widgets/module_resolver.h"
#include <Zydis/Zydis.h>
#include <cstdio>
#include <cstring>
#include <cctype>
#include <algorithm>

std::string DisassemblerPanel::try_read_string(uint64_t address, int max_len)
{
	if (address == 0) return {};

	char buf[128] = {};
	int read_len = max_len < (int)sizeof(buf) ? max_len : (int)sizeof(buf) - 1;
	if (!memory::read(buf, address, read_len))
		return {};

	int len = 0;
	for (int i = 0; i < read_len; i++)
	{
		if (buf[i] == '\0') break;
		if (buf[i] < 0x20 || buf[i] > 0x7E)
			return {};
		len++;
	}

	if (len >= 4)
		return std::string(buf, len);

	return {};
}

// ---- Tokenizer for syntax coloring ----

static bool is_register_name(const char* s, int len)
{
	static const char* regs[] = {
		"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
		"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip",
		"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
		"ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
		"r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
		"al", "bl", "cl", "dl", "sil", "dil", "spl", "bpl",
		"r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
		"ah", "bh", "ch", "dh",
		"cs", "ds", "es", "fs", "gs", "ss",
		"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
		"xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
		"ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
		"ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
		"cr0", "cr2", "cr3", "cr4", "cr8",
		"dr0", "dr1", "dr2", "dr3", "dr6", "dr7",
		"st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
		nullptr
	};

	for (int i = 0; regs[i]; i++)
	{
		int rlen = (int)strlen(regs[i]);
		if (rlen == len)
		{
			bool match = true;
			for (int j = 0; j < len; j++)
			{
				if (tolower(s[j]) != regs[i][j])
				{
					match = false;
					break;
				}
			}
			if (match) return true;
		}
	}
	return false;
}

std::vector<DisassemblerPanel::operand_token_t> DisassemblerPanel::tokenize_operands(const char* ops)
{
	std::vector<operand_token_t> tokens;
	if (!ops || !ops[0]) return tokens;

	const char* p = ops;
	while (*p)
	{
		if (*p == ' ')
		{
			tokens.push_back({ token_type_t::text, " " });
			p++;
			continue;
		}

		if (*p == '[' || *p == ']')
		{
			tokens.push_back({ token_type_t::mem_bracket, std::string(1, *p) });
			p++;
			continue;
		}

		if (*p == ',')
		{
			tokens.push_back({ token_type_t::comma, "," });
			p++;
			continue;
		}

		if (*p == '+' || *p == '-' || *p == '*')
		{
			tokens.push_back({ token_type_t::plus, std::string(1, *p) });
			p++;
			continue;
		}

		if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
		{
			const char* start = p;
			p += 2;
			while (isxdigit(*p)) p++;
			tokens.push_back({ token_type_t::imm, std::string(start, p - start) });
			continue;
		}

		if (isdigit(*p))
		{
			const char* start = p;
			while (isxdigit(*p)) p++;
			if (*p == 'h' || *p == 'H')
			{
				p++;
				tokens.push_back({ token_type_t::imm, std::string(start, p - start) });
			}
			else
			{
				tokens.push_back({ token_type_t::imm, std::string(start, p - start) });
			}
			continue;
		}

		if (isalpha(*p) || *p == '_')
		{
			const char* start = p;
			while (isalnum(*p) || *p == '_') p++;
			int len = (int)(p - start);

			if (is_register_name(start, len))
				tokens.push_back({ token_type_t::reg, std::string(start, len) });
			else
				tokens.push_back({ token_type_t::text, std::string(start, len) });
			continue;
		}

		tokens.push_back({ token_type_t::text, std::string(1, *p) });
		p++;
	}

	return tokens;
}

// ---- Core decode logic ----

static void decode_instructions(uint8_t* code, size_t code_size, uint64_t base_address,
	int max_instructions, std::vector<DisassemblerPanel::disasm_line_t>& out_lines,
	uint64_t& out_end_address, bool& out_at_end)
{
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	size_t offset = 0;
	int count = 0;

	while (offset < code_size && count < max_instructions)
	{
		DisassemblerPanel::disasm_line_t line = {};

		if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
			code + offset, code_size - offset,
			&instruction, operands)))
		{
			line.address = base_address + offset;
			line.length = instruction.length;
			memcpy(line.bytes, code + offset, instruction.length);

			ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
				instruction.operand_count, line.operands, sizeof(line.operands),
				line.address, nullptr);

			const char* mnemonic_str = ZydisMnemonicGetString(instruction.mnemonic);
			if (mnemonic_str)
				strncpy(line.mnemonic, mnemonic_str, sizeof(line.mnemonic) - 1);

			line.is_call = (instruction.mnemonic == ZYDIS_MNEMONIC_CALL);
			line.is_jmp = (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
				instruction.meta.category == ZYDIS_CATEGORY_COND_BR);
			line.is_ret = (instruction.mnemonic == ZYDIS_MNEMONIC_RET);
			line.is_nop = (instruction.mnemonic == ZYDIS_MNEMONIC_NOP);

			line.branch_target = 0;
			line.mem_target = 0;

			if (line.is_call || line.is_jmp)
			{
				ZyanU64 result_addr = 0;
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[0],
					line.address, &result_addr)))
				{
					line.branch_target = result_addr;
				}
			}

			for (int op = 0; op < instruction.operand_count; op++)
			{
				if (operands[op].type == ZYDIS_OPERAND_TYPE_MEMORY &&
					operands[op].mem.base == ZYDIS_REGISTER_RIP)
				{
					ZyanU64 result_addr = 0;
					if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[op],
						line.address, &result_addr)))
					{
						line.mem_target = result_addr;
					}
				}
				if (operands[op].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
					operands[op].imm.is_relative == ZYAN_FALSE &&
					!line.is_call && !line.is_jmp)
				{
					uint64_t imm_val = operands[op].imm.value.u;
					if (imm_val > 0x10000 && imm_val < 0x7FFFFFFFFFFF)
					{
						std::string name;
						uint64_t mod_off;
						if (widgets::resolve_module(imm_val, name, mod_off))
							line.mem_target = imm_val;
					}
				}
			}

			// --- Build formatted operands (CE-style: module-relative addresses) ---
			if (line.branch_target)
			{
				line.operands_fmt = widgets::format_address_short(line.branch_target);
			}
			else if (line.mem_target)
			{
				std::string ops_str(line.operands);
				std::string target_fmt = widgets::format_address_short(line.mem_target);

				char hex_buf[24];
				snprintf(hex_buf, sizeof(hex_buf), "0x%016llX", line.mem_target);
				std::string hex_str(hex_buf);

				size_t pos = ops_str.find(hex_str);
				if (pos != std::string::npos)
				{
					ops_str.replace(pos, hex_str.length(), "[" + target_fmt + "]");
					line.operands_fmt = ops_str;
				}
				else
				{
					line.operands_fmt = ops_str;
				}
			}
			else
			{
				line.operands_fmt = line.operands;
			}

			if (!line.branch_target)
				line.tokens = DisassemblerPanel::tokenize_operands(line.operands_fmt.c_str());

			offset += instruction.length;
		}
		else
		{
			line.address = base_address + offset;
			line.length = 1;
			line.bytes[0] = code[offset];
			strncpy(line.mnemonic, "db", sizeof(line.mnemonic));
			snprintf(line.operands, sizeof(line.operands), "0x%02X", code[offset]);
			line.operands_fmt = line.operands;
			line.tokens = DisassemblerPanel::tokenize_operands(line.operands_fmt.c_str());
			offset++;
		}

		out_lines.push_back(std::move(line));
		count++;
	}

	out_end_address = base_address + offset;
	out_at_end = (offset >= code_size && count < max_instructions);
}

// ---- Comment resolution (CE-style) ----

void DisassemblerPanel::resolve_comments(size_t start_idx, size_t end_idx)
{
	for (size_t i = start_idx; i < end_idx && i < m_lines.size(); i++)
	{
		auto& line = m_lines[i];
		uint64_t comment_addr = line.branch_target ? line.branch_target : line.mem_target;
		if (!comment_addr)
			continue;

		// Memory operand (non-branch): CE-style { (hex),decimal } or { ("string") }
		if (line.mem_target && !line.is_call && !line.is_jmp)
		{
			std::string str_val = try_read_string(line.mem_target);
			if (!str_val.empty())
			{
				line.comment = "{ (\"" + str_val + "\") }";
			}
			else
			{
				uint64_t val = 0;
				if (memory::read(&val, line.mem_target, 8))
				{
					// check if value resolves to a module address
					std::string mod_name;
					uint64_t mod_off;
					if (widgets::resolve_module(val, mod_name, mod_off))
					{
						char buf[256];
						snprintf(buf, sizeof(buf), "{ ->%s+0x%llX }", mod_name.c_str(), mod_off);
						line.comment = buf;
					}
					else
					{
						// CE-style: { (hex),decimal }
						char buf[64];
						int32_t val32;
						memcpy(&val32, &val, 4);
						if (val <= 0xFFFFFFFF)
							snprintf(buf, sizeof(buf), "{ (%08llX),%d }", val, val32);
						else
							snprintf(buf, sizeof(buf), "{ (%016llX),%llu }", val, val);
						line.comment = buf;
					}
				}
			}
		}

		// Indirect call/jmp through memory (e.g., call [rip+xx])
		if (line.mem_target && (line.is_call || line.is_jmp) && !line.branch_target)
		{
			uint64_t indirect_target = 0;
			memory::read(&indirect_target, line.mem_target, 8);
			if (indirect_target)
			{
				std::string name;
				uint64_t off;
				if (widgets::resolve_module(indirect_target, name, off))
				{
					// Try to find export name
					std::string export_name = widgets::resolve_export_name(indirect_target);
					if (!export_name.empty())
						line.comment = "{ ->" + name + "." + export_name + " }";
					else
					{
						char buf[256];
						snprintf(buf, sizeof(buf), "{ ->%s+0x%llX }", name.c_str(), off);
						line.comment = buf;
					}
				}
				else
				{
					char buf[32];
					snprintf(buf, sizeof(buf), "{ ->0x%llX }", indirect_target);
					line.comment = buf;
				}
			}
		}

		// Direct call through thunk (call rel32 -> jmp [IAT])
		if (line.branch_target && line.is_call)
		{
			uint8_t thunk[6] = {};
			if (memory::read(thunk, line.branch_target, 6))
			{
				if (thunk[0] == 0xFF && thunk[1] == 0x25)
				{
					int32_t disp = 0;
					memcpy(&disp, thunk + 2, 4);
					uint64_t iat_addr = line.branch_target + 6 + disp;
					uint64_t import_addr = 0;
					memory::read(&import_addr, iat_addr, 8);
					if (import_addr)
					{
						std::string name;
						uint64_t off;
						if (widgets::resolve_module(import_addr, name, off))
						{
							std::string export_name = widgets::resolve_export_name(import_addr);
							if (!export_name.empty())
								line.comment = "{ ->->" + name + "." + export_name + " }";
							else
							{
								char buf[256];
								snprintf(buf, sizeof(buf), "{ ->->%s+0x%llX }", name.c_str(), off);
								line.comment = buf;
							}
						}
						else
						{
							char buf[32];
							snprintf(buf, sizeof(buf), "{ ->->0x%llX }", import_addr);
							line.comment = buf;
						}
					}
				}
			}
		}
	}
}

// ---- Navigation history ----

void DisassemblerPanel::navigate_to(uint64_t addr)
{
	// truncate forward entries
	if (m_nav_index >= 0 && m_nav_index < (int)m_nav_history.size() - 1)
		m_nav_history.resize(m_nav_index + 1);

	m_nav_history.push_back(addr);
	m_nav_index = (int)m_nav_history.size() - 1;

	// cap history size
	if (m_nav_history.size() > 100)
	{
		m_nav_history.erase(m_nav_history.begin());
		m_nav_index--;
	}

	disassemble_at(addr);
	m_selected_line = 0;
	m_scroll_to_top = true;
}

void DisassemblerPanel::go_back()
{
	if (m_nav_index > 0)
	{
		m_nav_index--;
		disassemble_at(m_nav_history[m_nav_index]);
		m_selected_line = 0;
		m_scroll_to_top = true;
	}
}

void DisassemblerPanel::go_forward()
{
	if (m_nav_index < (int)m_nav_history.size() - 1)
	{
		m_nav_index++;
		disassemble_at(m_nav_history[m_nav_index]);
		m_selected_line = 0;
		m_scroll_to_top = true;
	}
}

// ---- Core functions ----

void DisassemblerPanel::disassemble_at(uint64_t address, int max_instructions)
{
	m_lines.clear();
	m_base_address = address;
	m_decode_start_address = address;
	m_at_end = false;
	m_at_start = false;

	uint8_t code[4096] = {};
	if (!memory::read(code, address, sizeof(code)))
	{
		m_at_end = true;
		m_at_start = true;
		return;
	}

	decode_instructions(code, sizeof(code), address, max_instructions, m_lines,
		m_decode_end_address, m_at_end);

	resolve_comments(0, m_lines.size());
}

void DisassemblerPanel::decode_forward(int count)
{
	if (m_at_end || m_decode_end_address == 0) return;

	uint8_t code[4096] = {};
	if (!memory::read(code, m_decode_end_address, sizeof(code)))
	{
		m_at_end = true;
		return;
	}

	size_t old_size = m_lines.size();
	bool at_end = false;
	uint64_t end_addr = 0;

	decode_instructions(code, sizeof(code), m_decode_end_address, count, m_lines, end_addr, at_end);

	m_decode_end_address = end_addr;
	m_at_end = at_end;

	resolve_comments(old_size, m_lines.size());
}

void DisassemblerPanel::decode_backward(int count)
{
	if (m_at_start || m_decode_start_address == 0) return;

	// read count*15 bytes before our start (max x86 instruction size = 15)
	uint64_t read_size = (uint64_t)count * 15;
	if (read_size > m_decode_start_address)
		read_size = m_decode_start_address;

	uint64_t read_addr = m_decode_start_address - read_size;

	std::vector<uint8_t> code(read_size);
	if (!memory::read(code.data(), read_addr, (int)read_size))
	{
		m_at_start = true;
		return;
	}

	// decode forward from read_addr, stop when we reach m_decode_start_address
	std::vector<disasm_line_t> new_lines;
	uint64_t end_addr = 0;
	bool at_end = false;

	decode_instructions(code.data(), (size_t)read_size, read_addr,
		count * 2, new_lines, end_addr, at_end);

	// filter: only keep lines before m_decode_start_address
	std::vector<disasm_line_t> prepend_lines;
	for (auto& line : new_lines)
	{
		if (line.address >= m_decode_start_address)
			break;
		prepend_lines.push_back(std::move(line));
	}

	if (prepend_lines.empty())
	{
		m_at_start = true;
		return;
	}

	// resolve comments for the new lines
	size_t prepend_count = prepend_lines.size();

	// prepend to m_lines
	m_lines.insert(m_lines.begin(), prepend_lines.begin(), prepend_lines.end());
	m_decode_start_address = m_lines.front().address;

	resolve_comments(0, prepend_count);

	// adjust selected line index
	if (m_selected_line >= 0)
		m_selected_line += (int)prepend_count;

	// check if we can go further back
	if (read_addr == 0)
		m_at_start = true;
}

// ---- Signature maker ----

void DisassemblerPanel::build_signature()
{
	if (m_sig_start_line < 0 || m_sig_end_line < 0) return;

	int start = (std::min)(m_sig_start_line, m_sig_end_line);
	int end = (std::max)(m_sig_start_line, m_sig_end_line);
	if (start >= (int)m_lines.size() || end >= (int)m_lines.size()) return;

	// decode each instruction with Zydis to find relocatable bytes
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	m_sig_pattern.clear();

	for (int i = start; i <= end; i++)
	{
		auto& line = m_lines[i];

		ZydisDecodedInstruction instruction;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

		bool decoded = ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
			line.bytes, line.length, &instruction, operands));

		// determine which byte ranges to wildcard
		bool wildcard[15] = {};

		if (decoded)
		{
			// wildcard relative immediates
			for (int imm_idx = 0; imm_idx < 2; imm_idx++)
			{
				if (instruction.raw.imm[imm_idx].size > 0 && instruction.raw.imm[imm_idx].is_relative)
				{
					int off = instruction.raw.imm[imm_idx].offset;
					int sz = instruction.raw.imm[imm_idx].size / 8;
					for (int b = 0; b < sz && off + b < line.length; b++)
						wildcard[off + b] = true;
				}
			}

			// wildcard displacements for RIP-relative addressing
			if (instruction.raw.disp.size > 0)
			{
				// check if any operand is RIP-relative
				bool rip_relative = false;
				for (int op = 0; op < instruction.operand_count; op++)
				{
					if (operands[op].type == ZYDIS_OPERAND_TYPE_MEMORY &&
						operands[op].mem.base == ZYDIS_REGISTER_RIP)
					{
						rip_relative = true;
						break;
					}
				}
				if (rip_relative)
				{
					int off = instruction.raw.disp.offset;
					int sz = instruction.raw.disp.size / 8;
					for (int b = 0; b < sz && off + b < line.length; b++)
						wildcard[off + b] = true;
				}
			}
		}

		for (int j = 0; j < line.length; j++)
		{
			if (!m_sig_pattern.empty())
				m_sig_pattern += " ";

			if (wildcard[j])
				m_sig_pattern += "??";
			else
			{
				char hex[4];
				snprintf(hex, sizeof(hex), "%02X", line.bytes[j]);
				m_sig_pattern += hex;
			}
		}
	}

	// verify uniqueness: scan all loaded modules
	m_sig_match_count = 0;

	// parse the pattern for scanning
	std::vector<uint8_t> pat;
	std::vector<bool> mask;
	{
		std::string token;
		for (size_t ci = 0; ci <= m_sig_pattern.size(); ci++)
		{
			char c = ci < m_sig_pattern.size() ? m_sig_pattern[ci] : ' ';
			if (c == ' ' || ci == m_sig_pattern.size())
			{
				if (!token.empty())
				{
					if (token == "??")
					{
						pat.push_back(0);
						mask.push_back(false);
					}
					else
					{
						pat.push_back((uint8_t)strtoul(token.c_str(), nullptr, 16));
						mask.push_back(true);
					}
					token.clear();
				}
			}
			else
			{
				token += c;
			}
		}
	}

	if (pat.empty()) return;

	for (auto& mod : widgets::g_modules)
	{
		std::vector<uint8_t> mod_data(mod.size);
		if (!memory::read(mod_data.data(), mod.base, mod.size))
			continue;

		for (size_t off = 0; off + pat.size() <= mod.size; off++)
		{
			bool match = true;
			for (size_t j = 0; j < pat.size() && match; j++)
			{
				if (mask[j] && mod_data[off + j] != pat[j])
					match = false;
			}
			if (match)
				m_sig_match_count++;
		}
	}

	m_show_sig_modal = true;
}

// ---- Render colored tokens ----
static void render_tokens(const std::vector<DisassemblerPanel::operand_token_t>& tokens)
{
	for (int t = 0; t < (int)tokens.size(); t++)
	{
		if (t > 0) ImGui::SameLine(0, 0);

		ImVec4 color;
		switch (tokens[t].type)
		{
		case DisassemblerPanel::token_type_t::reg:
			color = ImVec4(0.4f, 0.85f, 0.9f, 1.0f);
			break;
		case DisassemblerPanel::token_type_t::imm:
			color = ImVec4(0.9f, 0.85f, 0.4f, 1.0f);
			break;
		case DisassemblerPanel::token_type_t::mem_bracket:
			color = ImVec4(1.0f, 0.42f, 0.0f, 1.0f);
			break;
		case DisassemblerPanel::token_type_t::comma:
		case DisassemblerPanel::token_type_t::plus:
			color = ImVec4(0.6f, 0.6f, 0.65f, 1.0f);
			break;
		default:
			color = ImVec4(0.92f, 0.92f, 0.94f, 1.0f);
			break;
		}

		ImGui::TextColored(color, "%s", tokens[t].text.c_str());
	}
}

void DisassemblerPanel::render()
{
	auto& st = app::state();

	if (!st.process_attached)
	{
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Attach a process to use the disassembler.");
		return;
	}

	if (!m_initialized)
	{
		m_goto_address = st.attached_process.base_address;
		navigate_to(m_goto_address);
		m_initialized = true;
	}

	// handle goto from other panels
	if (st.goto_address_pending && st.goto_tab == tab_id::disassembler)
	{
		st.goto_address_pending = false;
		m_goto_address = st.goto_address;
		navigate_to(m_goto_address);
	}

	// handle pending AOB pattern from sig maker
	if (!app::pending_aob_pattern().empty())
	{
		// the scanner will pick this up
	}

	// toolbar
	// back/forward buttons
	bool can_back = (m_nav_index > 0);
	bool can_fwd = (m_nav_index < (int)m_nav_history.size() - 1);

	if (!can_back) ImGui::BeginDisabled();
	if (ImGui::ArrowButton("##back", ImGuiDir_Left))
		go_back();
	if (!can_back) ImGui::EndDisabled();

	ImGui::SameLine();

	if (!can_fwd) ImGui::BeginDisabled();
	if (ImGui::ArrowButton("##fwd", ImGuiDir_Right))
		go_forward();
	if (!can_fwd) ImGui::EndDisabled();

	ImGui::SameLine(0, 12);
	ImGui::Text("Address:");
	ImGui::SameLine();

	if (widgets::address_input("##disasm_goto", m_goto_address, 200.0f))
		navigate_to(m_goto_address);

	ImGui::SameLine(0, 16);
	if (ImGui::Button("Go to Entry", ImVec2(0, 28)))
	{
		m_goto_address = st.attached_process.base_address;
		navigate_to(m_goto_address);
	}

	ImGui::SameLine(0, 8);
	if (ImGui::Button("Refresh", ImVec2(0, 28)))
		disassemble_at(m_base_address);

	// sig maker selection indicator
	if (m_sig_start_line >= 0 && m_sig_end_line >= 0)
	{
		ImGui::SameLine(0, 16);
		int s = (std::min)(m_sig_start_line, m_sig_end_line);
		int e = (std::max)(m_sig_start_line, m_sig_end_line);
		ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f),
			"Sig: %d instructions", e - s + 1);

		ImGui::SameLine(0, 8);
		if (ImGui::Button("Make Sig", ImVec2(0, 28)))
			build_signature();

		ImGui::SameLine(0, 4);
		if (ImGui::Button("Clear Sel", ImVec2(0, 28)))
		{
			m_sig_start_line = -1;
			m_sig_end_line = -1;
		}
	}

	ImGui::Spacing();

	// disassembly view
	ImGui::PushFont(renderer::font_mono());

	if (ImGui::BeginTable("##disasm", 5,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
		ImVec2(-1, -1)))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 180.0f);
		ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 160.0f);
		ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthFixed, 260.0f);
		ImGui::TableSetupColumn("Comment", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableHeadersRow();

		// scroll-to-top after goto
		if (m_scroll_to_top)
		{
			ImGui::SetScrollY(0);
			m_scroll_to_top = false;
		}

		for (int i = 0; i < (int)m_lines.size(); i++)
		{
			auto& line = m_lines[i];
			ImGui::TableNextRow();

			bool is_selected = (i == m_selected_line);

			// highlight sig selection range
			bool in_sig_range = false;
			if (m_sig_start_line >= 0 && m_sig_end_line >= 0)
			{
				int s = (std::min)(m_sig_start_line, m_sig_end_line);
				int e = (std::max)(m_sig_start_line, m_sig_end_line);
				in_sig_range = (i >= s && i <= e);
			}

			if (in_sig_range)
				ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(255, 107, 0, 30));

			// address column
			ImGui::TableNextColumn();
			std::string mod_addr = widgets::format_address_short(line.address);
			char addr_label[280];
			snprintf(addr_label, sizeof(addr_label), "%s##d%d", mod_addr.c_str(), i);

			if (ImGui::Selectable(addr_label, is_selected,
				ImGuiSelectableFlags_SpanAllColumns))
			{
				// shift+click for sig range selection
				if (ImGui::GetIO().KeyShift && m_selected_line >= 0)
				{
					if (m_sig_start_line < 0)
						m_sig_start_line = m_selected_line;
					m_sig_end_line = i;
				}
				m_selected_line = i;
			}

			// context menu
			if (ImGui::BeginPopupContextItem())
			{
				if (ImGui::MenuItem("Go to Address..."))
				{
					m_show_goto_modal = true;
					m_goto_modal_buf[0] = '\0';
				}

				if (ImGui::MenuItem("View in Memory"))
					app::navigate_to_address(line.address, tab_id::memory_viewer);

				if (line.branch_target && ImGui::MenuItem("Follow Branch"))
				{
					m_goto_address = line.branch_target;
					navigate_to(line.branch_target);
					ImGui::EndPopup();
					ImGui::EndTable();
					ImGui::PopFont();
					return;
				}

				if (line.branch_target && ImGui::MenuItem("Follow in Memory"))
					app::navigate_to_address(line.branch_target, tab_id::memory_viewer);

				if (line.mem_target && ImGui::MenuItem("View Target in Memory"))
					app::navigate_to_address(line.mem_target, tab_id::memory_viewer);

				ImGui::Separator();

				if (ImGui::MenuItem("Add Breakpoint"))
					app::add_breakpoint_from_disasm(line.address);

				ImGui::Separator();

				if (ImGui::MenuItem("Copy Address"))
				{
					char buf[32];
					snprintf(buf, sizeof(buf), "0x%llX", line.address);
					ImGui::SetClipboardText(buf);
				}
				if (ImGui::MenuItem("Copy Module+Offset"))
					ImGui::SetClipboardText(mod_addr.c_str());

				if (ImGui::MenuItem("Copy Line"))
				{
					// format: "address bytes mnemonic operands ; comment"
					char bytes_str[48] = {};
					int bpos = 0;
					for (int j = 0; j < line.length && bpos < 45; j++)
						bpos += snprintf(bytes_str + bpos, sizeof(bytes_str) - bpos, "%02X ", line.bytes[j]);

					std::string full_line = mod_addr + "  " + bytes_str + " " + line.mnemonic + " " + line.operands_fmt;
					if (!line.comment.empty())
						full_line += " ; " + line.comment;

					ImGui::SetClipboardText(full_line.c_str());
				}

				if (ImGui::MenuItem("Copy Bytes"))
				{
					std::string hex;
					for (int j = 0; j < line.length; j++)
					{
						if (j > 0) hex += " ";
						char hb[4];
						snprintf(hb, sizeof(hb), "%02X", line.bytes[j]);
						hex += hb;
					}
					ImGui::SetClipboardText(hex.c_str());
				}

				if (ImGui::MenuItem("Make Signature"))
				{
					if (m_sig_start_line < 0)
					{
						m_sig_start_line = i;
						m_sig_end_line = i;
					}
					build_signature();
				}

				ImGui::Separator();

				if (ImGui::MenuItem("Edit Instruction..."))
				{
					m_edit_line_idx = i;
					m_edit_address = line.address;
					m_edit_original_length = line.length;
					// pre-fill with current bytes
					m_edit_bytes_buf[0] = '\0';
					int bp = 0;
					for (int j = 0; j < line.length; j++)
					{
						if (j > 0) bp += snprintf(m_edit_bytes_buf + bp, sizeof(m_edit_bytes_buf) - bp, " ");
						bp += snprintf(m_edit_bytes_buf + bp, sizeof(m_edit_bytes_buf) - bp, "%02X", line.bytes[j]);
					}
					m_edit_nop_fill = true;
					m_show_edit_modal = true;
				}

				ImGui::EndPopup();
			}

			// bytes
			ImGui::TableNextColumn();
			char bytes_buf[48] = {};
			int pos = 0;
			for (int j = 0; j < line.length && pos < 45; j++)
				pos += snprintf(bytes_buf + pos, sizeof(bytes_buf) - pos, "%02X ", line.bytes[j]);
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "%s", bytes_buf);

			// mnemonic — double-click to edit instruction
			ImGui::TableNextColumn();
			ImVec4 mnemonic_color(0.92f, 0.92f, 0.94f, 1.0f);
			if (line.is_call) mnemonic_color = ImVec4(0.4f, 0.7f, 1.0f, 1.0f);
			else if (line.is_jmp) mnemonic_color = ImVec4(0.3f, 0.9f, 0.4f, 1.0f);
			else if (line.is_ret) mnemonic_color = ImVec4(0.9f, 0.3f, 0.3f, 1.0f);
			else if (line.is_nop) mnemonic_color = ImVec4(0.45f, 0.45f, 0.50f, 1.0f);

			ImGui::TextColored(mnemonic_color, "%s", line.mnemonic);
			if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0))
			{
				m_edit_line_idx = i;
				m_edit_address = line.address;
				m_edit_original_length = line.length;
				m_edit_bytes_buf[0] = '\0';
				int bp2 = 0;
				for (int j = 0; j < line.length; j++)
				{
					if (j > 0) bp2 += snprintf(m_edit_bytes_buf + bp2, sizeof(m_edit_bytes_buf) - bp2, " ");
					bp2 += snprintf(m_edit_bytes_buf + bp2, sizeof(m_edit_bytes_buf) - bp2, "%02X", line.bytes[j]);
				}
				m_edit_nop_fill = true;
				m_show_edit_modal = true;
			}

			// operands — double-click to edit instruction
			ImGui::TableNextColumn();

			if (line.branch_target)
			{
				std::string target_str = widgets::format_address_short(line.branch_target);
				char target_label[280];
				snprintf(target_label, sizeof(target_label), "%s##t%d", target_str.c_str(), i);

				ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.6f, 1.0f, 1.0f));
				if (ImGui::Selectable(target_label, false, ImGuiSelectableFlags_None,
					ImGui::CalcTextSize(target_str.c_str())))
				{
					m_goto_address = line.branch_target;
					navigate_to(line.branch_target);
					ImGui::PopStyleColor();
					ImGui::EndTable();
					ImGui::PopFont();
					return;
				}
				ImGui::PopStyleColor();
			}
			else if (!line.tokens.empty())
			{
				render_tokens(line.tokens);
				// double-click on operands to edit
				if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0))
				{
					m_edit_line_idx = i;
					m_edit_address = line.address;
					m_edit_original_length = line.length;
					m_edit_bytes_buf[0] = '\0';
					int bp3 = 0;
					for (int j = 0; j < line.length; j++)
					{
						if (j > 0) bp3 += snprintf(m_edit_bytes_buf + bp3, sizeof(m_edit_bytes_buf) - bp3, " ");
						bp3 += snprintf(m_edit_bytes_buf + bp3, sizeof(m_edit_bytes_buf) - bp3, "%02X", line.bytes[j]);
					}
					m_edit_nop_fill = true;
					m_show_edit_modal = true;
				}
			}
			else
			{
				ImGui::Text("%s", line.operands_fmt.c_str());
			}

			// comment column
			ImGui::TableNextColumn();
			if (!line.comment.empty())
			{
				ImGui::TextColored(ImVec4(0.4f, 0.75f, 0.4f, 1.0f), "%s", line.comment.c_str());
			}
		}

		// bidirectional infinite scroll
		if (ImGui::GetScrollY() <= 10.0f && !m_at_start && !m_lines.empty())
		{
			float old_scroll = ImGui::GetScrollY();
			size_t old_count = m_lines.size();
			decode_backward(200);
			size_t added = m_lines.size() - old_count;
			if (added > 0)
			{
				float row_height = ImGui::GetTextLineHeightWithSpacing();
				ImGui::SetScrollY(old_scroll + (float)added * row_height);
			}
		}

		if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 50.0f && !m_at_end && !m_lines.empty())
			decode_forward(200);

		ImGui::EndTable();
	}

	ImGui::PopFont();

	// ---- Go to Address modal ----
	if (m_show_goto_modal)
	{
		ImGui::OpenPopup("Go to Address##disasm_goto_modal");
		m_show_goto_modal = false;
	}

	ImVec2 center = ImGui::GetMainViewport()->GetCenter();
	ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
	if (ImGui::BeginPopupModal("Go to Address##disasm_goto_modal", nullptr,
		ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Enter address (hex):");
		ImGui::PushItemWidth(200);
		bool enter = ImGui::InputText("##goto_addr_input", m_goto_modal_buf,
			sizeof(m_goto_modal_buf),
			ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue);
		ImGui::PopItemWidth();

		ImGui::SameLine(0, 8);
		if (ImGui::Button("Go", ImVec2(60, 0)) || enter)
		{
			uint64_t addr = strtoull(m_goto_modal_buf, nullptr, 16);
			if (addr)
			{
				m_goto_address = addr;
				navigate_to(addr);
			}
			ImGui::CloseCurrentPopup();
		}

		ImGui::SameLine(0, 4);
		if (ImGui::Button("Cancel", ImVec2(60, 0)))
			ImGui::CloseCurrentPopup();

		ImGui::EndPopup();
	}

	// ---- Signature maker modal ----
	if (m_show_sig_modal)
	{
		ImGui::OpenPopup("Signature##sig_modal");
		m_show_sig_modal = false;
	}

	ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
	ImGui::SetNextWindowSize(ImVec2(600, 0), ImGuiCond_Appearing);
	if (ImGui::BeginPopupModal("Signature##sig_modal", nullptr,
		ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("AOB Pattern:");
		ImGui::PushFont(renderer::font_mono());
		ImGui::TextWrapped("%s", m_sig_pattern.c_str());
		ImGui::PopFont();

		ImGui::Spacing();

		if (m_sig_match_count >= 0)
		{
			ImVec4 count_color = (m_sig_match_count == 1)
				? ImVec4(0.3f, 0.9f, 0.4f, 1.0f)
				: ImVec4(0.9f, 0.3f, 0.3f, 1.0f);
			ImGui::TextColored(count_color, "Matches: %d", m_sig_match_count);
			if (m_sig_match_count == 1)
				ImGui::SameLine(), ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.4f, 1.0f), "(unique)");
		}

		ImGui::Spacing();

		if (ImGui::Button("Copy", ImVec2(80, 0)))
			ImGui::SetClipboardText(m_sig_pattern.c_str());

		ImGui::SameLine(0, 8);
		if (ImGui::Button("Scan in Scanner", ImVec2(120, 0)))
		{
			app::set_pending_aob_pattern(m_sig_pattern);
			app::switch_tab(tab_id::scanner);
			ImGui::CloseCurrentPopup();
		}

		ImGui::SameLine(0, 8);
		if (ImGui::Button("Close", ImVec2(80, 0)))
			ImGui::CloseCurrentPopup();

		ImGui::EndPopup();
	}

	// ---- Edit Instruction modal ----
	if (m_show_edit_modal)
	{
		ImGui::OpenPopup("Edit Instruction##edit_instr_modal");
		m_show_edit_modal = false;
	}

	ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
	if (ImGui::BeginPopupModal("Edit Instruction##edit_instr_modal", nullptr,
		ImGuiWindowFlags_AlwaysAutoResize))
	{
		ImGui::Text("Address: 0x%llX", m_edit_address);
		ImGui::Text("Original length: %d bytes", m_edit_original_length);

		// show original bytes
		if (m_edit_line_idx >= 0 && m_edit_line_idx < (int)m_lines.size())
		{
			auto& orig = m_lines[m_edit_line_idx];
			char orig_str[128] = {};
			int op = 0;
			for (int j = 0; j < orig.length; j++)
			{
				if (j > 0) op += snprintf(orig_str + op, sizeof(orig_str) - op, " ");
				op += snprintf(orig_str + op, sizeof(orig_str) - op, "%02X", orig.bytes[j]);
			}
			ImGui::PushFont(renderer::font_mono());
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "Original: %s", orig_str);
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "  -> %s %s",
				orig.mnemonic, orig.operands_fmt.c_str());
			ImGui::PopFont();
		}

		ImGui::Spacing();
		ImGui::Text("New bytes (hex):");
		ImGui::PushItemWidth(350);
		ImGui::InputText("##edit_bytes", m_edit_bytes_buf, sizeof(m_edit_bytes_buf),
			ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase);
		ImGui::PopItemWidth();

		// parse input to count bytes
		int new_byte_count = 0;
		{
			const char* p = m_edit_bytes_buf;
			while (*p)
			{
				while (*p == ' ') p++;
				if (isxdigit(*p))
				{
					new_byte_count++;
					p++;
					if (isxdigit(*p)) p++;
				}
				else if (*p) p++;
			}
		}

		ImGui::Text("New length: %d bytes", new_byte_count);

		if (new_byte_count > 0 && new_byte_count < m_edit_original_length)
		{
			ImGui::Checkbox("Fill remaining with NOP (90)", &m_edit_nop_fill);
			if (m_edit_nop_fill)
				ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.4f, 1.0f),
					"%d NOP(s) will be appended", m_edit_original_length - new_byte_count);
		}
		else if (new_byte_count > m_edit_original_length)
		{
			ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f),
				"WARNING: New code is %d byte(s) longer than original!",
				new_byte_count - m_edit_original_length);
			ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f),
				"This will overwrite the next instruction(s).");
		}

		// preview: disassemble the new bytes
		if (new_byte_count > 0)
		{
			uint8_t preview[64] = {};
			int pi = 0;
			const char* pp = m_edit_bytes_buf;
			while (*pp && pi < (int)sizeof(preview))
			{
				while (*pp == ' ') pp++;
				if (isxdigit(*pp))
				{
					char hex[3] = { *pp, 0, 0 };
					pp++;
					if (isxdigit(*pp)) { hex[1] = *pp; pp++; }
					preview[pi++] = (uint8_t)strtoul(hex, nullptr, 16);
				}
				else if (*pp) pp++;
			}

			// pad with NOPs for preview if enabled
			int total = pi;
			if (m_edit_nop_fill && pi < m_edit_original_length)
			{
				for (int j = pi; j < m_edit_original_length && j < (int)sizeof(preview); j++)
					preview[j] = 0x90;
				total = m_edit_original_length;
			}

			ZydisDecoder dec;
			ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
			ZydisFormatter fmt;
			ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);

			ImGui::Spacing();
			ImGui::Text("Preview:");
			ImGui::PushFont(renderer::font_mono());

			size_t off = 0;
			while (off < (size_t)total)
			{
				ZydisDecodedInstruction instr;
				ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
				if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, preview + off, total - off, &instr, ops)))
				{
					char buf[128] = {};
					ZydisFormatterFormatInstruction(&fmt, &instr, ops, instr.operand_count,
						buf, sizeof(buf), m_edit_address + off, nullptr);

					const char* mn = ZydisMnemonicGetString(instr.mnemonic);
					ImGui::TextColored(ImVec4(0.4f, 0.85f, 0.9f, 1.0f), "  %s", buf);
					off += instr.length;
				}
				else
				{
					ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "  db 0x%02X", preview[off]);
					off++;
				}
			}
			ImGui::PopFont();
		}

		ImGui::Spacing();

		bool can_apply = (new_byte_count > 0);
		if (!can_apply) ImGui::BeginDisabled();
		if (ImGui::Button("Apply", ImVec2(80, 0)))
		{
			// parse and write bytes
			uint8_t write_buf[64] = {};
			int wi = 0;
			const char* wp = m_edit_bytes_buf;
			while (*wp && wi < (int)sizeof(write_buf))
			{
				while (*wp == ' ') wp++;
				if (isxdigit(*wp))
				{
					char hex[3] = { *wp, 0, 0 };
					wp++;
					if (isxdigit(*wp)) { hex[1] = *wp; wp++; }
					write_buf[wi++] = (uint8_t)strtoul(hex, nullptr, 16);
				}
				else if (*wp) wp++;
			}

			int write_len = wi;

			// NOP fill if shorter
			if (m_edit_nop_fill && wi < m_edit_original_length)
			{
				for (int j = wi; j < m_edit_original_length && j < (int)sizeof(write_buf); j++)
					write_buf[j] = 0x90;
				write_len = m_edit_original_length;
			}

			memory::write(write_buf, m_edit_address, write_len);

			// refresh disassembly from the current base
			disassemble_at(m_base_address);
			ImGui::CloseCurrentPopup();
		}
		if (!can_apply) ImGui::EndDisabled();

		ImGui::SameLine(0, 8);
		if (ImGui::Button("Cancel", ImVec2(80, 0)))
			ImGui::CloseCurrentPopup();

		ImGui::EndPopup();
	}

	// Ctrl+C: copy selected line
	if (m_selected_line >= 0 && m_selected_line < (int)m_lines.size() &&
		ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C))
	{
		auto& line = m_lines[m_selected_line];
		std::string mod_addr = widgets::format_address_short(line.address);
		char bytes_str[48] = {};
		int bpos = 0;
		for (int j = 0; j < line.length && bpos < 45; j++)
			bpos += snprintf(bytes_str + bpos, sizeof(bytes_str) - bpos, "%02X ", line.bytes[j]);

		std::string full_line = mod_addr + "  " + bytes_str + " " + line.mnemonic + " " + line.operands_fmt;
		if (!line.comment.empty())
			full_line += " ; " + line.comment;

		ImGui::SetClipboardText(full_line.c_str());
	}
}

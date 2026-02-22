#pragma once
#include "panel.h"
#include <vector>
#include <string>
#include <cstdint>

class DisassemblerPanel : public IPanel
{
public:
	void render() override;
	tab_id get_id() const override { return tab_id::disassembler; }
	const char* get_name() const override { return "Disasm"; }

	// token types for syntax coloring (public for use by render helpers)
	enum class token_type_t { text, reg, imm, mem_bracket, comma, plus };

	struct operand_token_t
	{
		token_type_t type;
		std::string text;
	};

	struct disasm_line_t
	{
		uint64_t address;
		uint8_t bytes[15];
		int length;
		char mnemonic[32];
		char operands[128];       // raw Zydis operands
		std::string operands_fmt; // operands with module-relative addresses
		std::string comment;      // CE-style comment (export name, string ref, etc.)
		bool is_call;
		bool is_jmp;
		bool is_ret;
		bool is_nop;
		uint64_t branch_target;
		uint64_t mem_target;      // RIP-relative memory operand target
		std::vector<operand_token_t> tokens; // tokenized operands for syntax coloring
	};

	// tokenize operand string for syntax coloring
	static std::vector<operand_token_t> tokenize_operands(const char* ops);

private:
	uint64_t m_base_address = 0;
	uint64_t m_goto_address = 0;
	std::vector<disasm_line_t> m_lines;
	int m_selected_line = -1;
	bool m_initialized = false;

	// infinite scroll state
	uint64_t m_decode_end_address = 0;   // next address to decode forward from
	uint64_t m_decode_start_address = 0; // earliest decoded address
	bool m_at_end = false;               // can't go further forward
	bool m_at_start = false;             // can't go further back

	// scroll-to-top after goto
	bool m_scroll_to_top = false;

	// navigation history
	std::vector<uint64_t> m_nav_history;
	int m_nav_index = -1;

	// signature maker state
	int m_sig_start_line = -1;
	int m_sig_end_line = -1;
	bool m_show_sig_modal = false;
	std::string m_sig_pattern;
	int m_sig_match_count = -1;

	// go-to-address modal
	bool m_show_goto_modal = false;
	char m_goto_modal_buf[32] = {};

	// edit instruction modal
	bool m_show_edit_modal = false;
	int m_edit_line_idx = -1;
	uint64_t m_edit_address = 0;
	int m_edit_original_length = 0;
	char m_edit_bytes_buf[128] = {};
	bool m_edit_nop_fill = true;

	void disassemble_at(uint64_t address, int max_instructions = 200);
	void decode_forward(int count = 200);
	void decode_backward(int count = 200);

	void navigate_to(uint64_t addr);
	void go_back();
	void go_forward();

	void resolve_comments(size_t start_idx, size_t end_idx);
	void build_signature();

	// try to read a string at address (for comment resolution)
	std::string try_read_string(uint64_t address, int max_len = 64);
};

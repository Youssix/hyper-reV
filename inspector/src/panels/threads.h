#pragma once
#include "panel.h"
#include <vector>
#include <cstdint>
#include <string>

class ThreadsPanel : public IPanel
{
public:
	void render() override;
	tab_id get_id() const override { return tab_id::threads; }
	const char* get_name() const override { return "Threads"; }

private:
	// KTRAP_FRAME offsets (x64, stable across Win10/11)
	struct ktrap_offsets
	{
		static constexpr uint64_t rax = 0x30;
		static constexpr uint64_t rcx = 0x38;
		static constexpr uint64_t rdx = 0x40;
		static constexpr uint64_t r8  = 0x48;
		static constexpr uint64_t r9  = 0x50;
		static constexpr uint64_t r10 = 0x58;
		static constexpr uint64_t r11 = 0x60;
		static constexpr uint64_t rbx = 0x140;
		static constexpr uint64_t rdi = 0x148;
		static constexpr uint64_t rsi = 0x150;
		static constexpr uint64_t rbp = 0x158;
		static constexpr uint64_t rip = 0x168;
		static constexpr uint64_t cs  = 0x170;
		static constexpr uint64_t eflags = 0x178;
		static constexpr uint64_t rsp = 0x180;
	};

	struct register_set_t
	{
		uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
		uint64_t r8, r9, r10, r11;
		uint64_t rip;
		uint32_t eflags;
		bool valid = false;
	};

	struct thread_entry_t
	{
		uint64_t ethread;
		uint8_t state;          // KTHREAD.State
		uint64_t trap_frame_ptr;
		register_set_t regs;
	};

	struct stack_frame_t
	{
		uint64_t address;       // return address on stack
		uint64_t stack_ptr;     // where on the stack this was
		std::string module_str; // resolved "module.dll+0x1234"
		// first 4 QWORDs after the return address (like CE's stack view)
		uint64_t args[4];
	};

	std::vector<thread_entry_t> m_threads;
	std::vector<stack_frame_t> m_stack_frames;
	int m_selected_thread = -1;
	bool m_threads_loaded = false;

	void load_threads();
	void load_registers(int thread_index);
	void walk_stack(int thread_index);
};

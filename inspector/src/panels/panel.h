#pragma once
#include <imgui.h>

enum class tab_id
{
	memory_viewer,
	scanner,
	disassembler,
	modules,
	threads,
	struct_editor,
	hook_checker,
	breakpoints,
	pointer_scanner,
	code_filter,
	watch_list,
	system_info,
	function_filter
};

class IPanel
{
public:
	virtual ~IPanel() = default;
	virtual void render() = 0;
	virtual tab_id get_id() const = 0;
	virtual const char* get_name() const = 0;

	float m_enter_time = 0.0f;
};

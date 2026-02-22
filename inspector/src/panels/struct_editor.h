#pragma once
#include "panel.h"
#include "../project/project_file.h"
#include "../widgets/filter_bar.h"
#include <vector>
#include <string>

class StructEditorPanel : public IPanel
{
public:
	void render() override;
	tab_id get_id() const override { return tab_id::struct_editor; }
	const char* get_name() const override { return "Structs"; }

private:
	std::vector<project::struct_def_t> m_structs;
	int m_selected_struct = -1;
	uint64_t m_view_address = 0;
	char m_name_buf[128] = {};
	bool m_editing_name = false;

	void render_struct_list();
	void render_struct_view();
	void add_field(int struct_idx);
};

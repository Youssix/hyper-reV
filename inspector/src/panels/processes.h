#pragma once
#include "panel.h"
#include "../widgets/filter_bar.h"
#include "system/system.h"
#include <vector>

class ProcessesPanel : public IPanel
{
public:
	void render() override;
	tab_id get_id() const override { return tab_id::processes; }
	const char* get_name() const override { return "Processes"; }

private:
	std::vector<sys::process_info_t> m_processes;
	widgets::filter_state_t m_filter;
	float m_last_refresh = -10.0f;
	int m_sort_column = 1; // name
	bool m_sort_ascending = true;

	void refresh_list();
};

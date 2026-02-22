#pragma once
#include "panel.h"
#include "../widgets/hex_view.h"

class MemoryViewerPanel : public IPanel
{
public:
	void render() override;
	tab_id get_id() const override { return tab_id::memory_viewer; }
	const char* get_name() const override { return "Memory"; }

private:
	widgets::hex_view_state_t m_hex_state;
	uint64_t m_goto_address = 0;
	bool m_initialized = false;
};

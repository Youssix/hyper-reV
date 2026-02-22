#pragma once
#include "panel.h"

class SystemInfoPanel : public IPanel
{
public:
	void render() override;
	tab_id get_id() const override { return tab_id::system_info; }
	const char* get_name() const override { return "System"; }

private:
	bool m_kernel_modules_loaded = false;
};

#pragma once
#include "page.h"

class SystemCheckPage : public IPage
{
public:
	void on_enter() override;
	void on_exit() override;
	void render() override;
	page_id get_id() const override { return page_id::system_check; }

private:
	bool m_checks_done = false;
	bool m_force_skip = false;
};

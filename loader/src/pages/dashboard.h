#pragma once
#include "page.h"

class DashboardPage : public IPage
{
public:
	void on_enter() override;
	void on_exit() override;
	void render() override;
	page_id get_id() const override { return page_id::dashboard; }

private:
	void render_title_bar();
	void render_game_list();
	void render_patch_notes();
	void render_bottom_bar();
};

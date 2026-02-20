#pragma once
#include "page.h"
#include <string>
#include <future>

class LoginPage : public IPage
{
public:
	void on_enter() override;
	void on_exit() override;
	void render() override;
	page_id get_id() const override { return page_id::login; }

private:
	// tab: 0 = license key, 1 = account
	int m_tab = 0;

	char m_key_buf[256] = {};
	char m_username_buf[128] = {};
	char m_password_buf[128] = {};

	std::string m_error;
	bool m_logging_in = false;
	std::future<void> m_login_future;
};

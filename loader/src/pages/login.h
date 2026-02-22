#pragma once
#include "page.h"
#include "../security/credential_store.h"
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
	void try_auto_login();
	void do_login();

	// tab: 0 = license key, 1 = account
	int m_tab = 0;

	char m_key_buf[256] = {};
	char m_username_buf[128] = {};
	char m_password_buf[128] = {};

	std::string m_error;
	bool m_logging_in = false;
	std::future<void> m_login_future;

	// credential history
	credential_store::saved_credentials_t m_saved;
	bool m_loaded_creds = false;
	bool m_auto_login_tried = false;
	bool m_show_key_dropdown = false;
	int m_key_to_remove = -1; // deferred removal
};

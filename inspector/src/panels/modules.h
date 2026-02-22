#pragma once
#include "panel.h"
#include "../widgets/filter_bar.h"
#include <vector>
#include <string>

class ModulesPanel : public IPanel
{
public:
	void render() override;
	tab_id get_id() const override { return tab_id::modules; }
	const char* get_name() const override { return "Modules"; }

private:
	struct module_entry_t
	{
		std::string name;
		uint64_t base;
		uint32_t size;
		std::string path;
	};

	struct export_entry_t
	{
		std::string name;
		uint64_t address;
	};

	// global export for cross-module search
	struct global_export_t
	{
		std::string module_name;
		std::string export_name;
		uint64_t address;
	};

	std::vector<module_entry_t> m_modules;
	std::vector<export_entry_t> m_exports;
	std::vector<global_export_t> m_all_exports;
	widgets::filter_state_t m_module_filter;
	widgets::filter_state_t m_export_filter;
	int m_selected_module = -1;
	bool m_modules_loaded = false;

	// function finder search
	char m_function_search[256] = {};

	void load_modules();
	void load_exports(int module_index);
	void load_all_exports();
};

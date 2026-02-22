#pragma once
#include "panel.h"
#include <vector>
#include <string>
#include <cstdint>

class WatchListPanel : public IPanel
{
public:
	void render() override;
	tab_id get_id() const override { return tab_id::watch_list; }
	const char* get_name() const override { return "Watch List"; }

private:
	enum class watch_type_t { u8, u16, u32, u64, i32, f32, f64, aob };

	struct watch_entry_t
	{
		std::string label;
		uint64_t address;
		watch_type_t type = watch_type_t::u32;
		int aob_size = 4;
		bool frozen = false;
		uint64_t frozen_value = 0;
		std::string value_str;
	};

	std::vector<watch_entry_t> m_entries;
	float m_refresh_timer = 0.0f;

	// add entry modal
	bool m_show_add_modal = false;
	char m_add_addr_buf[32] = {};
	char m_add_label_buf[64] = {};
	int m_add_type_idx = 2; // default u32

	// inline edit
	int m_editing_value_idx = -1;
	char m_edit_value_buf[64] = {};

	void refresh_values();
	void add_entry(uint64_t address, watch_type_t type, const char* label);
	void write_value(int index, const char* value_str);

	static int type_size(watch_type_t type);
	static const char* type_name(watch_type_t type);
};

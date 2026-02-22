#include "data_inspector.h"
#include "../memory/memory_reader.h"
#include "../renderer/renderer.h"
#include "ui_helpers.h"
#include <imgui.h>
#include <cstring>
#include <cstdio>

namespace widgets
{
	void data_inspector(uint64_t address, float width)
	{
		uint8_t buf[8] = {};
		bool valid = memory::read(buf, address, 8);

		ImGui::BeginChild("##inspector", ImVec2(width, 0), true);

		ImGui::PushFont(renderer::font_bold());
		ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.0f, 1.0f), "Data Inspector");
		ImGui::PopFont();

		ImGui::Separator();

		if (!valid)
		{
			ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "Cannot read memory");
			ImGui::EndChild();
			return;
		}

		ImGui::PushFont(renderer::font_mono());

		char label[64];

		// click-to-copy row helper
		auto row = [&](const char* type_name, const char* value) {
			ImGui::TextColored(ImVec4(0.48f, 0.48f, 0.53f, 1.0f), "%-10s", type_name);
			ImGui::SameLine(90);
			char sel_id[80];
			snprintf(sel_id, sizeof(sel_id), "%s##di_%s", value, type_name);
			if (ImGui::Selectable(sel_id, false, 0, ImGui::CalcTextSize(value)))
			{
				ui::clipboard(value, "Value copied");
			}
			if (ImGui::IsItemHovered())
				ImGui::SetTooltip("Click to copy");
		};

		// int8
		snprintf(label, sizeof(label), "%d", (int8_t)buf[0]);
		row("Int8", label);

		// uint8
		snprintf(label, sizeof(label), "%u", buf[0]);
		row("UInt8", label);

		// int16
		int16_t i16; memcpy(&i16, buf, 2);
		snprintf(label, sizeof(label), "%d", i16);
		row("Int16", label);

		// uint16
		uint16_t u16; memcpy(&u16, buf, 2);
		snprintf(label, sizeof(label), "%u", u16);
		row("UInt16", label);

		// int32
		int32_t i32; memcpy(&i32, buf, 4);
		snprintf(label, sizeof(label), "%d", i32);
		row("Int32", label);

		// uint32
		uint32_t u32; memcpy(&u32, buf, 4);
		snprintf(label, sizeof(label), "%u", u32);
		row("UInt32", label);

		// int64
		int64_t i64; memcpy(&i64, buf, 8);
		snprintf(label, sizeof(label), "%lld", i64);
		row("Int64", label);

		// uint64
		uint64_t u64; memcpy(&u64, buf, 8);
		snprintf(label, sizeof(label), "%llu", u64);
		row("UInt64", label);

		// hex32
		snprintf(label, sizeof(label), "0x%08X", u32);
		row("Hex32", label);

		// hex64
		snprintf(label, sizeof(label), "0x%016llX", u64);
		row("Hex64", label);

		// float
		float f32; memcpy(&f32, buf, 4);
		snprintf(label, sizeof(label), "%.6g", f32);
		row("Float", label);

		// double
		double f64; memcpy(&f64, buf, 8);
		snprintf(label, sizeof(label), "%.10g", f64);
		row("Double", label);

		ImGui::PopFont();
		ImGui::EndChild();
	}
}

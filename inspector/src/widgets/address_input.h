#pragma once
#include <imgui.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace widgets
{
	// hex address input field. returns true if user pressed Enter.
	inline bool address_input(const char* label, uint64_t& address, float width = 180.0f)
	{
		char buf[32];
		snprintf(buf, sizeof(buf), "%llX", address);

		ImGui::PushItemWidth(width);
		bool entered = ImGui::InputText(label, buf, sizeof(buf),
			ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue);
		ImGui::PopItemWidth();

		if (entered)
		{
			address = strtoull(buf, nullptr, 16);
			return true;
		}

		return false;
	}

	// compact address display (clickable)
	inline bool address_link(uint64_t address)
	{
		char buf[24];
		snprintf(buf, sizeof(buf), "0x%llX", address);

		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.6f, 1.0f, 1.0f));
		bool clicked = ImGui::Selectable(buf, false, ImGuiSelectableFlags_None,
			ImGui::CalcTextSize(buf));
		ImGui::PopStyleColor();

		return clicked;
	}
}

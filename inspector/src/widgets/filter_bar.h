#pragma once
#include <imgui.h>
#include <cstring>
#include <algorithm>
#include <string>

namespace widgets
{
	struct filter_state_t
	{
		char text[256] = {};

		bool passes(const char* str) const
		{
			if (text[0] == '\0')
				return true;

			// case-insensitive substring match
			std::string haystack(str);
			std::string needle(text);
			std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
			std::transform(needle.begin(), needle.end(), needle.begin(), ::tolower);

			return haystack.find(needle) != std::string::npos;
		}

		void clear() { text[0] = '\0'; }
		bool is_active() const { return text[0] != '\0'; }
	};

	inline void filter_bar(const char* label, filter_state_t& state, float width = -1.0f)
	{
		if (width > 0.0f)
			ImGui::PushItemWidth(width);
		else
			ImGui::PushItemWidth(-1.0f);

		ImGui::InputTextWithHint(label, "Filter...", state.text, sizeof(state.text));
		ImGui::PopItemWidth();
	}
}

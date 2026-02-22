#pragma once
#include <imgui.h>
#include <cmath>

namespace anim
{
	inline float time() { return (float)ImGui::GetTime(); }
	inline float dt() { return ImGui::GetIO().DeltaTime; }

	inline float lerp(float a, float b, float t)
	{
		if (t < 0.0f) t = 0.0f;
		if (t > 1.0f) t = 1.0f;
		return a + (b - a) * t;
	}

	inline float ease_out(float t)
	{
		if (t < 0.0f) t = 0.0f;
		if (t > 1.0f) t = 1.0f;
		float f = 1.0f - t;
		return 1.0f - f * f * f;
	}

	inline float ease_in_out(float t)
	{
		if (t < 0.0f) t = 0.0f;
		if (t > 1.0f) t = 1.0f;
		return t * t * (3.0f - 2.0f * t);
	}

	inline float fade_in(float start_time, float duration = 0.35f)
	{
		float t = (time() - start_time) / duration;
		return ease_out(t < 0.0f ? 0.0f : (t > 1.0f ? 1.0f : t));
	}

	inline float pulse(float speed = 2.0f)
	{
		return (sinf(time() * speed) + 1.0f) * 0.5f;
	}

	inline float pulse_range(float min_val, float max_val, float speed = 2.0f)
	{
		return lerp(min_val, max_val, pulse(speed));
	}

	inline float stagger(float start_time, int index, float delay = 0.08f, float duration = 0.3f)
	{
		float item_start = start_time + index * delay;
		return fade_in(item_start, duration);
	}

	inline float slide_in(float start_time, float offset_px = 20.0f, float duration = 0.35f)
	{
		float t = fade_in(start_time, duration);
		return offset_px * (1.0f - t);
	}

	inline float slide_stagger(float start_time, int index, float offset_px = 20.0f, float delay = 0.08f, float duration = 0.3f)
	{
		float item_start = start_time + index * delay;
		float t = fade_in(item_start, duration);
		return offset_px * (1.0f - t);
	}

	inline float shimmer_x(float width, float speed = 0.8f, float start_time = 0.0f)
	{
		float t = fmodf((time() - start_time) * speed, 1.0f);
		return t * (width + 60.0f) - 30.0f;
	}

	inline ImVec4 lerp_color(const ImVec4& a, const ImVec4& b, float t)
	{
		return ImVec4(lerp(a.x, b.x, t), lerp(a.y, b.y, t), lerp(a.z, b.z, t), lerp(a.w, b.w, t));
	}
}

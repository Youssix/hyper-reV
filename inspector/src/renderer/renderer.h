#pragma once
#include <Windows.h>
#include <d3d11.h>

struct ImFont;

namespace renderer
{
	bool initialize();
	void shutdown();

	void begin_frame();
	void end_frame();

	bool should_close();
	void request_close();

	HWND get_hwnd();
	ID3D11Device* get_device();
	ID3D11DeviceContext* get_device_context();

	ImFont* font_regular();
	ImFont* font_bold();
	ImFont* font_title();
	ImFont* font_mono();
	ImFont* font_small();

	void draw_window_border();

	// borderless window helpers
	bool is_maximized();
	void set_caption_button_width(float w);

	constexpr int WINDOW_WIDTH = 1400;
	constexpr int WINDOW_HEIGHT = 900;
	constexpr float TITLE_BAR_HEIGHT = 44.0f;
}

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

	// fonts loaded at init
	ImFont* font_regular();
	ImFont* font_bold();
	ImFont* font_title();

	// draw accent border around the window (call at end of each page's render)
	void draw_window_border();

	constexpr int WINDOW_WIDTH = 920;
	constexpr int WINDOW_HEIGHT = 580;
}

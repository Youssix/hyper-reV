#include "renderer.h"
#include "theme.h"

#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>

#include <dxgi.h>
#include <windowsx.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace renderer
{
	static HWND                    g_hwnd = nullptr;
	static ID3D11Device*           g_device = nullptr;
	static ID3D11DeviceContext*    g_device_context = nullptr;
	static IDXGISwapChain*         g_swap_chain = nullptr;
	static ID3D11RenderTargetView* g_render_target = nullptr;
	static bool                    g_should_close = false;
	static WNDCLASSEXW             g_wc = {};

	static ImFont* g_font_regular = nullptr;
	static ImFont* g_font_bold    = nullptr;
	static ImFont* g_font_title   = nullptr;

	static void create_render_target()
	{
		ID3D11Texture2D* back_buffer = nullptr;
		g_swap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
		if (back_buffer)
		{
			g_device->CreateRenderTargetView(back_buffer, nullptr, &g_render_target);
			back_buffer->Release();
		}
	}

	static void cleanup_render_target()
	{
		if (g_render_target) { g_render_target->Release(); g_render_target = nullptr; }
	}

	static LRESULT CALLBACK wnd_proc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
			return true;

		switch (msg)
		{
		case WM_NCHITTEST:
		{
			// title bar drag: top 42px, only left portion (logo + label area)
			// right side has user info, logout button, min/close — must stay clickable
			POINT pt;
			pt.x = GET_X_LPARAM(lParam);
			pt.y = GET_Y_LPARAM(lParam);
			ScreenToClient(hWnd, &pt);
			if (pt.y < 42 && pt.x < 280)
				return HTCAPTION;
			return HTCLIENT;
		}
		case WM_SIZE:
			if (g_device && wParam != SIZE_MINIMIZED)
			{
				cleanup_render_target();
				g_swap_chain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
				create_render_target();
			}
			return 0;
		case WM_DESTROY:
			PostQuitMessage(0);
			return 0;
		}

		return DefWindowProcW(hWnd, msg, wParam, lParam);
	}

	bool initialize()
	{
		g_wc = { sizeof(WNDCLASSEXW), CS_CLASSDC, wnd_proc, 0L, 0L,
		          GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr,
		          L"ZeroHookLoader", nullptr };
		RegisterClassExW(&g_wc);

		int screen_w = GetSystemMetrics(SM_CXSCREEN);
		int screen_h = GetSystemMetrics(SM_CYSCREEN);
		int pos_x = (screen_w - WINDOW_WIDTH) / 2;
		int pos_y = (screen_h - WINDOW_HEIGHT) / 2;

		g_hwnd = CreateWindowExW(
			WS_EX_TOPMOST, g_wc.lpszClassName, L"ZeroHook",
			WS_POPUP,
			pos_x, pos_y, WINDOW_WIDTH, WINDOW_HEIGHT,
			nullptr, nullptr, g_wc.hInstance, nullptr);

		DXGI_SWAP_CHAIN_DESC sd = {};
		sd.BufferCount = 2;
		sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
		sd.BufferDesc.RefreshRate.Numerator = 60;
		sd.BufferDesc.RefreshRate.Denominator = 1;
		sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
		sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
		sd.OutputWindow = g_hwnd;
		sd.SampleDesc.Count = 1;
		sd.Windowed = TRUE;
		sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

		D3D_FEATURE_LEVEL feature_level;
		const D3D_FEATURE_LEVEL feature_levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };

		HRESULT hr = D3D11CreateDeviceAndSwapChain(
			nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
			feature_levels, 2, D3D11_SDK_VERSION,
			&sd, &g_swap_chain, &g_device, &feature_level, &g_device_context);

		if (FAILED(hr))
			return false;

		create_render_target();

		ShowWindow(g_hwnd, SW_SHOWDEFAULT);
		UpdateWindow(g_hwnd);

		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGuiIO& io = ImGui::GetIO();
		io.IniFilename = nullptr;
		io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

		// load fonts
		g_font_regular = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 16.0f);
		g_font_bold    = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\seguisb.ttf", 16.0f);
		g_font_title   = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\seguisb.ttf", 22.0f);

		if (!g_font_regular) g_font_regular = io.Fonts->AddFontDefault();
		if (!g_font_bold)    g_font_bold    = g_font_regular;
		if (!g_font_title)   g_font_title   = g_font_regular;

		ImGui_ImplWin32_Init(g_hwnd);
		ImGui_ImplDX11_Init(g_device, g_device_context);

		theme::apply();

		return true;
	}

	void shutdown()
	{
		ImGui_ImplDX11_Shutdown();
		ImGui_ImplWin32_Shutdown();
		ImGui::DestroyContext();

		cleanup_render_target();
		if (g_swap_chain)      { g_swap_chain->Release();      g_swap_chain = nullptr; }
		if (g_device_context)  { g_device_context->Release();  g_device_context = nullptr; }
		if (g_device)          { g_device->Release();          g_device = nullptr; }
		if (g_hwnd)            { DestroyWindow(g_hwnd);        g_hwnd = nullptr; }
		UnregisterClassW(g_wc.lpszClassName, g_wc.hInstance);
	}

	void begin_frame()
	{
		MSG msg;
		while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
			if (msg.message == WM_QUIT)
				g_should_close = true;
		}

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();
	}

	void end_frame()
	{
		ImGui::Render();

		const float clear_color[] = { 0.051f, 0.051f, 0.063f, 1.0f }; // #0D0D10
		g_device_context->OMSetRenderTargets(1, &g_render_target, nullptr);
		g_device_context->ClearRenderTargetView(g_render_target, clear_color);

		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

		g_swap_chain->Present(1, 0);
	}

	bool should_close() { return g_should_close; }

	void request_close()
	{
		PostMessage(g_hwnd, WM_CLOSE, 0, 0);
	}

	HWND get_hwnd() { return g_hwnd; }
	ID3D11Device* get_device() { return g_device; }
	ID3D11DeviceContext* get_device_context() { return g_device_context; }

	void draw_window_border()
	{
		// 1px accent border around the entire window
		ImDrawList* fg = ImGui::GetForegroundDrawList();
		ImVec2 p_min(0, 0);
		ImVec2 p_max((float)WINDOW_WIDTH, (float)WINDOW_HEIGHT);
		ImU32 accent = IM_COL32(255, 107, 0, 180);   // #FF6B00 with slight transparency
		ImU32 glow   = IM_COL32(255, 107, 0, 25);
		fg->AddRect(p_min, p_max, accent, 0.0f, 0, 1.0f);
		// subtle outer-ish glow (inner 2px border)
		fg->AddRect(ImVec2(1, 1), ImVec2(p_max.x - 1, p_max.y - 1), glow, 0.0f, 0, 1.0f);
	}

	ImFont* font_regular() { return g_font_regular; }
	ImFont* font_bold()    { return g_font_bold; }
	ImFont* font_title()   { return g_font_title; }
}

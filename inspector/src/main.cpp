#include "renderer/renderer.h"
#include "app.h"
#include "server/http_server.h"

#include <Windows.h>

int WINAPI WinMain(
	_In_ HINSTANCE /*hInstance*/,
	_In_opt_ HINSTANCE /*hPrevInstance*/,
	_In_ LPSTR /*lpCmdLine*/,
	_In_ int /*nCmdShow*/)
{
	if (!renderer::initialize())
	{
		MessageBoxA(nullptr, "Failed to initialize DirectX 11 renderer.",
			"HyperREV Inspector", MB_OK | MB_ICONERROR);
		return 1;
	}

	app::initialize();
	server::start();

	while (!renderer::should_close())
	{
		server::tick();
		renderer::begin_frame();
		app::render();
		renderer::end_frame();
	}

	server::stop();
	app::shutdown();
	renderer::shutdown();

	return 0;
}

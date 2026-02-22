#pragma once

namespace server
{
	void start(int port = 9742);
	void stop();
	void tick(); // call from main thread each frame to drain command queue
}

#pragma once
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <nlohmann/json.hpp>

namespace server
{
	using json = nlohmann::json;

	class command_queue_t
	{
	public:
		using command_fn = std::function<json()>;

		std::future<json> enqueue(command_fn fn)
		{
			auto promise = std::make_shared<std::promise<json>>();
			auto future = promise->get_future();

			std::lock_guard<std::mutex> lock(m_mutex);
			m_queue.push({ std::move(fn), std::move(promise) });

			return future;
		}

		void drain()
		{
			std::queue<entry_t> local;
			{
				std::lock_guard<std::mutex> lock(m_mutex);
				std::swap(local, m_queue);
			}

			while (!local.empty())
			{
				auto& entry = local.front();
				try
				{
					json result = entry.fn();
					entry.promise->set_value(std::move(result));
				}
				catch (const std::exception& e)
				{
					entry.promise->set_value(json{
						{"ok", false},
						{"error", e.what()}
					});
				}
				local.pop();
			}
		}

	private:
		struct entry_t
		{
			command_fn fn;
			std::shared_ptr<std::promise<json>> promise;
		};

		std::mutex m_mutex;
		std::queue<entry_t> m_queue;
	};
}

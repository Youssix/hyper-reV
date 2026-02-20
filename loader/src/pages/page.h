#pragma once

enum class page_id
{
	system_check,
	login,
	dashboard
};

class IPage
{
public:
	virtual ~IPage() = default;
	virtual void on_enter() = 0;
	virtual void on_exit() = 0;
	virtual void render() = 0;
	virtual page_id get_id() const = 0;
};

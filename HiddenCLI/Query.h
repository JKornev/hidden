#pragma once

#include "Commands.h"

class CommandQuery : public ICommand
{
	const wchar_t* m_command = nullptr;

	HidProcId m_targetProcId;

public:

	CommandQuery();
	virtual ~CommandQuery();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args);
	virtual void PerformCommand(Connection& connection);
};


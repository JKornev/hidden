#pragma once

#include "Commands.h"

class CommandState : public ICommand
{
	const wchar_t* m_command = nullptr;

	bool m_state;

public:

	CommandState();
	virtual ~CommandState();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args);
	virtual void PerformCommand(Connection& connection);

	virtual CommandPtr CreateInstance();
};

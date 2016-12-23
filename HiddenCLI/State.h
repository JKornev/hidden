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
	virtual void LoadArgs(Arguments& args, CommandModeType mode);
	virtual void PerformCommand(Connection& connection);
	virtual void InstallCommand(RegistryKey& configKey);
	virtual void UninstallCommand(RegistryKey& configKey);

	virtual CommandPtr CreateInstance();
};

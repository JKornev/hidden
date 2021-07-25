#pragma once

#include "Commands.h"

class CommandProtect : public ICommand, public ProcessParametersParser
{
	const wchar_t* m_command = nullptr;

	EProcTypes   m_procType;

public:

	CommandProtect();
	virtual ~CommandProtect();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args, CommandModeType mode);
	virtual void PerformCommand(Connection& connection);
	virtual void InstallCommand(RegistryKey& configKey);
	virtual void UninstallCommand(RegistryKey& configKey);

	virtual CommandPtr CreateInstance();
};

class CommandUnprotect : public ICommand
{
	const wchar_t* m_command = nullptr;

	enum ETargetIdType {
		RuleId,
		ProcId,
		All
	};

	ETargetIdType m_targetType;
	HidProcId     m_targetProcId;
	HidObjId      m_targetId;

public:

	CommandUnprotect();
	virtual ~CommandUnprotect();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args, CommandModeType mode);
	virtual void PerformCommand(Connection& connection);

	virtual CommandPtr CreateInstance();
};

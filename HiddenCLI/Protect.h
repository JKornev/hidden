#pragma once

#include "Commands.h"

class CommandProtect : public ICommand
{
	const wchar_t* m_command = nullptr;

	EProcTypes   m_procType;
	std::wstring m_targetImage;
	HidProcId    m_targetProcId;
	HidPsInheritTypes m_inheritType;
	bool         m_applyByDefault;

public:

	CommandProtect();
	virtual ~CommandProtect();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args);
	virtual void PerformCommand(Connection& connection);
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
	virtual void LoadArgs(Arguments& args);
	virtual void PerformCommand(Connection& connection);
};

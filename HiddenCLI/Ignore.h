#pragma once

#include "Commands.h"

class CommandIgnore : public ICommand
{
	const wchar_t* m_command = nullptr;

	EProcTypes   m_procType;
	std::wstring m_targetImage;
	HidProcId    m_targetProcId;
	HidPsInheritTypes m_inheritType;
	bool         m_applyByDefault;

public:

	CommandIgnore();
	virtual ~CommandIgnore();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args);
	virtual void PerformCommand(Connection& connection);

	virtual CommandPtr CreateInstance();
};

class CommandUnignore : public ICommand
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

	CommandUnignore();
	virtual ~CommandUnignore();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args);
	virtual void PerformCommand(Connection& connection);

	virtual CommandPtr CreateInstance();
};

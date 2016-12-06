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

	HidPsInheritTypes LoadInheritOption(Arguments& args, HidPsInheritTypes default);
	bool LoadApplyOption(Arguments& args, bool applyByDefault);

public:

	CommandIgnore();
	virtual ~CommandIgnore();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args);
	virtual void PerformCommand(Connection& connection);
};

class CommandUnignore : public ICommand
{
	const wchar_t* m_command = nullptr;

public:

	CommandUnignore();
	virtual ~CommandUnignore();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args);
	virtual void PerformCommand(Connection& connection);
};

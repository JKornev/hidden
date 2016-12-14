#pragma once

#include "Commands.h"

class CommandHide : public ICommand
{
	const wchar_t* m_command = nullptr;

	EObjTypes       m_hideType;
	HidRegRootTypes m_regRootType;
	std::wstring    m_path;

public:

	CommandHide();
	virtual ~CommandHide();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args);
	virtual void PerformCommand(Connection& connection);

	virtual CommandPtr CreateInstance();
};

class CommandUnhide : public ICommand
{
	const wchar_t* m_command = nullptr;

	EObjTypes       m_hideType;
	HidObjId        m_targetId;
	bool            m_targetAll;

public:

	CommandUnhide();
	virtual ~CommandUnhide();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args);
	virtual void PerformCommand(Connection& connection);

	virtual CommandPtr CreateInstance();
};

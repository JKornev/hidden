#pragma once

#include "Commands.h"

enum EHideTypes {
	TypeFile,
	TypeDir,
	TypeRegKey,
	TypeRegVal,
	TypeUnknown,
};

class CommandHide : public ICommand
{
	const wchar_t* m_command = nullptr;

	EHideTypes      m_hideType;
	HidRegRootTypes m_regRootType;
	std::wstring    m_path;

	HidRegRootTypes GetRegType(std::wstring& path);

public:

	CommandHide();
	virtual ~CommandHide();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args);
	virtual void PerformCommand(Connection& connection);
};

class CommandUnhide : public ICommand
{
	const wchar_t* m_command = nullptr;

public:

	CommandUnhide();
	virtual ~CommandUnhide();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args);
	virtual void PerformCommand(Connection& connection);
};

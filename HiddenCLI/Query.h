#pragma once

#include "Commands.h"

class CommandQuery : public ICommand
{
	enum EQueryType {
		QueryProcess,
		QueryState,
	};

	const wchar_t* m_command = nullptr;

	EQueryType m_queryType;
	HidProcId  m_targetProcId;

public:

	CommandQuery();
	virtual ~CommandQuery();

	virtual bool CompareCommand(std::wstring& command);
	virtual void LoadArgs(Arguments& args, CommandModeType mode);
	virtual void PerformCommand(Connection& connection);

	virtual CommandPtr CreateInstance();
};


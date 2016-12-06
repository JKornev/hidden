#pragma once

#include "Helper.h"
#include "Connection.h"
#include <memory>

class ICommand
{
public:

	virtual ~ICommand() {};

	virtual bool CompareCommand(std::wstring& command) = 0;
	virtual void LoadArgs(Arguments& args) = 0;
	virtual void PerformCommand(Connection& connection) = 0;
};

class Commands
{
	typedef std::shared_ptr<ICommand> CommandPtr;

	std::vector<CommandPtr> m_commandsStack;
	CommandPtr m_current;

	void LoadCommandsStack();

public:

	Commands(Arguments& args);
	~Commands();

	void Perform(Connection& connection);
};

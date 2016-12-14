#pragma once

#include "Helper.h"
#include "Connection.h"
#include <memory>

class ICommand
{
public:
	typedef std::shared_ptr<ICommand> CommandPtrInternal;

	virtual ~ICommand() {};

	virtual bool CompareCommand(std::wstring& command) = 0;
	virtual void LoadArgs(Arguments& args) = 0;
	virtual void PerformCommand(Connection& connection) = 0;
	
	virtual CommandPtrInternal CreateInstance() = 0;
};

typedef ICommand::CommandPtrInternal CommandPtr;

class ICommandMode
{
public:
	virtual ~ICommandMode() {}
	virtual void Perform(Connection& connection) = 0;
};

typedef std::shared_ptr<ICommandMode> CommandModePtr;

class SingleCommand : public ICommandMode
{
	std::vector<CommandPtr> m_commandsStack;
	CommandPtr m_current;

public:

	SingleCommand(Arguments& args);
	virtual ~SingleCommand();

	virtual void Perform(Connection& connection);
};

class MultipleCommands : public ICommandMode
{
	std::vector<CommandPtr> m_commandsStack;
	std::vector<CommandPtr> m_currentStack;

public:

	MultipleCommands(Arguments& args);
	virtual ~MultipleCommands();

	virtual void Perform(Connection& connection);
};

class MultipleCommandsFromFile : public ICommandMode
{
	std::vector<CommandPtr> m_commandsStack;
	std::vector<CommandPtr> m_currentStack;

public:

	MultipleCommandsFromFile(Arguments& args);
	virtual ~MultipleCommandsFromFile();

	virtual void Perform(Connection& connection);
};

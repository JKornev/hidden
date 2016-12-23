#pragma once

#include "Helper.h"
#include "Connection.h"
#include <memory>

enum CommandModeType {
	Execute,
	Install,
	Uninstall
};

class ICommand
{
public:
	typedef std::shared_ptr<ICommand> CommandPtrInternal;

	virtual ~ICommand() {};

	virtual bool CompareCommand(std::wstring& command) = 0;
	virtual void LoadArgs(Arguments& args, CommandModeType mode) = 0;
	virtual void PerformCommand(Connection& connection) = 0;
	virtual void InstallCommand(RegistryKey& configKey);
	virtual void UninstallCommand(RegistryKey& configKey);
	
	virtual CommandPtrInternal CreateInstance() = 0;
};

typedef ICommand::CommandPtrInternal CommandPtr;

class CommandMode
{
	std::wstring m_regConfigPath;
	CommandModeType m_type;

	void LoadConfigPath(Arguments& args);

public:
	CommandMode(Arguments& args);

	CommandModeType GetModeType();
	const std::wstring& GetConfigRegistryKeyPath();
};

class ICommandTemplate
{
public:
	virtual ~ICommandTemplate() {}
	virtual void Perform(Connection& connection) = 0;
	virtual void Install(RegistryKey& configKey) = 0;
	virtual void Uninstall(RegistryKey& configKey) = 0;
};

typedef std::shared_ptr<ICommandTemplate> CommandTemplatePtr;

class SingleCommand : public ICommandTemplate
{
	std::vector<CommandPtr> m_commandsStack;
	CommandPtr m_current;

public:

	SingleCommand(Arguments& args, CommandModeType mode);
	virtual ~SingleCommand();

	virtual void Perform(Connection& connection);
	virtual void Install(RegistryKey& configKey);
	virtual void Uninstall(RegistryKey& configKey);
};

class MultipleCommands : public ICommandTemplate
{
	std::vector<CommandPtr> m_commandsStack;
	std::vector<CommandPtr> m_currentStack;

public:

	MultipleCommands(Arguments& args, CommandModeType mode);
	virtual ~MultipleCommands();

	virtual void Perform(Connection& connection);
	virtual void Install(RegistryKey& configKey);
	virtual void Uninstall(RegistryKey& configKey);
};

class MultipleCommandsFromFile : public ICommandTemplate
{
	std::vector<CommandPtr> m_commandsStack;
	std::vector<CommandPtr> m_currentStack;

public:

	MultipleCommandsFromFile(Arguments& args, CommandModeType mode);
	virtual ~MultipleCommandsFromFile();

	virtual void Perform(Connection& connection);
	virtual void Install(RegistryKey& configKey);
	virtual void Uninstall(RegistryKey& configKey);
};

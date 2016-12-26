#include "Commands.h"
#include "Hide.h"
#include "Ignore.h"
#include "Protect.h"
#include "Query.h"
#include "State.h"
#include <fstream>
#include <algorithm>
#include <iostream>

using namespace std;

// =================

void LoadCommandsStack(vector<CommandPtr>& stack)
{
	stack.push_back(CommandPtr(new CommandHide()));
	stack.push_back(CommandPtr(new CommandUnhide()));
	stack.push_back(CommandPtr(new CommandIgnore()));
	stack.push_back(CommandPtr(new CommandUnignore()));
	stack.push_back(CommandPtr(new CommandProtect()));
	stack.push_back(CommandPtr(new CommandUnprotect()));
	stack.push_back(CommandPtr(new CommandQuery()));
	stack.push_back(CommandPtr(new CommandState()));
}

// =================

void ICommand::InstallCommand(RegistryKey& configKey) 
{
	throw WException(ERROR_UNSUPPORTED_TYPE, L"Error, install mode is not supported");
}

void ICommand::UninstallCommand(RegistryKey& configKey) 
{
}

// =================

CommandMode::CommandMode(Arguments& args) : m_type(CommandModeType::Execute)
{
	wstring mode, all;

	if (!args.Probe(mode))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, no command, please use 'hiddencli /help'");

	if (mode == L"/install")
	{
		args.SwitchToNext();
		m_type = CommandModeType::Install;
		LoadConfigPath(args);
	}
	else if (mode == L"/uninstall")
	{
		args.SwitchToNext();
		m_type = CommandModeType::Uninstall;
		LoadConfigPath(args);
	}

	if (m_type == CommandModeType::Uninstall)
	{
		if (!args.Probe(all) || all != L"all")
			throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid '/unistall' format");

		args.SwitchToNext();
	}
}

void CommandMode::LoadConfigPath(Arguments& args)
{
	wstring path;

	if (!args.Probe(path) || path.compare(0, 1, L"/") == 0 || path == L"all")
	{
		m_regConfigPath = L"System\\CurrentControlSet\\Services\\Hidden";
		return;
	}

	args.SwitchToNext();
	
	m_regConfigPath = L"System\\CurrentControlSet\\Services\\";
	m_regConfigPath += path;
}

CommandModeType CommandMode::GetModeType()
{
	return m_type;
}

const wstring& CommandMode::GetConfigRegistryKeyPath()
{
	return m_regConfigPath;
}

// =================

SingleCommand::SingleCommand(Arguments& args, CommandModeType mode)
{
	wstring arg;
	bool found = false;

	if (mode == CommandModeType::Uninstall)
	{
		if (args.SwitchToNext())
			throw WException(ERROR_INVALID_PARAMETER, L"Error, too many arguments");

		LoadCommandsStack(m_commandsStack);
		return;
	}

	if (!args.GetNext(arg))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, no command, please use 'hiddencli /help'");

	LoadCommandsStack(m_commandsStack);

	for (auto it = m_commandsStack.begin(); it != m_commandsStack.end(); it++)
	{
		if ((*it)->CompareCommand(arg))
		{
			(*it)->LoadArgs(args, mode);
			m_current = *it;
			found = true;
			break;
		}
	}

	if (!found)
		throw WException(ERROR_INVALID_PARAMETER, L"Error, unknown command, please use 'hiddencli /help'");

	if (args.SwitchToNext())
		throw WException(ERROR_INVALID_PARAMETER, L"Error, too many arguments");
}

SingleCommand::~SingleCommand()
{
}

void SingleCommand::Perform(Connection& connection)
{
	m_current->PerformCommand(connection);
}

void SingleCommand::Install(RegistryKey& configKey)
{
	m_current->InstallCommand(configKey);
}

void SingleCommand::Uninstall(RegistryKey& configKey)
{
	for (auto it = m_commandsStack.begin(); it != m_commandsStack.end(); it++)
	{
		try 
		{
			(*it)->UninstallCommand(configKey);
		}
		catch (WException&)
		{ 
			// Skip exceptions because we don't wan't break uninstall on registry deletion fails
		}
	}
}

// =================

MultipleCommands::MultipleCommands(Arguments& args, CommandModeType mode)
{
	wstring arg;

	if (mode == CommandModeType::Uninstall)
		throw WException(ERROR_INVALID_PARAMETER, L"Error, /uninstall can't be combined with /multi");

	if (!args.GetNext(arg))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, no command, please use 'hiddencli /help'");

	LoadCommandsStack(m_commandsStack);

	do
	{
		bool found = false;

		for (auto it = m_commandsStack.begin(); it != m_commandsStack.end(); it++)
		{
			if ((*it)->CompareCommand(arg))
			{
				CommandPtr command = (*it)->CreateInstance();
				command->LoadArgs(args, mode);
				m_currentStack.push_back(command);
				found = true;
				break;
			}
		}

		if (!found)
			throw WException(ERROR_INVALID_PARAMETER, L"Error, unknown command, please use 'hiddencli /help'");
	} 
	while (args.GetNext(arg));
}

MultipleCommands::~MultipleCommands()
{
}

void MultipleCommands::Perform(Connection& connection)
{
	for (auto it = m_currentStack.begin(); it != m_currentStack.end(); it++)
		(*it)->PerformCommand(connection);
}

void MultipleCommands::Install(RegistryKey& configKey)
{
	for (auto it = m_currentStack.begin(); it != m_currentStack.end(); it++)
		(*it)->InstallCommand(configKey);
}

void MultipleCommands::Uninstall(RegistryKey& configKey)
{
	throw WException(ERROR_UNSUPPORTED_TYPE, L"Error, uninstall mode is not supported");
}

// =================

class ArgsParser
{
private:

	shared_ptr<Arguments> m_args;
	bool m_haveArgs;

public:

	ArgsParser(wstring& line) : m_haveArgs(false)
	{
		int argc;
		LPWSTR* argv;

		if (line.compare(0, 1, L";") == 0) // comment
			return;

		if (all_of(line.begin(), line.end(), isspace)) // whitespace only string
			return;

		argv = CommandLineToArgvW(line.c_str(), &argc);
		if (!argv)
			throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid command format");

		try
		{
			m_args.reset(new Arguments(argc, argv, 0));
		}
		catch (WException& e)
		{
			LocalFree(argv);
			throw e;
		}

		LocalFree(argv);
		m_haveArgs = true;
	}

	bool HaveArgs()
	{
		return m_haveArgs;
	}

	Arguments& GetArgs()
	{
		return *m_args.get();
	}

};

MultipleCommandsFromFile::MultipleCommandsFromFile(Arguments& args, CommandModeType mode)
{
	wstring configFile;

	if (mode == CommandModeType::Uninstall)
		throw WException(ERROR_INVALID_PARAMETER, L"Error, /uninstall can't be combined with /config");

	if (!args.GetNext(configFile))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, no command, please use 'hiddencli /help'");

	if (args.SwitchToNext())
		throw WException(ERROR_INVALID_PARAMETER, L"Error, too many arguments");

	wifstream fconfig(configFile);
	wstring line;

	LoadCommandsStack(m_commandsStack);

	while (getline(fconfig, line))
	{
		ArgsParser parser(line);
		wstring arg;

		if (parser.HaveArgs())
		{
			Arguments lineArgs = parser.GetArgs();

			if (!lineArgs.GetNext(arg))
				throw WException(ERROR_INVALID_PARAMETER, L"Error, no command, please use 'hiddencli /help'");

			do
			{
				bool found = false;

				for (auto it = m_commandsStack.begin(); it != m_commandsStack.end(); it++)
				{
					if ((*it)->CompareCommand(arg))
					{
						CommandPtr command = (*it)->CreateInstance();
						command->LoadArgs(lineArgs, mode);
						m_currentStack.push_back(command);
						found = true;
						break;
					}
				}

				if (!found)
					throw WException(ERROR_INVALID_PARAMETER, L"Error, unknown command, please use 'hiddencli /help'");
			} 
			while (lineArgs.GetNext(arg));
		}
	}
}

MultipleCommandsFromFile::~MultipleCommandsFromFile()
{
}

void MultipleCommandsFromFile::Perform(Connection& connection)
{
	for (auto it = m_currentStack.begin(); it != m_currentStack.end(); it++)
		(*it)->PerformCommand(connection);
}

void MultipleCommandsFromFile::Install(RegistryKey& configKey)
{
	for (auto it = m_currentStack.begin(); it != m_currentStack.end(); it++)
		(*it)->InstallCommand(configKey);
}

void MultipleCommandsFromFile::Uninstall(RegistryKey& configKey)
{
	throw WException(ERROR_UNSUPPORTED_TYPE, L"Error, uninstall mode is not supported");
}

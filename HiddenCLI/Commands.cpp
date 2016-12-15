#include "Commands.h"
#include "Hide.h"
#include "Ignore.h"
#include "Protect.h"
#include "Query.h"
#include "State.h"
#include <fstream>
#include <algorithm>

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

SingleCommand::SingleCommand(Arguments& args)
{
	wstring arg;
	bool found = false;

	if (!args.GetNext(arg))
		throw WException(-2, L"Error, no command, please use 'hiddencli /help'");

	LoadCommandsStack(m_commandsStack);

	for (auto it = m_commandsStack.begin(); it != m_commandsStack.end(); it++)
	{
		if ((*it)->CompareCommand(arg))
		{
			(*it)->LoadArgs(args);
			m_current = *it;
			found = true;
			break;
		}
	}

	if (!found)
		throw WException(-2, L"Error, unknown command, please use 'hiddencli /help'");

	if (args.SwitchToNext())
		throw WException(-2, L"Error, too many arguments");
}

SingleCommand::~SingleCommand()
{
}

void SingleCommand::Perform(Connection& connection)
{
	m_current->PerformCommand(connection);
}

// =================

MultipleCommands::MultipleCommands(Arguments& args)
{
	wstring arg;

	if (!args.GetNext(arg))
		throw WException(-2, L"Error, no command, please use 'hiddencli /help'");

	LoadCommandsStack(m_commandsStack);

	do
	{
		bool found = false;

		for (auto it = m_commandsStack.begin(); it != m_commandsStack.end(); it++)
		{
			if ((*it)->CompareCommand(arg))
			{
				CommandPtr command = (*it)->CreateInstance();
				command->LoadArgs(args);
				m_currentStack.push_back(command);
				found = true;
				break;
			}
		}

		if (!found)
			throw WException(-2, L"Error, unknown command, please use 'hiddencli /help'");
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
			throw WException(-2, L"Error, invalid command format");

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

MultipleCommandsFromFile::MultipleCommandsFromFile(Arguments& args)
{
	wstring configFile;

	if (!args.GetNext(configFile))
		throw WException(-2, L"Error, no command, please use 'hiddencli /help'");

	if (args.SwitchToNext())
		throw WException(-2, L"Error, too many arguments");

	wifstream config(configFile);
	wstring line;

	LoadCommandsStack(m_commandsStack);

	while (getline(config, line))
	{
		ArgsParser parser(line);
		wstring arg;

		if (parser.HaveArgs())
		{
			Arguments lineArgs = parser.GetArgs();

			if (!lineArgs.GetNext(arg))
				throw WException(-2, L"Error, no command, please use 'hiddencli /help'");

			do
			{
				bool found = false;

				for (auto it = m_commandsStack.begin(); it != m_commandsStack.end(); it++)
				{
					if ((*it)->CompareCommand(arg))
					{
						CommandPtr command = (*it)->CreateInstance();
						command->LoadArgs(lineArgs);
						m_currentStack.push_back(command);
						found = true;
						break;
					}
				}

				if (!found)
					throw WException(-2, L"Error, unknown command, please use 'hiddencli /help'");
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


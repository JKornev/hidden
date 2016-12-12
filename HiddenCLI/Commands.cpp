#include "Commands.h"
#include "Hide.h"
#include "Ignore.h"
#include "Protect.h"
#include "Query.h"
#include "State.h"

using namespace std;

// =================

Commands::Commands(Arguments& args)
{
	wstring arg;

	if (!args.GetNext(arg))
		throw WException(-2, L"Error, no command, please use 'hiddencli help'");

	LoadCommandsStack();
	
	do
	{
		bool found = false;

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
			throw WException(-2, L"Error, unknown command, please use 'hiddencli help'");
	}
	while (args.GetNext(arg));

}

Commands::~Commands()
{
}

void Commands::LoadCommandsStack()
{
	m_commandsStack.push_back(CommandPtr(new CommandHide()));
	m_commandsStack.push_back(CommandPtr(new CommandUnhide()));
	m_commandsStack.push_back(CommandPtr(new CommandIgnore()));
	m_commandsStack.push_back(CommandPtr(new CommandUnignore()));
	m_commandsStack.push_back(CommandPtr(new CommandProtect()));
	m_commandsStack.push_back(CommandPtr(new CommandUnprotect()));
	m_commandsStack.push_back(CommandPtr(new CommandQuery()));
	m_commandsStack.push_back(CommandPtr(new CommandState()));
}

void Commands::Perform(Connection& connection)
{
	m_current->PerformCommand(connection);
}

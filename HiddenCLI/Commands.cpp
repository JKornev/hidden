#include "Commands.h"
#include "Hide.h"

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
		for (auto it = m_commandsStack.begin(); it != m_commandsStack.end(); it++)
		{
			if ((*it)->CompareCommand(arg))
			{
				(*it)->LoadArgs(args);
				break;
			}
		}
	}
	while (args.GetNext(arg));
}

Commands::~Commands()
{

}

void Commands::LoadCommandsStack()
{
	m_commandsStack.push_back(new CommandHide());
	m_commandsStack.push_back(new CommandUnhide());
}

void Commands::Perform(Connection& connection)
{

}

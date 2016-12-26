#include <Windows.h>
#include <iostream>
#include <string>
#include <stdio.h>
#include "Helper.h"
#include "Connection.h"
#include "Commands.h"

using namespace std;

bool PrintUsage(Arguments& args)
{
	wstring command;

	if (!args.Probe(command))
		return false;

	if (command != L"/help" && command != L"/?")
		return false;
	
	wchar_t message[] =
		L"hiddencli [mode] [connection] [perform] <command>\n"
		L"hiddencli /help\n"
		L"\n"
		L"mode:\n"
		L"\n"
		L"  By default perform current commands\n"
		L"\n"
		L"  /install [%driver%]\n"
		L"    Install commands to registry without execution, driver will load them on\n"
		L"    start. If this flag is set connection parameters shouldn't be set. Optional\n"
		L"    parameter is used for set valid registry path if driver name is changed, by\n"
		L"    default \"hidden\"\n"
		L"\n"
		L"  /uninstall [%driver%] all\n"
		L"    Uninstall all configs from registry. This flag is all-sufficient therefore\n"
		L"    if this flag is set no other parameters and commands should be set after\n"
		L"\n"
		L"connection:\n"
		L"\n"
		L"  /gate <%name%>\n"
		L"    Set specific connection gate name. By default \"HiddenGate\" is used\n"
		L"\n"
		L"perform:\n"
		L"\n"
		L"  By default perform one command by one execution\n"
		L"\n"
		L"  /multi\n"
		L"    Enable multiple commands per execution, just type commands one by one\n"
		L"    without any separator\n"
		L"\n"
		L"  /config <%path%>\n"
		L"    Loads multiple commands from file, each command should be on separate line\n"
		L"\n"
		L"commands:\n"
		L"\n"
		L"  /state <on|off>\n"
		L"    Enable or disable hidden\n"
		L"\n"
		L"  /query state\n"
		L"    Get enforcement state\n"
		L"\n"
		L"  /hide <file|dir|regval|regkey> <%path%>\n"
		L"    Hide filesystem or registry object by path\n"
		L"\n"
		L"  /unhide <file|dir|regval|regkey> all\n"
		L"    Unhide all filesystem or registry object by selected type\n"
		L"\n"
		L"  /unhide <file|dir|regval|regkey> <%ruleid%>\n"
		L"    Unhide all filesystem or registry object by selected type and rule ID\n"
		L"\n"
		L"  /ignore image [inherit:<none|always|once>] [apply:<fornew|forall>] <%path%>\n"
		L"    Set rule that allows to see hidden filesystem and registry objects for\n"
		L"    processes with specific image path\n"
		L"\n"
		L"  /unignore <%ruleid%>\n"
		L"    Remove rule that allows to see hidden filesystem and registry objects by\n"
		L"    rule ID\n"
		L"\n"
		L"  /unignore all\n"
		L"    Remove all rules that allow to see hidden filesystem and registry objects\n"
		L"\n"
		L"  /ignore pid [inherit:<none|always|once>] <%pid%>\n"
		L"    Turn on abillity to see hidden filesystem and registry objects for\n"
		L"    specific process by PID\n"
		L"\n"
		L"  /unignore pid <%pid%>\n"
		L"    Turn off abillity to see hidden filesystem and registry objects for\n"
		L"    specific process by PID\n"
		L"\n"
		L"  /protect image [inherit:<none|always|once>] [apply:<fornew|forall>] <%path%>\n"
		L"    Set rule that allows to enable process protection for processes with\n"
		L"    specific image path\n"
		L"\n"
		L"  /unprotect <%ruleid%>\n"
		L"    Remove rule that enables process protection by rule ID\n"
		L"\n"
		L"  /unprotect all\n"
		L"    Remove all rules that enable process protection\n"
		L"\n"
		L"  /protect pid [inherit:<none|always|once>] <%pid%>\n"
		L"    Turn on protection for specific process by PID\n"
		L"\n"
		L"  /unprotect pid <%pid%>\n"
		L"    Turn off protection for specific process by PID\n"
		L"\n"
		L"  /query process <%pid%>\n"
		L"    Query information about state of the process by PID\n"
		L"\n"
		L"options:\n"
		L"\n"
		L"  inherit:none\n"
		L"    Disable inheritance of the protected or ignored state\n"
		L"\n"
		L"  inherit:once\n"
		L"    Child process will inherit the same state but its children no\n"
		L"\n"
		L"  inherit:always\n"
		L"    Child process will inherit the same state and its children too\n"
		L"\n"
		L"  apply:forall\n"
		L"    Apply policy for existing processes and for all new processes\n"
		L"\n"
		L"  apply:fornew\n"
		L"    Don't apply policy for existing processes only for new\n";

	wcout << message << endl;
	return true;
}

CommandTemplatePtr LoadCommandsTemplate(Arguments& args, CommandMode& mode)
{
	wstring templateType;

	if (mode.GetModeType() == CommandModeType::Uninstall)
		return CommandTemplatePtr(new SingleCommand(args, mode.GetModeType()));

	if (!args.Probe(templateType))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, unknown perform mode, please use 'hiddencli /help'");

	if (templateType == L"/multi")
	{
		args.SwitchToNext();
		return CommandTemplatePtr(new MultipleCommands(args, mode.GetModeType()));
	}
	else if (templateType == L"/config")
	{
		args.SwitchToNext();
		return CommandTemplatePtr(new MultipleCommandsFromFile(args, mode.GetModeType()));
	}
	
	return CommandTemplatePtr(new SingleCommand(args, mode.GetModeType()));
}

int wmain(int argc, wchar_t* argv[])
{
	try 
	{
		Arguments arguments(argc , argv);

		if (!arguments.ArgsCount())
			throw WException(
				ERROR_INVALID_PARAMETER,
				L"Welcome to HiddenCLI, please use 'hiddencli /help'"
			);

		if (PrintUsage(arguments))
			return 0;


		CommandMode mode(arguments);

		if (mode.GetModeType() == CommandModeType::Execute)
		{
			Connection connection(arguments);
			{
				CommandTemplatePtr commands = LoadCommandsTemplate(arguments, mode);
				connection.Open();
				commands->Perform(connection);
			}
		}
		else if (mode.GetModeType() == CommandModeType::Install)
		{
			LibInitializator lib;
			{
				CommandTemplatePtr commands = LoadCommandsTemplate(arguments, mode);
				RegistryKey key(mode.GetConfigRegistryKeyPath());
				commands->Install(key);
			}
		}
		else if (mode.GetModeType() == CommandModeType::Uninstall)
		{
			LibInitializator lib;
			{
				CommandTemplatePtr commands = LoadCommandsTemplate(arguments, mode);
				RegistryKey key(mode.GetConfigRegistryKeyPath());
				commands->Uninstall(key);
			}
		}

		const wstring output = g_stdout.str();

		wcerr << g_stderr.str();
		
		if (output.empty())
			wcout << L"status:ok" << endl;
		else
			wcout << L"status:ok;" << output << endl;
	}
	catch (WException& exception)
	{
		wcerr << exception.What() << endl;
		wcout << L"status:failed" << endl;
		return exception.Code();
	}
	catch (exception& exception)
	{
		cerr << exception.what() << endl;
		wcout << L"status:failed" << endl;
		return -1;
	}

	return 0;
}

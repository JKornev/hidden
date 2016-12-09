#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include "Helper.h"
#include "Connection.h"
#include "Commands.h"

using namespace std;

int wmain(int argc, wchar_t* argv[])
{
	try 
	{
		Arguments arguments(argc, argv);
		Connection connection(arguments);

		if (!arguments.ArgsCount())
			throw WException(
				-2,
				L"Welcome to HiddenCLI, please use 'hiddencli /help'"
			);

		{
			Commands commands(arguments);

			connection.Open();
			commands.Perform(connection);
		}
	}
	catch (WException& exception)
	{
		wcerr << exception.What() << endl;
		return exception.Code();
	}
	catch (exception& exception)
	{
		cerr << exception.what() << endl;
		return -1;
	}

	return 0;
}

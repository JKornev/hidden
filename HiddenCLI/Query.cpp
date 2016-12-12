#include "Query.h"
#include <iostream>

using namespace std;

CommandQuery::CommandQuery() : m_command(L"/query")
{
}

CommandQuery::~CommandQuery()
{
}

bool CommandQuery::CompareCommand(std::wstring& command)
{
	return (command == m_command);
}

void CommandQuery::LoadArgs(Arguments& args)
{
	wstring object, target;

	if (!args.GetNext(object))
		throw WException(-2, L"Error, mismatched argument #1 for command 'query'");

	if (object == L"process")
	{
		m_queryType = EQueryType::QueryProcess;

		if (!args.GetNext(target))
			throw WException(-2, L"Error, mismatched argument #2 for command 'query'");

		m_targetProcId = _wtol(target.c_str());
		if (!m_targetProcId)
			throw WException(-2, L"Error, invalid target pid for command 'query'");
	}
	else if (object == L"state")
	{
		m_queryType = EQueryType::QueryState;
	}
	else
	{

		throw WException(-2, L"Error, invalid object type for command 'query'");
	}
}

void CommandQuery::PerformCommand(Connection& connection)
{
	HidStatus status;

	if (m_queryType == EQueryType::QueryState)
	{
		HidActiveState state;

		status = Hid_GetState(connection.GetContext(), &state);
		if (!HID_STATUS_SUCCESSFUL(status))
			throw WException(HID_STATUS_CODE(status), L"Error, query state rejected");

		wcerr << L"Driver state:" << (state == HidActiveState::StateEnabled ? L"enabled" : L"disabled") << endl;
		wcout << L"status:ok;state:" << (state == HidActiveState::StateEnabled ? 1 : 0) << endl;
	}
	else if (m_queryType == EQueryType::QueryProcess)
	{
		HidActiveState excludeState, protectedState;
		HidPsInheritTypes excludedInherit, protectedInherit;

		status = Hid_GetExcludedState(connection.GetContext(), m_targetProcId, &excludeState, &excludedInherit);
		if (!HID_STATUS_SUCCESSFUL(status))
			throw WException(HID_STATUS_CODE(status), L"Error, query ignored state rejected");

		status = Hid_GetProtectedState(connection.GetContext(), m_targetProcId, &protectedState, &protectedInherit);
		if (!HID_STATUS_SUCCESSFUL(status))
			throw WException(HID_STATUS_CODE(status), L"Error, query protected state rejected");

		wcerr << L"Ignored state:" << (excludeState == HidActiveState::StateEnabled ? L"true" : L"false")
			<< L", inherit:" << ConvertInheritTypeToUnicode(excludedInherit) << endl;
		wcerr << L"Protected state:" << (protectedState == HidActiveState::StateEnabled ? L"true" : L"false")
			<< L", inherit:" << ConvertInheritTypeToUnicode(protectedInherit) << endl;

		wcout << L"status:ok;ignored:" << excludeState << L"," << excludedInherit
			<< L";protected:" << protectedState << L"," << protectedInherit << endl;
	}
}

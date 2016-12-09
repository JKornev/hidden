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

	if (object != L"process")
		throw WException(-2, L"Error, invalid object type for command 'query'");

	if (!args.GetNext(target))
		throw WException(-2, L"Error, mismatched argument #2 for command 'query'");

	m_targetProcId = _wtol(target.c_str());
	if (!m_targetProcId)
		throw WException(-2, L"Error, invalid target pid for command 'query'");
}

const wchar_t* ConvertInheritTypeToUnicode(HidPsInheritTypes type)
{
	switch (type)
	{
	case HidPsInheritTypes::WithoutInherit:
		return L"none";
		break;
	case HidPsInheritTypes::InheritOnce:
		return L"once";
		break;
	case HidPsInheritTypes::InheritAlways:
		return L"always";
		break;
	}
	return L"unknown";
}

void CommandQuery::PerformCommand(Connection& connection)
{
	HidStatus status;
	HidActiveState excludeState, protectedState;
	HidPsInheritTypes excludedInherit, protectedInherit;

	status = Hid_GetExcludedState(connection.GetContext(), m_targetProcId, &excludeState, &excludedInherit);
	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, query ignored state rejected");

	status = Hid_GetProtectedState(connection.GetContext(), m_targetProcId, &protectedState, &protectedInherit);
	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, query protected state rejected");

	wcerr << L"ignore state:" << (excludeState == HidActiveState::StateEnabled ? L"true" : L"false") 
		<< L", inherit:" << ConvertInheritTypeToUnicode(excludedInherit) << endl;
	wcerr << L"protect state:" << (protectedState == HidActiveState::StateEnabled ? L"true" : L"false")
		<< L", inherit:" << ConvertInheritTypeToUnicode(protectedInherit) << endl;

	wcout << L"status:ok;ignore:" << excludeState << L"," << excludedInherit 
		<< L";protect:" << protectedState << L"," << protectedInherit << endl;
}

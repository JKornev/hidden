#include "Ignore.h"
#include <iostream>

using namespace std;

// =================

CommandIgnore::CommandIgnore() : m_command(L"/ignore")
{
}

CommandIgnore::~CommandIgnore()
{
}

bool CommandIgnore::CompareCommand(std::wstring& command)
{
	return (command == m_command);
}

void CommandIgnore::LoadArgs(Arguments& args)
{
	wstring object, target;

	if (!args.GetNext(object))
		throw WException(-2, L"Error, mismatched argument #1 for command 'ignore'");

	if (object == L"image")
	{
		m_procType = EProcTypes::TypeImage;
	}
	else if (object == L"pid")
	{
		m_procType = EProcTypes::TypeProcessId;
	}
	else
	{
		throw WException(-2, L"Error, invalid object type in command 'ignore'");
	}

	m_inheritType = LoadInheritOption(args, HidPsInheritTypes::WithoutInherit);

	m_applyByDefault = false;
	if (m_procType == EProcTypes::TypeImage)
		m_applyByDefault = LoadApplyOption(args, m_applyByDefault);

	if (!args.GetNext(target))
		throw WException(-2, L"Error, mismatched argument #2 for command 'ignore'");

	if (m_procType == EProcTypes::TypeImage)
	{
		m_targetImage = target;
	}
	else
	{
		m_targetProcId = _wtoll(target.c_str());
		if (!m_targetProcId)
			throw WException(-2, L"Error, invalid target pid for command 'ignore'");
	}
}

void CommandIgnore::PerformCommand(Connection& connection)
{
	HidStatus status;
	HidObjId objId;

	switch (m_procType)
	{
	case EProcTypes::TypeProcessId:
		status = Hid_AttachExcludedState(connection.GetContext(), m_targetProcId, m_inheritType);
		break;
	case EProcTypes::TypeImage:
		status = Hid_AddExcludedImage(connection.GetContext(), m_targetImage.c_str(), m_inheritType, m_applyByDefault, &objId);
		break;
	default:
		throw WException(-2, L"Internal error, invalid type for command 'ignore'");
	}

	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, command 'ignore' rejected");

	wcerr << L"Command 'unhide' successful" << endl;
	if (EProcTypes::TypeProcessId)
		wcout << L"status:ok" << endl;
	else
		wcout << L"status:ok;objid:" << objId << endl;
}

HidPsInheritTypes CommandIgnore::LoadInheritOption(Arguments& args, HidPsInheritTypes default)
{
	return default;
}

bool CommandIgnore::LoadApplyOption(Arguments& args, bool applyByDefault)
{
	return applyByDefault;
}

// =================

CommandUnignore::CommandUnignore() : m_command(L"/unignore")
{
}

CommandUnignore::~CommandUnignore()
{
}

bool CommandUnignore::CompareCommand(std::wstring& command)
{
	return (command == m_command);
}

void CommandUnignore::LoadArgs(Arguments& args)
{
}

void CommandUnignore::PerformCommand(Connection& connection)
{
}

#include "Protect.h"
#include <iostream>

using namespace std;

// =================

CommandProtect::CommandProtect() : m_command(L"/protect")
{
}

CommandProtect::~CommandProtect()
{
}

bool CommandProtect::CompareCommand(std::wstring& command)
{
	return (command == m_command);
}

void CommandProtect::LoadArgs(Arguments& args)
{
	wstring object, target;

	if (!args.GetNext(object))
		throw WException(-2, L"Error, mismatched argument #1 for command 'protect'");

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
		throw WException(-2, L"Error, invalid object type in command 'protect'");
	}

	m_inheritType = LoadInheritOption(args, HidPsInheritTypes::WithoutInherit);

	m_applyByDefault = false;
	if (m_procType == EProcTypes::TypeImage)
		m_applyByDefault = LoadApplyOption(args, m_applyByDefault);

	if (!args.GetNext(target))
		throw WException(-2, L"Error, mismatched argument #2 for command 'protect'");

	if (m_procType == EProcTypes::TypeImage)
	{
		m_targetImage = target;
	}
	else
	{
		m_targetProcId = _wtol(target.c_str());
		if (!m_targetProcId)
			throw WException(-2, L"Error, invalid target pid for command 'protect'");
	}
}

void CommandProtect::PerformCommand(Connection& connection)
{
	HidStatus status;
	HidObjId objId;

	switch (m_procType)
	{
	case EProcTypes::TypeProcessId:
		status = Hid_AttachProtectedState(connection.GetContext(), m_targetProcId, m_inheritType);
		break;
	case EProcTypes::TypeImage:
		status = Hid_AddProtectedImage(connection.GetContext(), m_targetImage.c_str(), m_inheritType, m_applyByDefault, &objId);
		break;
	default:
		throw WException(-2, L"Internal error, invalid type for command 'protect'");
	}

	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, command 'protect' rejected");

	wcerr << L"Command 'protect' successful" << endl;
	if (m_procType == EProcTypes::TypeProcessId)
		wcout << L"status:ok" << endl;
	else
		wcout << L"status:ok;objid:" << objId << endl;
}

// =================

CommandUnprotect::CommandUnprotect() : m_command(L"/unprotect")
{
}

CommandUnprotect::~CommandUnprotect()
{
}

bool CommandUnprotect::CompareCommand(std::wstring& command)
{
	return (command == m_command);
}

void CommandUnprotect::LoadArgs(Arguments& args)
{
	wstring object, target;

	if (!args.GetNext(object))
		throw WException(-2, L"Error, mismatched argument #1 for command 'unprotect'");

	if (object == L"pid")
	{
		m_targetType = ETargetIdType::ProcId;

		if (!args.GetNext(target))
			throw WException(-2, L"Error, mismatched argument #2 for command 'unprotect'");

		m_targetProcId = _wtol(target.c_str());
		if (!m_targetProcId)
			throw WException(-2, L"Error, invalid target ruleid for command 'unprotect'");
	}
	else if (object == L"all")
	{
		m_targetType = ETargetIdType::All;
	}
	else
	{
		m_targetType = ETargetIdType::RuleId;

		m_targetId = _wtoll(object.c_str());
		if (!m_targetId)
			throw WException(-2, L"Error, invalid target ruleid for command 'unprotect'");
	}
}

void CommandUnprotect::PerformCommand(Connection& connection)
{
	HidStatus status;

	switch (m_targetType)
	{
	case ETargetIdType::All:
		status = Hid_RemoveAllProtectedImages(connection.GetContext());
		break;
	case ETargetIdType::ProcId:
		status = Hid_RemoveProtectedState(connection.GetContext(), m_targetProcId);
		break;
	case ETargetIdType::RuleId:
		status = Hid_RemoveProtectedImage(connection.GetContext(), m_targetId);
		break;
	default:
		throw WException(-2, L"Internal error, invalid type for command 'unprotect'");
	}

	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, command 'unprotect' rejected");

	wcerr << L"Command 'unprotect' successful" << endl;
	wcout << L"status:ok" << endl;
}

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

void CommandProtect::LoadArgs(Arguments& args, CommandModeType mode)
{
	wstring object, target;

	if (!args.GetNext(object))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument #1 for command 'protect'");

	if (object == L"image")
	{
		m_procType = EProcTypes::TypeImage;
	}
	else if (object == L"pid")
	{
		if (!CommandModeType::Execute)
			throw WException(ERROR_INVALID_PARAMETER, L"Error, target 'pid' isn't allowed");

		m_procType = EProcTypes::TypeProcessId;
	}
	else
	{
		throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid object type in command 'protect'");
	}

	m_inheritType = LoadInheritOption(args, HidPsInheritTypes::WithoutInherit);

	m_applyByDefault = false;
	if (m_procType == EProcTypes::TypeImage && mode == CommandModeType::Execute)
		m_applyByDefault = LoadApplyOption(args, m_applyByDefault);

	if (!args.GetNext(target))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument #2 for command 'protect'");

	if (m_procType == EProcTypes::TypeImage)
	{
		m_targetImage = target;
	}
	else
	{
		m_targetProcId = _wtol(target.c_str());
		if (!m_targetProcId)
			throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid target pid for command 'protect'");
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
		throw WException(ERROR_UNKNOWN_COMPONENT, L"Internal error, invalid type for command 'protect'");
	}

	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, command 'protect' rejected");

	g_stderr << L"Command 'protect' successful" << endl;
	if (m_procType == EProcTypes::TypeImage)
		g_stdout << L"status:ok;ruleid:" << objId << endl;
}

void CommandProtect::InstallCommand(RegistryKey& configKey)
{
	vector<wstring> commands;
	wstring temp, entry;
	HidStatus status;

	temp.insert(0, m_targetImage.size() + HID_NORMALIZATION_OVERHEAD, L'\0');

	status = Hid_NormalizeFilePath(m_targetImage.c_str(), const_cast<wchar_t*>(temp.c_str()), temp.size());
	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, can't normalize path, 'protect' rejected");

	entry += temp.c_str();
	entry += L";";
	entry += ConvertInheritTypeToUnicode(m_inheritType);

	configKey.GetMultiStrValue(L"Hid_ProtectedImages", commands);
	commands.push_back(entry);
	configKey.SetMultiStrValue(L"Hid_ProtectedImages", commands);

	g_stderr << L"Install 'protect' successful" << endl;
}

void CommandProtect::UninstallCommand(RegistryKey& configKey)
{
	configKey.RemoveValue(L"Hid_ProtectedImages");

	g_stderr << L"Uninstall 'protect' successful" << endl;
}

CommandPtr CommandProtect::CreateInstance()
{
	return CommandPtr(new CommandProtect());
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

void CommandUnprotect::LoadArgs(Arguments& args, CommandModeType mode)
{
	wstring object, target;

	if (mode != CommandModeType::Execute)
		throw WException(ERROR_INVALID_PARAMETER, L"Error, install/uninstall mode isn't supported for this command");

	if (!args.GetNext(object))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument #1 for command 'unprotect'");

	if (object == L"pid")
	{
		m_targetType = ETargetIdType::ProcId;

		if (!args.GetNext(target))
			throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument #2 for command 'unprotect'");

		m_targetProcId = _wtol(target.c_str());
		if (!m_targetProcId)
			throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid target ruleid for command 'unprotect'");
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
			throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid target ruleid for command 'unprotect'");
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
		throw WException(ERROR_UNKNOWN_COMPONENT, L"Internal error, invalid type for command 'unprotect'");
	}

	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, command 'unprotect' rejected");

	g_stderr << L"Command 'unprotect' successful" << endl;
}

CommandPtr CommandUnprotect::CreateInstance()
{
	return CommandPtr(new CommandUnprotect());
}

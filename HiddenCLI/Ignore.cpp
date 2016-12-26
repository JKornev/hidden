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

void CommandIgnore::LoadArgs(Arguments& args, CommandModeType mode)
{
	wstring object, target;

	if (!args.GetNext(object))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument #1 for command 'ignore'");

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
		throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid object type in command 'ignore'");
	}

	m_inheritType = LoadInheritOption(args, HidPsInheritTypes::WithoutInherit);

	m_applyByDefault = false;
	if (m_procType == EProcTypes::TypeImage && mode == CommandModeType::Execute)
		m_applyByDefault = LoadApplyOption(args, m_applyByDefault);

	if (!args.GetNext(target))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument #2 for command 'ignore'");

	if (m_procType == EProcTypes::TypeImage)
	{
		m_targetImage = target;
	}
	else
	{
		m_targetProcId = _wtol(target.c_str());
		if (!m_targetProcId)
			throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid target pid for command 'ignore'");
	}
}

void CommandIgnore::PerformCommand(Connection& connection)
{
	HidStatus status;
	HidObjId objId = 0;

	switch (m_procType)
	{
	case EProcTypes::TypeProcessId:
		status = Hid_AttachExcludedState(connection.GetContext(), m_targetProcId, m_inheritType);
		break;
	case EProcTypes::TypeImage:
		status = Hid_AddExcludedImage(connection.GetContext(), m_targetImage.c_str(), m_inheritType, m_applyByDefault, &objId);
		break;
	default:
		throw WException(ERROR_UNKNOWN_COMPONENT, L"Internal error, invalid type for command 'ignore'");
	}

	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, command 'ignore' rejected");

	g_stderr << L"Command 'ignore' successful" << endl;
	if (m_procType == EProcTypes::TypeImage)
		g_stdout << L"ruleid:" << objId << endl;
}

void CommandIgnore::InstallCommand(RegistryKey& configKey)
{
	vector<wstring> commands;
	wstring temp, entry;
	HidStatus status;

	temp.insert(0, m_targetImage.size() + HID_NORMALIZATION_OVERHEAD, L'\0');

	status = Hid_NormalizeFilePath(m_targetImage.c_str(), const_cast<wchar_t*>(temp.c_str()), temp.size());
	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, can't normalize path, 'ignore' rejected");

	entry += temp.c_str();
	entry += L";";
	entry += ConvertInheritTypeToUnicode(m_inheritType);

	configKey.GetMultiStrValue(L"Hid_IgnoredImages", commands);
	commands.push_back(entry);
	configKey.SetMultiStrValue(L"Hid_IgnoredImages", commands);

	g_stderr << L"Install 'ignore' successful" << endl;
}

void CommandIgnore::UninstallCommand(RegistryKey& configKey)
{
	configKey.RemoveValue(L"Hid_IgnoredImages");

	g_stderr << L"Uninstall 'ignore' successful" << endl;
}

CommandPtr CommandIgnore::CreateInstance()
{
	return CommandPtr(new CommandIgnore());
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

void CommandUnignore::LoadArgs(Arguments& args, CommandModeType mode)
{
	wstring object, target;

	if (mode != CommandModeType::Execute)
		throw WException(ERROR_INVALID_PARAMETER, L"Error, install/uninstall mode isn't supported for this command");

	if (!args.GetNext(object))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument #1 for command 'unignore'");

	if (object == L"pid")
	{
		m_targetType = ETargetIdType::ProcId;

		if (!args.GetNext(target))
			throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument #2 for command 'unignore'");

		m_targetProcId = _wtol(target.c_str());
		if (!m_targetProcId)
			throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid target ruleid for command 'unignore'");
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
			throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid target ruleid for command 'unignore'");
	}
}

void CommandUnignore::PerformCommand(Connection& connection)
{
	HidStatus status;

	switch (m_targetType)
	{
	case ETargetIdType::All:
		status = Hid_RemoveAllExcludedImages(connection.GetContext());
		break;
	case ETargetIdType::ProcId:
		status = Hid_RemoveExcludedState(connection.GetContext(), m_targetProcId);
		break;
	case ETargetIdType::RuleId:
		status = Hid_RemoveExcludedImage(connection.GetContext(), m_targetId);
		break;
	default:
		throw WException(ERROR_UNKNOWN_COMPONENT, L"Internal error, invalid type for command 'unignore'");
	}

	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, command 'unignore' rejected");

	g_stderr << L"Command 'unignore' successful" << endl;
}

CommandPtr CommandUnignore::CreateInstance()
{
	return CommandPtr(new CommandUnignore());
}

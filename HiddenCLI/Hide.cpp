#include "Hide.h"
#include <iostream>
#include <algorithm>

using namespace std;

// =================

CommandHide::CommandHide() : m_command(L"/hide")
{
}

CommandHide::~CommandHide()
{
}

bool CommandHide::CompareCommand(std::wstring& command)
{
	return (command == m_command);
}

HidRegRootTypes CommandHide::GetTypeAndNormalizeRegPath(std::wstring& regPath)
{
	HidRegRootTypes type = GetRegType(regPath);
	size_t pos = regPath.find(L"\\");
	if (pos == wstring::npos)
		throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid registry path");

	regPath = std::move(wstring(regPath.c_str() + pos + 1));
	return type;
}

void CommandHide::LoadArgs(Arguments& args, CommandModeType mode)
{
	wstring object;

	if (!args.GetNext(object))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument #1 for command 'hide'");

	if (!args.GetNext(m_path))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument #2 for command 'hide'");

	if (object == L"file")
	{
		m_hideType = EObjTypes::TypeFile;
	}
	else if (object == L"dir")
	{
		m_hideType = EObjTypes::TypeDir;
	}
	else if (object == L"regkey")
	{
		m_hideType = EObjTypes::TypeRegKey;
		m_regRootType = GetTypeAndNormalizeRegPath(m_path);
	}
	else if (object == L"regval")
	{
		m_hideType = EObjTypes::TypeRegVal;
		m_regRootType = GetTypeAndNormalizeRegPath(m_path);
	}
	else
	{
		throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid argument for command 'hide'");
	}
}

void CommandHide::PerformCommand(Connection& connection)
{
	HidStatus status;
	HidObjId objId;

	switch (m_hideType)
	{
	case EObjTypes::TypeFile:
		status = Hid_AddHiddenFile(connection.GetContext(), m_path.c_str(), &objId);
		break;
	case EObjTypes::TypeDir:
		status = Hid_AddHiddenDir(connection.GetContext(), m_path.c_str(), &objId);
		break;
	case EObjTypes::TypeRegKey:
		status = Hid_AddHiddenRegKey(connection.GetContext(), m_regRootType, m_path.c_str(), &objId);
		break;
	case EObjTypes::TypeRegVal:
		status = Hid_AddHiddenRegValue(connection.GetContext(), m_regRootType, m_path.c_str(), &objId);
		break;
	default:
		throw WException(ERROR_UNKNOWN_COMPONENT, L"Internal error, invalid type for command 'hide'");
	}

	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, command 'hide' rejected");

	g_stderr << L"Command 'hide' successful" << endl;
	g_stdout << L"ruleid:" << objId << endl;
}

void CommandHide::InstallCommand(RegistryKey& configKey)
{
	vector<wstring> commands;
	const wchar_t* valueName;
	HidStatus status;
	wstring entry;

	entry.insert(0, m_path.size() + HID_NORMALIZATION_OVERHEAD, L'\0');

	switch (m_hideType)
	{
	case EObjTypes::TypeFile:
		valueName = L"Hid_HideFsFiles";
		status = Hid_NormalizeFilePath(m_path.c_str(), const_cast<wchar_t*>(entry.c_str()), entry.size());
		break;
	case EObjTypes::TypeDir:
		valueName = L"Hid_HideFsDirs";
		status = Hid_NormalizeFilePath(m_path.c_str(), const_cast<wchar_t*>(entry.c_str()), entry.size());
		break;
	case EObjTypes::TypeRegKey:
		valueName = L"Hid_HideRegKeys";
		status = Hid_NormalizeRegistryPath(m_regRootType, m_path.c_str(), const_cast<wchar_t*>(entry.c_str()), entry.size());
		break;
	case EObjTypes::TypeRegVal:
		valueName = L"Hid_HideRegValues";
		status = Hid_NormalizeRegistryPath(m_regRootType, m_path.c_str(), const_cast<wchar_t*>(entry.c_str()), entry.size());
		break;
	default:
		throw WException(ERROR_UNKNOWN_COMPONENT, L"Internal error, invalid type for command 'hide'");
	}
	
	configKey.GetMultiStrValue(valueName, commands);
	commands.push_back(entry);
	configKey.SetMultiStrValue(valueName, commands);

	g_stderr << L"Install 'hide' successful" << endl;
}

void CommandHide::UninstallCommand(RegistryKey& configKey)
{
	int errors = 0;

	try { configKey.RemoveValue(L"Hid_HideFsFiles");   } catch (...) { errors++; }
	try { configKey.RemoveValue(L"Hid_HideFsDirs");    } catch (...) { errors++; }
	try { configKey.RemoveValue(L"Hid_HideRegKeys");   } catch (...) { errors++; }
	try { configKey.RemoveValue(L"Hid_HideRegValues"); } catch (...) { errors++; }

	if (errors < 4)
		g_stderr << L"Uninstall 'hide' successful" << endl;
}

CommandPtr CommandHide::CreateInstance()
{
	return CommandPtr(new CommandHide());
}

// =================

CommandUnhide::CommandUnhide() : m_command(L"/unhide")
{
	m_targetId = 0;
}

CommandUnhide::~CommandUnhide()
{
}

bool CommandUnhide::CompareCommand(std::wstring& command)
{
	return (command == m_command);
}

void CommandUnhide::LoadArgs(Arguments& args, CommandModeType mode)
{
	wstring object, target;

	if (!args.GetNext(object))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument #1 for command 'unhide'");

	if (!args.GetNext(target))
		throw WException(ERROR_INVALID_PARAMETER, L"Error, mismatched argument #2 for command 'unhide'");

	if (object == L"file")
	{
		m_hideType = EObjTypes::TypeFile;
	}
	else if (object == L"dir")
	{
		m_hideType = EObjTypes::TypeDir;
	}
	else if (object == L"regkey")
	{
		m_hideType = EObjTypes::TypeRegKey;
	}
	else if (object == L"regval")
	{
		m_hideType = EObjTypes::TypeRegVal;
	}
	else
	{
		throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid argument for command 'unhide'");
	}

	m_targetAll = (target == L"all");
	if (!m_targetAll)
	{
		m_targetId = _wtoll(target.c_str());
		if (!m_targetId)
			throw WException(ERROR_INVALID_PARAMETER, L"Error, invalid target objid for command 'unhide'");
	}
}

void CommandUnhide::PerformCommand(Connection& connection)
{
	HidStatus status;

	if (m_targetAll)
	{
		switch (m_hideType)
		{
		case EObjTypes::TypeFile:
			status = Hid_RemoveAllHiddenFiles(connection.GetContext());
			break;
		case EObjTypes::TypeDir:
			status = Hid_RemoveAllHiddenDirs(connection.GetContext());
			break;
		case EObjTypes::TypeRegKey:
			status = Hid_RemoveAllHiddenRegKeys(connection.GetContext());
			break;
		case EObjTypes::TypeRegVal:
			status = Hid_RemoveAllHiddenRegValues(connection.GetContext());
			break;
		default:
			throw WException(ERROR_UNKNOWN_COMPONENT, L"Internal error #1, invalid type for command 'unhide'");
		}
	}
	else
	{
		switch (m_hideType)
		{
		case EObjTypes::TypeFile:
			status = Hid_RemoveHiddenFile(connection.GetContext(), m_targetId);
			break;
		case EObjTypes::TypeDir:
			status = Hid_RemoveHiddenDir(connection.GetContext(), m_targetId);
			break;
		case EObjTypes::TypeRegKey:
			status = Hid_RemoveHiddenRegKey(connection.GetContext(), m_targetId);
			break;
		case EObjTypes::TypeRegVal:
			status = Hid_RemoveHiddenRegValue(connection.GetContext(), m_targetId);
			break;
		default:
			throw WException(ERROR_UNKNOWN_COMPONENT, L"Internal error #2, invalid type for command 'unhide'");
		}
	}

	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, command 'unhide' rejected");

	g_stderr << L"Command 'unhide' successful" << endl;
}

CommandPtr CommandUnhide::CreateInstance()
{
	return CommandPtr(new CommandUnhide());
}

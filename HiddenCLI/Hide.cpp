#include "Hide.h"
#include <iostream>

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

void CommandHide::LoadArgs(Arguments& args)
{
	wstring object;

	if (!args.GetNext(object))
		throw WException(-2, L"Error, mismatched argument #1 for command 'hide'");

	if (!args.GetNext(m_path))
		throw WException(-2, L"Error, mismatched argument #2 for command 'hide'");

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
		m_regRootType = GetRegType(m_path);
	}
	else if (object == L"regval")
	{
		m_hideType = EObjTypes::TypeRegVal;
		m_regRootType = GetRegType(m_path);
	}
	else
	{
		throw WException(-2, L"Error, invalid argument for command 'hide'");
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
		throw WException(-2, L"Internal error, invalid type for command 'hide'");
	}

	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, command 'hide' rejected");

	wcerr << L"Command 'hide' successful" << endl;
	wcout << L"status:ok;ruleid:" << objId << endl;
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

void CommandUnhide::LoadArgs(Arguments& args)
{
	wstring object, target;

	if (!args.GetNext(object))
		throw WException(-2, L"Error, mismatched argument #1 for command 'unhide'");

	if (!args.GetNext(target))
		throw WException(-2, L"Error, mismatched argument #2 for command 'unhide'");

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
		throw WException(-2, L"Error, invalid argument for command 'unhide'");
	}

	m_targetAll = (target == L"all");
	if (!m_targetAll)
	{
		m_targetId = _wtoll(target.c_str());
		if (!m_targetId)
			throw WException(-2, L"Error, invalid target objid for command 'unhide'");
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
			throw WException(-2, L"Internal error #1, invalid type for command 'unhide'");
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
			throw WException(-2, L"Internal error #2, invalid type for command 'unhide'");
		}
	}

	if (!HID_STATUS_SUCCESSFUL(status))
		throw WException(HID_STATUS_CODE(status), L"Error, command 'hide' rejected");

	wcerr << L"Command 'unhide' successful" << endl;
	wcout << L"status:ok" << endl;
}

CommandPtr CommandUnhide::CreateInstance()
{
	return CommandPtr(new CommandUnhide());
}

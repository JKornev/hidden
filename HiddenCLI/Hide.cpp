#include "Hide.h"

using namespace std;

// =================

CommandHide::CommandHide() : m_command(L"hide")
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
		m_hideType = EHideTypes::TypeFile;
	}
	else if (object == L"dir")
	{
		m_hideType = EHideTypes::TypeDir;
	}
	else if (object == L"regkey")
	{
		m_hideType = EHideTypes::TypeRegKey;
		m_regRootType = GetRegType(m_path);
	}
	else if (object == L"regval")
	{
		m_hideType = EHideTypes::TypeRegVal;
		m_regRootType = GetRegType(m_path);
	}
	else
	{
		throw WException(-2, L"Error, invalid argument for command 'hide'");
	}

}

void CommandHide::PerformCommand(Connection& connection)
{

}

HidRegRootTypes CommandHide::GetRegType(wstring& path)
{
	static wchar_t regHKLM[] = L"HKLM\\";
	static wchar_t regHKCU[] = L"HKCU\\";
	static wchar_t regHKU[]  = L"HKU\\";

	if (path.compare(0, _countof(regHKLM) - 1, regHKLM) == 0)
		return HidRegRootTypes::RegHKLM;
	else if (path.compare(0, _countof(regHKCU) - 1, regHKCU) == 0)
		return HidRegRootTypes::RegHKCU;
	else if (path.compare(0, _countof(regHKU) - 1, regHKU) == 0)
		return HidRegRootTypes::RegHKU;
	else
		throw WException(-2, L"Error, invalid registry prefix");
}

// =================

CommandUnhide::CommandUnhide() : m_command(L"unhide")
{
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

}

void CommandUnhide::PerformCommand(Connection& connection)
{

}

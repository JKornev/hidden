#pragma once

#include <string>
#include <sstream>
#include <vector>
#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>

#include "../HiddenLib/HiddenLib.h"

extern std::wstringstream g_stdout;
extern std::wstringstream g_stderr;

class WException
{
	std::wstring m_errorMessage;
	unsigned int m_errorCode;

public:

	WException(unsigned int Code, wchar_t* Format, ...);

	const wchar_t* What();
	unsigned int Code();
};

class Arguments
{
	std::vector<std::wstring> m_arguments;
	unsigned int    m_argPointer;

public:

	Arguments(int argc, wchar_t* argv[], int start = 1);

	size_t ArgsCount();

	bool Probe(std::wstring& arg);
	bool SwitchToNext();
	bool GetNext(std::wstring& arg);
};

class Handle
{
private:
	DWORD m_error;
	HANDLE m_handle;

public:

	Handle(HANDLE handle);
	~Handle();

	HANDLE Get();
	DWORD Error();

};

class RegistryKey
{
private:

	HKEY m_hkey;

public:

	RegistryKey(std::wstring regKey, HKEY root = HKEY_LOCAL_MACHINE, REGSAM access = KEY_ALL_ACCESS | KEY_WOW64_64KEY, bool newKey = false);
	~RegistryKey();

	void CopyTreeFrom(RegistryKey& src);

	void SetDwordValue(const wchar_t* name, DWORD value);
	DWORD GetDwordValue(const wchar_t* name, DWORD defValue);

	void SetStrValue(const wchar_t* name, std::wstring& value, bool expanded = false);
	void GetStrValue(const wchar_t* name, std::wstring& value, const wchar_t* defValue);

	void SetMultiStrValue(const wchar_t* name, const std::vector<std::wstring>& strs);
	void GetMultiStrValue(const wchar_t* name, std::vector<std::wstring>& strs);

	void RemoveValue(const wchar_t* name);

	static void DeleteKey(std::wstring regKey, HKEY root = HKEY_LOCAL_MACHINE);
};

enum EObjTypes {
	TypeFile,
	TypeDir,
	TypeRegKey,
	TypeRegVal,
};

enum EProcTypes {
	TypeProcessId,
	TypeImage,
};

HidRegRootTypes GetRegType(std::wstring& path);

HidPsInheritTypes LoadInheritOption(Arguments& args, HidPsInheritTypes default);
bool LoadApplyOption(Arguments& args, bool applyByDefault);

const wchar_t* ConvertInheritTypeToUnicode(HidPsInheritTypes type);
const wchar_t* ConvertRegRootTypeToUnicode(HidRegRootTypes type);

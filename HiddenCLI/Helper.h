#pragma once

#include <string>
#include <vector>
#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>

#include "../HiddenLib/HiddenLib.h"

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

	RegistryKey(std::wstring regKey);
	~RegistryKey();

	void SetDwordValue(const wchar_t* name, DWORD value);
	DWORD GetDwordValue(const wchar_t* name, DWORD defValue);
	
	void SetMultiStrValue(const wchar_t* name, const std::vector<std::wstring>& strs);
	void GetMultiStrValue(const wchar_t* name, std::vector<std::wstring>& strs);

	void RemoveValue(const wchar_t* name);
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

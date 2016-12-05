#pragma once

#include <string>
#include <vector>
#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>

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

	Arguments(int argc, wchar_t* argv[]);

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

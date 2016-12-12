#include "helper.h"

using namespace std;

WException::WException(unsigned int Code, wchar_t* Format, ...) :
	m_errorCode(Code)
{
	wchar_t buffer[256];

	va_list args;
	va_start(args, Format);
	_vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, Format, args);
	va_end(args);

	m_errorMessage = buffer;
}

const wchar_t* WException::What()
{
	return m_errorMessage.c_str();
}

unsigned int WException::Code()
{
	return m_errorCode;
}

Arguments::Arguments(int argc, wchar_t* argv[]) :
	m_argPointer(0)
{
	for (int i = 1; i < argc; i++)
		m_arguments.push_back(argv[i]);
}

size_t Arguments::ArgsCount()
{
	return m_arguments.size();
}

bool Arguments::Probe(std::wstring& arg)
{
	if (m_argPointer >= m_arguments.size())
		return false;

	arg = m_arguments[m_argPointer];
	return true;
}

bool Arguments::SwitchToNext()
{
	if (m_argPointer >= m_arguments.size())
		return false;

	m_argPointer++;
	return true;
}

bool Arguments::GetNext(wstring& arg)
{
	if (m_argPointer >= m_arguments.size())
		return false;

	arg = m_arguments[m_argPointer++];
	return true;
}

Handle::Handle(HANDLE handle) : 
	m_handle(handle), 
	m_error(::GetLastError())
{
}

Handle::~Handle()
{
	if (m_handle != INVALID_HANDLE_VALUE) 
		::CloseHandle(m_handle);
}

HANDLE Handle::Get()
{
	return m_handle; 
}

DWORD Handle::Error()
{
	return m_error;
}

HidRegRootTypes GetRegType(wstring& path)
{
	static wchar_t regHKLM[] = L"HKLM\\";
	static wchar_t regHKCU[] = L"HKCU\\";
	static wchar_t regHKU[] = L"HKU\\";

	if (path.compare(0, _countof(regHKLM) - 1, regHKLM) == 0)
		return HidRegRootTypes::RegHKLM;
	else if (path.compare(0, _countof(regHKCU) - 1, regHKCU) == 0)
		return HidRegRootTypes::RegHKCU;
	else if (path.compare(0, _countof(regHKU) - 1, regHKU) == 0)
		return HidRegRootTypes::RegHKU;
	else
		throw WException(-2, L"Error, invalid registry prefix");
}

HidPsInheritTypes LoadInheritOption(Arguments& args, HidPsInheritTypes default)
{
	wstring arg;

	if (!args.Probe(arg))
		return default;

	if (arg == L"inherit:none")
	{
		args.SwitchToNext();
		return HidPsInheritTypes::WithoutInherit;
	}
	else if (arg == L"inherit:always")
	{
		args.SwitchToNext();
		return HidPsInheritTypes::InheritAlways;
	}
	else if (arg == L"inherit:once")
	{
		args.SwitchToNext();
		return HidPsInheritTypes::InheritOnce;
	}

	return default;
}

bool LoadApplyOption(Arguments& args, bool applyByDefault)
{
	wstring arg;

	if (!args.Probe(arg))
		return applyByDefault;

	if (arg == L"apply:fornew")
	{
		args.SwitchToNext();
		return false;
	}
	else if (arg == L"apply:forall")
	{
		args.SwitchToNext();
		return true;
	}

	return applyByDefault;
}

const wchar_t* ConvertInheritTypeToUnicode(HidPsInheritTypes type)
{
	switch (type)
	{
	case HidPsInheritTypes::WithoutInherit:
		return L"none";
		break;
	case HidPsInheritTypes::InheritOnce:
		return L"once";
		break;
	case HidPsInheritTypes::InheritAlways:
		return L"always";
		break;
	}
	return L"unknown";
}

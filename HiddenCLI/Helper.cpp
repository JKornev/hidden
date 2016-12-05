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

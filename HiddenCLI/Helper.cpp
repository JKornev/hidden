#include "helper.h"
#include <memory>

using namespace std;

// =================

std::wstringstream g_stdout;
std::wstringstream g_stderr;

// =================

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

// =================

Arguments::Arguments(int argc, wchar_t* argv[], int start) :
	m_argPointer(0)
{
	for (int i = start; i < argc; i++)
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

// =================

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

// =================

RegistryKey::RegistryKey(std::wstring regKey, HKEY root, REGSAM access, bool newKey) : m_hkey(NULL)
{
	if (newKey)
	{
		LONG status = RegCreateKeyExW(root, regKey.c_str(), 0, NULL, 0, access, NULL, &m_hkey, NULL);
		if (status != ERROR_SUCCESS)
			throw WException(status, L"Error, can't create registry key");
	}
	else
	{
		LONG status = RegOpenKeyExW(root, regKey.c_str(), 0, access, &m_hkey);
		if (status != ERROR_SUCCESS)
			throw WException(status, L"Error, can't open registry key");
	}
}

RegistryKey::~RegistryKey()
{
	RegCloseKey(m_hkey);
}

void RegistryKey::CopyTreeFrom(RegistryKey& src)
{
	LONG status;

	status = RegCopyTree(src.m_hkey, NULL, m_hkey);
	if (status != ERROR_SUCCESS)
		throw WException(status, L"Error, can't copy registry tree");
}

void RegistryKey::DeleteKey(std::wstring regKey, HKEY root)
{
	LONG status;

	status = RegDeleteTreeW(root, regKey.c_str());
	if (status != ERROR_SUCCESS)
		throw WException(status, L"Error, can't copy registry tree");
}

void RegistryKey::SetDwordValue(const wchar_t* name, DWORD value)
{
	LONG status;

	status = RegSetValueExW(m_hkey, name, NULL, REG_DWORD, (LPBYTE)&value, sizeof(value));
	if (status != ERROR_SUCCESS)
		throw WException(status, L"Error, can't set registry value");
}

DWORD RegistryKey::GetDwordValue(const wchar_t* name, DWORD defValue)
{
	DWORD value, size = sizeof(value), type = REG_DWORD;
	LONG status;

	status = RegQueryValueEx(m_hkey, name, NULL, &type, (LPBYTE)&value, &size);
	if (status != ERROR_SUCCESS)
	{
		if (status != ERROR_FILE_NOT_FOUND)
			throw WException(status, L"Error, can't query registry value");

		return defValue;
	}

	return value;
}

void RegistryKey::SetStrValue(const wchar_t* name, std::wstring& value, bool expanded)
{
	LONG status;

	status = RegSetValueExW(m_hkey, name, NULL, (expanded ? REG_EXPAND_SZ : REG_SZ), (LPBYTE)value.c_str(), (DWORD)(value.size() + 1) * sizeof(wchar_t));
	if (status != ERROR_SUCCESS)
		throw WException(status, L"Error, can't set registry value");
}

void RegistryKey::GetStrValue(const wchar_t* name, std::wstring& value, const wchar_t* defValue)
{
	DWORD size = 0, type = REG_SZ;
	LONG status;

	status = RegQueryValueExW(m_hkey, name, NULL, &type, NULL, &size);
	if (status != ERROR_SUCCESS)
	{
		if (status != ERROR_FILE_NOT_FOUND)
			throw WException(status, L"Error, can't query registry value");

		value = defValue;
		return;
	}

	if (type != REG_SZ && type != REG_EXPAND_SZ)
		throw WException(status, L"Error, invalid registry key type");

	if (size == 0)
		return;

	value.clear();
	value.insert(0, size / sizeof(wchar_t), L'\0');

	status = RegQueryValueExW(m_hkey, name, NULL, &type, (LPBYTE)value.c_str(), &size);
	if (status != ERROR_SUCCESS)
		throw WException(status, L"Error, can't query registry value");

	while (value.size() > 0 && value[value.size() - 1] == L'\0')
		value.pop_back();
}

void RegistryKey::SetMultiStrValue(const wchar_t* name, const std::vector<std::wstring>& strs)
{
	DWORD size = 0, offset = 0;
	shared_ptr<BYTE> buffer;
	LONG status;

	for (auto it = strs.begin(); it != strs.end(); it++)
	{
		if (it->size() > 0)
			size += (DWORD)(it->size() + 1) * sizeof(wchar_t);
	}

	if (size == 0)
	{
		WCHAR value = 0;
		status = RegSetValueExW(m_hkey, name, NULL, REG_MULTI_SZ, (LPBYTE)&value, 2);
		if (status != ERROR_SUCCESS)
			throw WException(status, L"Error, can't set registry value");

		return;
	}

	buffer.reset(new BYTE[size]);
	memset(buffer.get(), 0, size);

	for (auto it = strs.begin(); it != strs.end(); it++)
	{
		if (it->size() == 0)
			continue;

		DWORD strSize = (DWORD)(it->size() + 1) * sizeof(wchar_t);
		memcpy(buffer.get() + offset, it->c_str(), strSize);
		offset += strSize;
	}

	status = RegSetValueExW(m_hkey, name, NULL, REG_MULTI_SZ, buffer.get(), size);
	if (status != ERROR_SUCCESS)
		throw WException(status, L"Error, can't set registry value");
}

void RegistryKey::GetMultiStrValue(const wchar_t* name, std::vector<std::wstring>& strs)
{
	DWORD size = 0, type = REG_MULTI_SZ;
	shared_ptr<BYTE> buffer;
	LPWSTR bufferPtr;
	LONG status;

	strs.clear();

	status = RegQueryValueExW(m_hkey, name, NULL, &type, NULL, &size);
	if (status != ERROR_SUCCESS)
	{
		if (status != ERROR_FILE_NOT_FOUND)
			throw WException(status, L"Error, can't query registry value");

		return;
	}

	if (type != REG_MULTI_SZ)
		throw WException(status, L"Error, invalid registry key type");

	if (size == 0)
		return;

	buffer.reset(new BYTE[size + sizeof(WCHAR)]);
	memset(buffer.get(), 0, size + sizeof(WCHAR));

	status = RegQueryValueExW(m_hkey, name, NULL, &type, buffer.get(), &size);
	if (status != ERROR_SUCCESS)
		throw WException(status, L"Error, can't query registry value");

	bufferPtr = (LPWSTR)buffer.get();
	while (size > 1)
	{
		ULONG inx, delta = 0;
		ULONG len = size / sizeof(WCHAR);

		for (inx = 0; inx < len; inx++)
		{
			if (bufferPtr[inx] == L'\0')
			{
				delta = 1;
				break;
			}
		}

		if (inx > 0)
			strs.push_back(bufferPtr);

		size -= (inx + delta) * sizeof(WCHAR);
		bufferPtr += (inx + delta);
	}
}

void RegistryKey::RemoveValue(const wchar_t* name)
{
	LONG status = RegDeleteKeyValueW(m_hkey, NULL, name);
	if (status != ERROR_SUCCESS)
		throw WException(status, L"Error, can't delete registry value");
}

// =================

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
		throw WException(ERROR_INVALID_DATA, L"Error, invalid registry prefix");
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

const wchar_t* ConvertRegRootTypeToUnicode(HidRegRootTypes type)
{
	switch (type)
	{
	case HidRegRootTypes::RegHKCU:
		return L"HKCU";
		break;
	case HidRegRootTypes::RegHKLM:
		return L"HKLM";
		break;
	case HidRegRootTypes::RegHKU:
		return L"HKU";
		break;
	}
	return L"unknown";
}

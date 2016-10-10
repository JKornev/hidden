#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <mutex>
#include <stdio.h>

#include "../HiddenLib/HiddenLib.h"

using namespace std;

class CHandle
{
private:
	DWORD m_error;
	HANDLE m_handle;

public:
	CHandle(HANDLE handle) : m_handle(handle), m_error(::GetLastError()) { }
	~CHandle() { if (m_handle != INVALID_HANDLE_VALUE) ::CloseHandle(m_handle); }

	HANDLE get() { return m_handle; }
	DWORD error() { return m_error; }
};

void gen_temp_path(wstring& path)
{
	wchar_t temp_file[MAX_PATH];
	wchar_t temp_dir[MAX_PATH];

	unsigned int error_code;

	if (::GetTempPathW(_countof(temp_dir), temp_dir) == 0)
	{
		error_code = GetLastError();
		wcout << L"Error, GetTempPathW() failed with code: " << error_code << endl;
		throw exception();
	}

	if (::GetTempFileNameW(temp_dir, L"hfs", rand(), temp_file) == 0)
	{
		error_code = GetLastError();
		wcout << L"Error, GetTempFileNameW() failed with code: " << error_code << endl;
		throw exception();
	}

	path = temp_file;
}

void do_fsmon_tests(HidContext context)
{
	HidStatus  hid_status;
	HidObjId objId[3];
	unsigned int error_code;
	wstring file_path, dir_path, file_paths[2];

	wcout << L"--------------------------------" << endl;
	wcout << L"File-System monitor tests result:" << endl;
	wcout << L"--------------------------------" << endl;

	try 
	{
		// Test 1
		wcout << L"Test 1: create single file, hide it, unhide it" << endl;

		gen_temp_path(file_path);

		CHandle hfile(
			::CreateFileW(
				file_path.c_str(),
				FILE_READ_ACCESS | FILE_WRITE_ACCESS, 
				FILE_SHARE_READ | FILE_SHARE_WRITE, 
				NULL, 
				CREATE_ALWAYS,
				FILE_FLAG_DELETE_ON_CLOSE,
				NULL
			)
		);
		if (hfile.get() == INVALID_HANDLE_VALUE)
		{
			wcout << L"Error, CreateFileW() failed with code: " << hfile.error() << endl;
			throw exception();
		}
		
		hid_status = Hid_AddHiddenFile(context, file_path.c_str(), &objId[0]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, Hid_AddHiddenFile() failed with code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		if (::GetFileAttributesW(file_path.c_str()) != INVALID_FILE_ATTRIBUTES)
		{
			wcout << L"Error, hidden file has been found" << hfile.error() << endl;
			throw exception();
		}

		hid_status = Hid_RemoveHiddenFile(context, objId[0]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, Hid_RemoveHiddenFile() failed with code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		if (::GetFileAttributesW(file_path.c_str()) == INVALID_FILE_ATTRIBUTES)
		{
			wcout << L"Error, unhidden file hasn't been found" << hfile.error() << endl;
			throw exception();
		}

		wcout << L" successful!" << endl;

		// Test 2
		wcout << L"Test 2: create single directory, hide it, unhide it" << endl;
		
		gen_temp_path(dir_path);
		
		if (::CreateDirectoryW(dir_path.c_str(), NULL) == 0)
		{
			error_code = GetLastError();
			wcout << L"Error, CreateDirectoryExW() failed with code: " << error_code << endl;
			throw exception();
		}

		CHandle hdir(
			::CreateFileW(
			dir_path.c_str(),
				FILE_READ_ACCESS, 
				FILE_SHARE_READ | FILE_SHARE_WRITE, 
				NULL, 
				OPEN_EXISTING,
				FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_DELETE_ON_CLOSE,
				NULL
			)
		);
		if (hdir.get() == INVALID_HANDLE_VALUE)
		{
			wcout << L"Error, CreateFileW() failed with code: " << hdir.error() << endl;
			throw exception();
		}

		hid_status = Hid_AddHiddenDir(context, dir_path.c_str(), &objId[1]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, Hid_AddHiddenDir() failed with code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}
		if (::GetFileAttributesW(dir_path.c_str()) != INVALID_FILE_ATTRIBUTES)
		{
			wcout << L"Error, hidden file has been found " << hfile.error() << endl;
			throw exception();
		}

		hid_status = Hid_RemoveHiddenDir(context, objId[1]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, Hid_RemoveHiddenDir() failed with code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		if (::GetFileAttributesW(dir_path.c_str()) == INVALID_FILE_ATTRIBUTES)
		{
			wcout << L"Error, unhidden dir hasn't been found " << hfile.error() << endl;
			throw exception();
		}

		wcout << L" successful!" << endl;

		// Test 3
		wcout << L"Test 3: create two files, hide them, unhide using unhide all feature" << endl;

		gen_temp_path(file_paths[0]);
		gen_temp_path(file_paths[1]);
		
		CHandle hfile2(
			::CreateFileW(
				file_paths[0].c_str(),
				FILE_READ_ACCESS | FILE_WRITE_ACCESS, 
				FILE_SHARE_READ | FILE_SHARE_WRITE, 
				NULL, 
				CREATE_ALWAYS,
				FILE_FLAG_DELETE_ON_CLOSE,
				NULL
			)
		);
		if (hfile.get() == INVALID_HANDLE_VALUE)
		{
			wcout << L"Error, CreateFileW() failed with code: " << hfile.error() << endl;
			throw exception();
		}

		CHandle hfile3(
			::CreateFileW(
				file_paths[1].c_str(),
				FILE_READ_ACCESS | FILE_WRITE_ACCESS, 
				FILE_SHARE_READ | FILE_SHARE_WRITE, 
				NULL, 
				CREATE_ALWAYS,
				FILE_FLAG_DELETE_ON_CLOSE,
				NULL
			)
		);
		if (hfile.get() == INVALID_HANDLE_VALUE)
		{
			wcout << L"Error, CreateFileW() failed with code: " << hfile.error() << endl;
			throw exception();
		}

		hid_status = Hid_AddHiddenFile(context, file_paths[0].c_str(), &objId[0]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, Hid_AddHiddenFile() failed with code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		hid_status = Hid_AddHiddenFile(context, file_paths[1].c_str(), &objId[0]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, Hid_AddHiddenFile() failed with code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		if (::GetFileAttributesW(file_paths[0].c_str()) != INVALID_FILE_ATTRIBUTES)
		{
			wcout << L"Error, hidden file has been found" << hfile.error() << endl;
			throw exception();
		}

		if (::GetFileAttributesW(file_paths[1].c_str()) != INVALID_FILE_ATTRIBUTES)
		{
			wcout << L"Error, hidden file has been found" << hfile.error() << endl;
			throw exception();
		}

		hid_status = Hid_RemoveAllHiddenFiles(context);

		if (::GetFileAttributesW(file_paths[0].c_str()) == INVALID_FILE_ATTRIBUTES)
		{
			wcout << L"Error, unhidden file hasn't been found" << hfile.error() << endl;
			throw exception();
		}

		if (::GetFileAttributesW(file_paths[1].c_str()) == INVALID_FILE_ATTRIBUTES)
		{
			wcout << L"Error, unhidden file hasn't been found" << hfile.error() << endl;
			throw exception();
		}

		wcout << L" successful!" << endl;

		// Test 4
		// TODO: repeat test 3 but with directories

	}
	catch (exception&)
	{
		wcout << L" failed!" << endl;
	}

	Hid_RemoveAllHiddenFiles(context);
	Hid_RemoveAllHiddenDirs(context);
}

void gen_random_string(wstring& path, const wchar_t* prefix)
{
	unsigned int value = (rand() << 16) + rand();
	wchar_t buff[32];

	wsprintf(buff, L"%d", value);

	path.clear();
	path += prefix;
	path += buff;
}

void do_regmon_tests(HidContext context)
{
	HidStatus  hid_status;
	HKEY hkey = 0, hkey2;
	wstring temp, reg_key, reg_value;
	DWORD disposition, value, type, size;
	unsigned int error_code;
	HidObjId objId[3];
	VALENT valList;

	wcout << L"--------------------------------" << endl;
	wcout << L"Registry monitor tests result:" << endl;
	wcout << L"--------------------------------" << endl;

	try
	{
		// Test 1
		wcout << L"Test 1: create single reg key, hide it, unhide it" << endl;

		gen_random_string(temp, L"Hid_");
		reg_key = L"Software\\";
		reg_key += temp;

		error_code = RegCreateKeyExW(HKEY_CURRENT_USER, reg_key.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hkey, &disposition);
		if (error_code != ERROR_SUCCESS)
		{
			wcout << L"Error, RegCreateKeyExW() failed with code: " << error_code << endl;
			throw exception();
		}

		if (disposition != REG_CREATED_NEW_KEY)
			wcout << L"Warning, existing key is used: " << reg_key.c_str() << endl;

		hid_status = Hid_AddHiddenRegKey(context, HidRegRootTypes::RegHKCU, reg_key.c_str(), &objId[0]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, Hid_AddHiddenRegKey() failed with code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		error_code = RegOpenKeyExW(HKEY_CURRENT_USER, reg_key.c_str(), 0, KEY_ALL_ACCESS, &hkey2);
		if (error_code == ERROR_SUCCESS)
		{
			wcout << L"Error, hidden reg key has been found " << endl;
			RegCloseKey(hkey2);
			throw exception();
		}

		hid_status = Hid_RemoveHiddenRegKey(context, objId[0]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, Hid_RemoveHiddenRegKey() failed with code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		error_code = RegOpenKeyExW(HKEY_CURRENT_USER, reg_key.c_str(), 0, KEY_ALL_ACCESS, &hkey2);
		if (error_code != ERROR_SUCCESS)
		{
			wcout << L"Error, unhidden reg key hasn't been found, code: " << error_code << endl;
			throw exception();
		}

		RegCloseKey(hkey2);

		wcout << L" successful!" << endl;

		// Test 2
		wcout << L"Test 2: create single reg value, hide it, unhide it" << endl;

		gen_random_string(temp, L"value");
		reg_value = reg_key;
		reg_value += L"\\";
		reg_value += temp;

		value = 0;

		error_code = RegSetKeyValueW(HKEY_CURRENT_USER, reg_key.c_str(), temp.c_str(), REG_DWORD, &value, sizeof(value));
		if (error_code != ERROR_SUCCESS)
		{
			wcout << L"Error, RegSetKeyValueW() failed with code: " << error_code << endl;
			throw exception();
		}

		hid_status = Hid_AddHiddenRegValue(context, HidRegRootTypes::RegHKCU, reg_value.c_str(), &objId[1]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, Hid_AddHiddenRegValue() failed with code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		error_code = RegSetKeyValueW(HKEY_CURRENT_USER, reg_key.c_str(), temp.c_str(), REG_DWORD, &value, sizeof(value));
		if (error_code == ERROR_SUCCESS)
		{
			wcout << L"Error, hidden reg value has been found " << endl;
			throw exception();
		}

		error_code = RegDeleteValueW(hkey, temp.c_str());
		if (error_code == ERROR_SUCCESS)
		{
			wcout << L"Error, hidden reg value has been deleted " << endl;
			throw exception();
		}

		error_code = RegQueryValueExW(hkey, temp.c_str(), NULL, &type, NULL, NULL);
		if (error_code == ERROR_SUCCESS)
		{
			wcout << L"Error, hidden reg value query has been performed " << endl;
			throw exception();
		}

		memset(&valList, 0, sizeof(valList));
		valList.ve_valuename = (LPWSTR)temp.c_str();

		size = sizeof(value);
		error_code = RegQueryMultipleValuesW(hkey, &valList, 1, (LPWSTR)&value, &size);
		if (error_code == ERROR_SUCCESS)
		{
			wcout << L"Error, hidden reg multiple value query has been performed " << endl;
			throw exception();
		}

		hid_status = Hid_RemoveHiddenRegValue(context, objId[1]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, unhidden reg value hasn't been found, code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		memset(&valList, 0, sizeof(valList));
		valList.ve_valuename = (LPWSTR)temp.c_str();

		size = sizeof(value);
		error_code = RegQueryMultipleValuesW(hkey, &valList, 1, (LPWSTR)&value, &size);
		if (error_code != ERROR_SUCCESS)
		{
			wcout << L"Error, unhidden reg value query hasn't been performed, code: " << error_code << endl;
			throw exception();
		}

		error_code = RegDeleteValueW(hkey, temp.c_str());
		if (error_code != ERROR_SUCCESS)
		{
			wcout << L"Error, unhidden reg value hasn't been removed, code: " << error_code << endl;
			throw exception();
		}

		wcout << L" successful!" << endl;

	}
	catch (exception&)
	{
		wcout << L" failed!" << endl;
	}

	if (hkey)
	{
		RegCloseKey(hkey);
		RegDeleteKeyW(HKEY_CURRENT_USER, reg_key.c_str());
	}

	Hid_RemoveAllHiddenRegKeys(context);
	Hid_RemoveAllHiddenRegValues(context);
}

void do_psmon_prot_tests(HidContext context)
{
	HidStatus  hid_status;
	unsigned int error_code;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	wchar_t path[] = L"c:\\windows\\system32\\calc.exe";
	HidObjId objId[3];
	HANDLE hproc = 0;
	HidActiveState state;
	HidPsInheritTypes inheritType;

	wcout << L"--------------------------------" << endl;
	wcout << L"Process monitor prot tests result:" << endl;
	wcout << L"--------------------------------" << endl;

	try
	{
		//TODO:
		// test 1: create proc, protect, check, unprotect

		wcout << L"Test 1: create process, protect, check, unprotect" << endl;

		memset(&si, 0, sizeof(si));
		memset(&pi, 0, sizeof(pi));
		si.cb = sizeof(si);

		wcout << L"step" << 1 << endl;

		hid_status = Hid_GetProtectedState(context, GetCurrentProcessId(), &state, &inheritType);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, can't get self state, code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		if (state != HidActiveState::StateDisabled)
		{
			wcout << L"Error, state isn't StateDisabled, state: " << state << " " << inheritType << endl;
			throw exception();
		}

		wcout << L"step" << 2 << endl;
		hid_status = Hid_AttachProtectedState(context, GetCurrentProcessId(), HidPsInheritTypes::WithoutInherit);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, can't protect self image, code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		hid_status = Hid_GetProtectedState(context, GetCurrentProcessId(), &state, &inheritType);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, can't get self status, code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		if (state != HidActiveState::StateEnabled || inheritType != HidPsInheritTypes::WithoutInherit)
		{
			wcout << L"Error, state isn't StateEnabled, state: " << state << " " << inheritType << endl;
			throw exception();
		}

		wcout << L"step" << 3 << endl;
		hid_status = Hid_AddProtectedImage(context, path, HidPsInheritTypes::WithoutInherit, &objId[1]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, can't protect image, code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		wcout << L"step" << 3 << endl;
		//hid_status = Hid_AttachProtectedState(context,  420, HidPsInheritTypes::WithoutInherit);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, can't protect csrss image, code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}


		wcout << L"step" << 4 << endl;
		if (!CreateProcessW(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
		{
			error_code = GetLastError();
			wcout << L"Error, CreateProcessW() failed with code: " << error_code << endl;
			throw exception();
		}

		wcout << L"step" << 5 << endl;
		CloseHandle(pi.hThread);

		hid_status = Hid_RemoveProtectedState(context, GetCurrentProcessId());
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, can't can't remove self protection, code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		wcout << L"step" << 6 << endl;
		hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
		if (!hproc)
		{
			error_code = GetLastError();
			wcout << L"Error, OpenProcess() failed with code: " << error_code << endl;
			throw exception();
		}

		wcout << L"step" << 7 << endl;
		if (VirtualAllocEx(hproc, 0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE))
		{
			wcout << L"Error, process protection doesn't work" << endl;
			throw exception();
		}

		CloseHandle(hproc);
		hproc = 0;

		wcout << L"step" << 8 << endl;
		hid_status = Hid_RemoveProtectedImage(context, objId[1]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, can't remove protected rule, code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		hid_status = Hid_RemoveProtectedState(context, pi.dwProcessId);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, can't unprotect image, code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
		if (!hproc)
		{
			error_code = GetLastError();
			wcout << L"Error, OpenProcess() failed with code " << error_code << endl;
			throw exception();
		}

		if (!VirtualAllocEx(hproc, 0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE))
		{
			error_code = GetLastError();
			wcout << L"Error, VirtualAllocEx() failed with code: " << error_code << endl;
			throw exception();
		}

		CloseHandle(hproc);
		hproc = 0;

		wcout << L" successful!" << endl;


	}
	catch (exception&)
	{
		wcout << L" failed!" << endl;
	}

	if (hproc)
		CloseHandle(hproc);

	if (pi.hProcess)
	{
		CloseHandle(hproc);
		TerminateProcess(pi.hProcess, 0);
	}

	Hid_RemoveAllProtectedImages(context);
}

void do_psmon_excl_tests(HidContext context)
{
	//HidStatus  hid_status;

	wcout << L"--------------------------------" << endl;
	wcout << L"Process monitor excl tests result:" << endl;
	wcout << L"--------------------------------" << endl;

	try
	{

	}
	catch (exception&)
	{
		wcout << L" failed!" << endl;
	}


}

int wmain(int argc, wchar_t* argv[])
{
	HidContext hid_context;
	HidStatus  hid_status;

	srand(time(0));

	hid_status = Hid_Initialize(&hid_context);
	if (!HID_STATUS_SUCCESSFUL(hid_status))
	{
		cout << "Error, HiddenLib initialization failed with code: " << HID_STATUS_CODE(hid_status) << endl;
	//	return 1;
	}

	do_fsmon_tests(hid_context);
	do_regmon_tests(hid_context);
	do_psmon_prot_tests(hid_context);
	do_psmon_excl_tests(hid_context);

	//Hid_Destroy(hid_context);

	return 0;
}

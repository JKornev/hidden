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
	CHandle(HANDLE handle) : m_handle(handle), m_error(GetLastError()) { }
	~CHandle() { if (m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle); }

	HANDLE get() { return m_handle; }
	DWORD error() { return m_error; }
};

void GenTempPath(wstring& path)
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

		GenTempPath(file_path);

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
			wcout << L"Error, Hid_AddHiddenFile failed with code: " << HID_STATUS_CODE(hid_status) << endl;
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
			wcout << L"Error, Hid_RemoveHiddenFile failed with code: " << HID_STATUS_CODE(hid_status) << endl;
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
		
		GenTempPath(dir_path);
		
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
			wcout << L"Error, Hid_AddHiddenDir failed with code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}
		if (::GetFileAttributesW(dir_path.c_str()) != INVALID_FILE_ATTRIBUTES)
		{
			wcout << L"Error, hidden file has been found" << hfile.error() << endl;
			throw exception();
		}

		hid_status = Hid_RemoveHiddenDir(context, objId[1]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, Hid_RemoveHiddenDir failed with code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		if (::GetFileAttributesW(dir_path.c_str()) == INVALID_FILE_ATTRIBUTES)
		{
			wcout << L"Error, unhidden dir hasn't been found" << hfile.error() << endl;
			throw exception();
		}

		wcout << L" successful!" << endl;

		// Test 3
		wcout << L"Test 3: create two files, hide them, unhide using unhide all feature" << endl;

		GenTempPath(file_paths[0]);
		GenTempPath(file_paths[1]);
		
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
			wcout << L"Error, Hid_AddHiddenFile failed with code: " << HID_STATUS_CODE(hid_status) << endl;
			throw exception();
		}

		hid_status = Hid_AddHiddenFile(context, file_paths[1].c_str(), &objId[0]);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
		{
			wcout << L"Error, Hid_AddHiddenFile failed with code: " << HID_STATUS_CODE(hid_status) << endl;
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
	}
	catch (exception&)
	{
		wcout << L" failed!" << endl;
		return;
	}
}

void do_regmon_tests(HidContext context)
{
	//HidStatus  hid_status;
	wcout << L"--------------------------------" << endl;
	wcout << L"Registry monitor tests result:" << endl;
	wcout << L"--------------------------------" << endl;
}

void do_psmon_tests(HidContext context)
{
	//HidStatus  hid_status;
	wcout << L"--------------------------------" << endl;
	wcout << L"Process monitor tests result:" << endl;
	wcout << L"--------------------------------" << endl;
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
		return 1;
	}

	do_fsmon_tests(hid_context);
	do_regmon_tests(hid_context);
	do_psmon_tests(hid_context);

	//Hid_Destroy(hid_context);

	return 0;
}

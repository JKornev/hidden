#include <Windows.h>
#include <iostream>
#include <stdio.h>

#include "../HiddenLib/HiddenLib.h"

using namespace std;

CONST PWCHAR g_excludeFiles[] = {
//	L"c:\\Windows\\System32\\calc.exe",
//	L"c:\\test.txt",
//	L"c:\\abcd\\test.txt",
	L"\\Device\\HarddiskVolume1\\Windows\\System32\\calc.exe",
	L"\\??\\C:\\test.txt",
	L"\\??\\C:\\abcd\\test.txt",
};

CONST PWCHAR g_excludeDirs[] = {
//	L"\\Device\\HarddiskVolume1\\abc",
//	L"\\Device\\HarddiskVolume1\\abcd\\abc",
//	L"\\Device\\HarddiskVolume1\\New folder",
	L"\\Device\\HarddiskVolume1\\abc",
	L"\\??\\C:\\abcd\\abc",
	L"\\??\\C:\\New folder",
};

CONST PWCHAR g_excludeRegKeys[] = {
	L"\\REGISTRY\\MACHINE\\SOFTWARE\\test",
	L"\\Registry\\MACHINE\\SOFTWARE\\test2",
};

CONST PWCHAR g_excludeRegValues[] = {
	L"\\REGISTRY\\MACHINE\\SOFTWARE\\aaa",
	L"\\Registry\\MACHINE\\SOFTWARE\\xxx",
	L"\\Registry\\MACHINE\\SOFTWARE\\aa",
	L"\\Registry\\MACHINE\\SOFTWARE\\aaa",
	L"\\Registry\\MACHINE\\SOFTWARE\\aaaa",
	L"\\Registry\\MACHINE\\SOFTWARE\\zz",
};


int wmain(int argc, wchar_t *argv[])
{
	HidContext hid_context;
	HidStatus  hid_status;
	int count;

	cout << "Start!" << endl;

	hid_status = Hid_Initialize(&hid_context);
	if (!HID_STATUS_SUCCESSFUL(hid_status))
	{
		cout << "Error, HiddenLib initialization failed with code: " << HID_STATUS_CODE(hid_status) << endl;
		return 1;
	}

	// Load Reg Keys
	count = _countof(g_excludeRegKeys);
	for (int i = 0; i < count; i++)
	{
		HidObjId objId;
		hid_status = Hid_AddHiddenRegKey(hid_context, g_excludeRegKeys[i], &objId);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
			cout << "Error, Hid_AddHiddenRegKey failed with code: " << HID_STATUS_CODE(hid_status) << endl;
	}

	// Load Reg Values
	count = _countof(g_excludeRegValues);
	for (int i = 0; i < count; i++)
	{
		HidObjId objId;
		hid_status = Hid_AddHiddenRegValue(hid_context, g_excludeRegValues[i], &objId);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
			cout << "Error, Hid_AddHiddenRegValue failed with code: " << HID_STATUS_CODE(hid_status) << endl;
	}

	// Load Files
	count = _countof(g_excludeFiles);
	for (int i = 0; i < count; i++)
	{
		HidObjId objId;
		hid_status = Hid_AddHiddenFile(hid_context, g_excludeFiles[i], &objId);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
			cout << "Error, Hid_AddHiddenFile failed with code: " << HID_STATUS_CODE(hid_status) << endl;
	}

	// Load Dirs
	count = _countof(g_excludeDirs);
	for (int i = 0; i < count; i++)
	{
		HidObjId objId;
		hid_status = Hid_AddHiddenDir(hid_context, g_excludeDirs[i], &objId);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
			cout << "Error, Hid_AddHiddenDir failed with code: " << HID_STATUS_CODE(hid_status) << endl;
	}

	Hid_Destroy(hid_context);
	cout << "Completed!" << endl;

	return 0;
}

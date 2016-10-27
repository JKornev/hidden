#include <Windows.h>
#include <iostream>
#include <stdio.h>

#include "../HiddenLib/HiddenLib.h"

using namespace std;

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!! HiddenCLI ISN'T IMPLEMENTED YET, IT CONTAINS TEST CODE !!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

CONST PWCHAR g_excludeFiles[] = {
//	L"c:\\Windows\\System32\\calc.exe",
//	L"c:\\test.txt",
//	L"c:\\abcd\\test.txt",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\calc.exe",
	L"\\??\\C:\\test.txt",
	//L"c:\\Program Files\\VMware",
};

CONST PWCHAR g_excludeDirs[] = {
	L"c:\\Program Files\\VMware",
	L"c:\\ProgramData\\VMware",
	L"c:\\Windows\\Temp\\vmware-SYSTEM",
	L"c:\\Program Files\\Common Files\\VMware",
};

typedef struct _RegEntry {
	HidRegRootTypes root;
	LPWSTR path;
} RegEntry, *PRegEntry;

CONST RegEntry g_excludeRegKeys[] = {
	{ RegHKLM, L"Software\\VMware, Inc." },
	{ RegHKLM, L"System\\ControlSet001\\Control\\Print\\Monitors\\ThinPrint Print Port Monitor for VMWare" },
	{ RegHKLM, L"System\\ControlSet002\\Control\\Print\\Monitors\\ThinPrint Print Port Monitor for VMWare" },
	{ RegHKLM, L"System\\CurrentControlSet\\Control\\Print\\Monitors\\ThinPrint Print Port Monitor for VMWare" },
	{ RegHKCU, L"Software\\VMware, Inc." },
};

CONST RegEntry g_excludeRegValues[] = {
	{ RegHKLM, L"Hardware\\Description\\System\\BIOS\\SystemManufacturer" },
	{ RegHKLM, L"Hardware\\Description\\System\\BIOS\\SystemProductName" },
};

CONST PWCHAR g_protectProcesses[] = {
	L"c:\\Windows\\System32\\calc.exe",
	L"c:\\Windows\\System32\\calc2.exe",
};

CONST PWCHAR g_excludeProcesses[] = {
	L"C:\\Windows\\System32\\Services.exe",
	L"C:\\Windows\\System32\\csrss.exe",
	L"C:\\Windows\\System32\\vssvc.exe",
	L"C:\\Windows\\System32\\spoolsv.exe",
	L"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
	L"C:\\Program Files\\VMware\\VMware Tools\\TPAutoConnSvc.exe",
	L"C:\\Program Files\\VMware\\VMware Tools\\rpctool.exe",
	L"C:\\Program Files\\VMware\\VMware Tools\\rvmSetup.exe",
	L"C:\\Program Files\\VMware\\VMware Tools\\TPAutoConnect.exe",
	L"C:\\Program Files\\VMware\\VMware Tools\\TPVCGateway.exe",
	L"C:\\Program Files\\VMware\\VMware Tools\\VMwareHgfsClient.exe",
	L"C:\\Program Files\\VMware\\VMware Tools\\VMwareHostOpen.exe",
	L"C:\\Program Files\\VMware\\VMware Tools\\VMwareResolutionSet.exe",
	L"C:\\Program Files\\VMware\\VMware Tools\\VMwareToolboxCmd.exe",
	L"C:\\Program Files\\VMware\\VMware Tools\\VMwareXferlogs.exe",
	L"C:\\Program Files\\VMware\\VMware Tools\\zip.exe",
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
		hid_status = Hid_AddHiddenRegKey(hid_context, g_excludeRegKeys[i].root, g_excludeRegKeys[i].path, &objId);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
			cout << "Error, Hid_AddHiddenRegKey failed with code: " << HID_STATUS_CODE(hid_status) << endl;
	}

	// Load Reg Values
	count = _countof(g_excludeRegValues);
	for (int i = 0; i < count; i++)
	{
		HidObjId objId;
		hid_status = Hid_AddHiddenRegValue(hid_context, g_excludeRegValues[i].root, g_excludeRegValues[i].path, &objId);
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

	// Load excluded processes
	count = _countof(g_excludeProcesses);
	for (int i = 0; i < count; i++)
	{
		HidObjId objId;
		hid_status = Hid_AddExcludedImage(hid_context, g_excludeProcesses[i], WithoutInherit, TRUE, &objId);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
			cout << "Error, Hid_AddExcludedImage failed with code: " << HID_STATUS_CODE(hid_status) << endl;
	}

	// Load protected processes
	count = _countof(g_protectProcesses);
	for (int i = 0; i < count; i++)
	{
		HidObjId objId;
		hid_status = Hid_AddProtectedImage(hid_context, g_protectProcesses[i], WithoutInherit, TRUE, &objId);
		if (!HID_STATUS_SUCCESSFUL(hid_status))
			cout << "Error, Hid_AddProtectedImage failed with code: " << HID_STATUS_CODE(hid_status) << endl;
	}

	Hid_Destroy(hid_context);
	cout << "Completed!" << endl;

	return 0;
}

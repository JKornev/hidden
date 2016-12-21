#include <fltKernel.h>
#include <Ntddk.h>
#include "ExcludeList.h"

#include "RegFilter.h"
#include "FsFilter.h"
#include "PsMonitor.h"
#include "Device.h"
#include "Driver.h"
#include "Configs.h"

PDRIVER_OBJECT g_driverObject = NULL;

volatile LONG g_driverActive = FALSE;

// =========================================================================================

VOID EnableDisableDriver(BOOLEAN enabled)
{
	InterlockedExchange(&g_driverActive, (LONG)enabled);
}

BOOLEAN IsDriverEnabled()
{
	return (g_driverActive ? TRUE : FALSE);
}

// =========================================================================================

NTSTATUS InitializeStealthMode(PUNICODE_STRING RegistryPath)
{
	if (!CfgGetStealthState())
		return STATUS_SUCCESS;

	//TODO: implement me
	UNREFERENCED_PARAMETER(RegistryPath);

	return STATUS_SUCCESS;
}

// =========================================================================================

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	DestroyDevice();
	DestroyRegistryFilter();
	DestroyFSMiniFilter();
	DestroyPsMonitor();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(RegistryPath);

	EnableDisableDriver(TRUE);

	status = InitializeConfigs(RegistryPath);
	if (!NT_SUCCESS(status))
		DbgPrint("FsFilter1!" __FUNCTION__ ": can't initialize configs\n");

	EnableDisableDriver(CfgGetDriverState());

	status = InitializePsMonitor(DriverObject);
	if (!NT_SUCCESS(status))
		DbgPrint("FsFilter1!" __FUNCTION__ ": object monitor didn't start\n");

	status = InitializeFSMiniFilter(DriverObject);
	if (!NT_SUCCESS(status))
		DbgPrint("FsFilter1!" __FUNCTION__ ": file-system mini-filter didn't start\n");

	status = InitializeRegistryFilter(DriverObject);
	if (!NT_SUCCESS(status))
		DbgPrint("FsFilter1!" __FUNCTION__ ": registry filter didn't start\n");

	status = InitializeDevice(DriverObject);
	if (!NT_SUCCESS(status))
		DbgPrint("FsFilter1!" __FUNCTION__ ": can't create device\n");

	status = InitializeStealthMode(RegistryPath);
	if (!NT_SUCCESS(status))
		DbgPrint("FsFilter1!" __FUNCTION__ ": can't activate stealth mode\n");

	DestroyConfigs();

	DriverObject->DriverUnload = DriverUnload;
	g_driverObject = DriverObject;

	return STATUS_SUCCESS;
}


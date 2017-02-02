#include <fltKernel.h>
#include <Ntddk.h>
#include "ExcludeList.h"

#include "RegFilter.h"
#include "FsFilter.h"
#include "PsMonitor.h"
#include "Device.h"
#include "Driver.h"
#include "Configs.h"
#include "Helper.h"

#define DRIVER_ALLOC_TAG 'nddH'

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

ULONGLONG g_hiddenRegConfigId = 0;
ULONGLONG g_hiddenDriverFileId = 0;

NTSTATUS InitializeStealthMode(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	UNICODE_STRING normalized;
	NTSTATUS status;

	if (!CfgGetStealthState())
		return STATUS_SUCCESS;
	
	LdrEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

	normalized.Length = 0;
	normalized.MaximumLength = LdrEntry->FullModuleName.Length + NORMALIZE_INCREAMENT;
	normalized.Buffer = (PWCH)ExAllocatePoolWithQuotaTag(PagedPool, normalized.MaximumLength, DRIVER_ALLOC_TAG);
	
	if (!normalized.Buffer)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": error, can't allocate buffer\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(&LdrEntry->FullModuleName, &normalized);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": path normalization failed with code:%08x, path:%wZ\n", status, &LdrEntry->FullModuleName);
		ExFreePoolWithTag(normalized.Buffer, DRIVER_ALLOC_TAG);
		return status;
	}

	status = AddHiddenFile(&normalized, &g_hiddenDriverFileId);
	if (!NT_SUCCESS(status))
		DbgPrint("FsFilter1!" __FUNCTION__ ": can't hide self registry key\n");

	ExFreePoolWithTag(normalized.Buffer, DRIVER_ALLOC_TAG);

	status = AddHiddenRegKey(RegistryPath, &g_hiddenRegConfigId);
	if (!NT_SUCCESS(status))
		DbgPrint("FsFilter1!" __FUNCTION__ ": can't hide self registry key\n");

	return STATUS_SUCCESS;
}

// =========================================================================================

_Function_class_(DRIVER_UNLOAD)
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	DestroyDevice();
	DestroyRegistryFilter();
	DestroyFSMiniFilter();
	DestroyPsMonitor();
}

_Function_class_(DRIVER_INITIALIZE)
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

	status = InitializeStealthMode(DriverObject, RegistryPath);
	if (!NT_SUCCESS(status))
		DbgPrint("FsFilter1!" __FUNCTION__ ": can't activate stealth mode\n");

	DestroyConfigs();

	DriverObject->DriverUnload = DriverUnload;
	g_driverObject = DriverObject;

	return STATUS_SUCCESS;
}


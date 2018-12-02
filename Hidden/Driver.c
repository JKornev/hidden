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
		LogError("Error, can't allocate buffer");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(&LdrEntry->FullModuleName, &normalized);
	if (!NT_SUCCESS(status))
	{
		LogError("Error, path normalization failed with code:%08x, path:%wZ", status, &LdrEntry->FullModuleName);
		ExFreePoolWithTag(normalized.Buffer, DRIVER_ALLOC_TAG);
		return status;
	}

	status = AddHiddenFile(&normalized, &g_hiddenDriverFileId);
	if (!NT_SUCCESS(status))
		LogWarning("Error, can't hide self registry key");

	ExFreePoolWithTag(normalized.Buffer, DRIVER_ALLOC_TAG);

	status = AddHiddenRegKey(RegistryPath, &g_hiddenRegConfigId);
	if (!NT_SUCCESS(status))
		LogWarning("Error, can't hide self registry key");

	LogTrace("Stealth mode has been activated");
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
		LogWarning("Error, can't initialize configs");

	EnableDisableDriver(CfgGetDriverState());

	status = InitializePsMonitor(DriverObject);
	if (!NT_SUCCESS(status))
		LogWarning("Error, object monitor haven't started");

	status = InitializeFSMiniFilter(DriverObject);
	if (!NT_SUCCESS(status))
		LogWarning("Error, file-system mini-filter haven't started");

	status = InitializeRegistryFilter(DriverObject);
	if (!NT_SUCCESS(status))
		LogWarning("Error, registry filter haven't started");

	status = InitializeDevice(DriverObject);
	if (!NT_SUCCESS(status))
		LogWarning("Error, can't create device");

	status = InitializeStealthMode(DriverObject, RegistryPath);
	if (!NT_SUCCESS(status))
		LogWarning("Error, can't activate stealth mode");

	DestroyConfigs();

	DriverObject->DriverUnload = DriverUnload;
	g_driverObject = DriverObject;

	return STATUS_SUCCESS;
}


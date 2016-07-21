#pragma once

#include <Ntifs.h>

NTSTATUS InitializeRegistryFilter(PDRIVER_OBJECT DriverObject);
NTSTATUS DestroyRegistryFilter();

NTSTATUS AddHiddenRegKey(PUNICODE_STRING KeyPath, PULONGLONG ObjId);
NTSTATUS RemoveHiddenRegKey(ULONGLONG ObjId);
NTSTATUS RemoveAllHiddenRegKeys();

NTSTATUS AddHiddenRegValue(PUNICODE_STRING ValuePath, PULONGLONG ObjId);
NTSTATUS RemoveHiddenRegValue(ULONGLONG ObjId);
NTSTATUS RemoveAllHiddenRegValues();


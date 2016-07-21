#pragma once

#include <Ntddk.h>

NTSTATUS InitializePsMonitor(PDRIVER_OBJECT DriverObject);
NTSTATUS DestroyPsMonitor();

BOOLEAN IsProcessExcluded(HANDLE ProcessId);
BOOLEAN IsProcessProtected(HANDLE ProcessId);

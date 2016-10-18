#pragma once

#include <Ntddk.h>

typedef struct _ProcessId {
	HANDLE        id;
	LARGE_INTEGER creationTime;
} ProcessId, *PProcessId;

NTSTATUS InitializePsMonitor(PDRIVER_OBJECT DriverObject);
NTSTATUS DestroyPsMonitor();

BOOLEAN IsProcessExcluded(HANDLE ProcessId);
BOOLEAN IsProcessProtected(HANDLE ProcessId);

NTSTATUS AddProtectedImage(PUNICODE_STRING ImagePath, ULONG InheritType, BOOLEAN ApplyForProcesses, PULONGLONG ObjId);
NTSTATUS GetProtectedProcessState(HANDLE ProcessId, PULONG InheritType, PBOOLEAN Enable);
NTSTATUS SetProtectedProcessState(HANDLE ProcessId, ULONG InheritType, BOOLEAN Enable);
NTSTATUS RemoveProtectedImage(ULONGLONG ObjId);
NTSTATUS RemoveAllProtectedImages();

NTSTATUS AddExcludedImage(PUNICODE_STRING ImagePath, ULONG InheritType, BOOLEAN ApplyForProcesses, PULONGLONG ObjId);
NTSTATUS GetExcludedProcessState(HANDLE ProcessId, PULONG InheritType, PBOOLEAN Enable);
NTSTATUS SetExcludedProcessState(HANDLE ProcessId, ULONG InheritType, BOOLEAN Enable);
NTSTATUS RemoveExcludedImage(ULONGLONG ObjId);
NTSTATUS RemoveAllExcludedImages();

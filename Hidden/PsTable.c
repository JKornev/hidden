#include "PsTable.h"
#include "Helper.h"

#define PSTREE_ALLOC_TAG 'rTsP'

RTL_AVL_TABLE g_processTable;
KSPIN_LOCK    g_processTableLock;

RTL_GENERIC_COMPARE_RESULTS CompareProcessTableEntry(struct _RTL_AVL_TABLE  *Table, PVOID  FirstStruct, PVOID  SecondStruct)
{
	PProcessTableEntry first = (PProcessTableEntry)FirstStruct;
	PProcessTableEntry second = (PProcessTableEntry)SecondStruct;

	UNREFERENCED_PARAMETER(Table);

	if (first->processId > second->processId)
		return GenericGreaterThan;

	if (first->processId < second->processId)
		return GenericLessThan;

	return GenericEqual;
}

PVOID AllocateProcessTableEntry(struct _RTL_AVL_TABLE  *Table, CLONG  ByteSize)
{
	UNREFERENCED_PARAMETER(Table);
	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, PSTREE_ALLOC_TAG);
}

VOID FreeProcessTableEntry(struct _RTL_AVL_TABLE  *Table, PVOID  Buffer)
{
	UNREFERENCED_PARAMETER(Table);
	ExFreePoolWithTag(Buffer, PSTREE_ALLOC_TAG);
}

// API

BOOLEAN AddProcessToProcessTable(PProcessTableEntry entry)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	BOOLEAN result = FALSE;
	PVOID buf;

	KeAcquireInStackQueuedSpinLock(&g_processTableLock, &lockHandle);
	buf = RtlInsertElementGenericTableAvl(&g_processTable, entry, sizeof(ProcessTableEntry), &result);
	KeReleaseInStackQueuedSpinLock(&lockHandle);

	if (buf == NULL)
		return FALSE;

	return result;
}

BOOLEAN RemoveProcessFromProcessTable(PProcessTableEntry entry)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	BOOLEAN result;

	KeAcquireInStackQueuedSpinLock(&g_processTableLock, &lockHandle);
	result = RtlDeleteElementGenericTableAvl(&g_processTable, entry);
	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return result;
}

BOOLEAN GetProcessInProcessTable(PProcessTableEntry entry)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	PProcessTableEntry entry2;

	KeAcquireInStackQueuedSpinLock(&g_processTableLock, &lockHandle);
	entry2 = (PProcessTableEntry)RtlLookupElementGenericTableAvl(&g_processTable, entry);
	KeReleaseInStackQueuedSpinLock(&lockHandle);

	if (!entry2)
		return FALSE;

	RtlCopyMemory(entry, entry2, sizeof(ProcessTableEntry));

	return TRUE;
}

BOOLEAN UpdateProcessInProcessTable(PProcessTableEntry entry)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	PProcessTableEntry entry2;

	KeAcquireInStackQueuedSpinLock(&g_processTableLock, &lockHandle);
	entry2 = (PProcessTableEntry)RtlLookupElementGenericTableAvl(&g_processTable, entry);
	KeReleaseInStackQueuedSpinLock(&lockHandle);

	if (!entry2)
		return FALSE;

	RtlCopyMemory(entry2, entry, sizeof(ProcessTableEntry));

	return TRUE;
}

// Initialization

NTSTATUS InitializeProcessTable(VOID(*InitProcessEntryCallback)(PProcessTableEntry, PCUNICODE_STRING, HANDLE))
{
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL, first;
	NTSTATUS status;
	ULONG size = 0, offset;

	// Init process table 

	KeInitializeSpinLock(&g_processTableLock);
	RtlInitializeGenericTableAvl(&g_processTable, CompareProcessTableEntry, AllocateProcessTableEntry, FreeProcessTableEntry, NULL);

	// We should query processes information for creation process table for existing processes

	status = QuerySystemInformation(SystemProcessInformation, &processInfo, &size);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": query system information(pslist) failed with code:%08x\n", status);
		return status;
	}

	offset = 0;
	first = processInfo;
	do
	{
		ProcessTableEntry entry;
		PUNICODE_STRING procName;
		CLIENT_ID clientId;
		OBJECT_ATTRIBUTES attribs;
		HANDLE hProcess;
		SIZE_T size;

		// Get process path

		processInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)processInfo + offset);
		
		InitializeObjectAttributes(&attribs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		clientId.UniqueProcess = processInfo->ProcessId;
		clientId.UniqueThread = 0;

		status = NtOpenProcess(&hProcess, 0x1000/*PROCESS_QUERY_LIMITED_INFORMATION*/, &attribs, &clientId);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": can't open process (pid:%d) failed with code:%08x\n", processInfo->ProcessId, status);
			offset = processInfo->NextEntryOffset;
			continue;
		}

		status = QueryProcessInformation(ProcessImageFileName, hProcess, &procName, &size);
		ZwClose(hProcess);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": query process information(pid:%d) failed with code:%08x\n", processInfo->ProcessId, status);
			offset = processInfo->NextEntryOffset;
			continue;
		}

		// Add process in process table

		RtlZeroMemory(&entry, sizeof(entry));
		entry.processId = processInfo->ProcessId;

		DbgPrint("FsFilter1!" __FUNCTION__ ": add process: %d, %wZ\n", processInfo->ProcessId, procName);

		InitProcessEntryCallback(&entry, procName, processInfo->InheritedFromProcessId);
		if (!AddProcessToProcessTable(&entry))
			DbgPrint("FsFilter1!" __FUNCTION__ ": can't add process(pid:%d) to process table\n", processInfo->ProcessId);

		// Go to next

		FreeInformation(procName);
		offset = processInfo->NextEntryOffset;
	} 
	while (offset);

	FreeInformation(first);
	return status;
}

VOID DestroyProcessTable()
{
	KLOCK_QUEUE_HANDLE lockHandle;
	PProcessTableEntry entry;
	PVOID restartKey = NULL;

	KeAcquireInStackQueuedSpinLock(&g_processTableLock, &lockHandle);

	for (entry = RtlEnumerateGenericTableWithoutSplayingAvl(&g_processTable, &restartKey);
		entry != NULL;
		entry = RtlEnumerateGenericTableWithoutSplayingAvl(&g_processTable, &restartKey))
	{
		if (!RtlDeleteElementGenericTableAvl(&g_processTable, entry))
			DbgPrint("FsFilter1!" __FUNCTION__ ": can't remove element from process table, looks like memory leak\n");

		restartKey = NULL; // reset enum
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);
}

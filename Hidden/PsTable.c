#include "PsTable.h"
#include "Helper.h"

#define PSTREE_ALLOC_TAG 'rTsP'

RTL_AVL_TABLE  g_processTable;

RTL_AVL_TABLE  g_hiddenProcessTable;
FAST_MUTEX     g_hiddenProcessTableLock;

_Function_class_(RTL_AVL_COMPARE_ROUTINE)
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

_Function_class_(RTL_AVL_ALLOCATE_ROUTINE)
PVOID AllocateProcessTableEntry(struct _RTL_AVL_TABLE  *Table, CLONG  ByteSize)
{
	UNREFERENCED_PARAMETER(Table);
	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, PSTREE_ALLOC_TAG);
}

_Function_class_(RTL_AVL_FREE_ROUTINE)
VOID FreeProcessTableEntry(struct _RTL_AVL_TABLE  *Table, PVOID  Buffer)
{
	UNREFERENCED_PARAMETER(Table);
	ExFreePoolWithTag(Buffer, PSTREE_ALLOC_TAG);
}

// API

BOOLEAN AddProcessToProcessTable(PProcessTableEntry entry)
{
	BOOLEAN newone = FALSE;

	ObReferenceObject(entry->reference);
	
	if (!RtlInsertElementGenericTableAvl(&g_processTable, entry, sizeof(ProcessTableEntry), &newone))
	{
		ObDereferenceObject(entry->reference);
		return FALSE;
	}

	if (!newone)
	{
		ObDereferenceObject(entry->reference);
		return FALSE;
	}

	return TRUE;
}

BOOLEAN RemoveProcessFromProcessTable(HANDLE ProcessId)
{
	BOOLEAN result = FALSE;
	PProcessTableEntry entry = GetProcessInProcessTable(ProcessId);

	if (entry)
	{
		ProcessTableEntry entry2 = {0};
		entry2.processId = entry->processId;
		entry2.reference = entry->reference;
		
		result = RtlDeleteElementGenericTableAvl(&g_processTable, &entry2);
		if (result)
			ObDereferenceObject(entry2.reference);
	}

	return result;
}

PProcessTableEntry GetProcessInProcessTable(HANDLE ProcessId)
{
	ProcessTableEntry query = {0};
	query.processId = ProcessId;
	return (PProcessTableEntry)RtlLookupElementGenericTableAvl(&g_processTable, &query);
}

// Initialization

NTSTATUS InitializeProcessTable(VOID(*InitProcessEntryCallback)(PProcessTableEntry, PCUNICODE_STRING, HANDLE))
{
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL, first;
	NTSTATUS status;
	SIZE_T size = 0, offset;

	// Init process table 

	RtlInitializeGenericTableAvl(&g_processTable, CompareProcessTableEntry, AllocateProcessTableEntry, FreeProcessTableEntry, NULL);

	// We should query processes information for creation process table for existing processes

	status = QuerySystemInformation(SystemProcessInformation, &processInfo, &size);
	if (!NT_SUCCESS(status))
	{
		LogError("Error, query system information(pslist) failed with code:%08x", status);
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
		PEPROCESS process = 0;

		// Get process path

		processInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)processInfo + offset);
		
		if (processInfo->ProcessId == 0)
		{
			offset = processInfo->NextEntryOffset;
			continue;
		}

		InitializeObjectAttributes(&attribs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		clientId.UniqueProcess = processInfo->ProcessId;
		clientId.UniqueThread = 0;

		status = ZwOpenProcess(&hProcess, 0x1000/*PROCESS_QUERY_LIMITED_INFORMATION*/, &attribs, &clientId);
		if (!NT_SUCCESS(status))
		{
			LogWarning("Warning, can't open process (pid:%p) failed with code:%08x", processInfo->ProcessId, status);
			offset = processInfo->NextEntryOffset;
			continue;
		}

		status = QueryProcessInformation(ProcessImageFileName, hProcess, &procName, &size);
		ZwClose(hProcess);

		if (!NT_SUCCESS(status))
		{
			LogWarning("Warning, query process information(pid:%p) failed with code:%08x", processInfo->ProcessId, status);
			offset = processInfo->NextEntryOffset;
			continue;
		}

		// Add process in process table

		RtlZeroMemory(&entry, sizeof(entry));
		entry.processId = processInfo->ProcessId;

		status = PsLookupProcessByProcessId(processInfo->ProcessId, &process);
		if (!NT_SUCCESS(status))
		{
			LogWarning("Warning, lookup eprocess (pid:%p) failed with code:%08x", processInfo->ProcessId, status);
			FreeInformation(procName);
			offset = processInfo->NextEntryOffset;
			continue;
		}

		entry.reference = process;

		LogTrace("New process: %p, %wZ", processInfo->ProcessId, procName);

		InitProcessEntryCallback(&entry, procName, processInfo->InheritedFromProcessId);
		if (!AddProcessToProcessTable(&entry))
			LogWarning("Warning, can't add process(pid:%p) to process table", processInfo->ProcessId);

		ObDereferenceObject(process);

		if (entry.excluded)
			LogTrace(" excluded process:%p", entry.processId);

		if (entry.protected)
			LogTrace(" protected process:%p", entry.processId);

		if (entry.subsystem)
			LogTrace(" subsystem process:%p", entry.processId);

		if (entry.hidden)
			LogTrace(" hidden process:%p", entry.processId);

		// Go to next

		FreeInformation(procName);
		offset = processInfo->NextEntryOffset;
	} 
	while (offset);

	FreeInformation(first);
	LogTrace("Initialization is completed");
	return status;
}

VOID ClearProcessTable(VOID(*CleanupCallback)(PProcessTableEntry))
{
	PProcessTableEntry entry;
	PVOID restartKey = NULL;

	for (entry = RtlEnumerateGenericTableWithoutSplayingAvl(&g_processTable, &restartKey);
		 entry != NULL;
		 entry = RtlEnumerateGenericTableWithoutSplayingAvl(&g_processTable, &restartKey))
	{
		if (CleanupCallback)
			CleanupCallback(entry);

		ObDereferenceObject(entry->reference);

		if (!RtlDeleteElementGenericTableAvl(&g_processTable, entry))
			LogWarning("Warning, can't remove element from process table, looks like memory leak");

		restartKey = NULL; // reset enum
	}
	LogTrace("Deinitialization is completed");
}

VOID EnumProcessTable(VOID(*EnumCallback)(PProcessTableEntry))
{
	PProcessTableEntry entry;
	PVOID restartKey = NULL;

	for (entry = RtlEnumerateGenericTableWithoutSplayingAvl(&g_processTable, &restartKey);
		 entry != NULL;
		 entry = RtlEnumerateGenericTableWithoutSplayingAvl(&g_processTable, &restartKey))
	{
		EnumCallback(entry);
	}
}

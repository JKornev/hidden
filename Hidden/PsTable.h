#pragma once

#include <Ntddk.h>
#include "PsTable.h"

typedef struct _ProcessTableEntry{
	HANDLE processId;

	BOOLEAN excluded;
	ULONG   inheritExclusion;

	BOOLEAN protected;
	ULONG   inheritProtection;

} ProcessTableEntry, *PProcessTableEntry;

NTSTATUS InitializeProcessTable(VOID(*InitProcessEntryCallback)(PProcessTableEntry, PCUNICODE_STRING, HANDLE));
VOID DestroyProcessTable();

BOOLEAN AddProcessToProcessTable(PProcessTableEntry entry);
BOOLEAN RemoveProcessFromProcessTable(PProcessTableEntry entry);
BOOLEAN GetProcessInProcessTable(PProcessTableEntry entry);
BOOLEAN UpdateProcessInProcessTable(PProcessTableEntry entry);


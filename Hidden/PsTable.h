#pragma once

#include <Ntddk.h>
#include "Helper.h"

typedef struct _ProcessTableEntry {
	HANDLE      processId;

	BOOLEAN     excluded;
	ULONG       inheritExclusion;

	BOOLEAN     protected;
	ULONG       inheritProtection;

	BOOLEAN     hidden;
	BOOLEAN     postponeHiding;
	ULONG       inheritStealth;
	PEPROCESS   reference;
	HANDLE_TABLE_ENTRY cidEntryBackup;
	PHANDLE_TABLE_ENTRY cidEntry;

	BOOLEAN     subsystem;
	BOOLEAN     inited;

} ProcessTableEntry, *PProcessTableEntry;

NTSTATUS InitializeProcessTable(VOID(*InitProcessEntryCallback)(PProcessTableEntry, PCUNICODE_STRING, HANDLE));
VOID ClearProcessTable(VOID(*CleanupCallback)(PProcessTableEntry));
VOID EnumProcessTable(VOID(*EnumCallback)(PProcessTableEntry));

// Important notice:
// Keep in mind that internal sync mechanisms removed from functions below (including DestroyProcessTable) 
// because in some situations we need to perform two operation under one lock, for instance we should 
// perform GetProcessInProcessTable and UpdateProcessInProcessTable under one lock. So in this case all 
// functions, excluding InitializeProcessTable, should be synced manualy from external code

BOOLEAN AddProcessToProcessTable(PProcessTableEntry entry);
BOOLEAN RemoveProcessFromProcessTable(HANDLE ProcessId);
PProcessTableEntry GetProcessInProcessTable(HANDLE ProcessId);

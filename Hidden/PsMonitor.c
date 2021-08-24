#include "PsMonitor.h"
#include "ExcludeList.h"
#include "Helper.h"
#include "PsTable.h"
#include "PsRules.h"
#include "Driver.h"
#include "Configs.h"
#include "KernelAnalyzer.h"


#define PSMON_ALLOC_TAG 'nMsP'

#define PROCESS_QUERY_LIMITED_INFORMATION      0x1000
#define SYSTEM_PROCESS_ID (HANDLE)4

BOOLEAN g_psMonitorInited = FALSE;
PVOID g_obRegCallback = NULL;

OB_OPERATION_REGISTRATION g_regOperation[2];
OB_CALLBACK_REGISTRATION g_regCallback;

PsRulesContext g_excludeProcessRules;
PsRulesContext g_protectProcessRules;
PsRulesContext g_hideProcessRules;

FAST_MUTEX      g_processTableLock;
KGUARDED_MUTEX  g_activeProcListLock;

volatile ULONG g_activeProcessListOffset = 0;

typedef struct _ProcessListEntry {
	LPCWSTR path;
	ULONG inherit;
} ProcessListEntry, *PProcessListEntry;

// Use this variable for hard code full path to applications that can see hidden objects
// For instance: L"\\Device\\HarddiskVolume1\\Windows\\System32\\calc.exe",
// Notice: this array should be NULL terminated
CONST ProcessListEntry g_excludeProcesses[] = {
	{ NULL, PsRuleTypeWithoutInherit }
};

// Use this variable for hard code full path to applications that will be protected 
// For instance: L"\\Device\\HarddiskVolume1\\Windows\\System32\\cmd.exe",
// Notice: this array should be NULL terminated
CONST ProcessListEntry g_protectProcesses[] = {
	{ NULL, PsRuleTypeWithoutInherit }
};

#define CSRSS_PAHT_BUFFER_SIZE 256

UNICODE_STRING g_csrssPath;
WCHAR          g_csrssPathBuffer[CSRSS_PAHT_BUFFER_SIZE];

BOOLEAN CheckProtectedOperation(HANDLE Source, HANDLE Destination)
{
	PProcessTableEntry srcInfo, destInfo;
	BOOLEAN result = TRUE;

	if (Source == Destination)
		return FALSE;

	ExAcquireFastMutex(&g_processTableLock);
	
	srcInfo = GetProcessInProcessTable(Source);
	if (!srcInfo)
	{
		ExReleaseFastMutex(&g_processTableLock);
		return FALSE;
	}

	destInfo = GetProcessInProcessTable(Destination);
	if (!destInfo)
	{
		ExReleaseFastMutex(&g_processTableLock);
		return FALSE;
	}

	if (!destInfo->inited)
		result = FALSE; // If the process isn't inited yet it can be opened by any process
	else if (!destInfo->protected)
		result = FALSE;
	else if (srcInfo->protected)
		result = FALSE;
	else if (srcInfo->subsystem)
		result = FALSE;

	ExReleaseFastMutex(&g_processTableLock);
	
	return result;
}

OB_PREOP_CALLBACK_STATUS ProcessPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (!IsDriverEnabled())
		return OB_PREOP_SUCCESS;

	if (OperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;
	
	LogInfo("Process object operation, destPid:%Iu, srcTid:%Iu, oper: %s, space: %s",
		PsGetProcessId(OperationInformation->Object), PsGetCurrentThreadId(),
		(OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ? "create" : "dup"),
		(OperationInformation->KernelHandle ? "kernel" : "user")
	);

	if (!CheckProtectedOperation(PsGetCurrentProcessId(), PsGetProcessId(OperationInformation->Object)))
	{
		LogInfo("Allow protected process access from %Iu to %Iu", PsGetCurrentProcessId(), PsGetProcessId(OperationInformation->Object));
		return OB_PREOP_SUCCESS;
	}

	LogTrace("Disallow protected process access from %Iu to %Iu", PsGetCurrentProcessId(), PsGetProcessId(OperationInformation->Object));

	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
	else
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);

	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS ThreadPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (!IsDriverEnabled())
		return OB_PREOP_SUCCESS;

	if (OperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;

	LogInfo("Thread object operation, destPid:%Iu, destTid:%Iu, srcPid:%Iu, oper:%s, space:%s",
		PsGetThreadProcessId(OperationInformation->Object),
		PsGetThreadId(OperationInformation->Object),
		PsGetCurrentProcessId(),
		(OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ? "create" : "dup"),
		(OperationInformation->KernelHandle ? "kernel" : "user")
	);

	if (!CheckProtectedOperation(PsGetCurrentProcessId(), PsGetThreadProcessId(OperationInformation->Object)))
	{
		LogInfo("Allow protected thread access from %Iu to %Iu", PsGetCurrentProcessId(), PsGetThreadProcessId(OperationInformation->Object));
		return OB_PREOP_SUCCESS;
	}

	LogTrace("Disallow protected thread access from %Iu to %Iu", PsGetCurrentProcessId(), PsGetThreadProcessId(OperationInformation->Object));

	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);
	else
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);

	return OB_PREOP_SUCCESS;
}

//TODO:
// - Find an offset on driver initialization step

BOOLEAN FindActiveProcessLinksOffset(PEPROCESS Process, ULONG* Offset)
{
#ifdef _M_AMD64
	ULONG peak = 0x300;
#else
	ULONG peak = 0x150;
#endif
	HANDLE* ptr = (HANDLE*)Process;
	HANDLE processId;
	ULONG i;

	if (g_activeProcessListOffset)
	{
		*Offset = g_activeProcessListOffset;
		return TRUE;
	}

	processId = PsGetProcessId(Process);

	// EPROCESS ActiveProcessLinks field is next to UniqueProcessId
	//    ... 
	//	+ 0x0b4 UniqueProcessId : Ptr32 Void
	//	+ 0x0b8 ActiveProcessLinks : _LIST_ENTRY
	//	+ 0x0c0 Flags2 : Uint4B
	//    ...
	for (i = 15; i < peak / sizeof(HANDLE); i++)
	{
		if (ptr[i] == processId)
		{
			ULONG offset = sizeof(HANDLE) * (i + 1);
			InterlockedExchange((LONG volatile*)&g_activeProcessListOffset, offset);
			LogInfo("EPROCESS->ActiveProcessList offset is %x", offset);
			*Offset = offset;
			return TRUE;
		}
	}

	return FALSE;
}

VOID UnlinkProcessFromList(PLIST_ENTRY Current)
{ // https://github.com/landhb/HideProcess/blob/master/driver/hideprocess.c
	PLIST_ENTRY Previous, Next;

	Previous = (Current->Blink);
	Next = (Current->Flink);

	// Loop over self (connect previous with next)
	Previous->Flink = Next;
	Next->Blink = Previous;

	// Re-write the current LIST_ENTRY to point to itself (avoiding BSOD)
	Current->Blink = (PLIST_ENTRY)&Current->Flink;
	Current->Flink = (PLIST_ENTRY)&Current->Flink;
}

//
//Note: when we remove a process from ActiveProcessLinks it prevents a usermode
//      code to enum processes. But a process still accessible by PID. To fix it
//      we have to hack PspCidTable too.
//
VOID UnlinkProcessFromActiveProcessLinks(PProcessTableEntry Entry)
{
	PEPROCESS Process = Entry->reference;
	ULONG eprocListOffset = 0;
	PLIST_ENTRY CurrentList = NULL;

	if (!FindActiveProcessLinksOffset(Process, &eprocListOffset))
	{
		LogError("Error, can't find active process list offset, eprocess:%p", Process);
		return;
	}

	CurrentList = (PLIST_ENTRY)((ULONG_PTR)Process + eprocListOffset);

	// We use g_activeProcListLock to sync our modification inside hidden and raise
	// IRQL to disable special APC's because we want to minimize a BSOD chance because
	// of lack of the ActiveProcessLinks syncronization

	KeAcquireGuardedMutex(&g_activeProcListLock);
	UnlinkProcessFromList(CurrentList);
	KeReleaseGuardedMutex(&g_activeProcListLock);
}

VOID LinkProcessFromList(PLIST_ENTRY Current, PLIST_ENTRY Target)
{
	PLIST_ENTRY Previous, Next;

	if (Current->Blink != Current->Flink)
		return;

	Previous = Target;
	Next = Target->Flink;

	Current->Blink = Previous;
	Current->Flink = Next;

	Previous->Flink = (PLIST_ENTRY)&Current->Flink;
	Next->Blink = (PLIST_ENTRY)&Current->Flink;
}

VOID LinkProcessToActiveProcessLinks(PProcessTableEntry Entry)
{
	PEPROCESS Process = Entry->reference;
	ULONG eprocListOffset = 0;
	PLIST_ENTRY CurrentList = NULL, TargetList = NULL;
	PEPROCESS System;
	NTSTATUS status;

	if (!FindActiveProcessLinksOffset(Process, &eprocListOffset))
	{
		LogWarning("Warning, can't find active process list offset, eprocess:%p", Process);
		return;
	}

	status = PsLookupProcessByProcessId(SYSTEM_PROCESS_ID, &System);
	if (!NT_SUCCESS(status))
	{
		LogWarning("Warning, can't find active system process");
		return;
	}

	CurrentList = (PLIST_ENTRY)((ULONG_PTR)Process + eprocListOffset);
	TargetList  = (PLIST_ENTRY)((ULONG_PTR)System + eprocListOffset);

	KeAcquireGuardedMutex(&g_activeProcListLock);
	LinkProcessFromList(CurrentList, TargetList);
	KeReleaseGuardedMutex(&g_activeProcListLock);

	ObDereferenceObject(System);
}

typedef struct _CidTableContext {
	HANDLE ProcessId;
	BOOLEAN Found;
	HANDLE_TABLE_ENTRY EntryBackup;
	PHANDLE_TABLE_ENTRY Entry;
} CidTableContext, *PCidTableContext;

BOOLEAN RemoveHandleCallbackWin8(PVOID PspCidTable, PHANDLE_TABLE_ENTRY HandleTableEntry, HANDLE Handle, PVOID EnumParameter)
{
	PCidTableContext context = (PCidTableContext)EnumParameter;
	PHANDLE_TABLE_WIN8 cidTable = (PHANDLE_TABLE_WIN8)PspCidTable;
	BOOLEAN result = FALSE;

	if (PspCidTable != GetPspCidTablePointer())
	{
		LogWarning("Attempt to enumerate invalid table, %p != %p", PspCidTable, GetPspCidTablePointer());
		result = TRUE;
		goto cleanup;
	}

	if (context->ProcessId == Handle)
	{
		context->Found = TRUE;
		context->Entry = HandleTableEntry;
		context->EntryBackup = *HandleTableEntry;
		result = TRUE;

		HandleTableEntry->u1.Object = 0;
		HandleTableEntry->u2.NextFreeTableEntry = (ULONG_PTR)HandleTableEntry;

		LogInfo(
			"PID %Iu has been removed from PspCidTable, entry:%p, object:%p, access:%08x",
			Handle,
			HandleTableEntry,
			context->EntryBackup.u1.Object,
			context->EntryBackup.u2.GrantedAccess
		);

		goto cleanup_no_unlock;
	}

cleanup:

	_InterlockedExchangeAdd((volatile LONG*)&HandleTableEntry->u1.Value, EXHANDLE_TABLE_ENTRY_LOCK_BIT);
	_InterlockedOr((volatile LONG*)&HandleTableEntry->u1.Value, 0); // Why do we have it in ntoskrnl?

cleanup_no_unlock:

	if (cidTable->HandleTableLock)
		ExfUnblockPushLock(&cidTable->HandleTableLock, 0);

	return result;
}

BOOLEAN RemoveHandleCallback(PHANDLE_TABLE_ENTRY HandleTableEntry, HANDLE Handle, PVOID EnumParameter)
{
	PCidTableContext context = (PCidTableContext)EnumParameter;

	if (context->ProcessId != Handle)
		return FALSE;

	context->Found = TRUE;
	context->Entry = HandleTableEntry;
	context->EntryBackup = *HandleTableEntry;

	LogInfo(
		"PID %Iu has been removed from PspCidTable, entry:%p, object:%p, access:%08x",
		Handle,
		HandleTableEntry,
		context->EntryBackup.u1.Object,
		context->EntryBackup.u2.GrantedAccess
	);

	return TRUE;
}

VOID UnlinkProcessFromCidTable(PProcessTableEntry Entry)
{
	PVOID PspCidTable = GetPspCidTablePointer();

	if (!PspCidTable)
	{
		LogWarning("Can't unlink process %Iu from PspCidTable(NULL)", Entry->processId);
		return;
	}

	CidTableContext context;
	context.ProcessId = Entry->processId;
	context.Found = FALSE;

	EX_ENUMERATE_HANDLE_ROUTINE routine = (IsWin8OrAbove() ? (EX_ENUMERATE_HANDLE_ROUTINE)&RemoveHandleCallbackWin8 : &RemoveHandleCallback);
	if (!ExEnumHandleTable(PspCidTable, routine, &context, NULL))
	{
		LogWarning("Can't unlink process %Iu from PspCidTable", Entry->processId);
		return;
	}

	if (!context.Found)
	{
		LogWarning("Can't find process %Iu in PspCidTable", Entry->processId);
		return;
	}

	// Hack for Windows Vista, 7, to avoid lock bit leak
	if (!IsWin8OrAbove())
	{
		context.Entry->u1.Object = NULL;
		context.Entry->u2.GrantedAccess = 0;
	}

	Entry->cidEntryBackup = context.EntryBackup;
	Entry->cidEntry = context.Entry;
}

VOID RestoreProcessInCidTable(PProcessTableEntry Entry)
{
	//TODO: the check should be deleted
	if (!Entry->cidEntry)
		return;

	// Add a lock bit to avoid a deadlock when we return from CreateProcessNotifyCallback(destroy)
	Entry->cidEntryBackup.u1.Value |= EXHANDLE_TABLE_ENTRY_LOCK_BIT;
	*Entry->cidEntry = Entry->cidEntryBackup;

	LogInfo(
		"PID %Iu has been restored to PspCidTable, entry:%p, object:%p, access:%08x", 
		Entry->processId, 
		Entry->cidEntry, 
		Entry->cidEntry->u1.Object,
		Entry->cidEntry->u2.GrantedAccess
	);

	RtlZeroMemory(&Entry->cidEntryBackup, sizeof(Entry->cidEntryBackup));
	Entry->cidEntry = 0;
}

VOID HideProcess(PProcessTableEntry Entry)
{
	UnlinkProcessFromActiveProcessLinks(Entry);
	UnlinkProcessFromCidTable(Entry);
}

VOID RestoreHiddenProcess(PProcessTableEntry Entry)
{
	RestoreProcessInCidTable(Entry);
	LinkProcessToActiveProcessLinks(Entry);
}

VOID CheckProcessFlags(PProcessTableEntry Entry, PCUNICODE_STRING ImgPath, HANDLE ParentId)
{
	PProcessTableEntry lookup;
	ULONG inheritType;

	RtlZeroMemory(&lookup, sizeof(lookup));

	Entry->inited = (!g_psMonitorInited ? TRUE : FALSE);
	if (Entry->processId == SYSTEM_PROCESS_ID)
		Entry->subsystem = TRUE;
	else
		Entry->subsystem = RtlEqualUnicodeString(&g_csrssPath, ImgPath, TRUE);

	// Check exclude flag

	Entry->excluded = FALSE;
	Entry->inheritExclusion = PsRuleTypeWithoutInherit;

	if (FindInheritanceInPsRuleList(g_excludeProcessRules, ImgPath, &inheritType))
	{
		Entry->excluded = TRUE;
		Entry->inheritExclusion = inheritType;
	}
	else if (ParentId != 0)
	{
		ExAcquireFastMutex(&g_processTableLock);
		
		lookup = GetProcessInProcessTable(ParentId);
		if (lookup)
		{
			if (lookup->inheritExclusion == PsRuleTypeInherit)
			{
				Entry->excluded = TRUE;
				Entry->inheritExclusion = PsRuleTypeInherit;
			}
			else if (lookup->inheritExclusion == PsRuleTypeInheritOnce)
			{
				Entry->excluded = TRUE;
				Entry->inheritExclusion = PsRuleTypeWithoutInherit;
			}
		}

		ExReleaseFastMutex(&g_processTableLock);
	}

	// Check protected flag

	Entry->protected = FALSE;
	Entry->inheritProtection = PsRuleTypeWithoutInherit;

	if (FindInheritanceInPsRuleList(g_protectProcessRules, ImgPath, &inheritType))
	{
		Entry->protected = TRUE;
		Entry->inheritProtection = inheritType;
	}
	else if (ParentId != 0)
	{
		ExAcquireFastMutex(&g_processTableLock);
		
		lookup = GetProcessInProcessTable(ParentId);
		if (lookup)
		{
			if (lookup->inheritProtection == PsRuleTypeInherit)
			{
				Entry->protected = TRUE;
				Entry->inheritProtection = PsRuleTypeInherit;
			}
			else if (lookup->inheritProtection == PsRuleTypeInheritOnce)
			{
				Entry->protected = TRUE;
				Entry->inheritProtection = PsRuleTypeWithoutInherit;
			}
		}

		ExReleaseFastMutex(&g_processTableLock);
	}

	// Check hidden flag

	Entry->hidden = FALSE;
	Entry->inheritStealth = PsRuleTypeWithoutInherit;

	if (FindInheritanceInPsRuleList(g_hideProcessRules, ImgPath, &inheritType))
	{
		Entry->hidden = TRUE;
		Entry->inheritStealth = inheritType;
	}
	else if (ParentId != 0)
	{
		ExAcquireFastMutex(&g_processTableLock);
		
		lookup = GetProcessInProcessTable(ParentId);
		if (lookup)
		{
			if (lookup->inheritStealth == PsRuleTypeInherit)
			{
				Entry->hidden = TRUE;
				Entry->inheritStealth = PsRuleTypeInherit;
			}
			else if (lookup->inheritStealth == PsRuleTypeInheritOnce)
			{
				Entry->hidden = TRUE;
				Entry->inheritStealth = PsRuleTypeWithoutInherit;
			}
		}

		ExReleaseFastMutex(&g_processTableLock);
	}

	if (Entry->hidden)
	{
		// If CheckProcessFlags() performed for initialized process we can safely perform full process 
		// hiding code. But if a process isn't initialized (for instance on a ps create notification) we
		// need to postpone removing from PspCidTable because in a current step it would break a process
		// initialization
		if (Entry->inited)
			HideProcess(Entry);
		else
			UnlinkProcessFromActiveProcessLinks(Entry);
	}
}

VOID LoadProcessImageNotifyCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	PProcessTableEntry lookup;

	LogInfo(
		"Load image pid:%Iu, img:%wZ, addr:%p",
		ProcessId,
		FullImageName,
		ImageInfo->ImageBase
	);

	ExAcquireFastMutex(&g_processTableLock);

	lookup = GetProcessInProcessTable(ProcessId);
	if (lookup && !lookup->inited)
	{
		lookup->inited = TRUE;
		LogTrace("Process has been initialized:%Iu", ProcessId);

		if (lookup->hidden)
			UnlinkProcessFromCidTable(lookup);
	}

	ExReleaseFastMutex(&g_processTableLock);
}

VOID CreateProcessNotifyCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	BOOLEAN result;

	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo)
		LogInfo(
			"Created process, pid:%Iu, srcPid:%Iu, srcTid:%Iu, image:%wZ",
			ProcessId, 
			PsGetCurrentProcessId(), 
			PsGetCurrentThreadId(), 
			CreateInfo->ImageFileName
		);
	else
		LogInfo(
			"Destroyed process, pid:%Iu, srcPid:%Iu, srcTid:%Iu",
			ProcessId,
			PsGetCurrentProcessId(),
			PsGetCurrentThreadId()
		);

	if (CreateInfo)
	{
		ProcessTableEntry entry;
		const USHORT maxBufSize = CreateInfo->ImageFileName->Length + NORMALIZE_INCREAMENT;
		UNICODE_STRING normalized;
		NTSTATUS status;

		normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, maxBufSize, PSMON_ALLOC_TAG);
		normalized.Length = 0;
		normalized.MaximumLength = maxBufSize;

		if (!normalized.Buffer)
		{
			LogWarning("Error, can't allocate buffer");
			return;
		}

		status = NormalizeDevicePath(CreateInfo->ImageFileName, &normalized);
		if (!NT_SUCCESS(status))
		{
			LogWarning("Error, path normalization failed with code:%08x, path:%wZ", status, CreateInfo->ImageFileName);
			ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
			return;
		}

		RtlZeroMemory(&entry, sizeof(entry));
		entry.processId = ProcessId;
		entry.reference = Process;

		CheckProcessFlags(&entry, &normalized, PsGetCurrentProcessId());

		if (entry.excluded)
			LogTrace("Excluded process:%Iu", ProcessId);

		if (entry.protected)
			LogTrace("Protected process:%Iu", ProcessId);

		if (entry.hidden)
			LogTrace("Hidden process:%Iu", ProcessId);

		ExAcquireFastMutex(&g_processTableLock);
		result = AddProcessToProcessTable(&entry);
		ExReleaseFastMutex(&g_processTableLock);

		if (!result)
			LogWarning("Warning, can't add process(pid:%Iu) to process table", ProcessId);

		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
	}
	else
	{
		ExAcquireFastMutex(&g_processTableLock);
		PProcessTableEntry entry = GetProcessInProcessTable(ProcessId);
		if (entry && entry->hidden)
			RestoreProcessInCidTable(entry);
		result = RemoveProcessFromProcessTable(ProcessId);
		ExReleaseFastMutex(&g_processTableLock);

		if (!result)
			LogWarning("Warning, can't remove process(pid:%Iu) from process table", ProcessId);
	}
}

BOOLEAN IsProcessExcluded(HANDLE ProcessId)
{
	PProcessTableEntry entry;
	BOOLEAN result;

	// Exclude system process because we don't want affect to kernel-mode threads
	if (ProcessId == SYSTEM_PROCESS_ID)
		return TRUE;

	ExAcquireFastMutex(&g_processTableLock);
	entry = GetProcessInProcessTable(ProcessId);
	result = (entry && entry->excluded ? TRUE : FALSE);
	ExReleaseFastMutex(&g_processTableLock);

	return result;
}

BOOLEAN IsProcessProtected(HANDLE ProcessId)
{
	PProcessTableEntry entry;
	BOOLEAN result;

	ExAcquireFastMutex(&g_processTableLock);
	entry = GetProcessInProcessTable(ProcessId);
	result = (entry && entry->protected ? TRUE : FALSE);
	ExReleaseFastMutex(&g_processTableLock);

	return result;
}

NTSTATUS ParsePsConfigEntry(PUNICODE_STRING Entry, PUNICODE_STRING Path, PULONG Inherit)
{
	USHORT inx, length = Entry->Length / sizeof(WCHAR);
	LPWSTR str = Entry->Buffer;
	UNICODE_STRING command, template;

	RtlZeroMemory(&command, sizeof(command));

	for (inx = 0; inx < length; inx++)
	{
		if (str[inx] == L';')
		{
			command.Buffer = str + inx + 1;
			command.Length = (length - inx - 1) * sizeof(WCHAR);
			command.MaximumLength = command.Length;
			break;
		}
	}

	if (inx == 0)
		return STATUS_NO_DATA_DETECTED;

	Path->Buffer = Entry->Buffer;
	Path->Length = inx * sizeof(WCHAR);
	Path->MaximumLength = Path->Length;

	RtlInitUnicodeString(&template, L"none");
	if (RtlCompareUnicodeString(&command, &template, TRUE) == 0)
	{
		*Inherit = PsRuleTypeWithoutInherit;
		return STATUS_SUCCESS;
	}

	RtlInitUnicodeString(&template, L"always");
	if (RtlCompareUnicodeString(&command, &template, TRUE) == 0)
	{
		*Inherit = PsRuleTypeInherit;
		return STATUS_SUCCESS;
	}

	RtlInitUnicodeString(&template, L"once");
	if (RtlCompareUnicodeString(&command, &template, TRUE) == 0)
	{
		*Inherit = PsRuleTypeInheritOnce;
		return STATUS_SUCCESS;
	}

	return STATUS_NOT_FOUND;
}

VOID LoadProtectedRulesCallback(PUNICODE_STRING Str, PVOID Params)
{
	UNICODE_STRING path;
	ULONG inherit;
	PsRuleEntryId ruleId;

	UNREFERENCED_PARAMETER(Params);

	if (NT_SUCCESS(ParsePsConfigEntry(Str, &path, &inherit)))
		AddProtectedImage(&path, inherit, FALSE, &ruleId);
}

VOID LoadIgnoredRulesCallback(PUNICODE_STRING Str, PVOID Params)
{
	UNICODE_STRING path;
	ULONG inherit;
	PsRuleEntryId ruleId;

	UNREFERENCED_PARAMETER(Params);

	if (NT_SUCCESS(ParsePsConfigEntry(Str, &path, &inherit)))
		AddExcludedImage(&path, inherit, FALSE, &ruleId);
}

VOID LoadHiddenRulesCallback(PUNICODE_STRING Str, PVOID Params)
{
	UNICODE_STRING path;
	ULONG inherit;
	PsRuleEntryId ruleId;

	UNREFERENCED_PARAMETER(Params);
	
	if (NT_SUCCESS(ParsePsConfigEntry(Str, &path, &inherit)))
		AddHiddenImage(&path, inherit, FALSE, &ruleId);
}

NTSTATUS InitializePsMonitor(PDRIVER_OBJECT DriverObject)
{
	const USHORT maxBufSize = 512;
	NTSTATUS status;
	UNICODE_STRING str, normalized, csrss;
	UINT32 i;
	PsRuleEntryId ruleId;

	UNREFERENCED_PARAMETER(DriverObject);

	// Set csrss path

	RtlZeroMemory(g_csrssPathBuffer, sizeof(g_csrssPathBuffer));
	g_csrssPath.Buffer = g_csrssPathBuffer;
	g_csrssPath.Length = 0;
	g_csrssPath.MaximumLength = sizeof(g_csrssPathBuffer);

	RtlInitUnicodeString(&csrss, L"\\SystemRoot\\System32\\csrss.exe");
	status = NormalizeDevicePath(&csrss, &g_csrssPath);
	if (!NT_SUCCESS(status))
	{
		LogError("Error, subsystem path normalization failed with code:%08x", status);
		return status;
	}

	LogTrace("Subsystem path: %wZ", &g_csrssPath);

	// Init normalization buffer

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, maxBufSize, PSMON_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;
	if (!normalized.Buffer)
	{
		LogError("Error, allocation failed");
		return STATUS_ACCESS_DENIED;
	}

	// Initialize and fill exclude file\dir lists 

	// exclude

	status = InitializePsRuleListContext(&g_excludeProcessRules);
	if (!NT_SUCCESS(status))
	{
		LogError("Error, excluded process rules initialization failed with code:%08x", status);
		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
		return status;
	}

	for (i = 0; g_excludeProcesses[i].path; i++)
	{
		RtlInitUnicodeString(&str, g_excludeProcesses[i].path);

		status = NormalizeDevicePath(&str, &normalized);
		LogTrace("Normalized excluded: %wZ", &normalized);
		if (!NT_SUCCESS(status))
		{
			LogWarning("Path normalization failed with code:%08x, path:%wZ", status, &str);
			continue;
		}

		AddRuleToPsRuleList(g_excludeProcessRules, &normalized, g_excludeProcesses[i].inherit, &ruleId);
	}

	// Load entries from the config
	CfgEnumConfigsTable(IgnoreImagesTable, &LoadIgnoredRulesCallback, NULL);

	// protected

	status = InitializePsRuleListContext(&g_protectProcessRules);
	if (!NT_SUCCESS(status))
	{
		LogError("Error, protected process rules initialization failed with code:%08x", status);
		DestroyPsRuleListContext(g_excludeProcessRules);
		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
		return status;
	}

	for (i = 0; g_protectProcesses[i].path; i++)
	{
		RtlInitUnicodeString(&str, g_protectProcesses[i].path);

		status = NormalizeDevicePath(&str, &normalized);
		LogTrace("Normalized protected %wZ", &normalized);
		if (!NT_SUCCESS(status))
		{
			LogWarning("Path normalization failed with code:%08x, path:%wZ", status, &str);
			continue;
		}

		AddRuleToPsRuleList(g_protectProcessRules, &normalized, g_protectProcesses[i].inherit, &ruleId);
	}

	// Load entries from the config
	CfgEnumConfigsTable(ProtectImagesTable, &LoadProtectedRulesCallback, NULL);

	// hidden

	status = InitializePsRuleListContext(&g_hideProcessRules);
	if (!NT_SUCCESS(status))
	{
		LogError("Error, hidden process rules initialization failed with code:%08x", status);
		DestroyPsRuleListContext(g_excludeProcessRules);
		DestroyPsRuleListContext(g_protectProcessRules);
		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
		return status;
	}

	// Load entries from the config
	CfgEnumConfigsTable(HideImagesTable, &LoadHiddenRulesCallback, NULL);

	// Process table

	ExInitializeFastMutex(&g_processTableLock);
	KeInitializeGuardedMutex(&g_activeProcListLock);

	status = InitializeProcessTable(&CheckProcessFlags);
	if (!NT_SUCCESS(status))
	{
		DestroyPsRuleListContext(g_excludeProcessRules);
		DestroyPsRuleListContext(g_protectProcessRules);
		DestroyPsRuleListContext(g_hideProcessRules);
		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
		return status;
	}

	ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);

	g_psMonitorInited = TRUE;

	// Register ps\thr pre create\duplicate object callback

	g_regOperation[0].ObjectType = PsProcessType;
	g_regOperation[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	g_regOperation[0].PreOperation = ProcessPreCallback;
	g_regOperation[0].PostOperation = NULL;

	g_regOperation[1].ObjectType = PsThreadType;
	g_regOperation[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	g_regOperation[1].PreOperation = ThreadPreCallback;
	g_regOperation[1].PostOperation = NULL;

	g_regCallback.Version = OB_FLT_REGISTRATION_VERSION;
	g_regCallback.OperationRegistrationCount = 2;
	g_regCallback.RegistrationContext = NULL;
	g_regCallback.OperationRegistration = g_regOperation;
	RtlInitUnicodeString(&g_regCallback.Altitude, L"1000");

	status = ObRegisterCallbacks(&g_regCallback, &g_obRegCallback);
	if (!NT_SUCCESS(status))
	{
		LogError("Error, object filter registration failed with code:%08x", status);
		DestroyPsMonitor();
		return status;
	}

	// Register rocess create\destroy callback

	status = PsSetCreateProcessNotifyRoutineEx(&CreateProcessNotifyCallback, FALSE);
	if (!NT_SUCCESS(status))
	{
		LogError("Error, process notify registartion failed with code:%08x", status);
		DestroyPsMonitor();
		return status;
	}

	status = PsSetLoadImageNotifyRoutine(&LoadProcessImageNotifyCallback);
	if (!NT_SUCCESS(status))
	{
		LogError("Error, image load notify registartion failed with code:%08x", status);
		DestroyPsMonitor();
		return status;
	}

	LogTrace("Initialization is completed");
	return status;
}

VOID CleanupHiddenProcessCallback(PProcessTableEntry entry)
{
	if (!entry->hidden)
		return;

	RestoreHiddenProcess(entry);

	entry->hidden = FALSE;
}

NTSTATUS DestroyPsMonitor()
{
	if (!g_psMonitorInited)
		return STATUS_ALREADY_DISCONNECTED;

	if (g_obRegCallback)
	{
		ObUnRegisterCallbacks(g_obRegCallback);
		g_obRegCallback = NULL;
	}

	PsRemoveLoadImageNotifyRoutine(&LoadProcessImageNotifyCallback);
	PsSetCreateProcessNotifyRoutineEx(&CreateProcessNotifyCallback, TRUE);

	DestroyPsRuleListContext(g_excludeProcessRules);
	DestroyPsRuleListContext(g_protectProcessRules);
	DestroyPsRuleListContext(g_hideProcessRules);

	ExAcquireFastMutex(&g_processTableLock);
	ClearProcessTable(&CleanupHiddenProcessCallback);
	ExReleaseFastMutex(&g_processTableLock);

	g_psMonitorInited = FALSE;

	LogTrace("Deinitialization is completed");
	return STATUS_SUCCESS;
}

NTSTATUS SetStateForProcessesByImage(PCUNICODE_STRING ImagePath, BOOLEAN Excluded, BOOLEAN Protected, BOOLEAN Hidden)
{
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL, first;
	SIZE_T size = 0, offset;
	NTSTATUS status;

	status = QuerySystemInformation(SystemProcessInformation, &processInfo, &size);
	if (!NT_SUCCESS(status))
	{
		LogWarning("Query system information(pslist) failed with code:%08x", status);
		return status;
	}

	offset = 0;
	first = processInfo;
	do
	{
		HANDLE hProcess;
		CLIENT_ID clientId;
		OBJECT_ATTRIBUTES attribs;
		PUNICODE_STRING procName;

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
			LogWarning("Can't open process (pid:%Iu) failed with code:%08x", processInfo->ProcessId, status);
			offset = processInfo->NextEntryOffset;
			continue;
		}

		status = QueryProcessInformation(ProcessImageFileName, hProcess, &procName, &size);
		ZwClose(hProcess);

		if (!NT_SUCCESS(status))
		{
			LogWarning("Query process information(pid:%Iu) failed with code:%08x", processInfo->ProcessId, status);
			offset = processInfo->NextEntryOffset;
			continue;
		}

		if (RtlCompareUnicodeString(procName, ImagePath, TRUE) == 0)
		{
			PProcessTableEntry entry;

			ExAcquireFastMutex(&g_processTableLock);
			
			entry = GetProcessInProcessTable(processInfo->ProcessId);
			if (entry)
			{
				if (Excluded)
				{
					entry->excluded = TRUE;
					entry->inheritExclusion = PsRuleTypeWithoutInherit;
				}

				if (Protected)
				{
					entry->protected = TRUE;
					entry->inheritProtection = PsRuleTypeWithoutInherit;
				}

				if (Hidden)
				{
					if (!entry->hidden)
						HideProcess(entry);

					entry->hidden = TRUE;
					entry->inheritStealth = PsRuleTypeWithoutInherit;
				}
			}

			ExReleaseFastMutex(&g_processTableLock);
		}

		FreeInformation(procName);
		offset = processInfo->NextEntryOffset;
	} while (offset);

	FreeInformation(first);
	return STATUS_SUCCESS;
}

NTSTATUS AddProtectedImage(PUNICODE_STRING ImagePath, ULONG InheritType, BOOLEAN ApplyForProcesses, PULONGLONG ObjId)
{
	const USHORT maxBufSize = ImagePath->Length + NORMALIZE_INCREAMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, maxBufSize, PSMON_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;

	if (!normalized.Buffer)
	{
		LogWarning("Error, can't allocate buffer");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(ImagePath, &normalized);
	if (!NT_SUCCESS(status))
	{
		LogWarning("Error, path normalization failed with code:%08x, path:%wZ", status, ImagePath);
		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
		return status;
	}

	LogTrace("Adding protect image: %wZ", &normalized);
	status = AddRuleToPsRuleList(g_protectProcessRules, &normalized, InheritType, ObjId);

	if (ApplyForProcesses)
		SetStateForProcessesByImage(&normalized, FALSE, TRUE, FALSE);

	ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);

	return status;
}

NTSTATUS GetProtectedProcessState(HANDLE ProcessId, PULONG InheritType, PBOOLEAN Enable)
{
	PProcessTableEntry entry;
	BOOLEAN found = FALSE;

	ExAcquireFastMutex(&g_processTableLock);

	entry = GetProcessInProcessTable(ProcessId);
	if (entry)
	{
		*Enable = entry->protected;
		*InheritType = entry->inheritProtection;
		found = TRUE;
	}

	ExReleaseFastMutex(&g_processTableLock);

	return (found ? STATUS_SUCCESS : STATUS_NOT_FOUND);
}

NTSTATUS SetProtectedProcessState(HANDLE ProcessId, ULONG InheritType, BOOLEAN Enable)
{
	PProcessTableEntry entry;
	BOOLEAN found = FALSE;

	ExAcquireFastMutex(&g_processTableLock);

	entry = GetProcessInProcessTable(ProcessId);
	if (entry)
	{
		if (Enable)
		{
			entry->protected = TRUE;
			entry->inheritProtection = InheritType;
		}
		else
		{
			entry->protected = FALSE;
		}

		found = TRUE;
	}
	
	ExReleaseFastMutex(&g_processTableLock);

	return (found ? STATUS_SUCCESS : STATUS_NOT_FOUND);
}

NTSTATUS RemoveProtectedImage(ULONGLONG ObjId)
{
	return RemoveRuleFromPsRuleList(g_protectProcessRules, ObjId);
}

NTSTATUS RemoveAllProtectedImages()
{
	return RemoveAllRulesFromPsRuleList(g_protectProcessRules);
}

NTSTATUS AddExcludedImage(PUNICODE_STRING ImagePath, ULONG InheritType, BOOLEAN ApplyForProcesses, PULONGLONG ObjId)
{
	const USHORT maxBufSize = ImagePath->Length + NORMALIZE_INCREAMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, maxBufSize, PSMON_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;

	if (!normalized.Buffer)
	{
		LogWarning("Error, can't allocate buffer");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(ImagePath, &normalized);
	if (!NT_SUCCESS(status))
	{
		LogWarning("Error, path normalization failed with code:%08x, path:%wZ", status, ImagePath);
		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
		return status;
	}

	LogTrace("Adding exclude image: %wZ", &normalized);
	status = AddRuleToPsRuleList(g_excludeProcessRules, &normalized, InheritType, ObjId);

	if (ApplyForProcesses)
		SetStateForProcessesByImage(&normalized, TRUE, FALSE, FALSE);

	ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);

	return status;
}

NTSTATUS GetExcludedProcessState(HANDLE ProcessId, PULONG InheritType, PBOOLEAN Enable)
{
	PProcessTableEntry entry;
	BOOLEAN found = FALSE;

	ExAcquireFastMutex(&g_processTableLock);

	entry = GetProcessInProcessTable(ProcessId);
	if (entry)
	{
		*Enable = entry->excluded;
		*InheritType = entry->inheritExclusion;
		found = TRUE;
	}

	ExReleaseFastMutex(&g_processTableLock);

	return (found ? STATUS_SUCCESS : STATUS_NOT_FOUND);
}

NTSTATUS SetExcludedProcessState(HANDLE ProcessId, ULONG InheritType, BOOLEAN Enable)
{
	PProcessTableEntry entry;
	BOOLEAN found = FALSE;

	ExAcquireFastMutex(&g_processTableLock);

	entry = GetProcessInProcessTable(ProcessId);
	if (entry)
	{
		if (Enable)
		{
			entry->excluded = TRUE;
			entry->inheritExclusion = InheritType;
		}
		else
		{
			entry->excluded = FALSE;
		}

		found = TRUE;
	}

	ExReleaseFastMutex(&g_processTableLock);

	return (found ? STATUS_SUCCESS : STATUS_NOT_FOUND);
}

NTSTATUS RemoveExcludedImage(ULONGLONG ObjId)
{
	return RemoveRuleFromPsRuleList(g_excludeProcessRules, ObjId);
}

NTSTATUS RemoveAllExcludedImages()
{
	return RemoveAllRulesFromPsRuleList(g_excludeProcessRules);
}

NTSTATUS AddHiddenImage(PUNICODE_STRING ImagePath, ULONG InheritType, BOOLEAN ApplyForProcesses, PULONGLONG ObjId)
{
	const USHORT maxBufSize = ImagePath->Length + NORMALIZE_INCREAMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, maxBufSize, PSMON_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;

	if (!normalized.Buffer)
	{
		LogWarning("Error, can't allocate buffer");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(ImagePath, &normalized);
	if (!NT_SUCCESS(status))
	{
		LogWarning("Error, path normalization failed with code:%08x, path:%wZ", status, ImagePath);
		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
		return status;
	}

	LogTrace("Adding hidden image: %wZ", &normalized);
	status = AddRuleToPsRuleList(g_hideProcessRules, &normalized, InheritType, ObjId);

	//TODO: 
	if (ApplyForProcesses)
		SetStateForProcessesByImage(&normalized, FALSE, FALSE, TRUE);

	ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);

	return status;
}

NTSTATUS GetHiddenProcessState(HANDLE ProcessId, PULONG InheritType, PBOOLEAN Enable)
{
	PProcessTableEntry entry;
	BOOLEAN found = FALSE;

	ExAcquireFastMutex(&g_processTableLock);

	entry = GetProcessInProcessTable(ProcessId);
	if (entry)
	{
		*Enable = entry->hidden;
		*InheritType = entry->inheritStealth;
		found = TRUE;
	}

	ExReleaseFastMutex(&g_processTableLock);

	return (found ? STATUS_SUCCESS : STATUS_NOT_FOUND);
}

NTSTATUS SetHiddenProcessState(HANDLE ProcessId, ULONG InheritType, BOOLEAN Enable) 
{
	PProcessTableEntry entry;
	BOOLEAN found = FALSE;

	ExAcquireFastMutex(&g_processTableLock);

	entry = GetProcessInProcessTable(ProcessId);
	if (entry)
	{
		if (Enable)
		{
			if (!entry->hidden)
				HideProcess(entry);

			entry->hidden = TRUE;
			entry->inheritStealth = InheritType;
		}
		else
		{
			if (!entry->hidden)
			{
				ExReleaseFastMutex(&g_processTableLock);
				return STATUS_NOT_CAPABLE;
			}

			RestoreHiddenProcess(entry);

			entry->hidden = FALSE;
			entry->inheritStealth = 0;
		}

		found = TRUE;
	}

	ExReleaseFastMutex(&g_processTableLock);

	return (found ? STATUS_SUCCESS : STATUS_NOT_FOUND);
}

NTSTATUS RemoveHiddenImage(ULONGLONG ObjId)
{
	return RemoveRuleFromPsRuleList(g_hideProcessRules, ObjId);
}

NTSTATUS RemoveAllHiddenImages()
{
	return RemoveAllRulesFromPsRuleList(g_hideProcessRules);
}

NTSTATUS RemoveAllHiddenProcesses()
{
	ExAcquireFastMutex(&g_processTableLock);
	EnumProcessTable(&CleanupHiddenProcessCallback);
	ExReleaseFastMutex(&g_processTableLock);
	return STATUS_SUCCESS;
}
#include "PsMonitor.h"
#include "ExcludeList.h"
#include "Helper.h"
#include "PsTable.h"
#include "PsRules.h"

#define PROCESS_QUERY_LIMITED_INFORMATION      0x1000
#define SYSTEM_PROCESS_ID (HANDLE)4

BOOLEAN g_psMonitorInited = FALSE;
PVOID g_obRegCallback = NULL;

OB_OPERATION_REGISTRATION g_regOperation[2];
OB_CALLBACK_REGISTRATION g_regCallback;

PsRulesContext g_excludeProcessRules;
PsRulesContext g_protectProcessRules;

typedef struct _ProcessListEntry {
	LPCWSTR path;
	ULONG inherit;
} ProcessListEntry, *PProcessListEntry;

// Use this variable for hard code full path to applications that can see hidden objects
// For instance: L"\\Device\\HarddiskVolume1\\Windows\\System32\\calc.exe",
// Notice: this array should be NULL terminated
CONST ProcessListEntry g_excludeProcesses[] = {
	{ NULL, 0 }
};

// Use this variable for hard code full path to applications that will be protected 
// For instance: L"\\Device\\HarddiskVolume1\\Windows\\System32\\cmd.exe",
// Notice: this array should be NULL terminated
CONST ProcessListEntry g_protectProcesses[] = {
	{ NULL, 0 }
};

#define CSRSS_PAHT_BUFFER_SIZE 256

UNICODE_STRING g_csrssPath;
WCHAR          g_csrssPathBuffer[CSRSS_PAHT_BUFFER_SIZE];

BOOLEAN CheckProtectedOperation(HANDLE Source, HANDLE Destination)
{
	ProcessTableEntry srcInfo, destInfo;

	if (Source == Destination)
		return FALSE;

	destInfo.processId = Destination;
	if (!GetProcessInProcessTable(&destInfo))
		return FALSE;

	srcInfo.processId = Source;
	if (!GetProcessInProcessTable(&srcInfo))
		return FALSE;

	// Not-inited process can open any process (parent, csrss, etc)
	if (!destInfo.inited)
	{
		// Update if source is subsystem and destination isn't inited
		if (srcInfo.subsystem)
		{
			destInfo.inited = TRUE;
			if (!UpdateProcessInProcessTable(&destInfo))
				DbgPrint("FsFilter1!" __FUNCTION__ ": can't update initial state for process: %d\n", destInfo.processId);
		}

		return FALSE;
	}

	if (!destInfo.protected)
		return FALSE;

	if (srcInfo.protected)
		return FALSE;

	if (srcInfo.subsystem)
		return FALSE;
	
	return TRUE;
}

OB_PREOP_CALLBACK_STATUS ProcessPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (OperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;
	
	//DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! Process: %d(%d:%d), Oper: %s, Space: %s\n",
	//	PsGetProcessId(OperationInformation->Object), PsGetCurrentProcessId(), PsGetCurrentThreadId(),
	//	(OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ? "create" : "dup"),
	//	(OperationInformation->KernelHandle ? "kernel" : "user")
	//);

	if (!CheckProtectedOperation(PsGetCurrentProcessId(), PsGetProcessId(OperationInformation->Object)))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! allow protected process %d\n", PsGetCurrentProcessId());
		return OB_PREOP_SUCCESS;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! disallow protected process %d\n", PsGetCurrentProcessId());

	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
	else
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);

	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS ThreadPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (OperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;

	//DbgPrint("FsFilter1!" __FUNCTION__ ": Thread: %d(%d:%d), Oper: %s, Space: %s\n",
	//	PsGetThreadId(OperationInformation->Object), PsGetCurrentProcessId(), PsGetCurrentThreadId(),
	//	(OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ? "create" : "dup"),
	//	(OperationInformation->KernelHandle ? "kernel" : "user")
	//);

	if (!CheckProtectedOperation(PsGetCurrentProcessId(), PsGetProcessId(OperationInformation->Object)))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! allow protected thread %d\n", PsGetCurrentProcessId());
		return OB_PREOP_SUCCESS;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! disallow protected thread %d\n", PsGetCurrentProcessId());

	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);
	else
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);

	return OB_PREOP_SUCCESS;
}

VOID CheckProcessFlags(PProcessTableEntry Entry, PCUNICODE_STRING ImgPath, HANDLE ParentId)
{
	ProcessTableEntry lookup;
	ULONG inheritType;

	RtlZeroMemory(&lookup, sizeof(lookup));

	Entry->inited = (!g_psMonitorInited ? TRUE : FALSE);
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
		lookup.processId = ParentId;
		if (GetProcessInProcessTable(&lookup))
		{
			if (lookup.inheritExclusion == PsRuleTypeInherit)
			{
				Entry->excluded = TRUE;
				Entry->inheritExclusion = PsRuleTypeInherit;
			}
			else if (lookup.inheritExclusion == PsRuleTypeInheritOnce)
			{
				Entry->excluded = TRUE;
				Entry->inheritExclusion = PsRuleTypeWithoutInherit;
			}
		}
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
		lookup.processId = ParentId;
		if (GetProcessInProcessTable(&lookup))
		{
			if (lookup.inheritProtection == PsRuleTypeInherit)
			{
				Entry->protected = TRUE;
				Entry->inheritProtection = PsRuleTypeInherit;
			}
			else if (lookup.inheritProtection == PsRuleTypeInheritOnce)
			{
				Entry->protected = TRUE;
				Entry->inheritProtection = PsRuleTypeWithoutInherit;
			}
		}
	}
}

VOID CreateProcessNotifyCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	ProcessTableEntry entry;

	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo)
		DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! new process: %d (%d:%d), %wZ\n", ProcessId, PsGetCurrentProcessId(), PsGetCurrentThreadId(), CreateInfo->ImageFileName);
	else
		DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! destroy process: %d (%d:%d)\n", ProcessId, PsGetCurrentProcessId(), PsGetCurrentThreadId());

	RtlZeroMemory(&entry, sizeof(entry));
	entry.processId = ProcessId;

	if (CreateInfo)
	{
		const USHORT maxBufSize = CreateInfo->ImageFileName->Length + NORMALIZE_INCREAMENT;
		UNICODE_STRING normalized;
		NTSTATUS status;

		normalized.Buffer = (PWCH)ExAllocatePool(PagedPool, maxBufSize);
		normalized.Length = 0;
		normalized.MaximumLength = maxBufSize;

		if (!normalized.Buffer)
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": error, can't allocate buffer\n");
			return;
		}

		status = NormalizeDevicePath(CreateInfo->ImageFileName, &normalized);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": path normalization failed with code:%08x, path:%wZ\n", status, CreateInfo->ImageFileName);
			ExFreePool(normalized.Buffer);
			return;
		}

		CheckProcessFlags(&entry, &normalized, CreateInfo->ParentProcessId);

		if (entry.excluded)
			DbgPrint("FsFilter1!" __FUNCTION__ ": excluded process:%d\n", ProcessId);

		if (entry.protected)
			DbgPrint("FsFilter1!" __FUNCTION__ ": protected process:%d\n", ProcessId);

		if (!AddProcessToProcessTable(&entry))
			DbgPrint("FsFilter1!" __FUNCTION__ ": can't add process(pid:%d) to process table\n", ProcessId);

		ExFreePool(normalized.Buffer);
	}
	else
	{
		if (!RemoveProcessFromProcessTable(&entry))
			DbgPrint("FsFilter1!" __FUNCTION__ ": can't remove process(pid:%d) from process table\n", ProcessId);
	}

}

BOOLEAN IsProcessExcluded(HANDLE ProcessId)
{
	ProcessTableEntry entry;

	entry.processId = ProcessId;
	if (!GetProcessInProcessTable(&entry))
		return FALSE;

	return entry.excluded;
}

BOOLEAN IsProcessProtected(HANDLE ProcessId)
{
	ProcessTableEntry entry;

	entry.processId = ProcessId;
	if (!GetProcessInProcessTable(&entry))
		return FALSE;

	return entry.protected;
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
		DbgPrint("FsFilter1!" __FUNCTION__ ": subsystem path normalization failed with code:%08x\n", status);
		return status;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ": subsystem path: %wZ\n", &g_csrssPath);

	// Init normalization buffer

	normalized.Buffer = (PWCH)ExAllocatePool(NonPagedPool, maxBufSize);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;
	if (!normalized.Buffer)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": allocation failed\n");
		return STATUS_ACCESS_DENIED;
	}

	// Initialize and fill exclude file\dir lists 

	// exclude

	status = InitializePsRuleListContext(&g_excludeProcessRules);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": excluded process rules initialization failed with code:%08x\n", status);
		ExFreePool(normalized.Buffer);
		return status;
	}

	for (i = 0; g_excludeProcesses[i].path; i++)
	{
		RtlInitUnicodeString(&str, g_excludeProcesses[i].path);

		status = NormalizeDevicePath(&str, &normalized);
		DbgPrint("FsFilter1!" __FUNCTION__ ": normalized excluded %wZ\n", &normalized);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": path normalization failed with code:%08x, path:%wZ\n", status, &str);
			continue;
		}

		AddRuleToPsRuleList(g_excludeProcessRules, &normalized, g_excludeProcesses[i].inherit, &ruleId);
	}

	// protected

	status = InitializePsRuleListContext(&g_protectProcessRules);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": protected process rules initialization failed with code:%08x\n", status);
		DestroyPsRuleListContext(g_excludeProcessRules);
		ExFreePool(normalized.Buffer);
		return status;
	}

	for (i = 0; g_protectProcesses[i].path; i++)
	{
		RtlInitUnicodeString(&str, g_protectProcesses[i].path);

		status = NormalizeDevicePath(&str, &normalized);
		DbgPrint("FsFilter1!" __FUNCTION__ ": normalized protected %wZ\n", &normalized);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": path normalization failed with code:%08x, path:%wZ\n", status, &str);
			continue;
		}

		AddRuleToPsRuleList(g_protectProcessRules, &normalized, g_protectProcesses[i].inherit, &ruleId);
	}

	status = InitializeProcessTable(CheckProcessFlags);
	if (!NT_SUCCESS(status))
	{
		DestroyPsRuleListContext(g_excludeProcessRules);
		DestroyPsRuleListContext(g_protectProcessRules);
		ExFreePool(normalized.Buffer);
		return status;
	}

	ExFreePool(normalized.Buffer);

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
		DbgPrint("FsFilter1!" __FUNCTION__ ": Object filter registration failed with code:%08x\n", status);
		DestroyPsMonitor();
		return status;
	}

	// Register rocess create\destroy callback

	status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, FALSE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": process notify registartion failed with code:%08x\n", status);
		DestroyPsMonitor();
		return status;
	}

	return status;
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

	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, TRUE);

	DestroyPsRuleListContext(g_excludeProcessRules);
	DestroyPsRuleListContext(g_protectProcessRules);

	DestroyProcessTable();
	g_psMonitorInited = FALSE;

	return STATUS_SUCCESS;
}

NTSTATUS AddProtectedImage(PUNICODE_STRING ImagePath, ULONG InheritType, PULONGLONG ObjId)
{
	const USHORT maxBufSize = ImagePath->Length + NORMALIZE_INCREAMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePool(PagedPool, maxBufSize);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;

	if (!normalized.Buffer)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": error, can't allocate buffer\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(ImagePath, &normalized);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": path normalization failed with code:%08x, path:%wZ\n", status, ImagePath);
		ExFreePool(normalized.Buffer);
		return status;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ": protect image: %wZ\n", &normalized);
	status = AddRuleToPsRuleList(g_protectProcessRules, &normalized, InheritType, ObjId);

	ExFreePool(normalized.Buffer);

	return status;
}

NTSTATUS GetProtectedProcessState(HANDLE ProcessId, PULONG InheritType, PBOOLEAN Enable)
{
	ProcessTableEntry entry;

	entry.processId = ProcessId;
	if (!GetProcessInProcessTable(&entry))
		return STATUS_NOT_FOUND;

	*Enable = entry.protected;
	*InheritType = entry.inheritProtection;

	return STATUS_SUCCESS;
}

NTSTATUS SetProtectedProcessState(HANDLE ProcessId, ULONG InheritType, BOOLEAN Enable)
{
	NTSTATUS status = STATUS_SUCCESS;
	ProcessTableEntry entry;

	entry.processId = ProcessId;
	if (!GetProcessInProcessTable(&entry))
		return STATUS_NOT_FOUND;

	if (Enable)
	{
		entry.protected = TRUE;
		entry.inheritProtection = InheritType;
	}
	else
	{
		entry.protected = FALSE;
	}

	if (!UpdateProcessInProcessTable(&entry))
		return STATUS_NOT_FOUND;

	return status;
}

NTSTATUS RemoveProtectedImage(ULONGLONG ObjId)
{
	return RemoveRuleFromPsRuleList(g_protectProcessRules, ObjId);
}

NTSTATUS RemoveAllProtectedImages()
{
	return RemoveAllRulesFromPsRuleList(g_protectProcessRules);
}

NTSTATUS AddExcludedImage(PUNICODE_STRING ImagePath, ULONG InheritType, PULONGLONG ObjId)
{
	const USHORT maxBufSize = ImagePath->Length + NORMALIZE_INCREAMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePool(PagedPool, maxBufSize);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;

	if (!normalized.Buffer)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": error, can't allocate buffer\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(ImagePath, &normalized);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": path normalization failed with code:%08x, path:%wZ\n", status, ImagePath);
		ExFreePool(normalized.Buffer);
		return status;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ": exclude image: %wZ\n", &normalized);
	status = AddRuleToPsRuleList(g_excludeProcessRules, &normalized, InheritType, ObjId);

	ExFreePool(normalized.Buffer);

	return status;
}

NTSTATUS GetExcludedProcessState(HANDLE ProcessId, PULONG InheritType, PBOOLEAN Enable)
{
	ProcessTableEntry entry;

	entry.processId = ProcessId;
	if (!GetProcessInProcessTable(&entry))
		return STATUS_NOT_FOUND;

	*Enable = entry.excluded;
	*InheritType = entry.inheritExclusion;

	return STATUS_SUCCESS;
}

NTSTATUS SetExcludedProcessState(HANDLE ProcessId, ULONG InheritType, BOOLEAN Enable)
{
	NTSTATUS status = STATUS_SUCCESS;
	ProcessTableEntry entry;

	entry.processId = ProcessId;
	if (!GetProcessInProcessTable(&entry))
		return STATUS_NOT_FOUND;

	if (Enable)
	{
		entry.excluded = TRUE;
		entry.inheritExclusion = InheritType;
	}
	else
	{
		entry.excluded = FALSE;
	}

	if (!UpdateProcessInProcessTable(&entry))
		return STATUS_NOT_FOUND;

	return status;
}

NTSTATUS RemoveExcludedImage(ULONGLONG ObjId)
{
	return RemoveRuleFromPsRuleList(g_excludeProcessRules, ObjId);
}

NTSTATUS RemoveAllExcludedImages()
{
	return RemoveAllRulesFromPsRuleList(g_excludeProcessRules);
}

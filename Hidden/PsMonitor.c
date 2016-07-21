#include "PsMonitor.h"
#include "ExcludeList.h"
#include "Helper.h"
#include "PsTable.h"

PVOID g_obRegCallback = NULL;

OB_OPERATION_REGISTRATION g_regOperation[2];
OB_CALLBACK_REGISTRATION g_regCallback;

ExcludeContext g_excludeProcessContext;
ExcludeContext g_protectProcessContext;

CONST PWCHAR g_excludeProcesses[] = {
	L"\\??\\C:\\Windows\\System32\\calc.exe",
	L"\\??\\C:\\Windows\\System32\\cmd.exe",
	L"\\??\\C:\\Windows\\System32\\reg.exe",
	NULL
};

CONST PWCHAR g_protectProcesses[] = {
	L"\\??\\C:\\Windows\\System32\\cmd.exe",
	L"\\??\\C:\\Windows\\System32\\csrss.exe",
	L"\\??\\C:\\Windows\\System32\\services.exe",
	NULL
};

CONST PWCHAR g_systemProcesses[] = {
	L"\\??\\C:\\Windows\\System32\\smss.exe",
	L"\\??\\C:\\Windows\\System32\\csrss.exe",
	L"\\??\\C:\\Windows\\System32\\wininit.exe",
	L"\\??\\C:\\Windows\\System32\\services.exe",
	NULL
};

#define PROCESS_QUERY_LIMITED_INFORMATION      0x1000

OB_PREOP_CALLBACK_STATUS ProcessPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (OperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;

	DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! Process: %d(%d:%d), Oper: %s, Space: %s\n", 
		PsGetProcessId(OperationInformation->Object), PsGetCurrentProcessId(), PsGetCurrentThreadId(),
		(OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ? "create" : "dup"),
		(OperationInformation->KernelHandle ? "kernel" : "user")
	);
	
	if (!IsProcessProtected(PsGetProcessId(OperationInformation->Object)))
		return OB_PREOP_SUCCESS;

	if (IsProcessProtected(PsGetCurrentProcessId()))
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

	DbgPrint("FsFilter1!" __FUNCTION__ ": Thread: %d(%d:%d), Oper: %s, Space: %s\n", 
		PsGetThreadId(OperationInformation->Object), PsGetCurrentProcessId(), PsGetCurrentThreadId(),
		(OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ? "create" : "dup"),
		(OperationInformation->KernelHandle ? "kernel" : "user")
	);

	if (!IsProcessProtected(PsGetProcessId(OperationInformation->Object)))
		return OB_PREOP_SUCCESS;

	if (IsProcessProtected(PsGetCurrentProcessId()))
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
	RtlZeroMemory(&lookup, sizeof(lookup));

	// Check exclude flag

	if (CheckExcludeListFile(g_excludeProcessContext, ImgPath))
	{
		Entry->excluded = TRUE;
	}
	else if (ParentId != 0)
	{
		lookup.processId = ParentId;
		if (!GetProcessInProcessTable(&lookup))
			DbgPrint("FsFilter1!" __FUNCTION__ ": can't find parent process(pid:%d) in process table (exclude)\n", ParentId);
		else
			Entry->excluded = lookup.excluded;
	}

	// Check protected flag

	if (CheckExcludeListFile(g_protectProcessContext, ImgPath))
	{
		Entry->protected = TRUE;
	}
	else if (ParentId != 0)
	{
		if (!lookup.processId)
		{
			lookup.processId = ParentId;
			if (!GetProcessInProcessTable(&lookup))
				DbgPrint("FsFilter1!" __FUNCTION__ ": can't find parent process(pid:%d) in process table (protected)\n", ParentId);
			else
				Entry->protected = lookup.protected;
		}
		else
		{
			Entry->protected = lookup.protected;
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
		ExFreePool(normalized.Buffer);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": path normalization failed with code:%08x, path:%wZ\n", status, CreateInfo->ImageFileName);
			return;
		}

		CheckProcessFlags(&entry, CreateInfo->ImageFileName, CreateInfo->ParentProcessId);

		if (entry.excluded)
			DbgPrint("FsFilter1!" __FUNCTION__ ": excluded process:%d\n", ProcessId);

		if (entry.protected)
			DbgPrint("FsFilter1!" __FUNCTION__ ": protected process:%d\n", ProcessId);

		if (!AddProcessToProcessTable(&entry))
			DbgPrint("FsFilter1!" __FUNCTION__ ": can't add process(pid:%d) to process table\n", ProcessId);
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
	UNICODE_STRING str, normalized;
	UINT32 i;
	ExcludeEntryId id;

	UNREFERENCED_PARAMETER(DriverObject);

	normalized.Buffer = (PWCH)ExAllocatePool(NonPagedPool, maxBufSize);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;
	if (!normalized.Buffer)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": allocation failed\n");
		return STATUS_ACCESS_DENIED;
	}

	// Initialize and fill exclude file\dir lists 

	status = InitializeExcludeListContext(&g_excludeProcessContext, ExcludeFile);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": exclude process list initialization failed with code:%08x\n", status);
		return status;
	}

	for (i = 0; g_excludeProcesses[i]; i++)
	{
		RtlInitUnicodeString(&str, g_excludeProcesses[i]);

		status = NormalizeDevicePath(&str, &normalized);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": path normalization failed with code:%08x, path:%wZ\n", status, &str);
			continue;
		}

		AddExcludeListFile(g_excludeProcessContext, &normalized, &id);
	}

	status = InitializeExcludeListContext(&g_protectProcessContext, ExcludeDirectory);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": protect process list initialization failed with code:%08x\n", status);
		DestroyExcludeListContext(g_excludeProcessContext);
		ExFreePool(normalized.Buffer);
		return status;
	}

	for (i = 0; g_protectProcesses[i]; i++)
	{
		RtlInitUnicodeString(&str, g_protectProcesses[i]);

		status = NormalizeDevicePath(&str, &normalized);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": path normalization failed with code:%08x, path:%wZ\n", status, &str);
			continue;
		}

		AddExcludeListDirectory(g_protectProcessContext, &normalized, &id);
	}

	status = InitializeProcessTable(CheckProcessFlags);
	if (!NT_SUCCESS(status))
	{
		DestroyExcludeListContext(g_excludeProcessContext);
		DestroyExcludeListContext(g_protectProcessContext);
		ExFreePool(normalized.Buffer);
		return status;
	}

	ExFreePool(normalized.Buffer);

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
	if (g_obRegCallback)
	{
		ObUnRegisterCallbacks(g_obRegCallback);
		g_obRegCallback = NULL;
	}

	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, TRUE);

	DestroyExcludeListContext(g_excludeProcessContext);
	DestroyExcludeListContext(g_protectProcessContext);

	DestroyProcessTable();

	return STATUS_SUCCESS;
}

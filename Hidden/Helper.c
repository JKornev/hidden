#include "Helper.h"

#define HELPER_ALLOC_TAG 'rplH'

NTSTATUS QuerySystemInformation(SYSTEM_INFORMATION_CLASS Class, PVOID* InfoBuffer, PSIZE_T InfoSize)
{
	PVOID info = NULL;
	NTSTATUS status;
	ULONG size = 0, written = 0;

	// Query required size
	status = NtQuerySystemInformation(Class, 0, 0, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return status;

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		size += written; // We should allocate little bit more space

		if (info)
			ExFreePoolWithTag(info, HELPER_ALLOC_TAG);

		info = ExAllocatePoolWithTag(NonPagedPool, size, HELPER_ALLOC_TAG);
		if (!info)
			break;

		status = NtQuerySystemInformation(Class, info, size, &written);
	}

	if (!info)
		return STATUS_ACCESS_DENIED;

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(info, HELPER_ALLOC_TAG);
		return status;
	}

	*InfoBuffer = info;
	*InfoSize = size;
	
	return status;
}

NTSTATUS QueryProcessInformation(PROCESSINFOCLASS Class, HANDLE Process, PVOID* InfoBuffer, PSIZE_T InfoSize)
{
	PVOID info = NULL;
	NTSTATUS status;
	ULONG size = 0, written = 0;

	// Query required size
	status = NtQueryInformationProcess(Process, Class, 0, 0, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return status;

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		size += written; // We should allocate little bit more space

		if (info)
			ExFreePoolWithTag(info, HELPER_ALLOC_TAG);

		info = ExAllocatePoolWithTag(NonPagedPool, size, HELPER_ALLOC_TAG);
		if (!info)
			break;

		status = NtQueryInformationProcess(Process, Class, info, size, &written);
	}

	if (!info)
		return STATUS_ACCESS_DENIED;

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(info, HELPER_ALLOC_TAG);
		return status;
	}

	*InfoBuffer = info;
	*InfoSize = size;

	return status;
}

VOID FreeInformation(PVOID Buffer)
{
	ExFreePoolWithTag(Buffer, HELPER_ALLOC_TAG);
}

//
// Convertion template:
//   \\??\\C:\\Windows -> \\Device\\HarddiskVolume1\\Windows
//
NTSTATUS NormalizeDevicePath(PCUNICODE_STRING Path, PUNICODE_STRING Normalized)
{
	UNICODE_STRING globalPrefix , dvcPrefix;
	NTSTATUS status;
	
	RtlInitUnicodeString(&globalPrefix, L"\\??\\");
	RtlInitUnicodeString(&dvcPrefix, L"\\Device\\");

	if (RtlPrefixUnicodeString(&globalPrefix, Path, TRUE))
	{
		OBJECT_ATTRIBUTES attribs;
		UNICODE_STRING subPath;
		HANDLE hsymLink;
		ULONG i, written, size;

		subPath.Buffer = (PWCH)((PUCHAR)Path->Buffer + globalPrefix.Length);
		subPath.Length = Path->Length - globalPrefix.Length;

		for (i = 0; i < subPath.Length; i++)
		{
			if (subPath.Buffer[i] == L'\\')
			{
				subPath.Length = (USHORT)(i * sizeof(WCHAR));
				break;
			}
		}

		if (subPath.Length == 0)
			return STATUS_INVALID_PARAMETER_1;

		subPath.Buffer = Path->Buffer;
		subPath.Length += globalPrefix.Length;

		// Open symlink

		InitializeObjectAttributes(&attribs, &subPath, OBJ_KERNEL_HANDLE, NULL, NULL);

		status = ZwOpenSymbolicLinkObject(&hsymLink, GENERIC_READ, &attribs);
		if (!NT_SUCCESS(status))
			return status;

		// Query original name

		status = ZwQuerySymbolicLinkObject(hsymLink, Normalized, &written);
		ZwClose(hsymLink);
		if (!NT_SUCCESS(status))
			return status;

		// Construct new variable

		size = Path->Length - subPath.Length + Normalized->Length;
		if (size > Normalized->MaximumLength)
			return STATUS_BUFFER_OVERFLOW;

		subPath.Buffer = (PWCH)((PUCHAR)Path->Buffer + subPath.Length);
		subPath.Length = Path->Length - subPath.Length;

		status = RtlAppendUnicodeStringToString(Normalized, &subPath);
		if (!NT_SUCCESS(status))
			return status;
	}
	else if (RtlPrefixUnicodeString(&dvcPrefix, Path, TRUE))
	{
		Normalized->Length = 0;
		status = RtlAppendUnicodeStringToString(Normalized, Path);
		if (!NT_SUCCESS(status))
			return status;
	}
	else
	{
		return STATUS_INVALID_PARAMETER;
	}

	return STATUS_SUCCESS;
}

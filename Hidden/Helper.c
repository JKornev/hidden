#include "Helper.h"

#define HELPER_ALLOC_TAG 'rplH'

NTSTATUS QuerySystemInformation(SYSTEM_INFORMATION_CLASS Class, PVOID* InfoBuffer, PSIZE_T InfoSize)
{
	PVOID info = NULL;
	NTSTATUS status;
	ULONG size = 0, written = 0;

	// Query required size
	status = ZwQuerySystemInformation(Class, 0, 0, &size);
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

		status = ZwQuerySystemInformation(Class, info, size, &written);
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
	status = ZwQueryInformationProcess(Process, Class, 0, 0, &size);
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

		status = ZwQueryInformationProcess(Process, Class, info, size, &written);
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

NTSTATUS ResolveSymbolicLink(PUNICODE_STRING Link, PUNICODE_STRING Resolved)
{
	OBJECT_ATTRIBUTES attribs;
	HANDLE hsymLink;
	ULONG written;
	NTSTATUS status = STATUS_SUCCESS;

	// Open symlink

	InitializeObjectAttributes(&attribs, Link, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwOpenSymbolicLinkObject(&hsymLink, GENERIC_READ, &attribs);
	if (!NT_SUCCESS(status))
		return status;

	// Query original name

	status = ZwQuerySymbolicLinkObject(hsymLink, Resolved, &written);
	ZwClose(hsymLink);
	if (!NT_SUCCESS(status))
		return status;

	return status;
}

//
// Convertion template:
//   \\??\\C:\\Windows -> \\Device\\HarddiskVolume1\\Windows
//
NTSTATUS NormalizeDevicePath(PCUNICODE_STRING Path, PUNICODE_STRING Normalized)
{
	UNICODE_STRING globalPrefix, dvcPrefix, sysrootPrefix;
	NTSTATUS status;
	
	RtlInitUnicodeString(&globalPrefix, L"\\??\\");
	RtlInitUnicodeString(&dvcPrefix, L"\\Device\\");
	RtlInitUnicodeString(&sysrootPrefix, L"\\SystemRoot\\");

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
		subPath.MaximumLength = subPath.Length;

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
		subPath.MaximumLength = subPath.Length;

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
	else if (RtlPrefixUnicodeString(&sysrootPrefix, Path, TRUE))
	{
		UNICODE_STRING subPath, resolvedLink, winDir;
		WCHAR buffer[64];
		SHORT i;

		// Open symlink

		subPath.Buffer = sysrootPrefix.Buffer;
		subPath.MaximumLength = subPath.Length = sysrootPrefix.Length - sizeof(WCHAR);

		resolvedLink.Buffer = buffer;
		resolvedLink.Length = 0;
		resolvedLink.MaximumLength = sizeof(buffer);

		status = ResolveSymbolicLink(&subPath, &resolvedLink);
		if (!NT_SUCCESS(status))
			return status;

		// \Device\Harddisk0\Partition0\Windows -> \Device\Harddisk0\Partition0
		// Win10: \Device\BootDevice\Windows -> \Device\BootDevice

		winDir.Length = 0;
		for (i = (resolvedLink.Length - sizeof(WCHAR)) / sizeof(WCHAR); i >= 0; i--)
		{
			if (resolvedLink.Buffer[i] == L'\\')
			{
				winDir.Buffer = resolvedLink.Buffer + i;
				winDir.Length = resolvedLink.Length - (i * sizeof(WCHAR));
				winDir.MaximumLength = winDir.Length;
				resolvedLink.Length = (i * sizeof(WCHAR));
				break;
			}
		}

		// \Device\Harddisk0\Partition0 -> \Device\HarddiskVolume1
		// Win10: \Device\BootDevice -> \Device\HarddiskVolume2

		status = ResolveSymbolicLink(&resolvedLink, Normalized);
		if (!NT_SUCCESS(status))
			return status;

		// Construct new variable

		subPath.Buffer = (PWCHAR)((PCHAR)Path->Buffer + sysrootPrefix.Length - sizeof(WCHAR));
		subPath.MaximumLength = subPath.Length = Path->Length - sysrootPrefix.Length + sizeof(WCHAR);

		status = RtlAppendUnicodeStringToString(Normalized, &winDir);
		if (!NT_SUCCESS(status))
			return status;

		status = RtlAppendUnicodeStringToString(Normalized, &subPath);
		if (!NT_SUCCESS(status))
			return status;
	}
	else
	{
		return STATUS_INVALID_PARAMETER;
	}

	return STATUS_SUCCESS;
}

BOOLEAN IsWin8OrAbove()
{//TODO: cache it
	RTL_OSVERSIONINFOW version;
	NTSTATUS status;

	RtlZeroMemory(&version, sizeof(version));

	status = RtlGetVersion(&version);
	if (!NT_SUCCESS(status))
		LogWarning("Can't get an OS version, status:%x", status);

	if (version.dwMajorVersion < 6)
		return FALSE;

	if (version.dwMajorVersion == 6 && version.dwMinorVersion < 2) // NT 6.2 == Win8
		return FALSE;

	return TRUE;
}
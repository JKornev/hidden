#include "Configs.h"

#define CONFIG_ALLOC_TAG 'gfnC'

typedef struct _HidConfigContext {
	BOOLEAN state;
	BOOLEAN stealth;
	UNICODE_STRING hideFSDirs;
	UNICODE_STRING hideFSFiles;
	UNICODE_STRING hideRegKeys;
	UNICODE_STRING hideRegValues;
	UNICODE_STRING ignoreImages;
	UNICODE_STRING protectImages;
} HidConfigContext, *PHidConfigContext;

PHidConfigContext g_configContext = NULL;

VOID ReleaseConfigContext(PHidConfigContext context);

NTSTATUS GetRegistryDWORD(HANDLE hKey, LPCWSTR Value, PULONG Data, ULONG Default);
NTSTATUS QueryAndAllocRegistryData(HANDLE hKey, LPCWSTR Value, ULONG Type, PUNICODE_STRING Data, PUNICODE_STRING Default);
VOID ReleaseRegistryData(PUNICODE_STRING Data);

// =========================================================================================

NTSTATUS InitializeConfigs(PUNICODE_STRING RegistryPath)
{
	HidConfigContext config;
	OBJECT_ATTRIBUTES attribs;
	NTSTATUS status;
	HANDLE hkey;
	ULONG value;

	if (g_configContext)
		return STATUS_ALREADY_REGISTERED;

	RtlZeroMemory(&config, sizeof(config));

	InitializeObjectAttributes(&attribs, RegistryPath, 0, NULL, NULL);

	status = ZwOpenKey(&hkey, KEY_ALL_ACCESS, &attribs);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": can't open config registry key, code:%08x\n", status);
		return status;
	}

	GetRegistryDWORD(hkey, L"Hid_State", &value, 1);
	config.state = (value ? TRUE : FALSE);

	GetRegistryDWORD(hkey, L"Hid_StealthMode", &value, 0);
	config.stealth = (value ? TRUE : FALSE);

	QueryAndAllocRegistryData(hkey, L"Hid_HideFsDirs",      REG_MULTI_SZ, &config.hideFSDirs,    NULL);
	QueryAndAllocRegistryData(hkey, L"Hid_HideFsFiles",     REG_MULTI_SZ, &config.hideFSFiles,   NULL);
	QueryAndAllocRegistryData(hkey, L"Hid_HideRegKeys",     REG_MULTI_SZ, &config.hideRegKeys,   NULL);
	QueryAndAllocRegistryData(hkey, L"Hid_HideRegValues",   REG_MULTI_SZ, &config.hideRegValues, NULL);

	QueryAndAllocRegistryData(hkey, L"Hid_IgnoredImages",   REG_MULTI_SZ, &config.ignoreImages,  NULL);
	QueryAndAllocRegistryData(hkey, L"Hid_ProtectedImages", REG_MULTI_SZ, &config.protectImages, NULL);

	ZwClose(hkey);

	g_configContext = (PHidConfigContext)ExAllocatePoolWithTag(NonPagedPool, sizeof(config), CONFIG_ALLOC_TAG);
	if (!g_configContext)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": can't allocate memory for the config context\n");
		ReleaseConfigContext(&config);
		return STATUS_NO_MEMORY;
	}

	RtlCopyMemory(g_configContext, &config, sizeof(config));

	return STATUS_SUCCESS;
}

NTSTATUS DestroyConfigs()
{
	if (!g_configContext)
		return STATUS_NOT_FOUND;

	ReleaseConfigContext(g_configContext);
	ExFreePoolWithTag(g_configContext, CONFIG_ALLOC_TAG);

	return STATUS_SUCCESS;
}

// =========================================================================================

BOOLEAN CfgGetDriverState()
{
	if (!g_configContext)
		return TRUE; // Enable by default

	return g_configContext->state;
}

BOOLEAN CfgGetStealthState()
{
	if (!g_configContext)
		return FALSE; // Disable by default

	return g_configContext->stealth;
}

NTSTATUS CfgEnumConfigsTable(enum CfgMultiStringTables Table, CfgMultiStringCallback Callback, PVOID Params)
{
	PUNICODE_STRING table;
	LPWSTR buffer;
	ULONG length;

	if (!g_configContext)
		return STATUS_NOT_FOUND;

	switch (Table)
	{
	case HideFilesTable:
		table = &g_configContext->hideFSFiles;
		break;
	case HideDirsTable:
		table = &g_configContext->hideFSDirs;
		break;
	case HideRegKeysTable:
		table = &g_configContext->hideRegKeys;
		break;
	case HideRegValuesTable:
		table = &g_configContext->hideRegValues;
		break;
	case IgnoreImagesTable:
		table = &g_configContext->ignoreImages;
		break;
	case ProtectImagesTable:
		table = &g_configContext->protectImages;
		break;
	default:
		return STATUS_INVALID_VARIANT;
	}

	if (table->Length == 0)
		return STATUS_SUCCESS;

	buffer = table->Buffer;
	length = table->Length;
	while (length > 1)
	{
		UNICODE_STRING entry;
		ULONG inx, delta = 0;

		for (inx = 0; inx < length / sizeof(WCHAR); inx++)
		{
			if (buffer[inx] == L'\0')
			{
				delta = 1;
				break;
			}
		}

		entry.Buffer = buffer;
		entry.Length = (USHORT)(inx * sizeof(WCHAR));
		entry.MaximumLength = entry.Length;

		length -= (inx + delta) * sizeof(WCHAR);
		buffer += (inx + delta);

		if (entry.Length)
			Callback(&entry, Params);
	}

	return STATUS_SUCCESS;
}

// =========================================================================================

VOID ReleaseConfigContext(PHidConfigContext context)
{
	ReleaseRegistryData(&context->hideFSDirs);
	ReleaseRegistryData(&context->hideFSFiles);
	ReleaseRegistryData(&context->hideRegKeys);
	ReleaseRegistryData(&context->hideRegValues);
	ReleaseRegistryData(&context->ignoreImages);
	ReleaseRegistryData(&context->protectImages);
}

NTSTATUS GetRegistryDWORD(HANDLE hKey, LPCWSTR Value, PULONG Data, ULONG Default)
{
	UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
	NTSTATUS status;
	UNICODE_STRING valueName;
	ULONG length;

	RtlInitUnicodeString(&valueName, Value);

	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, buffer, sizeof(buffer), &length);
	if (NT_SUCCESS(status) && length <= sizeof(buffer))
	{
		PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
		if (info->Type == REG_DWORD && info->DataLength == sizeof(ULONG))
			*Data = *(ULONG*)(info->Data);
		else
			*Data = Default;
	}
	else
	{
		*Data = Default;
	}

	return STATUS_SUCCESS;
}

NTSTATUS QueryAndAllocRegistryData(HANDLE hKey, LPCWSTR Value, ULONG Type, PUNICODE_STRING Data, PUNICODE_STRING Default)
{
	PKEY_VALUE_PARTIAL_INFORMATION info = NULL;
	UNICODE_STRING valueName;
	ULONG length, dataLength;
	NTSTATUS status;
	PVOID dataBuffer;

	if (Default)
	{
		dataLength = Default->Length;
		dataBuffer = ExAllocatePoolWithTag(NonPagedPool, dataLength, CONFIG_ALLOC_TAG);
		if (!dataBuffer)
			return STATUS_NO_MEMORY;

		RtlCopyMemory(dataBuffer, Default->Buffer, dataLength);
	}
	else
	{
		dataLength = 0;
		dataBuffer = NULL;
	}

	RtlInitUnicodeString(&valueName, Value);

	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, NULL, 0, &length);
	if (status != STATUS_BUFFER_OVERFLOW && status != STATUS_BUFFER_TOO_SMALL)
		goto end_proc;

	if (length < sizeof(KEY_VALUE_PARTIAL_INFORMATION))
		goto end_proc;

	info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, length, CONFIG_ALLOC_TAG);
	if (!info)
		goto end_proc;

	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, info, length, &length);
	if (!NT_SUCCESS(status))
		goto end_proc;

	if (info->Type != Type)
		goto end_proc;

	if (info->DataLength == 0 || info->DataLength > 0xFFFF)
		goto end_proc;

	if (dataBuffer)
		ExFreePoolWithTag(dataBuffer, CONFIG_ALLOC_TAG);

	dataLength = info->DataLength;
	dataBuffer = ExAllocatePoolWithTag(NonPagedPool, dataLength, CONFIG_ALLOC_TAG);
	if (!dataBuffer)
	{
		ExFreePoolWithTag(info, CONFIG_ALLOC_TAG);
		return STATUS_NO_MEMORY;
	}

	RtlCopyMemory(dataBuffer, info->Data, dataLength);

end_proc:

	if (info)
		ExFreePoolWithTag(info, CONFIG_ALLOC_TAG);

	Data->Buffer = (PWCH)dataBuffer;
	Data->Length = (USHORT)dataLength;
	Data->MaximumLength = (USHORT)dataLength;

	return STATUS_SUCCESS;
}

VOID ReleaseRegistryData(PUNICODE_STRING Data)
{
	if (Data->Length)
		ExFreePoolWithTag(Data->Buffer, CONFIG_ALLOC_TAG);
}

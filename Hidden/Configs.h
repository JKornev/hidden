#pragma once

#include <ntddk.h>

NTSTATUS InitializeConfigs(PUNICODE_STRING RegistryPath);
NTSTATUS DestroyConfigs();

BOOLEAN CfgGetDriverState();
BOOLEAN CfgGetStealthState();

enum CfgMultiStringTables {
	HideFilesTable,
	HideDirsTable,
	HideRegKeysTable,
	HideRegValuesTable,
	IgnoreImagesTable,
	ProtectImagesTable,
	MaxTableEntries,
};

typedef VOID(NTAPI*CfgMultiStringCallback)(PUNICODE_STRING str, PVOID Params);

NTSTATUS CfgEnumConfigsTable(enum CfgMultiStringTables Table, CfgMultiStringCallback Callback, PVOID Params);

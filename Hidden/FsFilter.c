// =========================================================================================
//       Filesystem Minifilter
// =========================================================================================

#include <fltKernel.h>
#include "ExcludeList.h"
#include "FsFilter.h"
#include "Helper.h"
#include "PsMonitor.h"
#include "Driver.h"
#include "Configs.h"

#define FSFILTER_ALLOC_TAG 'DHlF'

NTSTATUS FilterSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType);

FLT_PREOP_CALLBACK_STATUS FltCreatePreOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
//FLT_POSTOP_CALLBACK_STATUS FltCreatePostOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS FltDirCtrlPreOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS FltDirCtrlPostOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);

NTSTATUS CleanFileFullDirectoryInformation(PFILE_FULL_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileBothDirectoryInformation(PFILE_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileDirectoryInformation(PFILE_DIRECTORY_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileIdFullDirectoryInformation(PFILE_ID_FULL_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileIdBothDirectoryInformation(PFILE_ID_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileNamesInformation(PFILE_NAMES_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);


const FLT_CONTEXT_REGISTRATION Contexts[] = {
	{ FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE, 0, FltCreatePreOperation,  /*FltCreatePostOperation*/ NULL },
	{ IRP_MJ_DIRECTORY_CONTROL, 0, FltDirCtrlPreOperation, FltDirCtrlPostOperation },
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION), //  Size
	FLT_REGISTRATION_VERSION, //  Version
	FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,                        //  Flags
	Contexts,                 //  Context
	Callbacks,                //  Operation callbacks
	/*FilterUnload*/NULL,     //  MiniFilterUnload
	FilterSetup,              //  InstanceSetup
	NULL,                     //  InstanceQueryTeardown
	NULL,                     //  InstanceTeardownStart
	NULL,                     //  InstanceTeardownComplete
	NULL,                     //  GenerateFileName
	NULL,                     //  GenerateDestinationFileName
	NULL                      //  NormalizeNameComponent
};

BOOLEAN g_fsMonitorInited = FALSE;
PFLT_FILTER gFilterHandle = NULL;

ExcludeContext g_excludeFileContext;
ExcludeContext g_excludeDirectoryContext;

// Use this variable for hard code full file paths that you would like to hide
// For instance: L"\\Device\\HarddiskVolume1\\Windows\\System32\\calc.exe"
// Notice: this array should be NULL terminated
CONST PWCHAR g_excludeFiles[] = {
	NULL
};

// Use this variable for hard code full directory paths that you would like to hide
// For instance: L"\\Device\\HarddiskVolume1\\Windows\\System32\\mysecretdir"
// Notice: this array should be NULL terminated
CONST PWCHAR g_excludeDirs[] = {
	NULL
};

NTSTATUS FilterSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	DbgPrint("FsFilter1!" __FUNCTION__ ": Entered %d\n", (UINT32)KeGetCurrentIrql());

	return STATUS_SUCCESS;
}

enum {
	FoundExcludeFile = 1,
	FoundExcludeDir = 2,
};

FLT_PREOP_CALLBACK_STATUS FltCreatePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
	UINT32 disposition, options;
	PFLT_FILE_NAME_INFORMATION fltName;
	NTSTATUS status;
	BOOLEAN neededPrevent = FALSE;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	if (!IsDriverEnabled())
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	//DbgPrint("!!!!! " __FUNCTION__ ": Entered %d\n", (ULONG)KeGetCurrentIrql());
	//DbgPrint("%wZ %x\n", &Data->Iopb->TargetFileObject->FileName, Data->Iopb->Parameters.Create.Options);

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		//DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! process excluded %d\n", PsGetCurrentProcessId());
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	options = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
	disposition = (Data->Iopb->Parameters.Create.Options & 0xFF000000) >> 24;

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fltName);
	if (!NT_SUCCESS(status))
	{
		if (status != STATUS_OBJECT_PATH_NOT_FOUND)
			DbgPrint("FsFilter1!" __FUNCTION__ ": FltGetFileNameInformation failed with code:%08x\n", status);

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!(options & FILE_DIRECTORY_FILE))
	{
		// If it is create file event
		if (CheckExcludeListDirectory(g_excludeFileContext, &fltName->Name))
			neededPrevent = TRUE;
	}

	// If it is create directory/file event
	if (!neededPrevent && CheckExcludeListDirectory(g_excludeDirectoryContext, &fltName->Name))
		neededPrevent = TRUE;

	FltReleaseFileNameInformation(fltName);

	if (neededPrevent)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": Create file\\dir operation canceled for: %wZ, %p\n", &Data->Iopb->TargetFileObject->FileName, PsGetCurrentProcessId());
		Data->IoStatus.Status = STATUS_NO_SUCH_FILE;
		return FLT_PREOP_COMPLETE;
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FltDirCtrlPreOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	
	if (!IsDriverEnabled())
		return FLT_POSTOP_FINISHED_PROCESSING;

	//DbgPrint("!!!!! " __FUNCTION__ ": Entered\n");
	//DbgPrint("%wZ\n", &Data->Iopb->TargetFileObject->FileName);

	if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	switch (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass)
	{
	case FileIdFullDirectoryInformation:
	case FileIdBothDirectoryInformation:
	case FileBothDirectoryInformation:
	case FileDirectoryInformation:
	case FileFullDirectoryInformation:
	case FileNamesInformation:
		break;
	default:
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FltDirCtrlPostOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	PFLT_PARAMETERS params = &Data->Iopb->Parameters;
	PFLT_FILE_NAME_INFORMATION fltName;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	if (!IsDriverEnabled())
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (!NT_SUCCESS(Data->IoStatus.Status))
		return FLT_POSTOP_FINISHED_PROCESSING;

	//DbgPrint("!!!!! " __FUNCTION__ ": Entered %d\n", (UINT32)KeGetCurrentIrql());
	//DbgPrint("%wZ\n", &Data->Iopb->TargetFileObject->FileName);

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! process excluded %p\n", PsGetCurrentProcessId());
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fltName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": FltGetFileNameInformation failed with code:%08x\n", status);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	__try
	{
		status = STATUS_SUCCESS;

		switch (params->DirectoryControl.QueryDirectory.FileInformationClass)
		{
		case FileFullDirectoryInformation:
			status = CleanFileFullDirectoryInformation((PFILE_FULL_DIR_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		case FileBothDirectoryInformation:
			status = CleanFileBothDirectoryInformation((PFILE_BOTH_DIR_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		case FileDirectoryInformation:
			status = CleanFileDirectoryInformation((PFILE_DIRECTORY_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		case FileIdFullDirectoryInformation:
			status = CleanFileIdFullDirectoryInformation((PFILE_ID_FULL_DIR_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		case FileIdBothDirectoryInformation:
			status = CleanFileIdBothDirectoryInformation((PFILE_ID_BOTH_DIR_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		case FileNamesInformation:
			status = CleanFileNamesInformation((PFILE_NAMES_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		}

		Data->IoStatus.Status = status;
	}
	__finally
	{
		FltReleaseFileNameInformation(fltName);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS CleanFileFullDirectoryInformation(PFILE_FULL_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_FULL_DIR_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN matched, search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			matched = CheckExcludeListDirFile(g_excludeDirectoryContext, &fltName->Name, &fileName);
		else
			matched = CheckExcludeListDirFile(g_excludeFileContext, &fltName->Name, &fileName);

		if (matched)
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_FULL_DIR_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			DbgPrint("FsFilter1!" __FUNCTION__ ": removed: %wZ\\%wZ\n", &fltName->Name, &fileName);

			if (retn)
				return status;

			info = (PFILE_FULL_DIR_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_FULL_DIR_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return STATUS_SUCCESS;
}

NTSTATUS CleanFileBothDirectoryInformation(PFILE_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_BOTH_DIR_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN matched, search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			matched = CheckExcludeListDirFile(g_excludeDirectoryContext, &fltName->Name, &fileName);
		else
			matched = CheckExcludeListDirFile(g_excludeFileContext, &fltName->Name, &fileName);

		if (matched)
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_BOTH_DIR_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			DbgPrint("FsFilter1!" __FUNCTION__ ": removed: %wZ\\%wZ\n", &fltName->Name, &fileName);

			if (retn)
				return status;

			info = (PFILE_BOTH_DIR_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_BOTH_DIR_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return STATUS_SUCCESS;
}

NTSTATUS CleanFileDirectoryInformation(PFILE_DIRECTORY_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_DIRECTORY_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN matched, search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			matched = CheckExcludeListDirFile(g_excludeDirectoryContext, &fltName->Name, &fileName);
		else
			matched = CheckExcludeListDirFile(g_excludeFileContext, &fltName->Name, &fileName);

		if (matched)
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_DIRECTORY_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			DbgPrint("FsFilter1!" __FUNCTION__ ": removed: %wZ\\%wZ\n", &fltName->Name, &fileName);

			if (retn)
				return status;

			info = (PFILE_DIRECTORY_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_DIRECTORY_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return STATUS_SUCCESS;
}

NTSTATUS CleanFileIdFullDirectoryInformation(PFILE_ID_FULL_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_ID_FULL_DIR_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN matched, search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			matched = CheckExcludeListDirFile(g_excludeDirectoryContext, &fltName->Name, &fileName);
		else
			matched = CheckExcludeListDirFile(g_excludeFileContext, &fltName->Name, &fileName);

		if (matched)
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_ID_FULL_DIR_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			DbgPrint("FsFilter1!" __FUNCTION__ ": removed: %wZ\\%wZ\n", &fltName->Name, &fileName);

			if (retn)
				return status;

			info = (PFILE_ID_FULL_DIR_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_ID_FULL_DIR_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return STATUS_SUCCESS;
}

NTSTATUS CleanFileIdBothDirectoryInformation(PFILE_ID_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_ID_BOTH_DIR_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN matched, search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			matched = CheckExcludeListDirFile(g_excludeDirectoryContext, &fltName->Name, &fileName);
		else
			matched = CheckExcludeListDirFile(g_excludeFileContext, &fltName->Name, &fileName);

		if (matched)
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_ID_BOTH_DIR_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			DbgPrint("FsFilter1!" __FUNCTION__ ": removed: %wZ\\%wZ\n", &fltName->Name, &fileName);

			if (retn)
				return status;

			info = (PFILE_ID_BOTH_DIR_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_ID_BOTH_DIR_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return status;
}

NTSTATUS CleanFileNamesInformation(PFILE_NAMES_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_NAMES_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		//TODO: check, are there can be directories?
		if (CheckExcludeListDirFile(g_excludeFileContext, &fltName->Name, &fileName))
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_NAMES_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			DbgPrint("FsFilter1!" __FUNCTION__ ": removed: %wZ\\%wZ\n", &fltName->Name, &fileName);

			if (retn)
				return status;

			info = (PFILE_NAMES_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_NAMES_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return STATUS_SUCCESS;
}

VOID LoadConfigFilesCallback(PUNICODE_STRING Str, PVOID Params)
{
	ULONGLONG id;
	UNREFERENCED_PARAMETER(Params);
	AddHiddenFile(Str, &id);
}

VOID LoadConfigDirsCallback(PUNICODE_STRING Str, PVOID Params)
{
	ULONGLONG id;
	UNREFERENCED_PARAMETER(Params);
	AddHiddenDir(Str, &id);
}

NTSTATUS InitializeFSMiniFilter(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status;
	UNICODE_STRING str;
	UINT32 i;
	ExcludeEntryId id;

	DbgPrint("FsFilter1!" __FUNCTION__ ": Entered %d\n", (UINT32)KeGetCurrentIrql());

	// Initialize and fill exclude file\dir lists 

	status = InitializeExcludeListContext(&g_excludeFileContext, ExcludeFile);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": exclude file list initialization failed with code:%08x\n", status);
		return status;
	}

	for (i = 0; g_excludeFiles[i]; i++)
	{
		RtlInitUnicodeString(&str, g_excludeFiles[i]);
		AddExcludeListFile(g_excludeFileContext, &str, &id, 0);
	}

	CfgEnumConfigsTable(HideFilesTable, &LoadConfigFilesCallback, NULL);

	status = InitializeExcludeListContext(&g_excludeDirectoryContext, ExcludeDirectory);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": exclude file list initialization failed with code:%08x\n", status);
		DestroyExcludeListContext(g_excludeFileContext);
		return status;
	}

	for (i = 0; g_excludeDirs[i]; i++)
	{
		RtlInitUnicodeString(&str, g_excludeDirs[i]);
		AddExcludeListDirectory(g_excludeDirectoryContext, &str, &id, 0);
	}

	CfgEnumConfigsTable(HideDirsTable, &LoadConfigDirsCallback, NULL);

	// Filesystem mini-filter initialization

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
	if (NT_SUCCESS(status))
	{
		status = FltStartFiltering(gFilterHandle);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": can't start filtering, code:%08x\n", status);
			FltUnregisterFilter(gFilterHandle);
		}
	}

	if (!NT_SUCCESS(status))
	{
		DestroyExcludeListContext(g_excludeFileContext);
		DestroyExcludeListContext(g_excludeDirectoryContext);
		return status;
	}

	g_fsMonitorInited = TRUE;

	return status;
}

NTSTATUS DestroyFSMiniFilter()
{
	DbgPrint("FsFilter1!" __FUNCTION__ ": Entered %d\n", (UINT32)KeGetCurrentIrql());

	if (!g_fsMonitorInited)
		return STATUS_NOT_FOUND;

	FltUnregisterFilter(gFilterHandle);
	gFilterHandle = NULL;

	DestroyExcludeListContext(g_excludeFileContext);
	DestroyExcludeListContext(g_excludeDirectoryContext);
	g_fsMonitorInited = FALSE;

	return STATUS_SUCCESS;
}

NTSTATUS AddHiddenFile(PUNICODE_STRING FilePath, PULONGLONG ObjId)
{
	const USHORT maxBufSize = FilePath->Length + NORMALIZE_INCREAMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, maxBufSize, FSFILTER_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;

	if (!normalized.Buffer)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": error, can't allocate buffer\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(FilePath, &normalized);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": path normalization failed with code:%08x, path:%wZ\n", status, FilePath);
		ExFreePoolWithTag(normalized.Buffer, FSFILTER_ALLOC_TAG);
		return status;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ": add file:%wZ\n", &normalized);
	status = AddExcludeListFile(g_excludeFileContext, &normalized, ObjId, 0);

	ExFreePoolWithTag(normalized.Buffer, FSFILTER_ALLOC_TAG);

	return status;
}

NTSTATUS RemoveHiddenFile(ULONGLONG ObjId)
{
	return RemoveExcludeListEntry(g_excludeFileContext, ObjId);
}

NTSTATUS RemoveAllHiddenFiles()
{
	return RemoveAllExcludeListEntries(g_excludeFileContext);
}

NTSTATUS AddHiddenDir(PUNICODE_STRING DirPath, PULONGLONG ObjId)
{
	const USHORT maxBufSize = DirPath->Length + NORMALIZE_INCREAMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, maxBufSize, FSFILTER_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;

	if (!normalized.Buffer)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": error, can't allocate buffer\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(DirPath, &normalized);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": path normalization failed with code:%08x, path:%wZ\n", status, DirPath);
		ExFreePoolWithTag(normalized.Buffer, FSFILTER_ALLOC_TAG);
		return status;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ": add dir:%wZ\n", &normalized);
	status = AddExcludeListDirectory(g_excludeDirectoryContext, &normalized, ObjId, 0);
	ExFreePoolWithTag(normalized.Buffer, FSFILTER_ALLOC_TAG);

	return status;
}

NTSTATUS RemoveHiddenDir(ULONGLONG ObjId)
{
	return RemoveExcludeListEntry(g_excludeDirectoryContext, ObjId);
}

NTSTATUS RemoveAllHiddenDirs()
{
	return RemoveAllExcludeListEntries(g_excludeDirectoryContext);
}

#include <Windows.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "HiddenLib.h"
#include "..\\Hidden\DeviceAPI.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS     ((NTSTATUS)0x00000000L)

typedef struct _HidContextInternal {
	HANDLE hdevice;
} HidContextInternal, *PHidContextInternal;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_RELATIVE_NAME {
	UNICODE_STRING RelativeName;
	HANDLE         ContainingDirectory;
	void*          CurDirRef;
} RTL_RELATIVE_NAME, *PRTL_RELATIVE_NAME;

typedef BOOLEAN(NTAPI*RtlDosPathNameToRelativeNtPathName_U_Prototype)(
	_In_       PCWSTR DosFileName,
	_Out_      PUNICODE_STRING NtFileName,
	_Out_opt_  PWSTR* FilePath,
	_Out_opt_  PRTL_RELATIVE_NAME RelativeName
);

typedef NTSTATUS(WINAPI*RtlFormatCurrentUserKeyPath_Prototype)(
	PUNICODE_STRING CurrentUserKeyPath
);

typedef VOID(WINAPI*RtlFreeUnicodeString_Prototype)(
	PUNICODE_STRING UnicodeString
);

static RtlDosPathNameToRelativeNtPathName_U_Prototype RtlDosPathNameToRelativeNtPathName_U = nullptr;
static RtlFormatCurrentUserKeyPath_Prototype RtlFormatCurrentUserKeyPath = nullptr;
static RtlFreeUnicodeString_Prototype RtlFreeUnicodeString = nullptr;

HidStatus Hid_Initialize(PHidContext pcontext)
{
	HANDLE hdevice = INVALID_HANDLE_VALUE;
	PHidContextInternal context;

	if (!RtlDosPathNameToRelativeNtPathName_U)
	{
		*(FARPROC*)&RtlDosPathNameToRelativeNtPathName_U = GetProcAddress(
			GetModuleHandleW(L"ntdll.dll"),
			"RtlDosPathNameToRelativeNtPathName_U"
			);
		if (!RtlDosPathNameToRelativeNtPathName_U)
			return HID_SET_STATUS(FALSE, GetLastError());
	}

	if (!RtlFormatCurrentUserKeyPath)
	{
		*(FARPROC*)&RtlFormatCurrentUserKeyPath = GetProcAddress(
			GetModuleHandleW(L"ntdll.dll"),
			"RtlFormatCurrentUserKeyPath"
			);
		if (!RtlFormatCurrentUserKeyPath)
			return HID_SET_STATUS(FALSE, GetLastError());
	}

	if (!RtlFreeUnicodeString)
	{
		*(FARPROC*)&RtlFreeUnicodeString = GetProcAddress(
			GetModuleHandleW(L"ntdll.dll"),
			"RtlFreeUnicodeString"
			);
		if (!RtlFreeUnicodeString)
			return HID_SET_STATUS(FALSE, GetLastError());
	}

	hdevice = CreateFileW(
				DEVICE_WIN32_NAME,
				GENERIC_READ | GENERIC_WRITE,
				0,
				NULL, 
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL
			);
	if (hdevice == INVALID_HANDLE_VALUE)
		return HID_SET_STATUS(FALSE, GetLastError());

	context = (PHidContextInternal)malloc(sizeof(HidContextInternal));
	if (context == nullptr)
	{
		CloseHandle(hdevice);
		return HID_SET_STATUS(FALSE, ERROR_NOT_ENOUGH_MEMORY);
	}

	context->hdevice = hdevice;
	*pcontext = (HidContext)context;

	return HID_SET_STATUS(TRUE, 0);
}

void Hid_Destroy(HidContext context)
{
	PHidContextInternal cntx = (PHidContextInternal)context;
	CloseHandle(cntx->hdevice);
	free(cntx);
}

bool ConvertToNtPath(const wchar_t* path, wchar_t* normalized, size_t normalizedLen)
{
	UNICODE_STRING ntPath;
	DWORD size;
	bool result = false;

	size = GetFullPathNameW(path, normalizedLen, normalized, NULL);
	if (size == 0)
		return false;

	memset(&ntPath, 0, sizeof(ntPath));

	if (RtlDosPathNameToRelativeNtPathName_U(normalized, &ntPath, NULL, NULL) == FALSE)
		return false;

	if (normalizedLen * sizeof(wchar_t) > ntPath.Length)
	{
		memcpy(normalized, ntPath.Buffer, ntPath.Length);
		normalized[ntPath.Length / sizeof(wchar_t)] = L'\0';
		result = true;
	}

	HeapFree(GetProcessHeap(), 0, ntPath.Buffer);

	return result;
}

bool NormalizeRegistryPath(HidRegRootTypes root, const wchar_t* key, wchar_t* normalized, size_t normalizedLen)
{
	static const wchar_t* hklm = L"\\Registry\\Machine\\";
	static const wchar_t* hku = L"\\Registry\\User\\";
	size_t keyLen, rootLen;

	keyLen = wcslen(key);

	if (root == RegHKCU)
	{
		UNICODE_STRING currUser;

		RtlFormatCurrentUserKeyPath(&currUser);

		rootLen = currUser.Length / sizeof(wchar_t);

		if (normalizedLen < rootLen + keyLen + 2)
		{
			RtlFreeUnicodeString(&currUser);
			return false;
		}

		memcpy(normalized, currUser.Buffer, rootLen * sizeof(wchar_t));
		normalized[rootLen] = L'\\';
		memcpy(normalized + rootLen + 1, key, keyLen * sizeof(wchar_t));
		normalized[rootLen + keyLen + 1] = L'\0';

		RtlFreeUnicodeString(&currUser);
	}
	else if (root == RegHKLM)
	{
		rootLen = wcslen(hklm);

		if (normalizedLen < rootLen + keyLen + 1)
			return false;

		memcpy(normalized, hklm, rootLen * sizeof(wchar_t));
		memcpy(normalized + rootLen, key, keyLen * sizeof(wchar_t));
		normalized[rootLen + keyLen] = L'\0';
	}
	else if (root == RegHKU)
	{
		rootLen = wcslen(hku);

		if (normalizedLen < rootLen + keyLen + 1)
			return false;

		memcpy(normalized, hku, rootLen * sizeof(wchar_t));
		memcpy(normalized + rootLen, key, keyLen * sizeof(wchar_t));
		normalized[rootLen + keyLen] = L'\0';
	}
	else
	{
		return false;
	}

	return true;
}

HidStatus AllocNormalizedPath(const wchar_t* path, wchar_t** normalized)
{
	enum { NORMALIZATION_OVERHEAD = 32 };
	wchar_t* buf;
	size_t len;

	len = wcslen(path) + NORMALIZATION_OVERHEAD;

	buf = (wchar_t*)malloc(len * sizeof(wchar_t));
	if (!buf)
		return HID_SET_STATUS(FALSE, ERROR_NOT_ENOUGH_MEMORY);

	if (!ConvertToNtPath(path, buf, len))
	{
		free(buf);
		return HID_SET_STATUS(FALSE, ERROR_INVALID_DATA);
	}

	*normalized = buf;
	return HID_SET_STATUS(TRUE, 0);
}

HidStatus AllocNormalizedRegistryPath(HidRegRootTypes root, const wchar_t* key, wchar_t** normalized)
{
	enum { NORMALIZATION_OVERHEAD = 96 };
	wchar_t* buf;
	size_t len;

	len = wcslen(key) + NORMALIZATION_OVERHEAD;

	buf = (wchar_t*)malloc(len * sizeof(wchar_t));
	if (!buf)
		return HID_SET_STATUS(FALSE, ERROR_NOT_ENOUGH_MEMORY);

	if (!NormalizeRegistryPath(root, key, buf, len))
	{
		free(buf);
		return HID_SET_STATUS(FALSE, ERROR_INVALID_DATA);
	}

	*normalized = buf;
	return HID_SET_STATUS(TRUE, 0);
}

void FreeNormalizedPath(wchar_t* normalized)
{
	free(normalized);
}

HidStatus SendIoctl_HideObjectPacket(PHidContextInternal context, const wchar_t* path, unsigned short type, HidObjId* objId)
{
	PHid_HideObjectPacket hide;
	Hid_StatusPacket result;
	size_t size, len, total;
	DWORD returned;

	len = wcslen(path);
	if (len == 0 || len > 1024)
		return HID_SET_STATUS(FALSE, ERROR_INVALID_PARAMETER);

	// Pack data to packet

	total = (len + 1) * sizeof(wchar_t);
	size = sizeof(Hid_HideObjectPacket) + total;
	hide = (PHid_HideObjectPacket)_alloca(size);
	hide->dataSize = total;
	hide->objType = type;

	memcpy((char*)hide + sizeof(Hid_HideObjectPacket), path, total);

	// Send IOCTL to device

	if (!DeviceIoControl(context->hdevice, HID_IOCTL_ADD_HIDDEN_OBJECT, hide, size, &result, sizeof(result), &returned, NULL))
		return HID_SET_STATUS(FALSE, GetLastError());

	// Check result

	if (returned != sizeof(result))
		return HID_SET_STATUS(FALSE, ERROR_INVALID_PARAMETER);

	if (!NT_SUCCESS(result.status))
		return HID_SET_STATUS(FALSE, result.status);

	if (objId)
		*objId = result.info.id;

	return HID_SET_STATUS(TRUE, 0);
}

HidStatus SendIoctl_UnhideObjectPacket(PHidContextInternal context, unsigned short type, HidObjId objId)
{
	Hid_UnhideObjectPacket unhide;
	Hid_StatusPacket result;
	DWORD returned;

	unhide.objType = type;
	unhide.id = objId;

	// Send IOCTL to device

	if (!DeviceIoControl(context->hdevice, HID_IOCTL_REMOVE_HIDDEN_OBJECT, &unhide, sizeof(unhide), &result, sizeof(result), &returned, NULL))
		return HID_SET_STATUS(FALSE, GetLastError());

	// Check result

	if (returned != sizeof(result))
		return HID_SET_STATUS(FALSE, ERROR_INVALID_PARAMETER);

	if (!NT_SUCCESS(result.status))
		return HID_SET_STATUS(FALSE, result.status);

	return HID_SET_STATUS(TRUE, 0);
}

HidStatus SendIoctl_UnhideAllObjectsPacket(PHidContextInternal context, unsigned short type)
{
	Hid_UnhideAllObjectsPacket unhide;
	Hid_StatusPacket result;
	DWORD returned;

	unhide.objType = type;

	// Send IOCTL to device

	if (!DeviceIoControl(context->hdevice, HID_IOCTL_REMOVE_ALL_HIDDEN_OBJECTS, &unhide, sizeof(unhide), &result, sizeof(result), &returned, NULL))
		return HID_SET_STATUS(FALSE, GetLastError());

	// Check result

	if (returned != sizeof(result))
		return HID_SET_STATUS(FALSE, ERROR_INVALID_PARAMETER);

	if (!NT_SUCCESS(result.status))
		return HID_SET_STATUS(FALSE, result.status);

	return HID_SET_STATUS(TRUE, 0);
}

HidStatus SendIoctl_AddPsObjectPacket(PHidContextInternal context, const wchar_t* path, unsigned short type, HidPsInheritTypes inheritType, HidObjId* objId)
{
	PHid_AddPsObjectPacket hide;
	Hid_StatusPacket result;
	size_t size, len, total;
	DWORD returned;

	len = wcslen(path);
	if (len == 0 || len > 1024)
		return HID_SET_STATUS(FALSE, ERROR_INVALID_PARAMETER);

	// Pack data to packet

	total = (len + 1) * sizeof(wchar_t);
	size = sizeof(Hid_AddPsObjectPacket) + total;
	hide = (PHid_AddPsObjectPacket)_alloca(size);
	hide->dataSize = total;
	hide->objType = type;
	hide->inheritType = inheritType;

	memcpy((char*)hide + sizeof(Hid_AddPsObjectPacket), path, total);

	// Send IOCTL to device

	if (!DeviceIoControl(context->hdevice, HID_IOCTL_ADD_OBJECT, hide, size, &result, sizeof(result), &returned, NULL))
		return HID_SET_STATUS(FALSE, GetLastError());

	// Check result

	if (returned != sizeof(result))
		return HID_SET_STATUS(FALSE, ERROR_INVALID_PARAMETER);

	if (!NT_SUCCESS(result.status))
		return HID_SET_STATUS(FALSE, result.status);

	if (objId)
		*objId = result.info.id;

	return HID_SET_STATUS(TRUE, 0);
}

HidStatus SendIoctl_RemovePsObjectPacket(PHidContextInternal context, unsigned short type, HidObjId objId)
{
	Hid_RemovePsObjectPacket remove;
	Hid_StatusPacket result;
	DWORD returned;

	remove.objType = type;
	remove.id = objId;

	// Send IOCTL to device

	if (!DeviceIoControl(context->hdevice, HID_IOCTL_REMOVE_OBJECT, &remove, sizeof(remove), &result, sizeof(result), &returned, NULL))
		return HID_SET_STATUS(FALSE, GetLastError());

	// Check result

	if (returned != sizeof(result))
		return HID_SET_STATUS(FALSE, ERROR_INVALID_PARAMETER);

	if (!NT_SUCCESS(result.status))
		return HID_SET_STATUS(FALSE, result.status);

	return HID_SET_STATUS(TRUE, 0);
}

HidStatus SendIoctl_RemoveAllPsObjectsPacket(PHidContextInternal context, unsigned short type)
{
	Hid_UnhideAllObjectsPacket remove;
	Hid_StatusPacket result;
	DWORD returned;

	remove.objType = type;

	// Send IOCTL to device

	if (!DeviceIoControl(context->hdevice, HID_IOCTL_REMOVE_ALL_OBJECTS, &remove, sizeof(remove), &result, sizeof(result), &returned, NULL))
		return HID_SET_STATUS(FALSE, GetLastError());

	// Check result

	if (returned != sizeof(result))
		return HID_SET_STATUS(FALSE, ERROR_INVALID_PARAMETER);

	if (!NT_SUCCESS(result.status))
		return HID_SET_STATUS(FALSE, result.status);

	return HID_SET_STATUS(TRUE, 0);
}

// Control interface

HidStatus Hid_SetState(HidContext context, HidActiveState state)
{
	PHidContextInternal cntx = (PHidContextInternal)context;
	return HID_SET_STATUS(FALSE, ERROR_CALL_NOT_IMPLEMENTED);
}

HidStatus Hid_GetState(HidContext context, HidActiveState* pstate)
{
	PHidContextInternal cntx = (PHidContextInternal)context;
	return HID_SET_STATUS(FALSE, ERROR_CALL_NOT_IMPLEMENTED);
}

// Registry hiding interface

HidStatus Hid_AddHiddenRegKey(HidContext context, HidRegRootTypes root, const wchar_t* regKey, HidObjId* objId)
{
	HidStatus status;
	wchar_t* normalized;

	status = AllocNormalizedRegistryPath(root, regKey, &normalized);
	if (!HID_STATUS_SUCCESSFUL(status))
		return status;

	status = SendIoctl_HideObjectPacket((PHidContextInternal)context, normalized, RegKeyObject, objId);
	FreeNormalizedPath(normalized);

	return status;
	//return SendIoctl_HideObjectPacket((PHidContextInternal)context, regKey, RegKeyObject, objId);
}

HidStatus Hid_RemoveHiddenRegKey(HidContext context, HidObjId objId)
{
	return SendIoctl_UnhideObjectPacket((PHidContextInternal)context, RegKeyObject, objId);
}

HidStatus Hid_RemoveAllHiddenRegKeys(HidContext context)
{
	return SendIoctl_UnhideAllObjectsPacket((PHidContextInternal)context, RegKeyObject);
}

HidStatus Hid_AddHiddenRegValue(HidContext context, HidRegRootTypes root, const wchar_t* regValue, HidObjId* objId)
{
	HidStatus status;
	wchar_t* normalized;

	status = AllocNormalizedRegistryPath(root, regValue, &normalized);
	if (!HID_STATUS_SUCCESSFUL(status))
		return status;

	status = SendIoctl_HideObjectPacket((PHidContextInternal)context, normalized, RegValueObject, objId);
	FreeNormalizedPath(normalized);

	return status;
	//return SendIoctl_HideObjectPacket((PHidContextInternal)context, regValue, RegValueObject, objId);
}

HidStatus Hid_RemoveHiddenRegValue(HidContext context, HidObjId objId)
{
	return SendIoctl_UnhideObjectPacket((PHidContextInternal)context, RegValueObject, objId);
}

HidStatus Hid_RemoveAllHiddenRegValues(HidContext context)
{
	return SendIoctl_UnhideAllObjectsPacket((PHidContextInternal)context, RegValueObject);
}

// File system hiding interface

HidStatus Hid_AddHiddenFile(HidContext context, const wchar_t* filePath, HidObjId* objId)
{
	HidStatus status;
	wchar_t* normalized;

	status = AllocNormalizedPath(filePath, &normalized);
	if (!HID_STATUS_SUCCESSFUL(status))
		return status;

	status = SendIoctl_HideObjectPacket((PHidContextInternal)context, normalized, FsFileObject, objId);
	FreeNormalizedPath(normalized);

	return status;
}

HidStatus Hid_RemoveHiddenFile(HidContext context, HidObjId objId)
{
	return SendIoctl_UnhideObjectPacket((PHidContextInternal)context, FsFileObject, objId);
}

HidStatus Hid_RemoveAllHiddenFiles(HidContext context)
{
	return SendIoctl_UnhideAllObjectsPacket((PHidContextInternal)context, FsFileObject);
}

HidStatus Hid_AddHiddenDir(HidContext context, const wchar_t* dirPath, HidObjId* objId)
{
	HidStatus status;
	wchar_t* normalized;

	status = AllocNormalizedPath(dirPath, &normalized);
	if (!HID_STATUS_SUCCESSFUL(status))
		return status;

	status = SendIoctl_HideObjectPacket((PHidContextInternal)context, normalized, FsDirObject, objId);
	FreeNormalizedPath(normalized);

	return status;
}

HidStatus Hid_RemoveHiddenDir(HidContext context, HidObjId objId)
{
	return SendIoctl_UnhideObjectPacket((PHidContextInternal)context, FsDirObject, objId);
}

HidStatus Hid_RemoveAllHiddenDirs(HidContext context)
{
	return SendIoctl_UnhideAllObjectsPacket((PHidContextInternal)context, FsDirObject);
}

// Process exclude interface

HidStatus Hid_AddExcludedImage(HidContext context, const wchar_t* imagePath, HidPsInheritTypes inheritType, HidObjId* objId)
{
	HidStatus status;
	wchar_t* normalized;

	status = AllocNormalizedPath(imagePath, &normalized);
	if (!HID_STATUS_SUCCESSFUL(status))
		return status;

	status = SendIoctl_AddPsObjectPacket((PHidContextInternal)context, normalized, PsExcludedObject, inheritType, objId);
	FreeNormalizedPath(normalized);

	return status;
}

HidStatus Hid_RemoveExcludedImage(HidContext context, HidObjId objId)
{
	return SendIoctl_RemovePsObjectPacket((PHidContextInternal)context, PsExcludedObject, objId);
}

HidStatus Hid_RemoveAllExcludedImages(HidContext context)
{
	return SendIoctl_RemoveAllPsObjectsPacket((PHidContextInternal)context, PsExcludedObject);
}

HidStatus Hid_GetExcludedState(HidContext context, HidProcId procId, HidActiveState* state, HidPsInheritTypes* inheritType)
{
	return HID_SET_STATUS(FALSE, ERROR_CALL_NOT_IMPLEMENTED);
}

HidStatus Hid_AttachExcludedState(HidContext context, HidProcId procId, HidPsInheritTypes inheritType)
{
	return HID_SET_STATUS(FALSE, ERROR_CALL_NOT_IMPLEMENTED);
}

HidStatus Hid_RemoveExcludedState(HidContext context, HidProcId procId)
{
	return HID_SET_STATUS(FALSE, ERROR_CALL_NOT_IMPLEMENTED);
}

// Process protect interface

HidStatus Hid_AddProtectedImage(HidContext context, const wchar_t* imagePath, HidPsInheritTypes inheritType, HidObjId* objId)
{
	HidStatus status;
	wchar_t* normalized;

	status = AllocNormalizedPath(imagePath, &normalized);
	if (!HID_STATUS_SUCCESSFUL(status))
		return status;

	status = SendIoctl_AddPsObjectPacket((PHidContextInternal)context, normalized, PsProtectedObject, inheritType, objId);
	FreeNormalizedPath(normalized);

	return status;
}

HidStatus Hid_RemoveProtectedImage(HidContext context, HidObjId objId)
{
	return SendIoctl_RemovePsObjectPacket((PHidContextInternal)context, PsProtectedObject, objId);
}

HidStatus Hid_RemoveAllProtectedImages(HidContext context)
{
	return SendIoctl_RemoveAllPsObjectsPacket((PHidContextInternal)context, PsProtectedObject);
}

HidStatus Hid_GetProtectedState(HidContext context, HidProcId procId, HidActiveState* state, HidPsInheritTypes* inheritType)
{
	return HID_SET_STATUS(FALSE, ERROR_CALL_NOT_IMPLEMENTED);
}

HidStatus Hid_AttachProtectedState(HidContext context, HidProcId procId, HidPsInheritTypes inheritType)
{
	return HID_SET_STATUS(FALSE, ERROR_CALL_NOT_IMPLEMENTED);
}

HidStatus Hid_RemoveProtectedState(HidContext context, HidProcId procId)
{
	return HID_SET_STATUS(FALSE, ERROR_CALL_NOT_IMPLEMENTED);
}

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

HidStatus Hid_Initialize(PHidContext pcontext)
{
	HANDLE hdevice = INVALID_HANDLE_VALUE;
	PHidContextInternal context;

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

HidStatus SendIoctl_HideObjectPacket(PHidContextInternal context, wchar_t* path, unsigned short type, HidObjId* objId)
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

HidStatus SendIoctl_AddPsObjectPacket(PHidContextInternal context, wchar_t* path, unsigned short type, HidPsInheritTypes inheritType, HidObjId* objId)
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

HidStatus Hid_AddHiddenRegKey(HidContext context, wchar_t* regKey, HidObjId* objId)
{
	return SendIoctl_HideObjectPacket((PHidContextInternal)context, regKey, RegKeyObject, objId);
}

HidStatus Hid_RemoveHiddenRegKey(HidContext context, HidObjId objId)
{
	return SendIoctl_UnhideObjectPacket((PHidContextInternal)context, RegKeyObject, objId);
}

HidStatus Hid_RemoveAllHiddenRegKeys(HidContext context)
{
	return SendIoctl_UnhideAllObjectsPacket((PHidContextInternal)context, RegKeyObject);
}

HidStatus Hid_AddHiddenRegValue(HidContext context, wchar_t* regValue, HidObjId* objId)
{
	return SendIoctl_HideObjectPacket((PHidContextInternal)context, regValue, RegValueObject, objId);
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

HidStatus Hid_AddHiddenFile(HidContext context, wchar_t* filePath, HidObjId* objId)
{
	return SendIoctl_HideObjectPacket((PHidContextInternal)context, filePath, FsFileObject, objId);
}

HidStatus Hid_RemoveHiddenFile(HidContext context, HidObjId objId)
{
	return SendIoctl_UnhideObjectPacket((PHidContextInternal)context, FsFileObject, objId);
}

HidStatus Hid_RemoveAllHiddenFiles(HidContext context)
{
	return SendIoctl_UnhideAllObjectsPacket((PHidContextInternal)context, FsFileObject);
}

HidStatus Hid_AddHiddenDir(HidContext context, wchar_t* dirPath, HidObjId* objId)
{
	return SendIoctl_HideObjectPacket((PHidContextInternal)context, dirPath, FsDirObject, objId);
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

HidStatus Hid_AddExcludedImage(HidContext context, wchar_t* imagePath, HidPsInheritTypes inheritType, HidObjId* objId)
{
	return SendIoctl_AddPsObjectPacket((PHidContextInternal)context, imagePath, PsExcludedObject, inheritType, objId);
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

HidStatus Hid_AddProtectedImage(HidContext context, wchar_t* imagePath, HidPsInheritTypes inheritType, HidObjId* objId)
{
	return SendIoctl_AddPsObjectPacket((PHidContextInternal)context, imagePath, PsProtectedObject, inheritType, objId);
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

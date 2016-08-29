#include <Windows.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "HiddenLib.h"
#include "..\\Hidden\DeviceAPI.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)

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

HidStatus SendIoctlHideObjectPacket(PHidContextInternal context, wchar_t* path, unsigned short type, HidObjId* objId)
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
	hide->size = total;
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

HidStatus SendIoctlUnhideObjectPacket(PHidContextInternal context, unsigned short type, HidObjId objId)
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

HidStatus SendIoctlUnhideAllObjectsPacket(PHidContextInternal context, unsigned short type)
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

HidStatus Hid_SetState(HidContext context, int state)
{
	PHidContextInternal cntx = (PHidContextInternal)context;
	return HID_SET_STATUS(TRUE, 0);
}

HidStatus Hid_GetState(HidContext context, int* pstate)
{
	PHidContextInternal cntx = (PHidContextInternal)context;
	return HID_SET_STATUS(TRUE, 0);
}

HidStatus Hid_AddHiddenRegKey(HidContext context, wchar_t* regKey, HidObjId* objId)
{
	return SendIoctlHideObjectPacket((PHidContextInternal)context, regKey, RegKeyObject, objId);
}

HidStatus Hid_RemoveHiddenRegKey(HidContext context, HidObjId objId)
{
	return SendIoctlUnhideObjectPacket((PHidContextInternal)context, RegKeyObject, objId);
}

HidStatus Hid_RemoveAllHiddenRegKeys(HidContext context)
{
	return SendIoctlUnhideAllObjectsPacket((PHidContextInternal)context, RegKeyObject);
}

HidStatus Hid_AddHiddenRegValue(HidContext context, wchar_t* regValue, HidObjId* objId)
{
	return SendIoctlHideObjectPacket((PHidContextInternal)context, regValue, RegValueObject, objId);
}

HidStatus Hid_RemoveHiddenRegValue(HidContext context, HidObjId objId)
{
	return SendIoctlUnhideObjectPacket((PHidContextInternal)context, RegValueObject, objId);
}

HidStatus Hid_RemoveAllHiddenRegValues(HidContext context)
{
	return SendIoctlUnhideAllObjectsPacket((PHidContextInternal)context, RegValueObject);
}

HidStatus Hid_AddHiddenFile(HidContext context, wchar_t* filePath, HidObjId* objId)
{
	return SendIoctlHideObjectPacket((PHidContextInternal)context, filePath, FsFileObject, objId);
}

HidStatus Hid_RemoveHiddenFile(HidContext context, HidObjId objId)
{
	return SendIoctlUnhideObjectPacket((PHidContextInternal)context, FsFileObject, objId);
}

HidStatus Hid_RemoveAllHiddenFiles(HidContext context)
{
	return SendIoctlUnhideAllObjectsPacket((PHidContextInternal)context, FsFileObject);
}

HidStatus Hid_AddHiddenDir(HidContext context, wchar_t* dirPath, HidObjId* objId)
{
	return SendIoctlHideObjectPacket((PHidContextInternal)context, dirPath, FsDirObject, objId);
}

HidStatus Hid_RemoveHiddenDir(HidContext context, HidObjId objId)
{
	return SendIoctlUnhideObjectPacket((PHidContextInternal)context, FsDirObject, objId);
}

HidStatus Hid_RemoveAllHiddenDirs(HidContext context)
{
	return SendIoctlUnhideAllObjectsPacket((PHidContextInternal)context, FsDirObject);
}

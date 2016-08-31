#include "RegFilter.h"
#include "FsFilter.h"
#include "PsMonitor.h"
#include "Device.h"
#include "DeviceAPI.h"


PDEVICE_OBJECT g_deviceObject = NULL;

// =========================================================================================

NTSTATUS IrpDeviceCreate(PDEVICE_OBJECT  DeviceObject, PIRP  Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!!\n");

	return STATUS_SUCCESS;
}

NTSTATUS IrpDeviceClose(PDEVICE_OBJECT  DeviceObject, PIRP  Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!!\n");

	return STATUS_SUCCESS;
}
NTSTATUS IrpDeviceCleanup(PDEVICE_OBJECT  DeviceObject, PIRP  Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!!\n");

	return STATUS_SUCCESS;
}

NTSTATUS AddHiddenObject(PHid_HideObjectPacket packet, USHORT size, PULONGLONG objId)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING path;
	USHORT i, count;

	// Check can we access to the packet
	if (size < sizeof(Hid_HideObjectPacket))
		return STATUS_INVALID_PARAMETER;

	// Check packet data size overflow
	if (size < packet->size + sizeof(Hid_HideObjectPacket))
		return STATUS_INVALID_PARAMETER;

	// Unpack string to UNICODE_STRING

	path.Buffer = (LPWSTR)((PCHAR)packet + sizeof(Hid_HideObjectPacket));
	path.MaximumLength = size - sizeof(Hid_HideObjectPacket);

	// Just checking for zero-end string ends in the middle
	count = packet->size / sizeof(WCHAR);
	for (i = 0; i < count; i++)
		if (path.Buffer[i] == L'\0')
			break;
	
	path.Length = i * sizeof(WCHAR);

	// Perform the packet

	switch (packet->objType)
	{
	case RegKeyObject:
		status = AddHiddenRegKey(&path, objId);
		break;
	case RegValueObject:
		status = AddHiddenRegValue(&path, objId);
		break;
	case FsFileObject:
		status = AddHiddenFile(&path, objId);
		break;
	case FsDirObject:
		status = AddHiddenDir(&path, objId);
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS RemoveHiddenObject(PHid_UnhideObjectPacket packet, USHORT size)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (size != sizeof(Hid_UnhideObjectPacket))
		return STATUS_INVALID_PARAMETER;

	// Perform packet

	switch (packet->objType)
	{
	case RegKeyObject:
		status = RemoveHiddenRegKey(packet->id);
		break;
	case RegValueObject:
		status = RemoveHiddenRegValue(packet->id);
		break;
	case FsFileObject:
		status = RemoveHiddenFile(packet->id);
		break;
	case FsDirObject:
		status = RemoveHiddenDir(packet->id);
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS RemoveAllHiddenObjects(PHid_UnhideAllObjectsPacket packet, USHORT size)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (size != sizeof(Hid_UnhideAllObjectsPacket))
		return STATUS_INVALID_PARAMETER;

	// Perform packet

	switch (packet->objType)
	{
	case RegKeyObject:
		status = RemoveAllHiddenRegKeys();
		break;
	case RegValueObject:
		status = RemoveAllHiddenRegValues();
		break;
	case FsFileObject:
		status = RemoveAllHiddenFiles();
		break;
	case FsDirObject:
		status = RemoveAllHiddenDirs();
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS AddPsObject(PHid_AddPsObjectPacket packet, USHORT size, PULONGLONG objId)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING path;
	USHORT i, count;

	// Check can we access to the packet
	if (size < sizeof(Hid_AddPsObjectPacket))
		return STATUS_INVALID_PARAMETER;

	// Check packet data size overflow
	if (size < packet->size + sizeof(Hid_AddPsObjectPacket))
		return STATUS_INVALID_PARAMETER;

	// Unpack string to UNICODE_STRING

	path.Buffer = (LPWSTR)((PCHAR)packet + sizeof(Hid_AddPsObjectPacket));
	path.MaximumLength = size - sizeof(Hid_AddPsObjectPacket);

	// Just checking for zero-end string ends in the middle
	count = packet->size / sizeof(WCHAR);
	for (i = 0; i < count; i++)
	if (path.Buffer[i] == L'\0')
		break;

	path.Length = i * sizeof(WCHAR);

	// Perform the packet

	switch (packet->objType)
	{
	case PsExcludedObject:
		status = AddExcludedImage(&path, packet->inheritType, objId);
		break;
	case PsProtectedObject:
		status = AddProtectedImage(&path, packet->inheritType, objId);
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS RemovePsObject(PHid_RemovePsObjectPacket packet, USHORT size)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (size != sizeof(Hid_RemovePsObjectPacket))
		return STATUS_INVALID_PARAMETER;

	// Perform packet

	switch (packet->objType)
	{
	case PsExcludedObject:
		status = RemoveExcludedImage(packet->id);
		break;
	case PsProtectedObject:
		status = RemoveProtectedImage(packet->id);
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS RemoveAllPsObjects(PHid_RemoveAllPsObjectsPacket packet, USHORT size)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (size != sizeof(Hid_RemoveAllPsObjectsPacket))
		return STATUS_INVALID_PARAMETER;

	// Perform packet

	switch (packet->objType)
	{
	case PsExcludedObject:
		status = RemoveAllExcludedImages();
		break;
	case PsProtectedObject:
		status = RemoveAllProtectedImages();
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS IrpDeviceControlHandler(PDEVICE_OBJECT  DeviceObject, PIRP  Irp)
{
	PIO_STACK_LOCATION irpStack;
	Hid_StatusPacket result;
	NTSTATUS status = STATUS_SUCCESS;
	PVOID inputBuffer, outputBuffer;
	ULONG ioctl, inputBufferSize, outputBufferSize, outputBufferMaxSize;

	UNREFERENCED_PARAMETER(DeviceObject);

	// Get irp information

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	ioctl = irpStack->Parameters.DeviceIoControl.IoControlCode;

	inputBuffer = outputBuffer = Irp->AssociatedIrp.SystemBuffer;
	inputBufferSize = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outputBufferMaxSize = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	outputBufferSize = 0;

	RtlZeroMemory(&result, sizeof(result));

	// Check output buffer size

	if (outputBufferMaxSize < sizeof(result))
	{
		status = STATUS_INVALID_PARAMETER;
		goto EndProc;
	}

	switch (ioctl)
	{
	// Reg/Fs 
	case HID_IOCTL_ADD_HIDDEN_OBJECT:
		result.status = AddHiddenObject((PHid_HideObjectPacket)inputBuffer, (USHORT)inputBufferSize, &result.info.id);
		break;
	case HID_IOCTL_REMOVE_HIDDEN_OBJECT:
		result.status = RemoveHiddenObject((PHid_UnhideObjectPacket)inputBuffer, (USHORT)inputBufferSize);
		break;
	case HID_IOCTL_REMOVE_ALL_HIDDEN_OBJECTS:
		result.status = RemoveAllHiddenObjects((PHid_UnhideAllObjectsPacket)inputBuffer, (USHORT)inputBufferSize);
		break;
	// Ps
	case HID_IOCTL_ADD_OBJECT:
		result.status = AddPsObject((PHid_AddPsObjectPacket)inputBuffer, (USHORT)inputBufferSize, &result.info.id);
		break;
	case HID_IOCTL_GET_OBJECT_STATE:
		result.status = (ULONG)STATUS_NOT_IMPLEMENTED;
		break;
	case HID_IOCTL_SET_OBJECT_STATE:
		result.status = (ULONG)STATUS_NOT_IMPLEMENTED;
		break;
	case HID_IOCTL_REMOVE_OBJECT:
		result.status = RemovePsObject((PHid_RemovePsObjectPacket)inputBuffer, (USHORT)inputBufferSize);
		break;
	case HID_IOCTL_REMOVE_ALL_OBJECTS:
		result.status = RemoveAllPsObjects((PHid_RemoveAllPsObjectsPacket)inputBuffer, (USHORT)inputBufferSize);
		break;

	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": unknown IOCTL code:%08x\n", ioctl);
		status = STATUS_INVALID_PARAMETER;
		goto EndProc;
	}

EndProc:
	
	// Copy result to output buffer
	if (NT_SUCCESS(status)) 
	{
		outputBufferSize = sizeof(result);
		RtlCopyMemory(outputBuffer, &result, sizeof(result));
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = outputBufferSize;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS InitializeDevice(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
	UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING(DOS_DEVICES_LINK_NAME);
	PDEVICE_OBJECT deviceObject = NULL;

	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": device creation failed with code:%08x\n", status);
		return status;
	}

	status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(deviceObject);
		DbgPrint("FsFilter1!" __FUNCTION__ ": symbolic link creation failed with code:%08x\n", status);
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE]         = IrpDeviceCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]          = IrpDeviceClose;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = IrpDeviceCleanup;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControlHandler;
	g_deviceObject = deviceObject;

	return status;
}

NTSTATUS DestroyDevice()
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING(DOS_DEVICES_LINK_NAME);

	status = IoDeleteSymbolicLink(&dosDeviceName);
	if (!NT_SUCCESS(status))
		DbgPrint("FsFilter1!" __FUNCTION__ ": symbolic link deletion failed with code:%08x\n", status);

	IoDeleteDevice(g_deviceObject);

	return status;
}

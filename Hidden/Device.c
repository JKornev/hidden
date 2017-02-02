#include "RegFilter.h"
#include "FsFilter.h"
#include "PsMonitor.h"
#include "Device.h"
#include "DeviceAPI.h"
#include "Driver.h"

BOOLEAN g_deviceInited = FALSE;
PDEVICE_OBJECT g_deviceObject = NULL;

// =========================================================================================

_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_CREATE)
NTSTATUS IrpDeviceCreate(PDEVICE_OBJECT  DeviceObject, PIRP  Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_CLOSE)
NTSTATUS IrpDeviceClose(PDEVICE_OBJECT  DeviceObject, PIRP  Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_CLEANUP)
NTSTATUS IrpDeviceCleanup(PDEVICE_OBJECT  DeviceObject, PIRP  Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS AddHiddenObject(PHid_HideObjectPacket Packet, USHORT Size, PULONGLONG ObjId)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING path;
	USHORT i, count;

	// Check can we access to the packet
	if (Size < sizeof(Hid_HideObjectPacket))
		return STATUS_INVALID_PARAMETER;

	// Check packet data size overflow
	if (Size < Packet->dataSize + sizeof(Hid_HideObjectPacket))
		return STATUS_INVALID_PARAMETER;

	// Unpack string to UNICODE_STRING

	path.Buffer = (LPWSTR)((PCHAR)Packet + sizeof(Hid_HideObjectPacket));
	path.MaximumLength = Size - sizeof(Hid_HideObjectPacket);

	// Just checking for zero-end string ends in the middle
	count = Packet->dataSize / sizeof(WCHAR);
	for (i = 0; i < count; i++)
		if (path.Buffer[i] == L'\0')
			break;
	
	path.Length = i * sizeof(WCHAR);

	// Perform the packet

	switch (Packet->objType)
	{
	case RegKeyObject:
		status = AddHiddenRegKey(&path, ObjId);
		break;
	case RegValueObject:
		status = AddHiddenRegValue(&path, ObjId);
		break;
	case FsFileObject:
		status = AddHiddenFile(&path, ObjId);
		break;
	case FsDirObject:
		status = AddHiddenDir(&path, ObjId);
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", Packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS RemoveHiddenObject(PHid_UnhideObjectPacket Packet, USHORT Size)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (Size != sizeof(Hid_UnhideObjectPacket))
		return STATUS_INVALID_PARAMETER;

	// Perform packet

	switch (Packet->objType)
	{
	case RegKeyObject:
		status = RemoveHiddenRegKey(Packet->id);
		break;
	case RegValueObject:
		status = RemoveHiddenRegValue(Packet->id);
		break;
	case FsFileObject:
		status = RemoveHiddenFile(Packet->id);
		break;
	case FsDirObject:
		status = RemoveHiddenDir(Packet->id);
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", Packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS RemoveAllHiddenObjects(PHid_UnhideAllObjectsPacket Packet, USHORT Size)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (Size != sizeof(Hid_UnhideAllObjectsPacket))
		return STATUS_INVALID_PARAMETER;

	// Perform packet

	switch (Packet->objType)
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
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", Packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS AddPsObject(PHid_AddPsObjectPacket Packet, USHORT Size, PULONGLONG ObjId)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING path;
	USHORT i, count;

	// Check can we access to the packet
	if (Size < sizeof(Hid_AddPsObjectPacket))
		return STATUS_INVALID_PARAMETER;

	// Check packet data size overflow
	if (Size < Packet->dataSize + sizeof(Hid_AddPsObjectPacket))
		return STATUS_INVALID_PARAMETER;

	// Unpack string to UNICODE_STRING

	path.Buffer = (LPWSTR)((PCHAR)Packet + sizeof(Hid_AddPsObjectPacket));
	path.MaximumLength = Size - sizeof(Hid_AddPsObjectPacket);

	// Just checking for zero-end string ends in the middle
	count = Packet->dataSize / sizeof(WCHAR);
	for (i = 0; i < count; i++)
	if (path.Buffer[i] == L'\0')
		break;

	path.Length = i * sizeof(WCHAR);

	// Perform the packet

	switch (Packet->objType)
	{
	case PsExcludedObject:
		status = AddExcludedImage(&path, Packet->inheritType, (Packet->applyForProcesses ? TRUE : FALSE), ObjId);
		break;
	case PsProtectedObject:
		status = AddProtectedImage(&path, Packet->inheritType, (Packet->applyForProcesses ? TRUE : FALSE), ObjId);
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", Packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS GetPsObjectInfo(PHid_GetPsObjectInfoPacket Packet, USHORT Size, PHid_GetPsObjectInfoPacket OutPacket, PULONG OutSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG inheritType, outSize;
	BOOLEAN enable;

	outSize = *OutSize;
	*OutSize = 0;

	if (Size < sizeof(Hid_GetPsObjectInfoPacket))
		return STATUS_INVALID_PARAMETER;

	if (outSize < sizeof(Hid_GetPsObjectInfoPacket))
		return STATUS_INVALID_PARAMETER;

	// Perform packet

	switch (Packet->objType)
	{
	case PsExcludedObject:
		status = GetExcludedProcessState((HANDLE)Packet->procId, &inheritType, &enable);
		break;
	case PsProtectedObject:
		status = GetProtectedProcessState((HANDLE)Packet->procId, &inheritType, &enable);
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", Packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	Packet->enable = (USHORT)enable;
	Packet->inheritType = (USHORT)inheritType;
	
	RtlCopyMemory(OutPacket, Packet, sizeof(Hid_GetPsObjectInfoPacket));
	*OutSize = sizeof(Hid_GetPsObjectInfoPacket);

	return status;
}

NTSTATUS SetPsObjectInfo(PHid_SetPsObjectInfoPacket Packet, USHORT Size)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (Size != sizeof(Hid_SetPsObjectInfoPacket))
		return STATUS_INVALID_PARAMETER;

	// Perform packet

	switch (Packet->objType)
	{
	case PsExcludedObject:
		status = SetExcludedProcessState((HANDLE)Packet->procId, Packet->inheritType, (Packet->enable ? TRUE : FALSE));
		break;
	case PsProtectedObject:
		status = SetProtectedProcessState((HANDLE)Packet->procId, Packet->inheritType, (Packet->enable ? TRUE : FALSE));
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", Packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS RemovePsObject(PHid_RemovePsObjectPacket Packet, USHORT Size)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (Size != sizeof(Hid_RemovePsObjectPacket))
		return STATUS_INVALID_PARAMETER;

	// Perform packet

	switch (Packet->objType)
	{
	case PsExcludedObject:
		status = RemoveExcludedImage(Packet->id);
		break;
	case PsProtectedObject:
		status = RemoveProtectedImage(Packet->id);
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", Packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS RemoveAllPsObjects(PHid_RemoveAllPsObjectsPacket Packet, USHORT Size)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (Size != sizeof(Hid_RemoveAllPsObjectsPacket))
		return STATUS_INVALID_PARAMETER;

	// Perform packet

	switch (Packet->objType)
	{
	case PsExcludedObject:
		status = RemoveAllExcludedImages();
		break;
	case PsProtectedObject:
		status = RemoveAllProtectedImages();
		break;
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": Unsupported object type: %u\n", Packet->objType);
		return STATUS_INVALID_PARAMETER;
	}

	return status;
}

NTSTATUS SetDriverStateObject(PHid_DriverStatus Packet, USHORT Size)
{
	if (Size != sizeof(Hid_DriverStatus))
		return STATUS_INVALID_PARAMETER;

	EnableDisableDriver(Packet->state ? TRUE : FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS GetDriverStateObject(PHid_DriverStatus Packet, USHORT Size, PULONG state)
{
	UNREFERENCED_PARAMETER(Packet);

	if (Size != sizeof(Hid_DriverStatus))
		return STATUS_INVALID_PARAMETER;

	*state = IsDriverEnabled();
	return STATUS_SUCCESS;
}

_Function_class_(DRIVER_DISPATCH)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
NTSTATUS IrpDeviceControlHandler(PDEVICE_OBJECT  DeviceObject, PIRP  Irp)
{
	PIO_STACK_LOCATION irpStack;
	Hid_StatusPacket result;
	NTSTATUS status = STATUS_SUCCESS;
	PVOID inputBuffer, outputBuffer, outputData;
	ULONG ioctl, inputBufferSize, outputBufferSize, outputBufferMaxSize, 
		  outputDataMaxSize, outputDataSize;

	UNREFERENCED_PARAMETER(DeviceObject);
	
	// Get irp information

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	ioctl = irpStack->Parameters.DeviceIoControl.IoControlCode;

	inputBuffer = outputBuffer = Irp->AssociatedIrp.SystemBuffer;
	inputBufferSize = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outputBufferMaxSize = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	outputBufferSize  = 0;
	outputDataSize    = 0;
	outputDataMaxSize = 0;

	RtlZeroMemory(&result, sizeof(result));

	// Check output buffer size

	if (outputBufferMaxSize < sizeof(result))
	{
		status = STATUS_INVALID_PARAMETER;
		goto EndProc;
	}

	// Prepare additional buffer for output data 
	outputData = (PVOID)((UINT_PTR)outputBuffer + sizeof(result));
	outputDataMaxSize = outputBufferMaxSize - sizeof(result);

	// Important limitation:
	// Because both input (inputBuffer) and output data (outputData) are located in the same buffer there is a limitation for the output
	// buffer usage. When a ioctl handler is executing, it can use the input buffer only until first write to the output buffer, because
	// when you put data to the output buffer you can overwrite data in input buffer. Therefore if you gonna use both an input and output 
	// data in the same time you should make the copy of input data and work with it.
	switch (ioctl)
	{
	// Driver
	case HID_IOCTL_SET_DRIVER_STATE:
		result.status = SetDriverStateObject((PHid_DriverStatus)inputBuffer, (USHORT)inputBufferSize);
		break;
	case HID_IOCTL_GET_DRIVER_STATE:
		result.status = GetDriverStateObject((PHid_DriverStatus)inputBuffer, (USHORT)inputBufferSize, &result.info.state);
		break;
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
		outputDataSize = outputDataMaxSize;
		result.status = GetPsObjectInfo((PHid_SetPsObjectInfoPacket)inputBuffer, (USHORT)inputBufferSize, outputData, &outputDataSize);
		break;
	case HID_IOCTL_SET_OBJECT_STATE:
		result.status = SetPsObjectInfo((PHid_SetPsObjectInfoPacket)inputBuffer, (USHORT)inputBufferSize);
		break;
	case HID_IOCTL_REMOVE_OBJECT:
		result.status = RemovePsObject((PHid_RemovePsObjectPacket)inputBuffer, (USHORT)inputBufferSize);
		break;
	case HID_IOCTL_REMOVE_ALL_OBJECTS:
		result.status = RemoveAllPsObjects((PHid_RemoveAllPsObjectsPacket)inputBuffer, (USHORT)inputBufferSize);
		break;
	// Other
	default:
		DbgPrint("FsFilter1!" __FUNCTION__ ": unknown IOCTL code:%08x\n", ioctl);
		status = STATUS_INVALID_PARAMETER;
		goto EndProc;
	}

EndProc:
	
	// If additional output data has been presented
	if (NT_SUCCESS(status) && outputDataSize > 0)
	{
		if (outputDataSize > outputDataMaxSize)
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": An internal error that looks like a stack corruption!\n");
			outputDataSize = outputDataMaxSize;
			result.status = (ULONG)STATUS_PARTIAL_COPY;
		}

		result.dataSize = outputDataSize;
	}

	// Copy result to output buffer
	if (NT_SUCCESS(status)) 
	{
		outputBufferSize = sizeof(result) + outputDataSize;
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
	g_deviceInited = TRUE;

	return status;
}

NTSTATUS DestroyDevice()
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING(DOS_DEVICES_LINK_NAME);

	if (!g_deviceInited)
		return STATUS_NOT_FOUND;

	status = IoDeleteSymbolicLink(&dosDeviceName);
	if (!NT_SUCCESS(status))
		DbgPrint("FsFilter1!" __FUNCTION__ ": symbolic link deletion failed with code:%08x\n", status);

	IoDeleteDevice(g_deviceObject);

	g_deviceInited = FALSE;

	return status;
}

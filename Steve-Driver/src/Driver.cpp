#include "ntifs.h"
#include "wdm.h"

#include "Generic.h"

static UNICODE_STRING g_NtDeviceName = RTL_CONSTANT_STRING(L"\\Device\\Steve");
static UNICODE_STRING g_DosDeviceName = RTL_CONSTANT_STRING(L"\\DosDevices\\Steve");

PDEVICE_OBJECT g_SteveDevice = NULL;
ULONG g_AuthorizedProcess = 0;

_Success_(NT_SUCCESS(return))
static NTSTATUS HandleCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	NTSTATUS Status;
	ULONG Requestor;

	Requestor = IoGetRequestorProcessId(Irp);
	if(Irp->RequestorMode == KernelMode || !Requestor) {
		/* if the request didn't come from a process, allow it */
		Status = STATUS_SUCCESS;
		goto Exit;
	}

	if(!IsRequestorPermitted(Requestor)) {
		Status = STATUS_ACCESS_DENIED;
		goto Exit;
	}

	else {
		g_AuthorizedProcess = Requestor;
		Status = STATUS_SUCCESS;
	}

Exit:
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, 0);

	return STATUS_SUCCESS;
}

_Success_(NT_SUCCESS(return))
static NTSTATUS HandleClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	g_AuthorizedProcess = 0;

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, 0);

	return STATUS_SUCCESS;
}

_Success_(NT_SUCCESS(return))
static NTSTATUS HandleRead(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{

}

_Success_(NT_SUCCESS(return))
static NTSTATUS HandleIoctl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{

}

static VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	(VOID) IoDeleteSymbolicLink(&g_DosDeviceName);

	if(g_SteveDevice) {
		IoDeleteDevice(g_SteveDevice);
		g_SteveDevice = NULL;
	}
}

_Success_(NT_SUCCESS(return))
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status;

	DriverObject->DriverUnload = DriverUnload;

	/* Open and close handlers for managing Steve-Service's connection to Steve-Driver */
	DriverObject->MajorFunction[IRP_MJ_CREATE] = HandleCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = HandleClose;

	/* IRP_MJ_READ is used by Steve-Service to query new signatures */
	DriverObject->MajorFunction[IRP_MJ_READ] = HandleRead;

	/* IRP_MJ_DEVICE_CONTROL is used by Steve-Service to update the blacklist */
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleIoctl;

	Status = IoCreateDevice(
		DriverObject,
		0,
		&g_NtDeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		TRUE,
		&g_SteveDevice);
	ExitAndLogOnFailure(Status, IoCreateDevice(), Exit);

	Status = IoCreateSymbolicLink(
		&g_DosDeviceName,
		&g_NtDeviceName);
	ExitAndLogOnFailure(Status, IoCreateSymbolicLink(), Exit);

Exit:
	if(!NT_SUCCESS(Status) && g_SteveDevice) {
		IoDeleteDevice(g_SteveDevice);
		g_SteveDevice = NULL;
	}

	return Status;
}
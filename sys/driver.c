#include "regfltr.h"
#include "strsafe.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DeviceUnload;
LARGE_INTEGER g_cookie = {0};
PEX_CALLBACK_FUNCTION g_RegistryCallbackTable[MaxRegNtNotifyClass] = { 0 };
int notification;

_Dispatch_type_(IRP_MJ_CREATE)         DRIVER_DISPATCH DeviceCreate;
_Dispatch_type_(IRP_MJ_CLOSE)          DRIVER_DISPATCH DeviceClose;
_Dispatch_type_(IRP_MJ_CLEANUP)        DRIVER_DISPATCH DeviceCleanup;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH DeviceControl;

//
// Pointer to the device object used to register registry callbacks
//
PDEVICE_OBJECT g_DeviceObj;

//
// Registry callback version
//
ULONG g_MajorVersion;
ULONG g_MinorVersion;

//
// Set to TRUE if TM and RM were successfully created and the transaction
// callback was successfully enabled. 
//
BOOLEAN g_RMCreated;


//
// OS version globals initialized in driver entry 
//

BOOLEAN g_IsWin8OrGreater = FALSE;

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS Status;
    UNICODE_STRING NtDeviceName;
    UNICODE_STRING DosDevicesLinkName;
    UNICODE_STRING DeviceSDDLString;

    UNREFERENCED_PARAMETER(RegistryPath);

	notification = 0;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 
               DPFLTR_ERROR_LEVEL,
               "RegFltr: DriverEntry()\n");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 
               DPFLTR_ERROR_LEVEL,
               "RegFltr: Use ed nt!Kd_IHVDRIVER_Mask 8 to enable more detailed printouts\n");

    //
    // Create our device object.
    //

    RtlInitUnicodeString(&NtDeviceName, NT_DEVICE_NAME);
    RtlInitUnicodeString(&DeviceSDDLString, DEVICE_SDDL);

    Status = IoCreateDeviceSecure(
                            DriverObject,                 // pointer to driver object
                            0,                            // device extension size
                            &NtDeviceName,                // device name
                            FILE_DEVICE_UNKNOWN,          // device type
                            0,                            // device characteristics
                            TRUE,                         // not exclusive
                            &DeviceSDDLString,            // SDDL string specifying access
                            NULL,                         // device class guid
                            &g_DeviceObj);                // returned device object pointer

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Set dispatch routines.
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DeviceClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = DeviceCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload                         = DeviceUnload;

    //
    // Create a link in the Win32 namespace.
    //
    
    RtlInitUnicodeString(&DosDevicesLinkName, DOS_DEVICES_LINK_NAME);

    Status = IoCreateSymbolicLink(&DosDevicesLinkName, &NtDeviceName);

    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DriverObject->DeviceObject);
        return Status;
    }

    //
    // Get callback version.
    //

    CmGetCallbackVersion(&g_MajorVersion, &g_MinorVersion);
    InfoPrint("Callback version %u.%u", g_MajorVersion, g_MinorVersion);

    //
    // Some variations depend on knowing if the OS is win8 or above
    //
   
    //
    // Set up KTM resource manager and pass in RMCallback as our
    // callback routine.
    //
	////////////////////////////////////////////////////////
	g_RegistryCallbackTable[RegNtPreOpenKeyEx] = (PEX_CALLBACK_FUNCTION)RfPreOpenKeyEx;
	g_RegistryCallbackTable[RegNtPreDeleteKey] = (PEX_CALLBACK_FUNCTION)RfPreOpenKeyEx;
	g_RegistryCallbackTable[RegNtPreRenameKey] = (PEX_CALLBACK_FUNCTION)RfPreOpenKeyEx;
	UNICODE_STRING AltitudeString = RTL_CONSTANT_STRING(L"380000");
	NTSTATUS status = CmRegisterCallbackEx(RfRegistryCallback, &AltitudeString, DriverObject, NULL, &g_cookie, NULL);
	if (!NT_SUCCESS(status))
	{
		ErrorPrint("CmRegisterCallbackEx returned unexpected error status 0x%x.",status);
	}
	////////////////////////////////////////////////////////////
	Status = CreateKTMResourceManager(RMCallback, NULL);

	if (NT_SUCCESS(Status)) {
		g_RMCreated = TRUE;
	}

	//
	// Initialize the callback context list
	//

	InitializeListHead(&g_CallbackCtxListHead);
	ExInitializeFastMutex(&g_CallbackCtxListLock);
	g_NumCallbackCtxListEntries = 0;

    return STATUS_SUCCESS;
    
}



NTSTATUS
DeviceCreate (
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}



NTSTATUS
DeviceClose (
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}



NTSTATUS
DeviceCleanup (
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}



NTSTATUS
DeviceControl (
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION IrpStack;
    ULONG Ioctl;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    Status = STATUS_SUCCESS;

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    Ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;

    switch (Ioctl)
    {
	case IOCTL_WRITE_OBJ_INFO:
		Status = GetBufferFromApp(DeviceObject, Irp);
		break;
	case IOCTL_WRITE_NOTIF_INFO:
		Status = GetRequestNotification(DeviceObject, Irp);
		break;
    default:
        ErrorPrint("Unrecognized ioctl code 0x%x", Ioctl);
    }
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
    
}


VOID
DeviceUnload (
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING  DosDevicesLinkName;
	UNREFERENCED_PARAMETER(DriverObject);
	PAGED_CODE();
    //
    // Clean up the KTM data structures
    //
	/////////////////////////////////////////////////////////////
	//PAGED_CODE();

	NTSTATUS status = CmUnRegisterCallback(g_cookie);
	if (!NT_SUCCESS(status))
	{
		ErrorPrint("CmUnRegisterCallback returned unexpected error status 0x%x.",
			status);
	}
	//////////////////////////////////////////////////////
	if (notification == 1)
	{
		NTSTATUS remove = PsRemoveLoadImageNotifyRoutine(LoadImageCallback);
		if (!NT_SUCCESS(remove))
		{
			ErrorPrint("PsRemoveLoadImageNotifyRoutine returned unexpected error status 0x%x.", remove);
		}
		else {
			InfoPrint("PsRemoveLoadImageNotifyRoutine: notification remove.\n");
		}
	}

	DeleteKTMResourceManager();

	//
	// Delete the link from our device name to a name in the Win32 namespace.
	//

	RtlInitUnicodeString(&DosDevicesLinkName, DOS_DEVICES_LINK_NAME);
	IoDeleteSymbolicLink(&DosDevicesLinkName);

    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 
               DPFLTR_ERROR_LEVEL,
               "RegFltr: DeviceUnload\n");
}


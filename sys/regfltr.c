#include "regfltr.h"
#include "stdlib.h"
#include "stdio.h"
#define PR_LENGHT 128
struct
{
	char process[PR_LENGHT];
	char right[PR_LENGHT];

}right[10];
int num_process;
int num_proc;
char* rights;
LARGE_INTEGER g_cookie;
int notification;
NTSTATUS GetProcessImageName(HANDLE processId, PUNICODE_STRING ProcessImageName)
{
	NTSTATUS status;
	ULONG returnedLength;
	ULONG bufferLength;
	HANDLE hProcess=NULL;
	PVOID buffer;
	PEPROCESS eProcess;
	PUNICODE_STRING imageName;
	PAGED_CODE();
	status = PsLookupProcessByProcessId(processId, &eProcess);
	if (NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(eProcess, 0, NULL, 0, 0, KernelMode, &hProcess);
		if (NT_SUCCESS(status))
		{
		}
		else {

			DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
		}
		ObDereferenceObject(eProcess);
	}
	else {
		DbgPrint("PsLookupProcessByProcessId Failed: %08x\n", status);
	}
	if (NULL == ZwQueryInformationProcess) {
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		ZwQueryInformationProcess =
			(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

		if (NULL == ZwQueryInformationProcess) {
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
		}
	}
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		NULL, // buffer
		0, // buffer size
		&returnedLength);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		return status;
	}
	bufferLength = returnedLength - sizeof(UNICODE_STRING);
	if (ProcessImageName->MaximumLength < bufferLength)
	{
		ProcessImageName->MaximumLength = (USHORT)bufferLength;
		return STATUS_BUFFER_OVERFLOW;
	}
	buffer = ExAllocatePoolWithTag(NonPagedPool, returnedLength, 'uLT1');

	if (NULL == buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		buffer,
		returnedLength,
		&returnedLength);

	if (NT_SUCCESS(status))
	{
		imageName = (PUNICODE_STRING)buffer;
		RtlCopyUnicodeString(ProcessImageName, imageName);
	}
	ExFreePoolWithTag(buffer, 'uLT1');
	return status;
}
void LoadImageCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	NTSTATUS          status;
	UNICODE_STRING    fullFileName;
	HANDLE            fileHandle;
	IO_STATUS_BLOCK   iostatus;
	OBJECT_ATTRIBUTES oa;
	LARGE_INTEGER systemTime;
	LARGE_INTEGER localTime;
	TIME_FIELDS   timeFields;
	KeQuerySystemTime(&systemTime);
	ExSystemTimeToLocalTime(&systemTime, &localTime);
	RtlTimeToTimeFields(&localTime, &timeFields);
	char tmp[100];
	char proc[1024];
	RtlStringCbPrintfA(tmp, sizeof(tmp), "%2.2d:%2.2d:%2.2d %d\n", timeFields.Hour, timeFields.Minute,
		timeFields.Second, timeFields.Year);
	RtlStringCbPrintfA(proc, sizeof(proc), "name: %wZ, PID: %u, base: 0x%p, size: 0x%08x\n", 
		FullImageName, ProcessId, ImageInfo->ImageBase, ImageInfo->ImageSize);
	{
		strcat(tmp, proc);
		RtlInitUnicodeString(&fullFileName,
			L"\\??\\C:\\Users\\katr4\\Desktop\\info.txt");
		InitializeObjectAttributes(&oa,&fullFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		status = ZwCreateFile(&fileHandle,GENERIC_WRITE | SYNCHRONIZE, &oa, &iostatus, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE,
			FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
		if (NT_SUCCESS(status))
		{
			FILE_STANDARD_INFORMATION fileInfo;
			status =  ZwQueryInformationFile(fileHandle, &iostatus, &fileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
			ULONG len = strlen(tmp);
			if (NT_SUCCESS(status))
			{
				LARGE_INTEGER ByteOffset = fileInfo.EndOfFile;
				status = ZwWriteFile(fileHandle, NULL, NULL, NULL,&iostatus, tmp, len, &ByteOffset, NULL);
				if (!NT_SUCCESS(status) || iostatus.Information != len)
				{
					DbgPrint("Error on writing. Status = %x.", status);
				}
			}
			ZwClose(fileHandle);
		}
		else { DbgPrint("Error on open. Status = %x.", status); }
	}
	
}
NTSTATUS RfPreOpenKeyEx(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PREG_OPEN_KEY_INFORMATION CallbackData)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(Argument1);
		PUNICODE_STRING pKeyNameBeingOpened = CallbackData->CompleteName;
		char path[1024];
		NTSTATUS RtlPrint=RtlStringCbPrintfA(path, sizeof(path), "%wZ", pKeyNameBeingOpened);
		if (RtlPrint != STATUS_SUCCESS)
		{
			ErrorPrint("RtlStringCbPrintfA returned unexpected error status 0x%x.", RtlPrint);
			return STATUS_SUCCESS;
		}
		for (int r = 0; r < num_process; r++)
		{
			if (!strcmp(path, right[r].process))
			{
				if ((!strcmp(right[num_proc].right, "lowlevel") && (!strcmp(right[r].right, "mediumlevel") || !strcmp(right[r].right, "highlevel")))
					|| (!strcmp(right[num_proc].right, "mediumlevel") && (!strcmp(right[r].right, "highlevel")))|| (!strcmp(right[r].right, "protectedlevel")))
				{
					InfoPrint("Access for %wZ being denied!\n", pKeyNameBeingOpened);
					return STATUS_ACCESS_DENIED;
				}
				else 
				{
					InfoPrint("Access for %wZ being alloweed!\n", pKeyNameBeingOpened);
					return STATUS_SUCCESS;
				}
			}
		}

	return STATUS_SUCCESS;
}
NTSTATUS RfRegistryCallback(_In_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	HANDLE hProcess=PsGetCurrentProcessId();
	REG_NOTIFY_CLASS Operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;	
	if (Argument2 == NULL) 
	{ 
		ErrorPrint("\tCallback: Argument 2 unexpectedly 0. Filter will abort and return success.");
		return STATUS_SUCCESS; 
	}
	UNICODE_STRING fullPath;
	char ProcessName[1024];
	fullPath.Length = 0;
	fullPath.MaximumLength = 520;
	fullPath.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, 520, 'uUT1');
    GetProcessImageName(hProcess, &fullPath);
	RtlStringCbPrintfA(ProcessName, sizeof(ProcessName), "%S", fullPath.Buffer);
	for (int r = 0; r < num_process; r++)
	{
		if (strstr(ProcessName, right[r].process)!=NULL)
		{
			num_proc = r;
			ExFreePoolWithTag(fullPath.Buffer, 'uUT1');
			if (!g_RegistryCallbackTable[Operation])
			{
				return STATUS_SUCCESS;
			}
			return g_RegistryCallbackTable[Operation](CallbackContext, Argument1, Argument2);
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS  
RMCallback(
    _In_    PKENLISTMENT   EnlistmentObject,
    _In_    PVOID          RMContext,    
    _In_    PVOID          TransactionContext,    
    _In_    ULONG          TransactionNotification,    
    _Inout_ PLARGE_INTEGER TMVirtualClock,
    _In_    ULONG          ArgumentLength,
    _In_    PVOID          Argument
    )
/*++

Routine Description:

    This callback recieves transaction notifications.

Arguments:

    EnlistmentObject - Enlistment that this notification is about

    RMContext - The value specified for the RMKey parameter of the 
        TmEnableCallbacks routine

    TransactionContext - Value specified for the EnlistmentKey parameter 
        of the ZwCreateEnlistment routine

    TransactionNotification - Type of notification 

    TmVirtualClock - Pointer to virtual clock value of time when KTM prepared
        the notification.

    ArgumentLength - Length in bytes of the Argument buffer. 

    Argument - Buffer containing notification-spcefic arguments. 

Return Value:

    Always STATUS_SUCCESS

--*/
{
    PRMCALLBACK_CONTEXT Context = (PRMCALLBACK_CONTEXT) TransactionContext;
    NTSTATUS Status = STATUS_SUCCESS;
    
    UNREFERENCED_PARAMETER(EnlistmentObject);
    UNREFERENCED_PARAMETER(RMContext);
    UNREFERENCED_PARAMETER(ArgumentLength);
    UNREFERENCED_PARAMETER(Argument);

    //
    // Transaction notifications are bit masks. Record which one(s)
    // this callback received.
    //
    
    Context->Notification |= TransactionNotification;

    //
    // Call the Tm*Complete methods to inform KTM that we have completed
    // processing. (Note: It is possible to use the Zw version of
    // these APIs as well).
    //
    // Make sure that all the notifications you request are handled. The
    // type of notification this routine gets is specified when you enlist
    // in a transaction.
    //
    
    switch(TransactionNotification) {
        case TRANSACTION_NOTIFY_COMMIT:         
            Status = TmCommitComplete(EnlistmentObject,
                                      TMVirtualClock);
            break;
        case TRANSACTION_NOTIFY_ROLLBACK:
            Status = TmRollbackComplete(EnlistmentObject,
                                        TMVirtualClock);
            break;
        default:
            ErrorPrint("Unsupported Transaction Notification: %x", 
                       TransactionNotification);
            NT_ASSERT(FALSE);
    }
    
    //
    // It is safe to close the enlistment handle here.
    // Closing it before the transaction aborts or commits will abort 
    // the transaction.
    //
    
    if (Context->Enlistment != NULL) {
        ZwClose(Context->Enlistment);
        Context->Enlistment = NULL;
    }

    return Status;

}


NTSTATUS
GetBufferFromApp(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION IrpStack;
	ULONG OutputBufferLength;
	char buffer[256];
	
	UNREFERENCED_PARAMETER(DeviceObject);
	IrpStack = IoGetCurrentIrpStackLocation(Irp);

	OutputBufferLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	rights=(char*)Irp->AssociatedIrp.SystemBuffer;
	InfoPrint("DEBUG_KATE: %s ", rights);
	int i = 0, j = 0, h = 0;
	while (rights[i] != '}')
	{
		while (rights[i] != ':')
		{
			if (rights[i] != '"' && rights[i] != '{' && rights[i] != ' ')
			{
				while (rights[i] != '"')
				{
					right[j].process[h] = rights[i];
					i++; h++;
				}
				right[j].process[h] = '\0';
				i++;
			}
			if (rights[i] == ':') { h = 0; i++; break; }
			h = 0; i++;
		}

		while (rights[i] != ',' || rights[i] != ' ')
		{
			if (rights[i] != '"' && rights[i] != ':' && rights[i] != ',')
			{
				while (rights[i] != '"')
				{
					right[j].right[h] = rights[i];
					i++; h++;
				}
				right[j].right[h] = '\0';
				i++;
			}
			if (rights[i] == ',' || rights[i] == '}' || rights[i] == ' ') { h = 0; i++; j++; break; }
			h = 0;
			i++;
		}
	}
	num_process = j;
	/*for (int k = 0; k < num_process; k++)
	{
		InfoPrint("%s %s",  right[k].process, right[k].right);
	}*/
	if (OutputBufferLength < sizeof(buffer)) {
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}
	Irp->IoStatus.Information = sizeof(buffer);

Exit:

	if (!NT_SUCCESS(Status)) {
		ErrorPrint("FromApp failed. Status 0x%x", Status);
	}
	else {
		InfoPrint("FromAppSucced");
	}

	return Status;
}

NTSTATUS GetRequestNotification(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION IrpStack;
	ULONG OutputBufferLength;
	char buffer[2];
	char *buf;

	UNREFERENCED_PARAMETER(DeviceObject);
	IrpStack = IoGetCurrentIrpStackLocation(Irp);

	OutputBufferLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	buf = (char*)Irp->AssociatedIrp.SystemBuffer;
	InfoPrint("%s", buf);
	if (buf[0]=='Y'&& notification==0)
	{
		notification = 1;
		NTSTATUS ntStatus = PsSetLoadImageNotifyRoutine(LoadImageCallback);
		if (!NT_SUCCESS(ntStatus))
		{
			ErrorPrint("PsSetLoadImageNotifyRoutine returned unexpected error status 0x%x.", ntStatus);
		}
		else {
			InfoPrint("PsSetLoadImageNotifyRoutine: notification set.\n");
		}
	}
	else if (buf[0] == 'N' && notification == 1)
	{ 
	notification = 0;
	NTSTATUS remove = PsRemoveLoadImageNotifyRoutine(LoadImageCallback);
	if (!NT_SUCCESS(remove))
	{
		ErrorPrint("PsRemoveLoadImageNotifyRoutine returned unexpected error status 0x%x.", remove);
	}
	else {
		InfoPrint("PsRemoveLoadImageNotifyRoutine: notification remove.\n");
	}
	}
	if (OutputBufferLength < sizeof(buffer)) {
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}
	Irp->IoStatus.Information = sizeof(buffer);

Exit:

	if (!NT_SUCCESS(Status)) {
		ErrorPrint("FromApp failed. Status 0x%x", Status);
	}
	else {
		InfoPrint("FromAppSucced");
	}

	return Status;
}
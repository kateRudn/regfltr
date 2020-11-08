#include "regctrl.h"
#include "winioctl.h"
#include "stdlib.h"
#include "strsafe.h"

#define _CRT_SECURE_NO_WARNINGS

HANDLE g_Driver;

char access(char buf[])
{
	WCHAR InBuf[256] = { 0 };
	DWORD dwBuffLen = sizeof(InBuf);

	if (RegGetValueA(HKEY_CURRENT_USER, "Access", "Rights", RRF_RT_ANY|RRF_SUBKEY_WOW6464KEY, NULL, InBuf, &dwBuffLen) != ERROR_SUCCESS)
	{
		printf("Read:error!\n");
		UtilUnloadDriver(g_Driver, NULL, DRIVER_NAME);
		system("pause");
		return 3;
	};
	int i = 0;
	while (((char*)InBuf)[i] != '\0')
	{
		buf[i] = ((char*)InBuf)[i];
		i++;
	}
	buf[i] = '\0';

	return *buf;
}
VOID __cdecl
wmain(
	_In_ ULONG argc,
	_In_reads_(argc) LPCWSTR argv[]
)
{

	BOOL Result;

	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	Result = UtilLoadDriver(DRIVER_NAME,
		DRIVER_NAME_WITH_EXT,
		WIN32_DEVICE_NAME,
		&g_Driver);

	if (Result != TRUE) {
		ErrorPrint("UtilLoadDriver failed, exiting...");
		exit(1);
	}
	else {
		printf("The driver is loaded.\n");
	}
	typedef struct {
		char buf[256];
	} RMD_IN;
	typedef struct {
		char Name[256];
	} RMD_OUT;

	typedef struct {
		char buf[2];
	} NOTIF_IN;
	typedef struct {
		char buf[2];
	} NOTIF_OUT;

	RMD_IN rmd_in;
	RMD_OUT rmd_out;

	NOTIF_IN notif_in;
	NOTIF_OUT notif_out;

    access(rmd_in.buf);
	ULONG LBytesRecvd;
	ULONG LBytesRecv;
	Result = DeviceIoControl(g_Driver, IOCTL_WRITE_OBJ_INFO, &rmd_in, sizeof(RMD_IN), &rmd_out, sizeof(RMD_OUT), &LBytesRecvd, NULL);
	if (Result != TRUE) {
		ErrorPrint("DeviceIoControl for IOCTL_WRITE_OBJ_INFO failed, error %d\n", GetLastError());
	}
	else {
		printf("Rules successfully passed.");
	}
	while (1)
	{
		again:
		printf("\nNotification: Y or N?\n//if you want to unload the driver and exit, enter 0.\n");
		scanf("%s", &notif_in.buf);
		notif_in.buf[1] = '\0';
		if (notif_in.buf[0] != '0' && notif_in.buf[0] != 'Y' && notif_in.buf[0] != 'N') { goto again; }
		else if (notif_in.buf[0] == '0') { break; }
		else if (notif_in.buf[0] == 'Y') { printf("Notifier is set.\n"); }
		else if (notif_in.buf[0] == 'N') { printf("Notifier is unset.\n"); }
		Result = DeviceIoControl(g_Driver, IOCTL_WRITE_NOTIF_INFO, &notif_in, sizeof(NOTIF_IN), &notif_out, sizeof(NOTIF_OUT), &LBytesRecv, NULL);
		if (Result != TRUE) {
			ErrorPrint("DeviceIoControl for IOCTL_WRITE_NOTIF_INFO failed, error %d\n", GetLastError());
		}
	}
	UtilUnloadDriver(g_Driver, NULL, DRIVER_NAME);
	printf("The driver is unloaded.\n");
	system("pause");
}





#pragma once

#include <windows.h>
#include <winioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <devioctl.h>
#include <tchar.h>
#include <strsafe.h>
#include "common.h"

#define ARRAY_LENGTH(array)    (sizeof (array) / sizeof (array[0]))

#define InfoPrint(str, ...)                 \
    printf(##str"\n",                       \
            __VA_ARGS__)

#define ErrorPrint(str, ...)                \
    printf("ERROR: %u: "##str"\n",          \
            __LINE__,                       \
            __VA_ARGS__)

extern HANDLE g_Driver;


char access(char buf[]);

//
// Utility routines to load and unload the driver
//

BOOL 
UtilLoadDriver(
    _In_ LPTSTR szDriverNameNoExt,
    _In_ LPTSTR szDriverNameWithExt,
    _In_ LPTSTR szWin32DeviceName,
    _Out_ HANDLE *pDriver
    );

BOOL 
UtilUnloadDriver(
    _In_ HANDLE hDriver, 
    _In_opt_ SC_HANDLE hSCM, 
    _In_ LPTSTR szDriverNameNoExt
    );



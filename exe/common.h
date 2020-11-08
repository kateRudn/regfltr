
#pragma once

//
// Driver and device names.
//

#define DRIVER_NAME             L"RegFltr"
#define DRIVER_NAME_WITH_EXT    L"RegFltr.sys"

#define NT_DEVICE_NAME          L"\\Device\\RegFltr"
#define DOS_DEVICES_LINK_NAME   L"\\DosDevices\\RegFltr"
#define WIN32_DEVICE_NAME       L"\\\\.\\RegFltr"

//
// SDDL string used when creating the device. This string
// limits access to this driver to system and admins only.
//

#define DEVICE_SDDL             L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

//
// IOCTLs exposed by the driver.
//

#define IOCTL_WRITE_OBJ_INFO           CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 0), METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_NOTIF_INFO         CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 1), METHOD_BUFFERED, FILE_ANY_ACCESS)
//
// Common definitions
// 



#define MAX_ALTITUDE_BUFFER_LENGTH 10

//
// List of callback modes
//
typedef enum _CALLBACK_MODE {
    CALLBACK_MODE_PRE_NOTIFICATION_BLOCK,
    CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
    CALLBACK_MODE_POST_NOTIFICATION_OVERRIDE_ERROR,
    CALLBACK_MODE_POST_NOTIFICATION_OVERRIDE_SUCCESS,
    CALLBACK_MODE_TRANSACTION_REPLAY,
    CALLBACK_MODE_TRANSACTION_ENLIST,
    CALLBACK_MODE_MULTIPLE_ALTITUDE_BLOCK_DURING_PRE,
    CALLBACK_MODE_MULTIPLE_ALTITUDE_INTERNAL_INVOCATION,
    CALLBACK_MODE_MULTIPLE_ALTITUDE_MONITOR,
    CALLBACK_MODE_SET_CALL_CONTEXT,
    CALLBACK_MODE_SET_OBJECT_CONTEXT,
    CALLBACK_MODE_CAPTURE,
    CALLBACK_MODE_VERSION_BUGCHECK,
    CALLBACK_MODE_VERSION_CREATE_OPEN_V1,
} CALLBACK_MODE;


//
// List of kernel mode samples
//
typedef enum _KERNELMODE_SAMPLE {
    KERNELMODE_SAMPLE_PRE_NOTIFICATION_BLOCK = 0,
    KERNELMODE_SAMPLE_PRE_NOTIFICATION_BYPASS,
    KERNELMODE_SAMPLE_POST_NOTIFICATION_OVERRIDE_ERROR,
    KERNELMODE_SAMPLE_POST_NOTIFICATION_OVERRIDE_SUCCESS,
    KERNELMODE_SAMPLE_TRANSACTION_REPLAY,
    KERNELMODE_SAMPLE_TRANSACTION_ENLIST,
    KERNELMODE_SAMPLE_MULTIPLE_ALTITUDE_BLOCK_DURING_PRE,
    KERNELMODE_SAMPLE_MULTIPLE_ALTITUDE_INTERNAL_INVOCATION,
    KERNELMODE_SAMPLE_SET_CALL_CONTEXT,
    KERNELMODE_SAMPLE_SET_OBJECT_CONTEXT,
    KERNELMODE_SAMPLE_VERSION_CREATE_OPEN_V1,
    MAX_KERNELMODE_SAMPLES
} KERNELMODE_SAMPLE;


//
// Input and output data structures for the various driver IOCTLs
//

typedef struct _REGISTER_CALLBACK_INPUT {

    //
    // specifies the callback mode for the callback context
    //
    CALLBACK_MODE CallbackMode;

    //
    // specifies the altitude to register the callback at
    //
    WCHAR Altitude[MAX_ALTITUDE_BUFFER_LENGTH];
    
} REGISTER_CALLBACK_INPUT, *PREGISTER_CALLBACK_INPUT;

typedef struct _REGISTER_CALLBACK_OUTPUT {

    //
    // receives the cookie value from registering the callback
    //
    LARGE_INTEGER Cookie;

} REGISTER_CALLBACK_OUTPUT, *PREGISTER_CALLBACK_OUTPUT;


typedef struct _UNREGISTER_CALLBACK_INPUT {
    //
    // specifies the cookie value for the callback
    //
    LARGE_INTEGER Cookie;

} UNREGISTER_CALLBACK_INPUT, *PUNREGISTER_CALLBACK_INPUT;


typedef struct _GET_CALLBACK_VERSION_OUTPUT {

    //
    // Receives the version number of the registry callback
    //
    ULONG MajorVersion;
    ULONG MinorVersion;
    
} GET_CALLBACK_VERSION_OUTPUT, *PGET_CALLBACK_VERSION_OUTPUT;


typedef struct _DO_KERNELMODE_SAMPLES_OUTPUT {

    //
    // An array that receives the results of the kernel mode samples.
    //
    BOOLEAN SampleResults[MAX_KERNELMODE_SAMPLES];
    
} DO_KERNELMODE_SAMPLES_OUTPUT, *PDO_KERNELMODE_SAMPLES_OUTPUT;

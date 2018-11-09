/*++

Module Name:

    minifilterScanner.c

Abstract:

    This is the main module of the minifilterScanner miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>



#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

///////////////
const PWSTR ScannerPortName = L"\\ScannerPort";

#define SCANNER_READ_BUFFER_SIZE   1024

typedef struct _SCANNER_NOTIFICATION {

	ULONG BytesToScan;
	ULONG Reserved;             // for quad-word alignement of the Contents structure
	UCHAR Contents[SCANNER_READ_BUFFER_SIZE];

} SCANNER_NOTIFICATION, *PSCANNER_NOTIFICATION;

typedef struct _SCANNER_REPLY {

	BOOLEAN SafeToOpen;

} SCANNER_REPLY, *PSCANNER_REPLY;

////////////////
//PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

typedef struct _SCANNER_DATA {

	//
	//  The object that identifies this driver.
	//

	PDRIVER_OBJECT DriverObject;

	//
	//  The filter handle that results from a call to
	//  FltRegisterFilter.
	//

	PFLT_FILTER Filter;

	//
	//  Listens for incoming connections
	//

	PFLT_PORT ServerPort;

	//
	//  User process that connected to the port
	//

	PEPROCESS UserProcess;

	//
	//  Client port for a connection to user-mode
	//

	PFLT_PORT ClientPort;

} SCANNER_DATA, *PSCANNER_DATA;
//
//  Structure that contains all the global data structures
//  used throughout the scanner.
//

SCANNER_DATA ScannerData;
//
//  This is a static list of file name extensions files we are interested in scanning
//
typedef struct _SCANNER_STREAM_HANDLE_CONTEXT {

	BOOLEAN RescanRequired;

} SCANNER_STREAM_HANDLE_CONTEXT, *PSCANNER_STREAM_HANDLE_CONTEXT;

#pragma warning(push)
#pragma warning(disable:4200) // disable warnings for structures with zero length arrays.

typedef struct _SCANNER_CREATE_PARAMS {

	WCHAR String[0];

} SCANNER_CREATE_PARAMS, *PSCANNER_CREATE_PARAMS;
#pragma warning(pop)
const UNICODE_STRING ScannerExtensionsToScan[] =
{
	RTL_CONSTANT_STRING(L"doc"),
	RTL_CONSTANT_STRING(L"txt"),
	RTL_CONSTANT_STRING(L"bat"),
	RTL_CONSTANT_STRING(L"cmd"),
	RTL_CONSTANT_STRING(L"inf"),
	/*RTL_CONSTANT_STRING( L"ini"),   Removed, to much usage*/
	{ 0, 0, NULL }
};

/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
minifilterScannerInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
minifilterScannerInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
minifilterScannerInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
minifilterScannerUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
minifilterScannerInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
minifilterScannerPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
minifilterScannerOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
minifilterScannerPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
minifilterScannerPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
minifilterScannerDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

NTSTATUS
ScannerPortConnect(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionCookie
	);

VOID
ScannerPortDisconnect(
	__in_opt PVOID ConnectionCookie
	);

NTSTATUS ScannerPortMsgFromClient(PVOID PortCookie,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength,
	PULONG ReturnOutputbufLength);

FLT_PREOP_CALLBACK_STATUS
ScannerPreWrite(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
ScannerPreCleanup(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
ScannerPreCreate(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
ScannerPostCreate(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__in_opt PVOID CompletionContext,
__in FLT_POST_OPERATION_FLAGS Flags
);

NTSTATUS
ScannerpScanFileInUserMode(
__in PFLT_INSTANCE Instance,
__in PFILE_OBJECT FileObject,
__out PBOOLEAN SafeToOpen
);


//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, minifilterScannerUnload)
#pragma alloc_text(PAGE, minifilterScannerInstanceQueryTeardown)
#pragma alloc_text(PAGE, minifilterScannerInstanceSetup)
#pragma alloc_text(PAGE, minifilterScannerInstanceTeardownStart)
#pragma alloc_text(PAGE, minifilterScannerInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
	  ScannerPreCreate,
	  ScannerPostCreate },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_CLOSE,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_READ,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_WRITE,
      0,
	  ScannerPreWrite,
      NULL },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_SET_EA,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      minifilterScannerPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_CLEANUP,
      0,
	  ScannerPreCleanup,
      NULL },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_PNP,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      minifilterScannerPreOperation,
      minifilterScannerPostOperation },

    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_STREAMHANDLE_CONTEXT,
	0,
	NULL,
	sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
	'chBS' },

	{ FLT_CONTEXT_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

	ContextRegistration,                               //  Context
    Callbacks,                          //  Operation callbacks

    minifilterScannerUnload,                           //  MiniFilterUnload  ScannerUnload
    minifilterScannerInstanceSetup,                    //  InstanceSetup  ScannerInstanceSetup
    minifilterScannerInstanceQueryTeardown,            //  InstanceQueryTeardown  ScannerQueryTeardown
    minifilterScannerInstanceTeardownStart,            //  InstanceTeardownStart
    minifilterScannerInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
minifilterScannerInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("minifilterScanner!minifilterScannerInstanceSetup: Entered\n") );
	ASSERT(FltObjects->Filter == ScannerData.Filter);

	//
	//  Don't attach to network volumes.
	//

	if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {

		return STATUS_FLT_DO_NOT_ATTACH;
	}
    return STATUS_SUCCESS;
}


NTSTATUS
minifilterScannerInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("minifilterScanner!minifilterScannerInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
minifilterScannerInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("minifilterScanner!minifilterScannerInstanceTeardownStart: Entered\n") );
}


VOID
minifilterScannerInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("minifilterScanner!minifilterScannerInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR sd;
	
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("minifilterScanner!DriverEntry: Entered\n") );
	
	//DbgBreakPoint();
    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
								&ScannerData.Filter);

    FLT_ASSERT( NT_SUCCESS( status ) );
	////
	//
	//  Create a communication port.
	//

	RtlInitUnicodeString(&uniString, ScannerPortName);

	//
	//  We secure the port so only ADMINs & SYSTEM can acecss it.
	//

	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

	if (NT_SUCCESS(status))
	{

		InitializeObjectAttributes(&oa,
			&uniString,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			sd);

		status = FltCreateCommunicationPort(ScannerData.Filter,
			&ScannerData.ServerPort,
			&oa,
			NULL,
			ScannerPortConnect,
			ScannerPortDisconnect,
			ScannerPortMsgFromClient,//×÷Òµ£¬²¹³ä
			1);
		//
		//  Free the security descriptor in all cases. It is not needed once
		//  the call to FltCreateCommunicationPort() is made.
		//

		FltFreeSecurityDescriptor(sd);

		////
		if (NT_SUCCESS(status))
		{

			//
			//  Start filtering i/o
			//

			status = FltStartFiltering(ScannerData.Filter);

			if (NT_SUCCESS(status))
			{
				return STATUS_SUCCESS;
			}
			FltCloseCommunicationPort(ScannerData.ServerPort);
		}
	}

	////
	FltUnregisterFilter(ScannerData.Filter);

    return status;
}


NTSTATUS
ScannerPortConnect(
__in PFLT_PORT ClientPort,
__in_opt PVOID ServerPortCookie,
__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
__in ULONG SizeOfContext,
__deref_out_opt PVOID *ConnectionCookie
)
/*++

Routine Description

This is called when user-mode connects to the server port - to establish a
connection

Arguments

ClientPort - This is the client connection port that will be used to
send messages from the filter

ServerPortCookie - The context associated with this port when the
minifilter created this port.

ConnectionContext - Context from entity connecting to this port (most likely
your user mode service)

SizeofContext - Size of ConnectionContext in bytes

ConnectionCookie - Context to be passed to the port disconnect routine.

Return Value

STATUS_SUCCESS - to accept the connection

--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	ASSERT(ScannerData.ClientPort == NULL);
	ASSERT(ScannerData.UserProcess == NULL);

	//
	//  Set the user process and port.
	//

	ScannerData.UserProcess = PsGetCurrentProcess();
	ScannerData.ClientPort = ClientPort;

	DbgPrint("!!! scanner.sys --- connected, port=0x%p\n", ClientPort);

	return STATUS_SUCCESS;
}

VOID
ScannerPortDisconnect(
__in_opt PVOID ConnectionCookie
)
/*++

Routine Description

This is called when the connection is torn-down. We use it to close our
handle to the connection

Arguments

ConnectionCookie - Context from the port connect routine

Return value

None

--*/
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	DbgPrint("!!! scanner.sys --- disconnected, port=0x%p\n", ScannerData.ClientPort);

	//
	//  Close our handle to the connection: note, since we limited max connections to 1,
	//  another connect will not be allowed until we return from the disconnect routine.
	//

	FltCloseClientPort(ScannerData.Filter, &ScannerData.ClientPort);

	//
	//  Reset the user-process field.
	//

	ScannerData.UserProcess = NULL;
}

NTSTATUS ScannerPortMsgFromClient(PVOID PortCookie, 
	PVOID InputBuffer, 
	ULONG InputBufferLength, 
	PVOID OutputBuffer, 
	ULONG OutputBufferLength, 
	PULONG ReturnOutputbufLength )
{
	__try
	{
		ProbeForRead(InputBuffer, InputBufferLength, sizeof(ULONG));
		//get inputbuf
		//dosomething
		DbgPrint("%S", InputBuffer);
		ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(ULONG));
		//copy result to outputbuf
		RtlCopyMemory(OutputBuffer, InputBuffer, OutputBufferLength);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_NOT_IMPLEMENTED;
	}
	return STATUS_SUCCESS;
}

NTSTATUS
minifilterScannerUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("minifilterScanner!minifilterScannerUnload: Entered\n") );


	FltCloseCommunicationPort(ScannerData.ServerPort);

	FltUnregisterFilter(ScannerData.Filter);

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
ScannerPreCreate(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
)
/*++

Routine Description:

Pre create callback.  We need to remember whether this file has been
opened for write access.  If it has, we'll want to rescan it in cleanup.
This scheme results in extra scans in at least two cases:
-- if the create fails (perhaps for access denied)
-- the file is opened for write access but never actually written to
The assumption is that writes are more common than creates, and checking
or setting the context in the write path would be less efficient than
taking a good guess before the create.

Arguments:

Data - The structure which describes the operation parameters.

FltObject - The structure which describes the objects affected by this
operation.

CompletionContext - Output parameter which can be used to pass a context
from this pre-create callback to the post-create callback.

Return Value:

FLT_PREOP_SUCCESS_WITH_CALLBACK - If this is not our user-mode process.
FLT_PREOP_SUCCESS_NO_CALLBACK - All other threads.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	//
	//  See if this create is being done by our user process.
	//

	if (IoThreadToProcess(Data->Thread) == ScannerData.UserProcess) {

		DbgPrint("!!! scanner.sys -- allowing create for trusted process \n");

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

BOOLEAN
ScannerpCheckExtension(
__in PUNICODE_STRING Extension
)
/*++

Routine Description:

Checks if this file name extension is something we are interested in

Arguments

Extension - Pointer to the file name extension

Return Value

TRUE - Yes we are interested
FALSE - No
--*/
{
	const UNICODE_STRING *ext;

	if (Extension->Length == 0) {

		return FALSE;
	}

	//
	//  Check if it matches any one of our static extension list
	//

	ext = ScannerExtensionsToScan;

	while (ext->Buffer != NULL) {

		if (RtlCompareUnicodeString(Extension, ext, TRUE) == 0) {

			//
			//  A match. We are interested in this file
			//

			return TRUE;
		}
		ext++;
	}

	return FALSE;
}

FLT_POSTOP_CALLBACK_STATUS
ScannerPostCreate(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__in_opt PVOID CompletionContext,
__in FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

Post create callback.  We can't scan the file until after the create has
gone to the filesystem, since otherwise the filesystem wouldn't be ready
to read the file for us.

Arguments:

Data - The structure which describes the operation parameters.

FltObject - The structure which describes the objects affected by this
operation.

CompletionContext - The operation context passed fron the pre-create
callback.

Flags - Flags to say why we are getting this post-operation callback.

Return Value:

FLT_POSTOP_FINISHED_PROCESSING - ok to open the file or we wish to deny
access to this file, hence undo the open

--*/
{
	PSCANNER_STREAM_HANDLE_CONTEXT scannerContext;
	FLT_POSTOP_CALLBACK_STATUS returnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PFLT_FILE_NAME_INFORMATION nameInfo;
	NTSTATUS status;
	BOOLEAN safeToOpen, scanFile;

	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	//
	//  If this create was failing anyway, don't bother scanning now.
	//

	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		(STATUS_REPARSE == Data->IoStatus.Status)) {

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	//
	//  Check if we are interested in this file.
	//

	status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_DEFAULT,
		&nameInfo);

	if (!NT_SUCCESS(status)) {

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	FltParseFileNameInformation(nameInfo);

	//
	//  Check if the extension matches the list of extensions we are interested in
	//

	scanFile = ScannerpCheckExtension(&nameInfo->Extension);

	//
	//  Release file name info, we're done with it
	//

	FltReleaseFileNameInformation(nameInfo);

	if (!scanFile) {

		//
		//  Not an extension we are interested in
		//

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	(VOID)ScannerpScanFileInUserMode(FltObjects->Instance,
		FltObjects->FileObject,
		&safeToOpen);

	if (!safeToOpen) {

		//
		//  Ask the filter manager to undo the create.
		//

		DbgPrint("!!! scanner.sys -- foul language detected in postcreate !!!\n");

		DbgPrint("!!! scanner.sys -- undoing create \n");

		FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);

		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;

		returnStatus = FLT_POSTOP_FINISHED_PROCESSING;

	}
	else if (FltObjects->FileObject->WriteAccess) {

		//
		//
		//  The create has requested write access, mark to rescan the file.
		//  Allocate the context.
		//

		status = FltAllocateContext(ScannerData.Filter,
			FLT_STREAMHANDLE_CONTEXT,//file_object
			sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
			PagedPool,
			&scannerContext);

		if (NT_SUCCESS(status)) {

			//
			//  Set the handle context.
			//

			scannerContext->RescanRequired = TRUE;

			(VOID)FltSetStreamHandleContext(FltObjects->Instance,
				FltObjects->FileObject,
				FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
				scannerContext,
				NULL);

			//
			//  Normally we would check the results of FltSetStreamHandleContext
			//  for a variety of error cases. However, The only error status 
			//  that could be returned, in this case, would tell us that
			//  contexts are not supported.  Even if we got this error,
			//  we just want to release the context now and that will free
			//  this memory if it was not successfully set.
			//

			//
			//  Release our reference on the context (the set adds a reference)
			//

			FltReleaseContext(scannerContext);
		}
	}

	return returnStatus;
}

FLT_PREOP_CALLBACK_STATUS
ScannerPreCleanup(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
)
/*++

Routine Description:

Pre cleanup callback.  If this file was opened for write access, we want
to rescan it now.

Arguments:

Data - The structure which describes the operation parameters.

FltObject - The structure which describes the objects affected by this
operation.

CompletionContext - Output parameter which can be used to pass a context
from this pre-cleanup callback to the post-cleanup callback.

Return Value:

Always FLT_PREOP_SUCCESS_NO_CALLBACK.

--*/
{
	NTSTATUS status;
	PSCANNER_STREAM_HANDLE_CONTEXT context;
	BOOLEAN safe;

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(CompletionContext);

	status = FltGetStreamHandleContext(FltObjects->Instance,
		FltObjects->FileObject,
		&context);

	if (NT_SUCCESS(status)) {

		if (context->RescanRequired) {//Ð´¹Ø±Õ

			(VOID)ScannerpScanFileInUserMode(FltObjects->Instance,
				FltObjects->FileObject,
				&safe);

			if (!safe) {

				DbgPrint("!!! scanner.sys -- foul language detected in precleanup !!!\n");
			}
		}

		FltReleaseContext(context);
	}


	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
ScannerPreWrite(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
)
/*++

Routine Description:

Pre write callback.  We want to scan what's being written now.

Arguments:

Data - The structure which describes the operation parameters.

FltObject - The structure which describes the objects affected by this
operation.

CompletionContext - Output parameter which can be used to pass a context
from this pre-write callback to the post-write callback.

Return Value:

Always FLT_PREOP_SUCCESS_NO_CALLBACK.

--*/
{
	FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	NTSTATUS status;
	PSCANNER_NOTIFICATION notification = NULL;
	PSCANNER_STREAM_HANDLE_CONTEXT context = NULL;
	ULONG replyLength;
	BOOLEAN safe = TRUE;
	PUCHAR buffer;

	UNREFERENCED_PARAMETER(CompletionContext);

	//
	//  If not client port just ignore this write.
	//

	if (ScannerData.ClientPort == NULL) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	status = FltGetStreamHandleContext(FltObjects->Instance,
		FltObjects->FileObject,
		&context);

	if (!NT_SUCCESS(status)) {

		//
		//  We are not interested in this file
		//

		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	}

	//
	//  Use try-finally to cleanup
	//

	try {

		//
		//  Pass the contents of the buffer to user mode.
		//

		if (Data->Iopb->Parameters.Write.Length != 0) {

			//
			//  Get the users buffer address.  If there is a MDL defined, use
			//  it.  If not use the given buffer address.
			//

			if (Data->Iopb->Parameters.Write.MdlAddress != NULL) {

				buffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress,
					NormalPagePriority);

				//
				//  If we have a MDL but could not get and address, we ran out
				//  of memory, report the correct error
				//

				if (buffer == NULL) {

					Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					Data->IoStatus.Information = 0;
					returnStatus = FLT_PREOP_COMPLETE;
					leave;
				}

			}
			else {

				//
				//  Use the users buffer
				//

				buffer = Data->Iopb->Parameters.Write.WriteBuffer;
			}

			//
			//  In a production-level filter, we would actually let user mode scan the file directly.
			//  Allocating & freeing huge amounts of non-paged pool like this is not very good for system perf.
			//  This is just a sample!
			//

			notification = ExAllocatePoolWithTag(NonPagedPool,
				sizeof(SCANNER_NOTIFICATION),
				'nacS');
			if (notification == NULL) {

				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				returnStatus = FLT_PREOP_COMPLETE;
				leave;
			}

			notification->BytesToScan = min(Data->Iopb->Parameters.Write.Length, SCANNER_READ_BUFFER_SIZE);

			//
			//  The buffer can be a raw user buffer. Protect access to it
			//

			try  {

				RtlCopyMemory(&notification->Contents,
					buffer,
					notification->BytesToScan);

			} except(EXCEPTION_EXECUTE_HANDLER) {

				//
				//  Error accessing buffer. Complete i/o with failure
				//

				Data->IoStatus.Status = GetExceptionCode();
				Data->IoStatus.Information = 0;
				returnStatus = FLT_PREOP_COMPLETE;
				leave;
			}

			//
			//  Send message to user mode to indicate it should scan the buffer.
			//  We don't have to synchronize between the send and close of the handle
			//  as FltSendMessage takes care of that.
			//

			replyLength = sizeof(SCANNER_REPLY);

			status = FltSendMessage(ScannerData.Filter,
				&ScannerData.ClientPort,
				notification,
				sizeof(SCANNER_NOTIFICATION),
				notification,
				&replyLength,
				NULL);

			if (STATUS_SUCCESS == status) {

				safe = ((PSCANNER_REPLY)notification)->SafeToOpen;

			}
			else {

				//
				//  Couldn't send message. This sample will let the i/o through.
				//

				DbgPrint("!!! scanner.sys --- couldn't send message to user-mode to scan file, status 0x%X\n", status);
			}
		}

		if (!safe) {

			//
			//  Block this write if not paging i/o (as a result of course, this scanner will not prevent memory mapped writes of contaminated
			//  strings to the file, but only regular writes). The effect of getting ERROR_ACCESS_DENIED for many apps to delete the file they
			//  are trying to write usually.
			//  To handle memory mapped writes - we should be scanning at close time (which is when we can really establish that the file object
			//  is not going to be used for any more writes)
			//

			DbgPrint("!!! scanner.sys -- foul language detected in write !!!\n");

			if (!FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {

				DbgPrint("!!! scanner.sys -- blocking the write !!!\n");

				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
				returnStatus = FLT_PREOP_COMPLETE;
			}
		}

	}
	finally {

		if (notification != NULL) {

			ExFreePoolWithTag(notification, 'nacS');
		}

		if (context) {

			FltReleaseContext(context);
		}
	}

	return returnStatus;
}
NTSTATUS
ScannerpScanFileInUserMode(
__in PFLT_INSTANCE Instance,
__in PFILE_OBJECT FileObject,
__out PBOOLEAN SafeToOpen
)
/*++

Routine Description:

This routine is called to send a request up to user mode to scan a given
file and tell our caller whether it's safe to open this file.

Note that if the scan fails, we set SafeToOpen to TRUE.  The scan may fail
because the service hasn't started, or perhaps because this create/cleanup
is for a directory, and there's no data to read & scan.

If we failed creates when the service isn't running, there'd be a
bootstrapping problem -- how would we ever load the .exe for the service?

Arguments:

Instance - Handle to the filter instance for the scanner on this volume.

FileObject - File to be scanned.

SafeToOpen - Set to FALSE if the file is scanned successfully and it contains
foul language.

Return Value:

The status of the operation, hopefully STATUS_SUCCESS.  The common failure
status will probably be STATUS_INSUFFICIENT_RESOURCES.

--*/

{
	NTSTATUS status = STATUS_SUCCESS;
	PVOID buffer = NULL;
	ULONG bytesRead;
	PSCANNER_NOTIFICATION notification = NULL;
	FLT_VOLUME_PROPERTIES volumeProps;
	LARGE_INTEGER offset;
	ULONG replyLength, length;
	PFLT_VOLUME volume = NULL;

	*SafeToOpen = TRUE;

	//
	//  If not client port just return.
	//

	if (ScannerData.ClientPort == NULL) {

		return STATUS_SUCCESS;
	}

	try {

		//
		//  Obtain the volume object .
		//

		status = FltGetVolumeFromInstance(Instance, &volume);

		if (!NT_SUCCESS(status)) {

			leave;
		}

		//
		//  Determine sector size. Noncached I/O can only be done at sector size offsets, and in lengths which are
		//  multiples of sector size. A more efficient way is to make this call once and remember the sector size in the
		//  instance setup routine and setup an instance context where we can cache it.
		//

		status = FltGetVolumeProperties(volume,
			&volumeProps,
			sizeof(volumeProps),
			&length);
		//
		//  STATUS_BUFFER_OVERFLOW can be returned - however we only need the properties, not the names
		//  hence we only check for error status.
		//

		if (NT_ERROR(status)) {

			leave;
		}

		length = max(SCANNER_READ_BUFFER_SIZE, volumeProps.SectorSize);

		//
		//  Use non-buffered i/o, so allocate aligned pool
		//

		buffer = FltAllocatePoolAlignedWithTag(Instance,
			NonPagedPool,
			length,
			'nacS');

		if (NULL == buffer) {

			status = STATUS_INSUFFICIENT_RESOURCES;
			leave;
		}

		notification = ExAllocatePoolWithTag(NonPagedPool,
			sizeof(SCANNER_NOTIFICATION),
			'nacS');

		if (NULL == notification) {

			status = STATUS_INSUFFICIENT_RESOURCES;
			leave;
		}

		//
		//  Read the beginning of the file and pass the contents to user mode.
		//

		offset.QuadPart = bytesRead = 0;
		status = FltReadFile(Instance,
			FileObject,
			&offset,
			length,
			buffer,
			FLTFL_IO_OPERATION_NON_CACHED |
			FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			&bytesRead,
			NULL,
			NULL);

		if (NT_SUCCESS(status) && (0 != bytesRead)) {

			notification->BytesToScan = (ULONG)bytesRead;

			//
			//  Copy only as much as the buffer can hold
			//

			RtlCopyMemory(&notification->Contents,
				buffer,
				min(notification->BytesToScan, SCANNER_READ_BUFFER_SIZE));

			replyLength = sizeof(SCANNER_REPLY);

			status = FltSendMessage(ScannerData.Filter,
				&ScannerData.ClientPort,
				notification,//request
				sizeof(SCANNER_NOTIFICATION),
				notification,//reply
				&replyLength,
				NULL);

			if (STATUS_SUCCESS == status) {

				*SafeToOpen = ((PSCANNER_REPLY)notification)->SafeToOpen;

			}
			else {

				//
				//  Couldn't send message
				//

				DbgPrint("!!! scanner.sys --- couldn't send message to user-mode to scan file, status 0x%X\n", status);
			}
		}

	}
	finally {

		if (NULL != buffer) {

			FltFreePoolAlignedWithTag(Instance, buffer, 'nacS');
		}

		if (NULL != notification) {

			ExFreePoolWithTag(notification, 'nacS');
		}

		if (NULL != volume) {

			FltObjectDereference(volume);
		}
	}

	return status;
}
/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
minifilterScannerPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("minifilterScanner!minifilterScannerPreOperation: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (minifilterScannerDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    minifilterScannerOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("minifilterScanner!minifilterScannerPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
minifilterScannerOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("minifilterScanner!minifilterScannerOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("minifilterScanner!minifilterScannerOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
minifilterScannerPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("minifilterScanner!minifilterScannerPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
minifilterScannerPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("minifilterScanner!minifilterScannerPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
minifilterScannerDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}

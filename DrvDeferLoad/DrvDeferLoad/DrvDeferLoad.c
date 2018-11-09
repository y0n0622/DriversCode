#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <windef.h>
#include <ntimage.h>
//#include <ntlpcapi.h>
//#include <lpcp.h>
//#include <zwapi.h>
#define	DEVICE_NAME	L"\\device\\DrvDeferLoad"
#define	LINK_NAME	L"\\dosDevices\\DrvDeferLoad"

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

#define SYSTEMSERVICE(_function) KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]

#define SDT SYSTEMSERVICE

#define KSDT KeServiceDescriptorTable

NTKERNELAPI NTSTATUS ZwLoadDriver(IN PUNICODE_STRING DriverServiceName);

NTSTATUS Hook_ZwLoadDriver(IN PUNICODE_STRING DriverServiceName);

typedef NTSTATUS(*ZWLOADDRIVER)(IN PUNICODE_STRING DriverServiceName);

static ZWLOADDRIVER OldZwLoadDriver;

#define ProbeAndReadUnicodeString(Source)  \
    (((Source) >= (UNICODE_STRING * const)MM_USER_PROBE_ADDRESS) ? \
        (*(volatile UNICODE_STRING * const)MM_USER_PROBE_ADDRESS) : (*(volatile UNICODE_STRING *)(Source)))

NTSTATUS
NTAPI
ZwQueryInformationProcess(
__in HANDLE ProcessHandle,
__in PROCESSINFOCLASS ProcessInformationClass,
__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
__in ULONG ProcessInformationLength,
__out_opt PULONG ReturnLength
);

typedef struct _PORT_MESSAGE
{
	union
	{
		struct
        {
		    CSHORT DataLength;
			CSHORT TotalLength;
			} s1;
			ULONG Length;
	} u1;
	union
	{
		struct
		{
			CSHORT Type;
		    CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
	    ULONG CallbackId; // only valid for LPC_REQUEST messages
	};
} PORT_MESSAGE, *PPORT_MESSAGE;
//typedef struct _PORT_MESSAGE *PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	ULONG AllocatedAttributes;
	ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;
//typedef struct _ALPC_MESSAGE_ATTRIBUTES * PALPC_MESSAGE_ATTRIBUTES;

typedef struct _LPCP_NONPAGED_PORT_QUEUE
{
	KSEMAPHORE Semaphore;
	PVOID BackPointer;
} LPCP_NONPAGED_PORT_QUEUE, *PLPCP_NONPAGED_PORT_QUEUE;
typedef struct _LPCP_PORT_QUEUE
{
	PLPCP_NONPAGED_PORT_QUEUE NonPagedPortQueue;
	PKSEMAPHORE Semaphore;
	LIST_ENTRY ReceiveHead;
} LPCP_PORT_QUEUE, *PLPCP_PORT_QUEUE;
typedef struct _LPCP_PORT_OBJECT
{
	PVOID ConnectionPort;
	PVOID ConnectedPort;
	LPCP_PORT_QUEUE MsgQueue;
	CLIENT_ID Creator;
	PVOID ClientSectionBase;
	PVOID ServerSectionBase;
	PVOID PortContext;
	PETHREAD ClientThread;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SECURITY_CLIENT_CONTEXT StaticSecurity;
	LIST_ENTRY LpcReplyChainHead;
	LIST_ENTRY LpcDataInfoChainHead;
	union
	{
		PEPROCESS ServerProcess;
		PEPROCESS MappingProcess;
	};
	WORD MaxMessageLength;
	WORD MaxConnectionInfoLength;
	ULONG Flags;
	KEVENT WaitEvent;
}LPCP_PORT_OBJECT, *PLPCP_PORT_OBJECT;





NTSYSCALLAPI NTSTATUS NTAPI ZwAlpcSendWaitReceivePort(_In_ HANDLE PortHandle,
	_In_ ULONG 	Flags,
	_In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE 	SendMessage,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	SendMessageAttributes,
	_Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
	_Inout_opt_ PSIZE_T 	BufferLength,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	ReceiveMessageAttributes,
	_In_opt_ PLARGE_INTEGER 	Timeout
	);

//NTSYSCALLAPI NTSTATUS NTAPI HookNtAlpcSendWaitReceivePort(_In_ HANDLE PortHandle,
//	_In_ ULONG 	Flags,
//	_In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE 	SendMessage,
//	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	SendMessageAttributes,
//	_Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
//	_Inout_opt_ PSIZE_T 	BufferLength,
//	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	ReceiveMessageAttributes,
//	_In_opt_ PLARGE_INTEGER 	Timeout
//	);
NTSTATUS HookNtAlpcSendWaitReceivePort(HANDLE PortHandle,
	ULONG Flags,
	PPORT_MESSAGE SendMessage,
	PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
	PPORT_MESSAGE ReceiveMessage,
	PSIZE_T BufferLength,
	PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
	PLARGE_INTEGER 	Timeout);


typedef NTSTATUS (*RealNTALPCSENDWAITRECEIVEPORT)(_In_ HANDLE PortHandle,
	_In_ ULONG 	Flags,
	_In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE 	SendMessage,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	SendMessageAttributes,
	_Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
	_Inout_opt_ PSIZE_T 	BufferLength,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES 	ReceiveMessageAttributes,
	_In_opt_ PLARGE_INTEGER 	Timeout);

static RealNTALPCSENDWAITRECEIVEPORT OldNtAlpcSendWaitReceivePort;

VOID ntQueryRegStr(HANDLE key, const char * name, WCHAR * rtnBuf, int bufLen, const WCHAR * defValue);
BOOL IsDirSep(WCHAR ch);
BOOL ntIsDOS8Dot3Name(WCHAR * filename);
BOOL ntQueryDirectory(WCHAR * rootdir, WCHAR * shortname, WCHAR *longname, ULONG size);
BOOL ntGetLongName(WCHAR * shortname, WCHAR * longname, ULONG size);
BOOL ntGetDriverImagePath(PUNICODE_STRING uReg, WCHAR * filepath);
NTSTATUS  GetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath);
BOOL ntIsDosDeviceName(WCHAR * filename);
BOOL isRootDir(WCHAR * dir);
NTSTATUS ntQuerySymbolicLinkName(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING LinkTarget);
BOOL ntQueryVolumeName(WCHAR ch, WCHAR * name, USHORT size);
BOOL NTAPI ntGetNtDeviceName(WCHAR * filename, WCHAR * ntname);
NTSTATUS Hook_ZwLoadDriver(IN PUNICODE_STRING DriverServiceName);
void StartHook(void);
void RemoveHook(void);
VOID DriverUnload(IN PDRIVER_OBJECT	pDriverObject);
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath);

VOID ntQueryRegStr(HANDLE key, const char * name, WCHAR * rtnBuf, int bufLen, const WCHAR * defValue)
{

	NTSTATUS rc;
	char * buf;
	ULONG len = sizeof(buf);
	ANSI_STRING aName;
	UNICODE_STRING uName;
	UNICODE_STRING uRtn;

	RtlInitAnsiString(&aName, name);

	if (RtlAnsiStringToUnicodeString(&uName, &aName, TRUE) != STATUS_SUCCESS)
	{
		RtlStringCbCopyW(rtnBuf, bufLen * sizeof(WCHAR), defValue);
		rtnBuf[bufLen - 1] = 0;
		return;
	}
	uName.Buffer[uName.Length / 2] = 0;

	// get the size
	rc = ZwQueryValueKey(key, &uName, KeyValuePartialInformation, NULL, 0, &len);
	if ((rc == STATUS_OBJECT_NAME_NOT_FOUND) || (len == 0))
	{
		RtlFreeUnicodeString(&uName);
		RtlStringCbCopyW(rtnBuf, bufLen * sizeof(WCHAR), defValue);
		rtnBuf[bufLen - 1] = 0;
		return;
	}

	// get memory to use
	buf = ExAllocatePoolWithTag(PagedPool, len + 2, 'rtpR');
	if (buf == NULL)
	{
		RtlFreeUnicodeString(&uName);
		RtlStringCbCopyW(rtnBuf, bufLen * sizeof(WCHAR), defValue);
		rtnBuf[bufLen - 1] = 0;
		return;
	}

	// get it
	rc = ZwQueryValueKey(key, &uName, KeyValuePartialInformation, buf, len, &len);

	// string free
	RtlFreeUnicodeString(&uName);

	if ((!NT_SUCCESS(rc)) || (len == 0))
		RtlStringCbCopyW(rtnBuf, bufLen * sizeof(WCHAR), defValue);
	else
	{
		// make ansi
		RtlInitUnicodeString(&uName, (PCWSTR)((PKEY_VALUE_PARTIAL_INFORMATION)buf)->Data);
		uRtn.Length = 0;
		uRtn.MaximumLength = (USHORT)bufLen * sizeof(WCHAR);
		uRtn.Buffer = rtnBuf;
		RtlCopyUnicodeString(&uRtn, &uName);
	}
	rtnBuf[bufLen - 1] = 0;

	// free the buffer
	ExFreePool(buf);
}

BOOL IsDirSep(WCHAR ch)
{
	return (ch == L'\\' || ch == L'/');
}

BOOL ntIsDOS8Dot3Name(WCHAR * filename)
{
	int i = 0;

	for (i = 0; i < MAX_PATH; i++)
	{
		if (filename[i] == L'\0')
			break;

		if (filename[i] == L'~')
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOL ntQueryDirectory(WCHAR * rootdir, WCHAR * shortname, WCHAR *longname, ULONG size)
{
	UNICODE_STRING uRootDir;
	UNICODE_STRING uShortName;
	UNICODE_STRING uLongName;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK Iosb;
	PFILE_BOTH_DIR_INFORMATION pInfo = NULL;
	NTSTATUS Status = 0;
	HANDLE hRootDir = 0;
	BYTE  * Buffer = NULL;
	WCHAR * szRoot = NULL;

	RtlZeroMemory(&Iosb, sizeof(IO_STATUS_BLOCK));
	Iosb.Status = STATUS_NO_SUCH_FILE;

	szRoot = ExAllocatePoolWithTag(PagedPool,
		MAX_PATH * sizeof(WCHAR),
		'SPIH');
	if (szRoot == NULL)
	{
		return FALSE;
	}

	RtlZeroMemory(szRoot, MAX_PATH * sizeof(WCHAR));

	wcsncpy(szRoot, rootdir, MAX_PATH);

	RtlInitUnicodeString(&uRootDir, szRoot);
	RtlInitUnicodeString(&uShortName, shortname);

	if (isRootDir(szRoot))
		RtlAppendUnicodeToString(&uRootDir, L"\\");

	InitializeObjectAttributes(&oa,
		&uRootDir,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		0,
		0);

	Status = ZwCreateFile(&hRootDir,
		GENERIC_READ | SYNCHRONIZE,
		&oa,
		&Iosb,
		0,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0);

	if (!NT_SUCCESS(Status))
	{
		ExFreePool(szRoot);
		return FALSE;
	}

	ExFreePool(szRoot);

	Buffer = ExAllocatePoolWithTag(PagedPool,
		1024,
		'SPIH');
	if (Buffer == NULL)
	{
		ZwClose(hRootDir);
		return FALSE;
	}

	RtlZeroMemory(Buffer, 1024);

	Status = ZwQueryDirectoryFile(hRootDir,
		NULL,
		0, // No APC routine
		0, // No APC context
		&Iosb,
		Buffer,
		1024,
		FileBothDirectoryInformation,
		TRUE,
		&uShortName,
		TRUE);

	if (!NT_SUCCESS(Status))
	{
		ExFreePool(Buffer);
		ZwClose(hRootDir);
		return FALSE;
	}

	ZwClose(hRootDir);

	pInfo = (PFILE_BOTH_DIR_INFORMATION)Buffer;

	if (pInfo->FileNameLength == 0)
	{
		ExFreePool(Buffer);
		return FALSE;
	}

	uShortName.Length = uShortName.MaximumLength = (USHORT)pInfo->FileNameLength;
	uShortName.Buffer = pInfo->FileName;

	if (size < uShortName.Length)
	{
		ExFreePool(Buffer);
		return FALSE;
	}

	uLongName.Length = 0;
	uLongName.MaximumLength = (USHORT)size;
	uLongName.Buffer = longname;

	RtlCopyUnicodeString(&uLongName, &uShortName);
	ExFreePool(Buffer);
	return TRUE;
}

BOOL ntFindFile(WCHAR * fullpath, WCHAR * longname, ULONG size)
{
	BOOL rtn = FALSE;
	WCHAR * pchScan = fullpath;
	WCHAR * pchEnd = NULL;

	while (*pchScan)
	{
		if (IsDirSep(*pchScan))
			pchEnd = pchScan;

		pchScan++;
	}

	if (pchEnd)
	{
		*pchEnd++ = L'\0';
		rtn = ntQueryDirectory(fullpath, pchEnd, longname, size);
		*(--pchEnd) = L'\\';
	}
	return rtn;
}

BOOL ntGetLongName(WCHAR * shortname, WCHAR * longname, ULONG size)
{
	WCHAR * szResult = NULL;
	WCHAR* pchResult = NULL;
	WCHAR* pchScan = shortname;
	INT offset = 0;

	szResult = ExAllocatePoolWithTag(PagedPool,
		sizeof(WCHAR) * (MAX_PATH * 2 + 1),
		'SPIH');

	if (szResult == NULL)
		return FALSE;

	RtlZeroMemory(szResult, sizeof(WCHAR) * (MAX_PATH * 2 + 1));
	pchResult = szResult;

	if (pchScan[0] && pchScan[1] == L':')
	{
		*pchResult++ = L'\\';
		*pchResult++ = L'?';
		*pchResult++ = L'?';
		*pchResult++ = L'\\';
		*pchResult++ = *pchScan++;
		*pchResult++ = *pchScan++;
		offset = 4;
	}
	else if (IsDirSep(pchScan[0]) && IsDirSep(pchScan[1]))
	{
		*pchResult++ = L'\\';
		*pchResult++ = L'D';
		*pchResult++ = L'e';
		*pchResult++ = L'v';
		*pchResult++ = L'i';
		*pchResult++ = L'c';
		*pchResult++ = L'e';
		*pchResult++ = L'\\';
		*pchResult++ = L'L';
		*pchResult++ = L'a';
		*pchResult++ = L'n';
		*pchResult++ = L'M';
		*pchResult++ = L'a';
		*pchResult++ = L'n';
		*pchResult++ = L'R';
		*pchResult++ = L'e';
		*pchResult++ = L'd';
		*pchResult++ = L'i';
		*pchResult++ = L'r';
		*pchResult++ = L'e';
		*pchResult++ = L'c';
		*pchResult++ = L't';
		*pchResult++ = L'o';
		*pchResult++ = L'r';
		*pchResult++ = *pchScan++;
		*pchScan++;
		while (*pchScan && !IsDirSep(*pchScan))
			*pchResult++ = *pchScan++;

		offset = 24;
	}
	else if (_wcsnicmp(pchScan, L"\\DosDevices\\", 12) == 0)
	{
		RtlStringCbCopyW(pchResult, sizeof(WCHAR) * (MAX_PATH * 2 + 1), L"\\??\\");
		pchResult += 4;
		pchScan += 12;
		while (*pchScan && !IsDirSep(*pchScan))
			*pchResult++ = *pchScan++;
		offset = 4;
	}
	else if (_wcsnicmp(pchScan, L"\\Device\\HardDiskVolume", 22) == 0)
	{
		RtlStringCbCopyW(pchResult, sizeof(WCHAR) * (MAX_PATH * 2 + 1), L"\\Device\\HardDiskVolume");
		pchResult += 22;
		pchScan += 22;
		while (*pchScan && !IsDirSep(*pchScan))
			*pchResult++ = *pchScan++;
	}
	else if (_wcsnicmp(pchScan, L"\\??\\", 4) == 0)
	{
		RtlStringCbCopyW(pchResult, sizeof(WCHAR) * (MAX_PATH * 2 + 1), L"\\??\\");
		pchResult += 4;
		pchScan += 4;

		while (*pchScan && !IsDirSep(*pchScan))
			*pchResult++ = *pchScan++;
	}
	else
	{
		ExFreePool(szResult);
		return FALSE;
	}

	while (IsDirSep(*pchScan))
	{
		BOOL bShort = FALSE;
		WCHAR* pchEnd = NULL;
		WCHAR* pchReplace = NULL;
		*pchResult++ = *pchScan++;

		pchEnd = pchScan;
		pchReplace = pchResult;

		while (*pchEnd && !IsDirSep(*pchEnd))
		{
			if (*pchEnd == L'~')
				bShort = TRUE;

			*pchResult++ = *pchEnd++;
		}

		*pchResult = L'\0';

		if (bShort)
		{
			WCHAR  * szLong = NULL;

			szLong = ExAllocatePoolWithTag(PagedPool,
				sizeof(WCHAR) * MAX_PATH,
				'SPIH');
			if (szLong)
			{
				RtlZeroMemory(szLong, sizeof(WCHAR) * MAX_PATH);

				if (ntFindFile(szResult, szLong, sizeof(WCHAR) * MAX_PATH))
				{
					RtlStringCbCopyW(pchReplace, sizeof(WCHAR) * (MAX_PATH * 2 + 1), szLong);
					pchResult = pchReplace + wcslen(pchReplace);
				}

				ExFreePool(szLong);
			}
		}

		pchScan = pchEnd;
	}

	wcsncpy(longname, szResult + offset, size / sizeof(WCHAR));
	ExFreePool(szResult);
	return TRUE;
}

BOOL ntGetDriverImagePath(PUNICODE_STRING uReg, WCHAR * filepath)
{
	HANDLE key = NULL;
	OBJECT_ATTRIBUTES oa;
	memset(&oa, 0, sizeof(oa));

	InitializeObjectAttributes(&oa, uReg, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	if (NT_SUCCESS(ZwOpenKey(&key, KEY_READ, &oa)))
	{
		WCHAR path[MAX_PATH] = L"";

		RtlStringCbCopyW(path, sizeof(path), filepath);
		ntQueryRegStr(key, "ImagePath", filepath, MAX_PATH, path);

		if (ntIsDOS8Dot3Name(filepath))
		{
			WCHAR tmpName[MAX_PATH] = L"";

			RtlStringCbCopyW(tmpName, MAX_PATH * sizeof(WCHAR), filepath);
			ntGetLongName(tmpName, filepath, MAX_PATH*sizeof(WCHAR));
		}

		ZwClose(key);
		return TRUE;
	}

	return FALSE;
}

NTSTATUS  GetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath)
{

	HANDLE               hFile = NULL;
	ULONG                nNeedSize = 0;
	NTSTATUS             nStatus = STATUS_SUCCESS;
	NTSTATUS             nDeviceStatus = STATUS_DEVICE_DOES_NOT_EXIST;
	PEPROCESS            Process = NULL;
	KAPC_STATE           ApcState = { 0 };
	PVOID                lpBuffer = NULL;
	OBJECT_ATTRIBUTES	 ObjectAttributes = { 0 };
	IO_STATUS_BLOCK      IoStatus = { 0 };
	PFILE_OBJECT         FileObject = NULL;
	PFILE_NAME_INFORMATION FileName = NULL;
	WCHAR                FileBuffer[MAX_PATH] = { 0 };
	DECLARE_UNICODE_STRING_SIZE(ProcessPath, MAX_PATH);
	DECLARE_UNICODE_STRING_SIZE(DosDeviceName, MAX_PATH);

	PAGED_CODE();

	nStatus = PsLookupProcessByProcessId(nPid, &Process);
	if (NT_ERROR(nStatus))
	{
		KdPrint(("%s error PsLookupProcessByProcessId.\n", __FUNCTION__));
		return nStatus;
	}

	__try
	{

		KeStackAttachProcess(Process, &ApcState);

		nStatus = ZwQueryInformationProcess(
			NtCurrentProcess(),
			ProcessImageFileName,
			NULL,
			0,
			&nNeedSize
			);

		if (STATUS_INFO_LENGTH_MISMATCH != nStatus)
		{
			KdPrint(("%s NtQueryInformationProcess error.\n", __FUNCTION__));
			nStatus = STATUS_MEMORY_NOT_ALLOCATED;
			__leave;

		}

		lpBuffer = ExAllocatePoolWithTag(NonPagedPool, nNeedSize, 'GetP');
		if (lpBuffer == NULL)
		{
			KdPrint(("%s ExAllocatePoolWithTag error.\n", __FUNCTION__));
			nStatus = STATUS_MEMORY_NOT_ALLOCATED;
			__leave;
		}

		nStatus = ZwQueryInformationProcess(
			NtCurrentProcess(),
			ProcessImageFileName,
			lpBuffer,
			nNeedSize,
			&nNeedSize
			);

		if (NT_ERROR(nStatus))
		{
			KdPrint(("%s NtQueryInformationProcess error2.\n", __FUNCTION__));
			__leave;
		}

		RtlCopyUnicodeString(&ProcessPath, (PUNICODE_STRING)lpBuffer);
		InitializeObjectAttributes(
			&ObjectAttributes,
			&ProcessPath,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL
			);

		nStatus = ZwCreateFile(
			&hFile,
			FILE_READ_ATTRIBUTES,
			&ObjectAttributes,
			&IoStatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
			NULL,
			0
			);

		if (NT_ERROR(nStatus))
		{
			hFile = NULL;
			__leave;
		}

		nStatus = ObReferenceObjectByHandle(
			hFile,
			0,
			*IoFileObjectType,
			KernelMode,
			(PVOID*)&FileObject,
			NULL
			);

		if (NT_ERROR(nStatus))
		{
			FileObject = NULL;
			__leave;
		}

		FileName = (PFILE_NAME_INFORMATION)FileBuffer;

		nStatus = ZwQueryInformationFile(
			hFile,
			&IoStatus,
			FileName,
			sizeof(WCHAR)*MAX_PATH,
			FileNameInformation
			);

		if (NT_ERROR(nStatus))
		{
			__leave;
		}

		if (FileObject->DeviceObject == NULL)
		{
			nDeviceStatus = STATUS_DEVICE_DOES_NOT_EXIST;
			__leave;
		}

		nDeviceStatus = RtlVolumeDeviceToDosName(FileObject->DeviceObject, &DosDeviceName);

	}
	__finally
	{
		if (NULL != FileObject)
		{
			ObDereferenceObject(FileObject);
		}

		if (NULL != hFile)
		{
			ZwClose(hFile);
		}

		if (NULL != lpBuffer)
		{
			ExFreePool(lpBuffer);
		}

		KeUnstackDetachProcess(&ApcState);


	}

	if (NT_SUCCESS(nStatus))
	{
		RtlInitUnicodeString(&ProcessPath, FileName->FileName);

		if (NT_SUCCESS(nDeviceStatus))
		{
			RtlCopyUnicodeString(FullPath, &DosDeviceName);
			RtlUnicodeStringCat(FullPath, &ProcessPath);
		}
		else
		{
			RtlCopyUnicodeString(FullPath, &ProcessPath);
		}
	}


	return nStatus;
}

BOOL ntIsDosDeviceName(WCHAR * filename)
{
	int i = 0;

	for (i = 0; i < MAX_PATH; i++)
	{
		if (filename[i] == L'\0')
			break;

		if ((filename[i] == L':') && ((i == 1) || (i == 5)))
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOL isRootDir(WCHAR * dir)
{
	SIZE_T len = wcslen(dir);

	if ((len == 23) &&
		(_wcsnicmp(dir, L"\\Device\\HarddiskVolume", 22) == 0))
		return TRUE;

	if ((len == 2) && (dir[1] == L':'))
		return TRUE;

	if ((len == 6) &&
		(_wcsnicmp(dir, L"\\??\\", 4) == 0) &&
		(dir[5] == L':'))
		return TRUE;

	if ((len == 14) &&
		(_wcsnicmp(dir, L"\\DosDevices\\", 12) == 0) &&
		(dir[13] == L':'))
		return TRUE;

	return FALSE;
}

NTSTATUS ntQuerySymbolicLinkName(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING LinkTarget)
{
	OBJECT_ATTRIBUTES oa;
	NTSTATUS status = 0;
	HANDLE LinkHandle = 0;

	InitializeObjectAttributes(&oa,
		SymbolicLinkName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		0,
		0);

	status = ZwOpenSymbolicLinkObject(&LinkHandle, GENERIC_READ, &oa);

	if (NT_SUCCESS(status) == FALSE)
	{
		return status;
	}


	status = ZwQuerySymbolicLinkObject(LinkHandle, LinkTarget, NULL);
	ZwClose(LinkHandle);
	return status;
}

BOOL ntQueryVolumeName(WCHAR ch, WCHAR * name, USHORT size)
{
	WCHAR szVolume[7] = L"\\??\\C:";
	UNICODE_STRING LinkName;
	UNICODE_STRING VolName;

	RtlInitUnicodeString(&LinkName, szVolume);

	VolName.Buffer = name;
	VolName.Length = 0;
	VolName.MaximumLength = size;

	szVolume[4] = ch;

	return NT_SUCCESS(ntQuerySymbolicLinkName(&LinkName, &VolName));
}

BOOL NTAPI ntGetNtDeviceName(WCHAR * filename, WCHAR * ntname)
{
	UNICODE_STRING uVolName = { 0, 0, 0 };
	WCHAR volName[MAX_PATH] = L"";
	WCHAR tmpName[MAX_PATH] = L"";
	WCHAR chVol = L'\0';
	WCHAR * pPath = NULL;
	BOOL bExpanded = FALSE;
	int i = 0;

	if (ntIsDOS8Dot3Name(filename))
	{
		bExpanded = TRUE;
		ntGetLongName(filename, tmpName, MAX_PATH*sizeof(WCHAR));
	}
	else
		RtlStringCbCopyW(tmpName, MAX_PATH * sizeof(WCHAR), filename);

	for (i = 1; i < MAX_PATH - 1; i++)
	{
		if (tmpName[i] == L':')
		{
			pPath = &tmpName[(i + 1) % MAX_PATH];
			chVol = tmpName[i - 1];
			break;
		}
	}

	if (pPath == NULL)
	{
		if (bExpanded)
		{
			//If Nt device name is passed and was 8.3, return the expanded version
			RtlStringCbCopyW(ntname, MAX_PATH * sizeof(WCHAR), tmpName);
			return TRUE;
		}

		return FALSE;
	}

	if (chVol == L'?')
	{
		uVolName.Length = 0;
		uVolName.MaximumLength = MAX_PATH * sizeof(WCHAR);
		uVolName.Buffer = ntname;
		RtlAppendUnicodeToString(&uVolName, L"\\Device\\HarddiskVolume?");
		RtlAppendUnicodeToString(&uVolName, pPath);
		return TRUE;
	}
	else if (ntQueryVolumeName(chVol, volName, MAX_PATH * sizeof(WCHAR)))
	{
		uVolName.Length = 0;
		uVolName.MaximumLength = MAX_PATH * sizeof(WCHAR);
		uVolName.Buffer = ntname;
		RtlAppendUnicodeToString(&uVolName, volName);
		RtlAppendUnicodeToString(&uVolName, pPath);
		return TRUE;
	}

	return FALSE;
}

NTSTATUS Hook_ZwLoadDriver(IN PUNICODE_STRING DriverServiceName)
{
	UNICODE_STRING			uPath = { 0 };
	NTSTATUS				status = STATUS_SUCCESS;
	BOOL					skipOriginal = FALSE;
	WCHAR					szTargetDriver[MAX_PATH] = { 0 };
	WCHAR					szTarget[MAX_PATH] = { 0 };
	//R3_RESULT				CallBackResult = R3Result_Pass;
	WCHAR					wszPath[MAX_PATH] = { 0 };
	UNICODE_STRING ustrProcessPath = { 0 };
	WCHAR				wszProcessPath[MAX_PATH] = { 0 };
	__try
	{
		UNICODE_STRING CapturedName;

		if ((ExGetPreviousMode() == KernelMode) ||
			(DriverServiceName == NULL))
		{
			skipOriginal = TRUE;
			status = OldZwLoadDriver(DriverServiceName);
			return status;
		}

		uPath.Length = 0;
		uPath.MaximumLength = MAX_PATH * sizeof(WCHAR);
		uPath.Buffer = wszPath;


		CapturedName = ProbeAndReadUnicodeString(DriverServiceName);

		ProbeForRead(CapturedName.Buffer,
			CapturedName.Length,
			sizeof(WCHAR));

		RtlCopyUnicodeString(&uPath, &CapturedName);

		if (ntGetDriverImagePath(&uPath, szTargetDriver))
		{

			 if(ntIsDosDeviceName(szTargetDriver))
			 {
			 	if( ntGetNtDeviceName(szTargetDriver, szTarget))
			 	{
			 		RtlStringCbCopyW(szTargetDriver, sizeof(szTargetDriver), szTarget);
				}
			}
			DbgPrint("Driver:%ws will be loaded\n", szTargetDriver);
			ustrProcessPath.Buffer = wszProcessPath;
			ustrProcessPath.Length = 0;
			ustrProcessPath.MaximumLength = sizeof(wszProcessPath);
			GetProcessFullNameByPid(PsGetCurrentProcessId(), &ustrProcessPath);
			DbgPrint("Parent:%wZ\n", &ustrProcessPath);

			//CallBackResult = hipsGetResultFromUser(L"加载", szTargetDriver, NULL,User_DefaultNon);
			/*if (CallBackResult == R3Result_Block)
			{
				return STATUS_ACCESS_DENIED;
			}*/
			//return STATUS_ACCESS_DENIED;

			skipOriginal = TRUE;
			status = OldZwLoadDriver(DriverServiceName);
			return status;
		}


	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	if (skipOriginal)
		return status;

	return OldZwLoadDriver(DriverServiceName);
}


NTSTATUS HookNtAlpcSendWaitReceivePort(HANDLE PortHandle,
	ULONG Flags,
	PPORT_MESSAGE SendMessage,
	PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
	PPORT_MESSAGE ReceiveMessage,
	PSIZE_T BufferLength,
	PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
	PLARGE_INTEGER 	Timeout)
{
	/*DbgPrint("HookNtAlpcSendWaitReceivePort：\n");
	DbgPrint("%S", BufferLength);*/

	ULONG *ptr;
	ULONG i;
	ULONG uactLength;
	PLPCP_PORT_OBJECT LPCProt;
	PUNICODE_STRING pustr;//LPC 设备名
	ANSI_STRING aPustr = { 0 };//LPC 设备名
	PUNICODE_STRING uRealName = ExAllocatePool(NonPagedPool, 1024);// 字符串".\\RPC Control\\ntsvcs"
	RtlInitUnicodeString(uRealName, L"\\RPC Control\\ntsvcs");
	pustr = ExAllocatePool(NonPagedPool, 1024 + 4);//LPC 设备名
	ObReferenceObjectByHandle(PortHandle, (ACCESS_MASK)PROCESS_ALL_ACCESS, NULL, KernelMode, (PVOID *)&LPCProt, NULL);//获取对象

	UNICODE_STRING uProcessPath = { 0 };//进程路径
	ANSI_STRING aProcessPath = { 0 };//进程路径
	PCHAR aProcessName = ExAllocatePool(NonPagedPool, 256);
	HANDLE Pid = PsGetCurrentProcessId();
	GetProcessFullNameByPid(Pid, aProcessName);
	ObQueryNameString(LPCProt->ConnectionPort, pustr, 512, &uactLength);
	RtlUnicodeStringToAnsiString(&aPustr, pustr, TRUE);
	//--------------------------------------------------------------------------//进程信息

	RtlInitUnicodeString(&uProcessPath, aProcessName);
	RtlUnicodeStringToAnsiString(&aProcessPath, &uProcessPath, TRUE);
	strcpy(aProcessName, aProcessPath.Buffer);
	DbgPrint("进程%s 开启服务", aProcessName);//输出数据
	if (!(RtlCompareUnicodeString(pustr, uRealName, TRUE)))
	{
		ptr = (ULONG *)(SendMessage->u1.s1.TotalLength);
		for (i = 0; i < SendMessage->u1.s1.DataLength / sizeof(ULONG); i++)
		{
			DbgPrint("%x ", ptr[i]);//输出数据
		}
		//if(ptr[0]==0x01&&ptr[1]==0x1f0241)//有点问题
		if (ptr[1] == 0x1f0241)
		{
			DbgPrint("进程%s 开启服务", aProcessName);//输出数据
			//strcpy(LastCalled_Path, aProcessName);
			//LastCalled_Pid = PId;
		}
		return OldNtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage,
			SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes,
			Timeout);
	}
	/*return RealZwRequestWaitReplyPort(PortHandle, RequestMessage, ReplyMess
		age);*/
	else
	{
		return OldNtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage,
			SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes,
			Timeout);
	}
}

void StartHook(void)
{
	//获取未导出的服务函数索引号
	HANDLE    hFile;
	PCHAR    pDllFile;
	ULONG  ulSize;
	ULONG  ulByteReaded;

	__asm
	{
		push    eax
			mov        eax, CR0
			and        eax, 0FFFEFFFFh
			mov        CR0, eax
			pop        eax
	}

	OldZwLoadDriver = (ZWLOADDRIVER)InterlockedExchange((PLONG)&SDT(ZwLoadDriver), (LONG)Hook_ZwLoadDriver);
	OldNtAlpcSendWaitReceivePort = 
		(RealNTALPCSENDWAITRECEIVEPORT)InterlockedExchange(
			(PLONG)&SDT(ZwAlpcSendWaitReceivePort),
			(LONG)HookNtAlpcSendWaitReceivePort
		);

	//关闭
	__asm
	{
		push    eax
			mov        eax, CR0
			or        eax, NOT 0FFFEFFFFh
			mov        CR0, eax
			pop        eax
	}
}

void RemoveHook(void)
{
	__asm
	{
		push    eax
			mov        eax, CR0
			and        eax, 0FFFEFFFFh
			mov        CR0, eax
			pop        eax
	}

	InterlockedExchange((PLONG)&SDT(ZwLoadDriver), (LONG)OldZwLoadDriver);
	InterlockedExchange((PLONG)&SDT(ZwAlpcSendWaitReceivePort), (LONG)OldNtAlpcSendWaitReceivePort);

	__asm
	{
		push    eax
			mov        eax, CR0
			or        eax, NOT 0FFFEFFFFh
			mov        CR0, eax
			pop        eax
	}
	
}

NTSTATUS DispatchCreate(
	IN PDEVICE_OBJECT	pDevObj,
	IN PIRP	pIrp)
{
	//设置IO状态信息
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	//完成IRP操作，不向下层驱动发送
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(
	IN PDEVICE_OBJECT	pDevObj,
	IN PIRP	pIrp)
{
	//RemoveHook();
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS DispatchControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PIO_STACK_LOCATION      	lpIrpStack = NULL;
	PVOID                   	inputBuffer = NULL;
	PVOID                   	outputBuffer = NULL;
	ULONG                   	inputBufferLength = 0;
	ULONG                   	outputBufferLength = 0;
	ULONG                   	ioControlCode = 0;
	NTSTATUS		     		ntStatus = STATUS_SUCCESS;

	ntStatus = Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	//获取当前IRP堆栈位置
	lpIrpStack = IoGetCurrentIrpStackLocation(Irp);
	//获得输入缓冲和长度
	inputBuffer = Irp->AssociatedIrp.SystemBuffer;
	inputBufferLength = lpIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	//获得输出缓冲和长度
	outputBuffer = Irp->AssociatedIrp.SystemBuffer;
	outputBufferLength = lpIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	//获取控制码
	ioControlCode = lpIrpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (ioControlCode)
	{

	default:

		Irp->IoStatus.Information = sizeof(ULONG);
		Irp->IoStatus.Status = ntStatus;
		break;
	}
	//RemoveHook();
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ntStatus;
}
VOID DriverUnload(IN PDRIVER_OBJECT	pDriverObject)
{
	//在这里卸载hook会导致DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS蓝屏
	//应该通过DeviceIoControl来卸载Hook
	//RemoveHook();
	UNICODE_STRING         deviceLink = { 0 };

	RtlInitUnicodeString(&deviceLink, LINK_NAME);
	IoDeleteSymbolicLink(&deviceLink);
	IoDeleteDevice(pDriverObject->DeviceObject);


	return;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	NTSTATUS 		status = STATUS_SUCCESS;
	UNICODE_STRING 	uDevName = { 0 };
	PDEVICE_OBJECT 	pDevObj = NULL;
	UNICODE_STRING 	uLinkName = { 0 };
	
	pDriverObject->MajorFunction[IRP_MJ_CREATE] =
		DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] =
		DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
		DispatchControl;
	pDriverObject->DriverUnload = DriverUnload;
	RtlInitUnicodeString(&uDevName, DEVICE_NAME);
	//创建驱动设备
	status = IoCreateDevice(pDriverObject,
		0,//sizeof(DEVICE_EXTENSION)
		&uDevName,
		FILE_DEVICE_UNKNOWN,
		0, FALSE,
		&pDevObj);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateDevice Failed:%x\n", status);
		return status;
	}
	pDevObj->Flags |= DO_BUFFERED_IO;
	RtlInitUnicodeString(&uLinkName, LINK_NAME);
	//创建符号链接
	status = IoCreateSymbolicLink(&uLinkName, &uDevName);
	if (!NT_SUCCESS(status))
	{
		//STATUS_INSUFFICIENT_RESOURCES 	资源不足
		//STATUS_OBJECT_NAME_EXISTS 		指定对象名存在
		//STATUS_OBJECT_NAME_COLLISION 	对象名有冲突
		DbgPrint("IoCreateSymbolicLink Failed:%x\n", status);
		IoDeleteDevice(pDevObj);
		return status;
	}
	DbgPrint("Driver Load begin!\n");
	//DbgBreakPoint();
	StartHook();
	
	return status;
}
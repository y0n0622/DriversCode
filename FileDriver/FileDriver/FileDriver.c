#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntdef.h>
#include <ntimage.h>

PDEVICE_OBJECT g_HookDevice;


#define DEVICE_NAME L"\\device\\FileDriver"
#define LINK_NAME L"\\dosdevices\\FileDriver"
//#define LINK_GLOBAL_NAME L"\\DosDevices\\Global\\FileDriver"
#define SystemHandleInfortion 16
#define INVALID_PID_VALUE 0xFFFFFFFF
#define FILE_DEVICE_SWAP 0x0000800a //64bit???

#define IOCTRL_BASE 0x800
#define FILEIOCTRL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define CTL_CREATEFILE FILEIOCTRL_CODE(0)
#define CTL_CREATEDIRECTORY FILEIOCTRL_CODE(1)
#define CTL_WRITEFILE FILEIOCTRL_CODE(2)
#define CTL_READFILE FILEIOCTRL_CODE(3)
#define CTL_COPYFILE FILEIOCTRL_CODE(4)
#define CTL_MOVEFILE FILEIOCTRL_CODE(5)
#define CTL_DELETEFILE FILEIOCTRL_CODE(6)
#define CTL_GETFILEATTRIBUTES FILEIOCTRL_CODE(7)
#define CTL_SETFILEATTRIBUTE FILEIOCTRL_CODE(8)
#define CTL_FORCEDELETEFILE FILEIOCTRL_CODE(9)


NTSTATUS ntCreateFile(WCHAR *szFileName);
NTSTATUS ntCreateDirectory(WCHAR *szDirName);

NTSTATUS ntWriteFile(WCHAR *szFileName);
NTSTATUS ntReadFile(WCHAR *szFile);
NTSTATUS ntCopyFile(const WCHAR * src, const WCHAR * dst);
NTSTATUS ntMoveFile(const WCHAR * src, const WCHAR * dst);
//NTSTATUS ntDeleteFile1(const WCHAR * filename);
NTSTATUS ntDeleteFile2(const WCHAR *fileName);

ULONG ntGetFileAttributes(const WCHAR * filename);
NTSTATUS ntSetFileAttribute(WCHAR *szFileName);

NTSTATUS FileOper(VOID);

NTSTATUS ForceQuarySymLink(PUNICODE_STRING SymLinkName, PUNICODE_STRING LinkTarget);

BOOLEAN ForceCloseFileHandle(WCHAR *fileName);
NTSTATUS ForceDeleteFile(WCHAR *fileName);

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, 
	PVOID SystemInformation,
	ULONG SystemInformationLength, 
	PULONG ReturnLength
);


typedef struct _SUSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
}SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_INFORMATION_ENTRU_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION 
{
	ULONG NumOfHandle;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
}SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS ntStatus = 0;

	WCHAR *szFileName1 = L"\\??\\c:\\y0n.log";
	WCHAR *szFileName2 = L"\\??\\c:\\y0n2.log";

	ntStatus = ntDeleteFile2(szFileName1);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntDeleteFile2() failed%ws,%x\n", szFileName2, ntStatus);
		return -1;
	}

	//删除设备;
	UNICODE_STRING strLink;
	RtlInitUnicodeString(&strLink, LINK_NAME);
	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObject->DeviceObject);

	DbgPrint("Driver Unloaded\n");

	UNICODE_STRING usDeviceLink;
	PDEVICE_OBJECT p_NextObj;
	p_NextObj = pDriverObject->DeviceObject;
	if (p_NextObj != NULL)
	{
		RtlInitUnicodeString(&usDeviceLink, LINK_NAME);
		IoDeleteSymbolicLink(&usDeviceLink);
		IoDeleteDevice(pDriverObject->DeviceObject);
	}
	return STATUS_SUCCESS;
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS DispatchCommon(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS DispatchWrite(PDEVICE_OBJECT p_DriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(p_DriverObject);

	PVOID pWriteBuff = NULL;
	ULONG uWriteLength = 0;
	PIO_STACK_LOCATION pStack = NULL;

	PVOID pBuffer = NULL;

	pWriteBuff = pIrp->AssociatedIrp.SystemBuffer;

	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uWriteLength = pStack->Parameters.Write.Length;

	pBuffer = ExAllocatePoolWithTag(PagedPool, uWriteLength, 'TSET');

	if (pBuffer == NULL)
	{
		pIrp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		pIrp->IoStatus.Information = 0;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	memset(pBuffer, 0, uWriteLength);

	RtlCopyMemory(pBuffer, pWriteBuff, uWriteLength);

	ExFreePool(pBuffer);
	pBuffer = NULL;

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = uWriteLength;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchRead(PDEVICE_OBJECT p_DriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(p_DriverObject);

	PVOID pReadBuffer = NULL;
	ULONG uReadLength = 0;
	PIO_STACK_LOCATION pStack = NULL;
	ULONG uMin = 0;
	ULONG uHelloStr = 0;

	uHelloStr = (ULONG)(wcslen(L"hello world") + 1) * sizeof(WCHAR);

	pReadBuffer = pIrp->AssociatedIrp.SystemBuffer;
	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uReadLength = pStack->Parameters.Read.Length;

	uMin = uReadLength > uHelloStr ? uHelloStr : uReadLength;
	RtlCopyMemory(pReadBuffer, L"hello world", uMin);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = uMin;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

typedef struct _PATH
{
	WCHAR bufFileSrcInput[128];
	WCHAR bufFileDstInput[128];
}PATH, *pPATH;

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	//NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack = NULL;
	ULONG uIoControlCode = 0;
	PVOID pInBuffer = NULL;
	PVOID pOutBuffer = NULL;
	ULONG uInSize = 0;
	ULONG uOutSize = 0;

	
	
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	NTSTATUS ntStatus = STATUS_SUCCESS;
	ULONG ulAttributes = 0;
	//WCHAR *szDirName = L"\\??\\c:\\y0n\\";
	//WCHAR *szFileName1 = L"\\??\\c:\\y0n.log";
	//WCHAR *szFileName2 = L"\\??\\c:\\y0n2.log";
	//WCHAR *szFileName3 = L"\\??\\c:\\y0n\\y0n3.log";
	UNICODE_STRING pFileName = { 0 };// \\??\\path
	UNICODE_STRING pFileName2 = { 0 };//复制和移动到的路径 \\??\\path
	UNICODE_STRING pFilePath = { 0 };//Src path
	UNICODE_STRING pFileCMPath = { 0 };//Dst path
	
	WCHAR szFileName[260] = L"\\??\\";
	pFileName.Buffer = szFileName;
	pFileName.Length = (USHORT)(wcslen(L"\\??\\") * sizeof(WCHAR));
	pFileName.MaximumLength = sizeof(szFileName);

	WCHAR szFileName2[260] = L"\\??\\";
	pFileName2.Buffer = szFileName2;
	pFileName2.Length = (USHORT)(wcslen(L"\\??\\") * sizeof(WCHAR));
	pFileName2.MaximumLength = sizeof(szFileName2);

	
	if (uIoControlCode == CTL_COPYFILE
		|| uIoControlCode == CTL_MOVEFILE)
	{
		//R3 path
		pPATH path = { 0 };
		path = (pPATH)pIrp->AssociatedIrp.SystemBuffer;
		
		pFilePath.Buffer = path->bufFileSrcInput;
		pFilePath.Length = (USHORT)(wcslen(pFilePath.Buffer) * sizeof(WCHAR));
		pFilePath.MaximumLength = sizeof(path->bufFileSrcInput);
		//cat src path
		RtlUnicodeStringCat(&pFileName, &pFilePath);

		pFileCMPath.Buffer = path->bufFileDstInput;
		pFileCMPath.Length = (USHORT)(wcslen(pFileCMPath.Buffer) * sizeof(WCHAR));
		pFileCMPath.MaximumLength = sizeof(path->bufFileDstInput);
		//cat dst path
		RtlUnicodeStringCat(&pFileName2, &pFileCMPath);

	}
	else
	{
		pInBuffer = pOutBuffer = pIrp->AssociatedIrp.SystemBuffer;
		pFilePath.Buffer = pInBuffer;
		pFilePath.Length = (USHORT)(wcslen(pInBuffer) * sizeof(WCHAR));
		pFilePath.MaximumLength = (USHORT)uInSize;

		RtlUnicodeStringCat(&pFileName, &pFilePath);
	}
	

	switch (uIoControlCode)
	{
	case CTL_CREATEFILE:
		ntStatus = ntCreateFile(pFileName.Buffer);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("ntCreateFile() failed:%x\n", ntStatus);
			//return ntStatus;
		}
		break;
	case CTL_CREATEDIRECTORY:
		ntStatus = ntCreateDirectory(pFileName.Buffer);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("ntCreateDirectory() fialed:%x\n", ntStatus);
			//return ntStatus;
		}
		break;
	case CTL_WRITEFILE:
		ntStatus = ntWriteFile(pFileName.Buffer);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("ntWriteFile() fialed:%x\n", ntStatus);
			//return ntStatus;
		}
		break;
	case CTL_READFILE:
		ntStatus = ntReadFile(pFileName.Buffer);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("ntReadFile() fialed:%d\n", ntStatus);
			//return ntStatus;
		}
		break;
	case CTL_COPYFILE:
		ntStatus = ntCopyFile(pFileName.Buffer, pFileName2.Buffer);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("ntCopyFile() fialed:%d\n", ntStatus);
			//return ntStatus;
		}
		break;
	case CTL_MOVEFILE:
		ntStatus = ntMoveFile(pFileName.Buffer, pFileName2.Buffer);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("ntMoveFile() fialed:%d\n", ntStatus);
			//return ntStatus;
		}
		break;
	case CTL_DELETEFILE:
		ntStatus = ntDeleteFile2(pFileName.Buffer);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("ntDeleteFile2() failed\n", ntStatus);
			//return ntStatus;
		}
		break;
	case CTL_GETFILEATTRIBUTES:
		ulAttributes = ntGetFileAttributes(pFileName.Buffer);
		if (ulAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			DbgPrint("%S is a directory\n", pFileName.Buffer);
		}
		else
		{
			DbgPrint("%S is not a directory\n", pFileName.Buffer);
		}

		ulAttributes = ntGetFileAttributes(pFileName.Buffer);
		if (ulAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			DbgPrint("%S is not a directory\n", pFileName.Buffer);
		}
		else
		{
			DbgPrint("%S is not a directory\n", pFileName.Buffer);
		}

		break;
	case CTL_FORCEDELETEFILE:
		//test ForceDeleteFile
		if (ForceDeleteFile(pFileName.Buffer))
		{
			DbgPrint("force delete ok");
			ntStatus = 0;
		}
		else
		{
			DbgPrint("force delete failed");
		}
		break;
	default:
		DbgPrint("IoCtrl error!\n");
		break;
	}

	if (!NT_SUCCESS(ntStatus))
	{
		pIrp->IoStatus.Information = 0;
	}
	else
	{
		pIrp->IoStatus.Information = uOutSize;
	}
	//RtlZeroMemory(pOutBuffer, uOutSize);
	//RtlCopyMemory(pOutBuffer, L"执行完成！", sizeof(L"执行完成！"));
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchClean(PDEVICE_OBJECT p_DriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(p_DriverObject);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	DbgPrint("Driver begin\n");
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName = { 0 };
	UNICODE_STRING ustrDevName = { 0 };
	PDEVICE_OBJECT pDevObj = NULL;
	

	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
	status = IoCreateDevice(pDriverObject, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	/*if (IoIsWdmVersionAvailable(1, 0x10))
	{
	RtlInitUnicodeString(&ustrLinkName, LINK_GLOBAL_NAME);
	}
	else
	{
	RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
	}*/
	pDevObj->Flags |= DO_BUFFERED_IO;
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}
	DbgPrint("");
	//FileOper();
	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
	{
		pDriverObject->MajorFunction[i] = DispatchCommon;
	}
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWrite;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = DispatchClean;

	pDriverObject->DriverUnload = DriverUnload;
	DbgPrint("Driver load ok!");
	return STATUS_SUCCESS;
}

NTSTATUS FileOper(VOID)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ULONG ulAttributes = 0;
	WCHAR *szDirName = L"\\??\\c:\\y0n\\";
	WCHAR *szFileName1 = L"\\??\\c:\\y0n.log";
	WCHAR *szFileName2 = L"\\??\\c:\\y0n2.log";
	WCHAR *szFileName3 = L"\\??\\c:\\y0n\\y0n3.log";
//	WCHAR *szFileName4 = L"\\??\\c:\\y0n\\y0n4.log";

	ntStatus = ntCreateFile(szFileName1);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntCreateFile() failed:%x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntCreateDirectory(szDirName);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntCreateDirectory() fialed:%x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntWriteFile(szFileName1);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntWriteFile() fialed:%x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntReadFile(szFileName1);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntReadFile() fialed:%d\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntCopyFile(szFileName1, szFileName2);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntCopyFile() fialed:%d\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntMoveFile(szFileName1, szFileName3);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntMoveFile() fialed:%d\n", ntStatus);
		return ntStatus;
	}

	ulAttributes = ntGetFileAttributes(szFileName1);
	if (ulAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		DbgPrint("%S is a directory\n", szFileName1);
	}
	else
	{
		DbgPrint("%S is not a directory\n", szFileName1);
	}

	ulAttributes = ntGetFileAttributes(szDirName);
	if (ulAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		DbgPrint("%S is not a directory\n", szDirName);
	}
	else
	{
		DbgPrint("%S is not a directory\n", szDirName);
	}

	ntStatus = ntDeleteFile2(szFileName1);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntDeleteFile2() failed\n", ntStatus);
		return ntStatus;
	}

	return ntStatus;
}

NTSTATUS ntCreateFile(WCHAR *szFileName)
{
	OBJECT_ATTRIBUTES objAttrib = { 0 };
	UNICODE_STRING uFileName = { 0 };
	IO_STATUS_BLOCK io_status = { 0 };
	HANDLE hFile = NULL;
	NTSTATUS status = 0;

	RtlInitUnicodeString(&uFileName, szFileName);
	InitializeObjectAttributes(&objAttrib, &uFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateFile(&hFile, GENERIC_WRITE, &objAttrib, &io_status, NULL, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL, 0);//FILE_SYNCHRONOUS_IO_NONALERT以这种方式打开的设备或文件，不能够被APC例程打断

	if (NT_SUCCESS(status))
	{
		DbgPrint("ntCreateFile success!\n");
		ZwClose(hFile);
	}

	return status;
}

NTSTATUS ntCreateDirectory(WCHAR *szDirName)
{
	OBJECT_ATTRIBUTES objAttrib = { 0 };
	UNICODE_STRING uDirName = { 0 };
	IO_STATUS_BLOCK io_status = { 0 };
	HANDLE hFile = NULL;
	NTSTATUS status = 0;

	RtlInitUnicodeString(&uDirName, szDirName);
	InitializeObjectAttributes(&objAttrib, &uDirName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateFile(&hFile, GENERIC_WRITE | GENERIC_READ, &objAttrib, &io_status, NULL, FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (NT_SUCCESS(status))
	{
		DbgPrint("ntCreateDirectory success!\n");
		ZwClose(hFile);
	}
	return status;
}

ULONG ntGetFileAttributes(const WCHAR * filename)
{
	ULONG dwRtn = 0;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES objAttr = { 0 };
	UNICODE_STRING uName = { 0 };
	FILE_NETWORK_OPEN_INFORMATION info = { 0 };

	if (filename == NULL)
	{
		return ntStatus;
	}

	RtlInitUnicodeString(&uName, filename);
	RtlZeroMemory(&info, sizeof(FILE_NETWORK_OPEN_INFORMATION));

	InitializeObjectAttributes(&objAttr, &uName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ntStatus = ZwQueryFullAttributesFile(&objAttr, &info);
	if (NT_SUCCESS(ntStatus))
	{
		dwRtn = info.FileAttributes;
	}
	if (dwRtn & FILE_ATTRIBUTE_DIRECTORY)
	{
		DbgPrint("%S is a directory\n", filename);
	}
	return dwRtn;
}

NTSTATUS ntSetFileAttribute(WCHAR *szFileName)
{
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	IO_STATUS_BLOCK iostatus = { 0 };
	HANDLE hFile = NULL;
	UNICODE_STRING uFile = { 0 };
	FILE_STANDARD_INFORMATION fsi = { 0 };
	FILE_POSITION_INFORMATION fpi = { 0 };
	NTSTATUS ntStatus = 0;

	RtlInitUnicodeString(&uFile, szFileName);
	InitializeObjectAttributes(&objectAttributes, &uFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	ntStatus = ZwCreateFile(&hFile, GENERIC_READ, &objectAttributes, &iostatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	ntStatus = ZwQueryInformationFile(hFile, &iostatus, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(ntStatus))
	{
		ZwClose(hFile);
		return ntStatus;
	}

	fpi.CurrentByteOffset.QuadPart = 100i64;

	ntStatus = ZwSetInformationFile(hFile, &iostatus, &fpi, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);

	ZwClose(hFile);
	return ntStatus;
}

NTSTATUS ntWriteFile(WCHAR *szFileName)
{
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	IO_STATUS_BLOCK iostatus = { 0 };
	HANDLE hFile = NULL;
	UNICODE_STRING uFile = { 0 };
//	LARGE_INTEGER number = { 0 };
	PUCHAR pBuffer = NULL;
	NTSTATUS ntStatus = STATUS_SUCCESS;

	RtlInitUnicodeString(&uFile, szFileName);
	InitializeObjectAttributes(&objectAttributes, &uFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	//创建文件;
	ntStatus = ZwCreateFile(&hFile, GENERIC_WRITE, &objectAttributes, &iostatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE,
		FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	pBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, 1024, 'ELIF');
	if (pBuffer == NULL)
	{
		ZwClose(hFile);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(pBuffer, 1024);
	RtlCopyMemory(pBuffer, L"Hello world", wcslen(L"Hello world") * sizeof(WCHAR));
	//写文件;
	ntStatus = ZwWriteFile(hFile, NULL, NULL, NULL, &iostatus, pBuffer, 1024, NULL, NULL);

	ZwClose(hFile);
	ExFreePool(pBuffer);

	return ntStatus;
}

NTSTATUS ntReadFile(WCHAR *szFile)
{
	OBJECT_ATTRIBUTES object_attributes = { 0 };
	IO_STATUS_BLOCK iostatus = { 0 };
	HANDLE hFile = NULL;
	UNICODE_STRING uFile = { 0 };
	FILE_STANDARD_INFORMATION fsi = { 0 };
	PUCHAR pBuffer = NULL;
	NTSTATUS ntStatus = 0;

	RtlInitUnicodeString(&uFile, szFile);
	InitializeObjectAttributes(&object_attributes, &uFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	ntStatus = ZwCreateFile(&hFile, GENERIC_READ, &object_attributes, &iostatus, NULL, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	ntStatus = ZwQueryInformationFile(hFile, &iostatus, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(ntStatus))
	{
		ZwClose(hFile);
		return ntStatus;
	}

	pBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, (LONG)fsi.EndOfFile.QuadPart, 'ELIF');

	if (pBuffer == NULL)
	{
		ZwClose(hFile);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ntStatus = ZwReadFile(hFile, NULL, NULL, NULL, &iostatus, pBuffer, (LONG)fsi.EndOfFile.QuadPart, NULL, NULL);
	DbgPrint("%ws\n", pBuffer);
	ZwClose(hFile);
	ExFreePool(pBuffer);

	return ntStatus;
}

NTSTATUS ntCopyFile(const WCHAR * src, const WCHAR * dst)
{
	HANDLE hSrcFile = NULL;
	HANDLE hDstFile = NULL;
	UNICODE_STRING uSrc = { 0 };
	UNICODE_STRING uDst = { 0 };
	OBJECT_ATTRIBUTES objSrcAttrib = { 0 };
	OBJECT_ATTRIBUTES objDstAttrib = { 0 };
	NTSTATUS status = 0;
	//ULONG uReadSize = 0;
	//ULONG uWriteSize = 0;
	ULONG length = 0;
	PVOID buffer = NULL;
	LARGE_INTEGER offset = { 0 };
	IO_STATUS_BLOCK io_status = { 0 };

	RtlInitUnicodeString(&uSrc, src);
	RtlInitUnicodeString(&uDst, dst);

	InitializeObjectAttributes(&objSrcAttrib, &uSrc, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	InitializeObjectAttributes(&objDstAttrib, &uDst, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateFile(&hSrcFile, FILE_READ_DATA | FILE_READ_ATTRIBUTES, &objSrcAttrib, &io_status, NULL,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = ZwCreateFile(&hDstFile, GENERIC_WRITE, &objDstAttrib, &io_status, NULL, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hSrcFile);
		return status;
	}

	buffer = ExAllocatePoolWithTag(PagedPool, 1024, 'ELIF');
	if (buffer == NULL)
	{
		ZwClose(hSrcFile);
		ZwClose(hDstFile);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	while (status != STATUS_END_OF_FILE)
	{
		status = ZwReadFile(hSrcFile, NULL, NULL, NULL, &io_status, buffer, PAGE_SIZE, &offset, NULL);
		if (!NT_SUCCESS(status))
		{
			if (status == STATUS_END_OF_FILE)
			{
				status = STATUS_SUCCESS;
			}
			break;
		}
		length = (ULONG)io_status.Information;
		status = ZwWriteFile(hDstFile, NULL, NULL, NULL, &io_status, buffer, length, &offset, NULL);

		if (!NT_SUCCESS(status))
		{
			break;
		}
		offset.QuadPart += length;
	}

	ExFreePool(buffer);
	ZwClose(hSrcFile);
	ZwClose(hDstFile);

	return status;
}

NTSTATUS ntMoveFile(const WCHAR * src, const WCHAR * dst)
{
	NTSTATUS status = 0;
	status = ntCopyFile(src, dst);
	if (NT_SUCCESS(status))
	{
		status = ntDeleteFile2(src);
	}
	return status;
}

NTSTATUS ntDeleteFile2(const WCHAR *fileName)
{
	OBJECT_ATTRIBUTES objAttributes = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	HANDLE handle = NULL;
	FILE_DISPOSITION_INFORMATION fdisInfo = { 0 };
	UNICODE_STRING uFileName = { 0 };
	NTSTATUS status = 0;

	RtlInitUnicodeString(&uFileName, fileName);

	InitializeObjectAttributes(&objAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	//SYNCHRONIZE:返回的句柄能异步等待完成I/O操作;
	status = ZwCreateFile(&handle, SYNCHRONIZE | FILE_WRITE_DATA | DELETE, &objAttributes, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		if (status == STATUS_ACCESS_DENIED)
		{
			status = ZwCreateFile(&handle, SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, &objAttributes, &iosb,
				NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
			if (NT_SUCCESS(status))
			{
				FILE_BASIC_INFORMATION basicInfo = { 0 };
				status = ZwQueryInformationFile(handle, &iosb, &basicInfo, sizeof(basicInfo), FileBasicInformation);
				if (!NT_SUCCESS(status))
				{
					DbgPrint("ZwQueryInformationFile(%wZ) fialed;(%x)\n", &uFileName, status);
				}
				basicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
				status = ZwSetInformationFile(handle, &iosb, &basicInfo, sizeof(basicInfo), FileBasicInformation);
				if (!NT_SUCCESS(status))
				{
					DbgPrint("ZwSetInfomationFile(%wZ) fialed;(%x)\n", &uFileName, &status);
				}

				ZwClose(handle);
				status = ZwCreateFile(&handle, SYNCHRONIZE | FILE_WRITE_DATA | DELETE, &objAttributes, &iosb, NULL,
					FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
					FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE, NULL, 0);

			}
		}
		if (!NT_SUCCESS(status))
		{
			DbgPrint("ZwCreateFile(%wZ) failed(%x)\n", &uFileName, status);
			return status;
		}
	}
	fdisInfo.DeleteFile = TRUE;
	status = ZwSetInformationFile(handle, &iosb, &fdisInfo, sizeof(fdisInfo), FileDispositionInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwSetInformationFile(%wZ) failed(%x)\n", &uFileName, status);
	}

	ZwClose(handle);
	return status;
}

NTSTATUS ForceQuarySymLink(PUNICODE_STRING SymLinkName, PUNICODE_STRING LinkTarget)
{
	OBJECT_ATTRIBUTES oa;
	NTSTATUS status;
	HANDLE handle;
	InitializeObjectAttributes(&oa, SymLinkName, OBJ_CASE_INSENSITIVE, 0, 0);
	status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &oa);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	LinkTarget->MaximumLength = 1024 * sizeof(WCHAR);
	LinkTarget->Length = 0;
	LinkTarget->Buffer = ExAllocatePoolWithTag(PagedPool, LinkTarget->MaximumLength, 'A0');
	if (!LinkTarget->Buffer)
	{
		ZwClose(handle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);

	status = ZwQuerySymbolicLinkObject(handle, LinkTarget, NULL);
	ZwClose(handle);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(LinkTarget->Buffer);
	}
	return status;
}

BOOLEAN ForceCloseFileHandle(WCHAR *fileName)
{
	NTSTATUS status;
	PVOID buf = NULL;
	PSYSTEM_HANDLE_INFORMATION pSysHandleInfo;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO handleTableEnInfo;
	ULONG size = 1;
	ULONG NumOfHandle = 0;
	ULONG i;
	CLIENT_ID cid;
	HANDLE hHandle;
	HANDLE hProcess;
	HANDLE hDupObj;
	//HANDLE hFile;
	//HANDLE hLink;
	OBJECT_ATTRIBUTES oa;
	//ULONG FileType;
	ULONG processId;
	UNICODE_STRING uLinkName;
	UNICODE_STRING uLink;
	//OBJECT_ATTRIBUTES objAttributes;
	//IO_STATUS_BLOCK IoStatus;
	ULONG ulRet;
	PVOID fileObj;
	POBJECT_NAME_INFORMATION pObjName = NULL;
	UNICODE_STRING delFileName = { 0 };
	//int length;
	WCHAR wVolLetter[3];
	WCHAR *pFilePath;
	UNICODE_STRING uVol;
	UNICODE_STRING uFilePath;
	//UNICODE_STRING NullString = RTL_CONSTANT_STRING(L"");
	BOOLEAN bRet = FALSE;

	for (size = 1;; size *= 2)
	{
		if (NULL == (buf = ExAllocatePoolWithTag(NonPagedPool, size, 'FILE')))
		{
			DbgPrint(("alloc mem failed\n"));
			goto Exit;
		}
		RtlZeroMemory(buf, size);
		status = (LONG)ZwQuerySystemInformation(SystemHandleInfortion, buf, size, NULL);
		if (!NT_SUCCESS(status))
		{
			if (STATUS_INFO_LENGTH_MISMATCH == status)
			{
				ExFreePool(buf);
				buf = NULL;
			}
			else
			{
				DbgPrint(("ZwQuerySystemInformation() failed"));
				goto Exit;
			}
		}
		else
		{
			break;
		}
	}
	pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)buf;
	NumOfHandle = pSysHandleInfo->NumOfHandle;

	wVolLetter[0] = fileName[4];
	wVolLetter[1] = fileName[5];
	wVolLetter[2] = 0;
	uLinkName.Buffer = ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(ULONG), 'A1');
	uLinkName.MaximumLength = 256;
	RtlInitUnicodeString(&uVol, wVolLetter);
	RtlInitUnicodeString(&uLink, L"\\DosDevices\\");
	RtlCopyUnicodeString(&uLinkName, &uLink);

	status = RtlAppendUnicodeStringToString(&uLinkName, &uVol);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RtlAppendUnicodeStringToString() failed"));
		return FALSE;
	}
	ForceQuarySymLink(&uLinkName, &delFileName);
	RtlFreeUnicodeString(&uLinkName);
	KdPrint(("delFile:%wZ", &delFileName));

	pFilePath = (WCHAR *)&fileName[6];
	RtlInitUnicodeString(&uFilePath, pFilePath);

	RtlAppendUnicodeStringToString(&delFileName, &uFilePath);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RtlAppendUnicodeStringToString() failed"));
		return FALSE;
	}
	KdPrint(("delFile:%wZ", &delFileName));

	for (i = 0; i < NumOfHandle; i++)
	{
		handleTableEnInfo = pSysHandleInfo->Handles[i];
		//28表示文件，25设备对象
		if (handleTableEnInfo.ObjTypeIndex != 25 && handleTableEnInfo.ObjTypeIndex != 28)
		{
			continue;
		}
		processId = (ULONG)handleTableEnInfo.UniqueProcessId;
		cid.UniqueProcess = (HANDLE)processId;
		cid.UniqueThread = (HANDLE)0;
		hHandle = (HANDLE)handleTableEnInfo.HandleValue;
		InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
		status = ZwOpenProcess(&hProcess, PROCESS_DUP_HANDLE, &oa, &cid);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("ZwOpenProcess:%d Failed", processId));
			continue;
		}
		status = ZwDuplicateObject(hProcess, hHandle, NtCurrentProcess(), &hDupObj, PROCESS_ALL_ACCESS, 0, DUPLICATE_SAME_ACCESS);
		if (!NT_SUCCESS(status))
		{
			DbgPrint(("ZwDuplicateObject1:failed"));
			continue;
		}
		status = ObReferenceObjectByHandle(hDupObj, FILE_ANY_ACCESS, 0, KernelMode, &fileObj, NULL);
		if (!NT_SUCCESS(status))
		{
			DbgPrint(("ObReferenceObjectByHandle"));
			continue;
		}

		pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, sizeof(OBJECT_NAME_INFORMATION) + 1024 * sizeof(WCHAR), 'A1');

		if (STATUS_SUCCESS != (status = ObQueryNameString(fileObj, pObjName, sizeof(OBJECT_NAME_INFORMATION) + 1024 * sizeof(WCHAR), &ulRet)))
		{
			ObDereferenceObject(fileObj);
			continue;
		}

		if (RtlCompareUnicodeString(&pObjName->Name, &delFileName, TRUE) == 0)
		{
			ObDereferenceObject(fileObj);
			ZwClose(hDupObj);

			status = ZwDuplicateObject(hProcess, hHandle, NtCurrentProcess(), &hDupObj, PROCESS_ALL_ACCESS, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
			if (!NT_SUCCESS(status))
			{
				DbgPrint(("ZwDuplicateObject failed"));
			}
			else
			{
				ZwClose(hDupObj);
				bRet = TRUE;
			}
			break;
		}

		ExFreePool(pObjName);
		pObjName = NULL;

		ObDereferenceObject(fileObj);
		ZwClose(hDupObj);
		ZwClose(hProcess);
		
	}

Exit:
	if (pObjName != NULL)
	{
		ExFreePool(pObjName);
		pObjName = NULL;
	}
	if (delFileName.Buffer != NULL)
	{
		ExFreePool(delFileName.Buffer);
	}
	if (buf != NULL)
	{
		ExFreePool(buf);
		buf = NULL;
	}
	return bRet;
}

NTSTATUS ForceOpenFile(WCHAR *fName, PHANDLE phFileHandle, ACCESS_MASK access, ULONG share)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS stat;
	OBJECT_ATTRIBUTES obja;
	UNICODE_STRING usName;

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return 0;
	}

	RtlInitUnicodeString(&usName, fName);
	InitializeObjectAttributes(&obja, &usName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, 0);
	stat = IoCreateFile(phFileHandle, access, &obja, &iosb, 0, FILE_ATTRIBUTE_NORMAL, share, FILE_OPEN, 0, NULL, 0, 0, NULL, IO_NO_PARAMETER_CHECKING);
	return stat;
}

NTSTATUS FourceSkillSetFileCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->UserIosb->Status = Irp->IoStatus.Status;
	Irp->UserIosb->Information = Irp->IoStatus.Information;

	KeSetEvent(Irp->UserEvent, IO_NO_INCREMENT, FALSE);

	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

//强删文件
NTSTATUS ForceDeleteFile(WCHAR *fileName)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PFILE_OBJECT fileobj;
	PDEVICE_OBJECT DeviceObj;
	PIRP Irp;
	KEVENT event;
	FILE_DISPOSITION_INFORMATION FileInformation;
	IO_STATUS_BLOCK ioStatus;
	PIO_STACK_LOCATION irpSp;
	PSECTION_OBJECT_POINTERS pSectionObjectPointer;
	HANDLE handle = NULL;

	ntStatus = ForceOpenFile(fileName, &handle, FILE_READ_ATTRIBUTES | DELETE, FILE_SHARE_DELETE);
	if (ntStatus == STATUS_OBJECT_NAME_NOT_FOUND
		|| ntStatus == STATUS_OBJECT_PATH_NOT_FOUND)
	{
		KdPrint(("can not find file"));
		return FALSE;
	}
	else
	{
		//ForceCloseFileHandle 遍历全局句柄表打开句柄
		if (ForceCloseFileHandle(fileName))
		{
			ntStatus = ForceOpenFile(fileName, &handle, FILE_READ_ATTRIBUTES | DELETE, FILE_SHARE_DELETE);
			if (!NT_SUCCESS(ntStatus))
			{
				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
	}

	ntStatus = ObReferenceObjectByHandle(handle, DELETE, *IoFileObjectType, KernelMode, &fileobj, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ObReferenceObjectByHandle()");
		ZwClose(handle);
		return FALSE;
	}

	DeviceObj = IoGetRelatedDeviceObject(fileobj);
	Irp = IoAllocateIrp(DeviceObj->StackSize, TRUE);
	if (Irp == NULL)
	{
		ObDereferenceObject(fileobj);
		ZwClose(handle);
		return FALSE;
	}

	KeInitializeEvent(&event, SynchronizationEvent, FALSE);
	FileInformation.DeleteFile = TRUE;

	Irp->AssociatedIrp.SystemBuffer = &FileInformation;
	Irp->UserEvent = &event;
	Irp->UserIosb = &ioStatus;
	Irp->Tail.Overlay.OriginalFileObject = fileobj;
	Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
	Irp->RequestorMode = KernelMode;

	irpSp = IoGetNextIrpStackLocation(Irp);
	irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
	irpSp->DeviceObject = DeviceObj;
	irpSp->FileObject = fileobj;
	irpSp->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION);
	irpSp->Parameters.SetFile.FileInformationClass = FileDispositionInformation;
	irpSp->Parameters.SetFile.FileObject = fileobj;

	IoSetCompletionRoutine(Irp, FourceSkillSetFileCompletion, &event, TRUE, TRUE, TRUE);

	//处理正在运行的exe
	pSectionObjectPointer = fileobj->SectionObjectPointer;
	if (pSectionObjectPointer)
	{
		pSectionObjectPointer->ImageSectionObject = 0;
		pSectionObjectPointer->DataSectionObject = 0;
	}
	ntStatus = IoCallDriver(DeviceObj, Irp);
	if (!NT_SUCCESS(ntStatus))
	{
		ObDereferenceObject(fileobj);
		ZwClose(handle);
		return FALSE;
	}

	KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);
	//IoFreeIrp(Irp);这句会导致蓝屏
	ObDereferenceObject(fileobj);
	ZwClose(handle);
	return TRUE;
}


#include <ntifs.h>
#include <ntddk.h>
#include <WINDEF.H>


#define SystemHandleInformation 16
#define ObjectNameInformation 1
KAPC_STATE ApcState = { 0 };
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG            ProcessId;
	UCHAR            ObjectTypeNumber;
	UCHAR            Flags;
	USHORT          Handle;
	PVOID            Object;
	ACCESS_MASK      GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[1];
}SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

PServiceDescriptorTableEntry_t KeServiceDescriptorTableShadow = NULL;

NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	OUT PVOID              SystemInformation,
	IN ULONG                SystemInformationLength,
	OUT PULONG              ReturnLength OPTIONAL);

typedef BOOL(NTAPI *REAL_NtGdiStretchBlt)
(
IN HDC   hdcDst,
IN int   xDst,
IN int   yDst,
IN int   cxDst,
IN int   cyDst,
IN HDC   hdcSrc,
IN int   xSrc,
IN int   ySrc,
IN int   cxSrc,
IN int   cySrc,
IN DWORD dwRop,
IN DWORD dwBackColor
);

typedef BOOL(NTAPI *REAL_NtGdiBitBlt)
(
IN HDC    hdcDst,
IN int    x,
IN int    y,
IN int    cx,
IN int    cy,
IN HDC    hdcSrc,
IN int    xSrc,
IN int    ySrc,
IN DWORD  rop4,
IN DWORD  crBackColor,
IN FLONG  fl
);

REAL_NtGdiStretchBlt OldNtGdiStretchBlt;
REAL_NtGdiBitBlt OldNtGdiBitBlt = NULL;

BOOL NTAPI hook_NtGdiStretchBlt(
	IN HDC   hdcDst,
	IN int   xDst,
	IN int   yDst,
	IN int   cxDst,
	IN int   cyDst,
	IN HDC   hdcSrc,
	IN int   xSrc,
	IN int   ySrc,
	IN int   cxSrc,
	IN int   cySrc,
	IN DWORD dwRop,
	IN DWORD dwBackColor
	)
{
	PCHAR pIgnorePocess = "mspaint.exe";
	PEPROCESS pe = PsGetCurrentProcess();
	PCHAR pProcessName = (PCHAR)((ULONG)pe + 0x16c);
	
	if (RtlCompareMemory(pProcessName, pIgnorePocess, strlen(pIgnorePocess)))
	{
		DbgPrint("mspaint.exe\n");
		DbgPrint("执行hook_NtGdiStretchBlt\n");
		dwRop = 0;
		dwBackColor = 0;
		return OldNtGdiStretchBlt(
			hdcDst,
			xDst,
			yDst,
			cxDst,
			cyDst,
			hdcSrc,
			xSrc,
			ySrc,
			cxSrc,
			cySrc,
			dwRop,
			dwBackColor
			);
		//return TRUE;
	}
	else
	{
		return OldNtGdiStretchBlt(
			hdcDst,
			xDst,
			yDst,
			cxDst,
			cyDst,
			hdcSrc,
			xSrc,
			ySrc,
			cxSrc,
			cySrc,
			dwRop,
			dwBackColor
			);
	}
}

BOOL NTAPI hook_NtGdiBitBlt(
	IN HDC    hdcDst,
	IN int    x,
	IN int    y,
	IN int    cx,
	IN int    cy,
	IN HDC    hdcSrc,
	IN int    xSrc,
	IN int    ySrc,
	IN DWORD  rop4,
	IN DWORD  crBackColor,
	IN FLONG  fl
	)
{
	//test mspaint
	PCHAR pIgnorePocess = "mspaint.exe";
	PEPROCESS pe = PsGetCurrentProcess();
	PCHAR pProcessName = (PCHAR)((ULONG)pe + 0x16c);//0x16c通过dt eprocess获取

	if (RtlCompareMemory(pProcessName, pIgnorePocess, strlen(pIgnorePocess)))
	{
		DbgPrint("mspaint.exe\n");
		DbgPrint("执行hook_NtGdiBitBlt\n");
		rop4 = 0;
		crBackColor = 0;
		return OldNtGdiBitBlt(
			hdcDst,
			x,
			y,
			cx,
			cy,
			hdcSrc,
			xSrc,
			ySrc,
			rop4,
			crBackColor,
			fl
			);
		//return TRUE;
	}
	else
	{
		return OldNtGdiBitBlt(
			hdcDst,
			x,
			y,
			cx,
			cy,
			hdcSrc,
			xSrc,
			ySrc,
			rop4,
			crBackColor,
			fl
			);
	}
	
}

PVOID GetInfoTable(ULONG ATableType)
{
	ULONG mSize = 0x4000;
	PVOID mPtr = NULL;
	NTSTATUS St;

	do
	{
		mPtr = ExAllocatePoolWithTag(PagedPool, mSize, 'GIT');
		memset(mPtr, 0, mSize);

		if (mPtr)
		{
			St = ZwQuerySystemInformation(ATableType, mPtr, mSize, NULL);
		}
		else return NULL;

		if (St == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(mPtr);

			mSize = mSize * 2;
		}

	} while (St == STATUS_INFO_LENGTH_MISMATCH);

	if (St == STATUS_SUCCESS) return mPtr;

	ExFreePoolWithTag(mPtr, 'GIT');
	
	return NULL;
}


HANDLE GetCsrPid()
{
	HANDLE Process, hObject;

	HANDLE CsrId = (HANDLE)0;

	OBJECT_ATTRIBUTES obj;

	CLIENT_ID cid;

	UCHAR Buff[0x100];

	POBJECT_NAME_INFORMATION ObjName = (PVOID)&Buff;

	PSYSTEM_HANDLE_INFORMATION_EX Handles;

	ULONG r;

	Handles = GetInfoTable(SystemHandleInformation);

	if (!Handles) return CsrId;

	for (r = 0; r < Handles->NumberOfHandles; r++)
	{
		//PortObject,不同系统不同，需要获取,windbg,!handle 查看port类型的地址
		//dt _OBJECT_TYPE 地址  查看index的值就是port类型的值，这个结构的index对应的就是ObjectTypeNumber
		if (Handles->Information[r].ObjectTypeNumber == 0x24) 
		{
			InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

			cid.UniqueProcess = (HANDLE)Handles->Information[r].ProcessId;

			cid.UniqueThread = 0;

			if (NT_SUCCESS(NtOpenProcess(&Process, PROCESS_DUP_HANDLE, &obj, &cid)))
			{
				if (NT_SUCCESS(ZwDuplicateObject(Process, (HANDLE)Handles->Information[r].Handle, NtCurrentProcess(), &hObject, 0, 0, DUPLICATE_SAME_ACCESS)))
				{
					if (NT_SUCCESS(ZwQueryObject(hObject, ObjectNameInformation, ObjName, 0x100, NULL)))
					{
						if (ObjName->Name.Buffer&& !wcsncmp(L"\\Windows\\ApiPort", ObjName->Name.Buffer, 20))
						{
							CsrId = (HANDLE)Handles->Information[r].ProcessId;
						}
					}
					ZwClose(hObject);
				}
				ZwClose(Process);
			}
		}
	}
	
	ExFreePool(Handles);

	return CsrId;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PEPROCESS crsProcess = NULL;
	//KAPC_STATE apcstate = {0};

	if (OldNtGdiBitBlt && OldNtGdiStretchBlt && KeServiceDescriptorTableShadow)
	{
		ntStatus = PsLookupProcessByProcessId(GetCsrPid(), &crsProcess);

		if (NT_SUCCESS(ntStatus))
		{
			KeStackAttachProcess(crsProcess, &ApcState);

			__asm
			{
				push    eax
					mov        eax, CR0
					and        eax, 0FFFEFFFFh
					mov        CR0, eax
					pop        eax
			}

			InterlockedExchange(&KeServiceDescriptorTableShadow->ServiceTableBase[14], (ULONG)OldNtGdiBitBlt);
			InterlockedExchange(&KeServiceDescriptorTableShadow->ServiceTableBase[302], (ULONG)OldNtGdiStretchBlt);

			__asm
			{
				push    eax
					mov        eax, CR0
					or        eax, NOT 0FFFEFFFFh
					mov        CR0, eax
					pop        eax
			}
			KeUnstackDetachProcess(&ApcState);
		}
	}
}
ULONG GetAddressOfShadowTable()
{
	ULONG i;
	UCHAR* p;
	ULONG dwordatbyte;

	UNICODE_STRING usKeAddSystemServiceTable;

	RtlInitUnicodeString(&usKeAddSystemServiceTable, L"KeAddSystemServiceTable");

	p = (UCHAR*)MmGetSystemRoutineAddress(&usKeAddSystemServiceTable);

	for (i = 0; i < 4096; i++, p++)
	{
		__try
		{
			dwordatbyte = *(ULONG*)p;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return 0;
		}

		if (MmIsAddressValid((PVOID)dwordatbyte))
		{
			if (memcmp((PVOID)dwordatbyte, &KeServiceDescriptorTable, 16) == 0)    //比较的是地址指向的内容
			{
				if ((PVOID)dwordatbyte == &KeServiceDescriptorTable)
				{
					continue;
				}
				return dwordatbyte;
			}
		}
	}
	return 0;
}
NTSTATUS HookssdtShadow()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ULONG BuildNumber = 0;
	ULONG MinorVersion = 0;
	ULONG MajorVersion = 0;
	PEPROCESS crsProcess = NULL;
	

	PsGetVersion(&MajorVersion, &MinorVersion, &BuildNumber, NULL);

	DbgPrint("%d", BuildNumber);
	
	if (BuildNumber == 0x1db1) //win7 32bit
	{
		
		//KeServiceDescriptorTableShadow = (PServiceDescriptorTableEntry_t)((ULONG)&KeServiceDescriptorTable - 0x40 + 0x10);
		KeServiceDescriptorTableShadow = GetAddressOfShadowTable() + 0x10;
		DbgPrint("0x%x", KeServiceDescriptorTableShadow);

		if (KeServiceDescriptorTableShadow)
		{
			ntStatus = PsLookupProcessByProcessId(GetCsrPid(), &crsProcess);

			if (NT_SUCCESS(ntStatus))
			{
				
				KeStackAttachProcess(crsProcess, &ApcState);

				__asm
				{
					push    eax
						mov        eax, CR0
						and        eax, 0FFFEFFFFh
						mov        CR0, eax
						pop        eax
				}

				OldNtGdiBitBlt = (REAL_NtGdiBitBlt)InterlockedExchange(&KeServiceDescriptorTableShadow->ServiceTableBase[14], (ULONG)hook_NtGdiBitBlt);
				OldNtGdiStretchBlt = (REAL_NtGdiStretchBlt)InterlockedExchange(&KeServiceDescriptorTableShadow->ServiceTableBase[302], (ULONG)hook_NtGdiStretchBlt);

				__asm
				{
					push    eax
						mov        eax, CR0
						or        eax, NOT 0FFFEFFFFh
						mov        CR0, eax
						pop        eax
				}
				KeUnstackDetachProcess(&ApcState);
			}
		}
	}

	return ntStatus;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	pDriverObject->DriverUnload = DriverUnload;
	//DbgBreakPoint();
	HookssdtShadow();

	return STATUS_SUCCESS;
}
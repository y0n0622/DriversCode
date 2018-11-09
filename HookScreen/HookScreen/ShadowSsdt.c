#include "ShadowSsdt.h"

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()
 __declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

 REAL_NtGdiStretchBlt real_NtGdiStretchBlt;

 REAL_NtGdiBitBlt real_NtGdiBitBlt;

ULONG GetAddressOfShadowTable()
{
	ULONG i;
	UCHAR* p;
	ULONG dwordatbyte;

	UNICODE_STRING usKeAddSystemServiceTable;

	RtlInitUnicodeString(&usKeAddSystemServiceTable, L"KeAddSystemServiceTable");

	p = (UCHAR*)MmGetSystemRoutineAddress(&usKeAddSystemServiceTable);

	for (i = 0; i < 4096; i++,p++)
	{
		__try
		{
			dwordatbyte = *(ULONG*)p;
		}__except(EXCEPTION_EXECUTE_HANDLER)
		{
			return 0;
		}

		if(MmIsAddressValid((PVOID)dwordatbyte))
		{
			if(memcmp((PVOID)dwordatbyte, &KeServiceDescriptorTable, 16) == 0)    //比较的是地址指向的内容
			{
				if((PVOID)dwordatbyte == &KeServiceDescriptorTable)
				{
					continue;
				}
				return dwordatbyte;
			}
		}
	}
	return 0;
}


PDWORD NtGdiStretchBltAddr;
PDWORD NtGdiBitBltAddr;
BOOL flag = FALSE;
void StartHookShadow (void)
{
	DWORD SSDTShadowBaseAddr=GetAddressOfShadowTable()+0x10;//表基址所在地址  
	DWORD TableCount=SSDTShadowBaseAddr+0x8;//函数数量所在地址  
	DWORD dwCount=*((PDWORD)TableCount);  
	PDWORD Fun_Addr=(PDWORD)(*((PDWORD)SSDTShadowBaseAddr));  
	
	KdPrint(("ssdt shadow addr:0x%X  = 0x%X= 0x%X",SSDTShadowBaseAddr,
		*(PDWORD)SSDTShadowBaseAddr,Fun_Addr));  
	KdPrint(("数量是:%d",dwCount));  
	if (!MmIsAddressValid(Fun_Addr))
	{
		KdPrint(("Fun_Addr地址不可访问%X！",Fun_Addr));
		return;
	}
	NtGdiStretchBltAddr=Fun_Addr+292;  
	NtGdiBitBltAddr=Fun_Addr+13;  
	KdPrint(("NtGdiStretchBltAddr:%X",NtGdiStretchBltAddr));  
	KdPrint(("NtGdiBitBltAddr:%X",NtGdiBitBltAddr));  
	//Fun_Addr是KeServiceDescriptorTable表的首地址，但是一用*Fun_Addr就出现0x50的蓝屏代码
	//0x50 PAGE_FAULT_IN_NONPAGED_AREA Parameters 分页内存读取错误，但是这里没分配分页内存呢。
	KdPrint(("*Fun_Addr:%X",*Fun_Addr));  


	//保存原函数地址，SSDT HOOK是根据ZW函数地址硬编码得出的索引得到的函数地址  
	real_NtGdiStretchBlt=(REAL_NtGdiStretchBlt)(*NtGdiStretchBltAddr);  
	real_NtGdiBitBlt=(REAL_NtGdiBitBlt)(*NtGdiBitBltAddr);  
	
	
	KdPrint(("NtGdiStretchBlt原函数地址：%08X\n",*NtGdiStretchBltAddr));  
	KdPrint(("NtGdiStretchBlt新函数地址：%08X\n",HOOK_NtGdiStretchBlt));  
	KdPrint(("NtGdiBitBlt原函数地址：%08X\n",*NtGdiBitBltAddr));  
	KdPrint(("NtGdiBitBlt新函数地址：%08X\n",HOOK_NtGdiBitBlt));  
// 	获取未导出的服务函数索引号
// 		HANDLE    hFile;
// 		PCHAR    pDllFile;
// 		ULONG  ulSize;
// 		ULONG  ulByteReaded;

	__asm
	{
		push    eax
			mov        eax, CR0
			and        eax, 0FFFEFFFFh
			mov        CR0, eax
			pop        eax
	}

 	InterlockedExchange((PLONG)NtGdiStretchBltAddr, (LONG)HOOK_NtGdiStretchBlt);
 	InterlockedExchange((PLONG)NtGdiBitBltAddr, (LONG)HOOK_NtGdiBitBlt);

	//关闭
	__asm
	{
		push    eax
			mov        eax, CR0
			or        eax, NOT 0FFFEFFFFh
			mov        CR0, eax
			pop        eax
	}
	flag = TRUE;
	return ;
}

void RemoveHookShadow (void)
{
	if (!flag)
	{
		return;
	}
	
	__asm
	{
		push    eax
			mov        eax, CR0
			and        eax, 0FFFEFFFFh
			mov        CR0, eax
			pop        eax
	}
 	InterlockedExchange( (PLONG) NtGdiStretchBltAddr,  (LONG) real_NtGdiStretchBlt);
 	InterlockedExchange( (PLONG) NtGdiBitBltAddr,  (LONG) real_NtGdiBitBlt);
	__asm
	{
		push    eax
			mov        eax, CR0
			or        eax, NOT 0FFFEFFFFh
			mov        CR0, eax
			pop        eax
	}
}



BOOL NTAPI HOOK_NtGdiStretchBlt//293
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
	){
		DbgPrint("调用到了NtGdiStretchBlt");
		return FALSE;
		return real_NtGdiStretchBlt(
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

BOOL NTAPI HOOK_NtGdiBitBlt//14
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
	){
		DbgPrint("调用到了NtGdiBitBlt");
		return FALSE;
		return real_NtGdiBitBlt(
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

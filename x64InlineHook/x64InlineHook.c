#include <ntddk.h>
#include "LDE64x64.h"
#define kmalloc(_s) ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')
#define kfree(_p) ExFreePool(_p)

KIRQL WPOFFx64()
{
	KIRQL irql=KeRaiseIrqlToDpcLevel();
	UINT64 cr0=__readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPONx64(KIRQL irql)
{
	UINT64 cr0=__readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

void *GetFunctionAddr(PCWSTR FunctionName)
{
	UNICODE_STRING UniCodeFunctionName;
	RtlInitUnicodeString( &UniCodeFunctionName, FunctionName );
	return MmGetSystemRoutineAddress( &UniCodeFunctionName );   
}

ULONG GetPatchSize(PUCHAR Address)
{
	ULONG LenCount=0,Len=0;
	while(LenCount<=14)	//至少需要14字节
	{
		Len=LDE(Address,64);
		Address=Address+Len;
		LenCount=LenCount+Len;
	}
	return LenCount;
}

//传入：待HOOK函数地址，代理函数地址，接收原始函数地址的指针，接收补丁长度的指针；返回：原来头N字节的数据
PVOID HookKernelApi(IN PVOID ApiAddress, IN PVOID Proxy_ApiAddress, OUT PVOID *Original_ApiAddress, OUT ULONG *PatchSize)
{
	KIRQL irql;
	UINT64 tmpv;
	PVOID head_n_byte,ori_func;
	UCHAR jmp_code[]="\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	UCHAR jmp_code_orifunc[]="\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	//How many bytes shoule be patch
	*PatchSize=GetPatchSize((PUCHAR)ApiAddress);
	//step 1: Read current data
	head_n_byte=kmalloc(*PatchSize);
	irql=WPOFFx64();
	memcpy(head_n_byte,ApiAddress,*PatchSize);
	WPONx64(irql);
	//step 2: Create ori function
	ori_func=kmalloc(*PatchSize+14);	//原始机器码+跳转机器码
	RtlFillMemory(ori_func,*PatchSize+14,0x90);
	tmpv=(ULONG64)ApiAddress+*PatchSize;	//跳转到没被打补丁的那个字节
	memcpy(jmp_code_orifunc+6,&tmpv,8);
	memcpy((PUCHAR)ori_func,head_n_byte,*PatchSize);
	memcpy((PUCHAR)ori_func+*PatchSize,jmp_code_orifunc,14);
	*Original_ApiAddress=ori_func;
	//step 3: fill jmp code
	tmpv=(UINT64)Proxy_ApiAddress;
	memcpy(jmp_code+6,&tmpv,8);
	//step 4: Fill NOP and hook
	irql=WPOFFx64();
	RtlFillMemory(ApiAddress,*PatchSize,0x90);
	memcpy(ApiAddress,jmp_code,14);
	WPONx64(irql);
	//return ori code
	return head_n_byte;
}

//传入：被HOOK函数地址，原始数据，补丁长度
VOID UnhookKernelApi(IN PVOID ApiAddress, IN PVOID OriCode, IN ULONG PatchSize)
{
	KIRQL irql;
	irql=WPOFFx64();
	memcpy(ApiAddress,OriCode,PatchSize);
	WPONx64(irql);
}

typedef NTSTATUS (__fastcall *PSLOOKUPPROCESSBYPROCESSID)( HANDLE ProcessId, PEPROCESS *Process); 
ULONG64 my_eprocess=0;			//待保护进程的eprocess
ULONG pslp_patch_size=0;		//PsLookupProcessByProcessId被修改了N字节
PUCHAR pslp_head_n_byte=NULL;	//PsLookupProcessByProcessId的前N字节数组
PVOID ori_pslp=NULL;			//PsLookupProcessByProcessId的原函数

NTSTATUS Proxy_PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process)
{
	NTSTATUS st;
	st = ((PSLOOKUPPROCESSBYPROCESSID)ori_pslp)(ProcessId, Process);
	if (ProcessId == 2764)//test pid
	{
		st = STATUS_ACCESS_DENIED;//保护进程notepad.exe
	}
	return st;
}

VOID HookPsLookupProcessByProcessId()
{
	pslp_head_n_byte = HookKernelApi(GetFunctionAddr(L"PsLookupProcessByProcessId"),
									(PVOID)Proxy_PsLookupProcessByProcessId,
									&ori_pslp,
									&pslp_patch_size);
}

VOID UnhookPsLookupProcessByProcessId()
{
	UnhookKernelApi(GetFunctionAddr(L"PsLookupProcessByProcessId"),
					pslp_head_n_byte,
					pslp_patch_size);
}


HANDLE FileHandle;
VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	
	//UNHOOK KERNEL FUNCTION//
	//UnhookPspTerminateThreadByPointer();
	UnhookPsLookupProcessByProcessId();
	//UNHOOK KERNEL FUNCTION//
	
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	NTSTATUS status = STATUS_SUCCESS;
	pDriverObj->DriverUnload = DriverUnload;
	

	//初始化反汇编引擎
	LDE_init();
	//((PSLOOKUPPROCESSBYPROCESSID)ori_pslp)((ULONG64)1696, my_eprocess);
	my_eprocess = (ULONG64)PsGetCurrentProcess();
	HookPsLookupProcessByProcessId();
	
	//Proxy_PsLookupProcessByProcessId((ULONG64)PsGetCurrentProcessId(), my_eprocess);
	//test notepad.exe pid
	Proxy_PsLookupProcessByProcessId((ULONG64)2764, my_eprocess);

	return STATUS_SUCCESS;
}
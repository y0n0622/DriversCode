#include "InlineHookFunc_x64.h"


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
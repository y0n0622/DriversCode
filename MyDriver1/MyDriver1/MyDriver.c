#include <ntddk.h>

VOID DriverUnload(PDRIVER_OBJECT driver)
{
	DbgPrint("first:our driver is unloading...\r\n");

}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
{
	/*#if DBG
		_asm int 3
	#endif*/
	DbgPrint("first: hello");
	driver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;

}
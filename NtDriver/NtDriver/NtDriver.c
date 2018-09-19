#include <ntddk.h>
#define DEVICE_NAME L"\\device\\ntDriver"
#define LINK_NAME L"\\dosdevices\\ntDriver"

#define  IOCTRL_BASE 0x800
#define  MYIOCTRL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define  CTL_HELLO MYIOCTRL_CODE(0)
#define  CTL_PRINT MYIOCTRL_CODE(1)
#define  CTL_BYE MYIOCTRL_CODE(2)

NTSTATUS DispatchCommon(PDEVICE_OBJECT p_DriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(p_DriverObject);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS DispatchCreate(PDEVICE_OBJECT p_DriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(p_DriverObject);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
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

NTSTATUS DispatchIoctrl(PDEVICE_OBJECT p_DriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(p_DriverObject);

	ULONG uIoctrlCode = 0;
	PVOID pInputBuff = NULL;
	PVOID pOutputBuff = NULL;

	ULONG uInputLength = 0;
	ULONG uOutputLength = 0;
	PIO_STACK_LOCATION pStack = NULL;

	pInputBuff = pOutputBuff = pIrp->AssociatedIrp.SystemBuffer;

	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uInputLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutputLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;

	uIoctrlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

	switch (uIoctrlCode)
	{
	case CTL_HELLO:
		DbgPrint("Hello iocontrol;\n");
		break;
	case CTL_PRINT:
		DbgPrint("%ws;\n", pInputBuff);
		break;
	case CTL_BYE:
		DbgPrint("Goodbye iocontrol;\n");
		break;
	default:
		DbgPrint("Unknown iocontrol;\n");
		break;
	}

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
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

NTSTATUS DispatchClose(PDEVICE_OBJECT p_DriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(p_DriverObject);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT p_DriverObject)
{
	UNICODE_STRING uLinkName = { 0 };
	RtlInitUnicodeString(&uLinkName, LINK_NAME);
	IoDeleteSymbolicLink(&uLinkName);
	IoDeleteDevice(p_DriverObject->DeviceObject);
	DbgPrint("Driver unloaded\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT p_DriverObject,
	PUNICODE_STRING pRegisterPath)
{
	UNREFERENCED_PARAMETER(pRegisterPath);
	UNICODE_STRING uDeviceName = {0};
	UNICODE_STRING uLinkName = { 0 };

	NTSTATUS ntStatus = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	ULONG i = 0;

	DbgPrint("Driver load begin\n");

	RtlInitUnicodeString(&uDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&uLinkName, LINK_NAME);

	//创建设备;
	ntStatus = IoCreateDevice(p_DriverObject, 0, &uDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateDevice failed: %x\n", ntStatus);
		return ntStatus;
	}

	//设置flags 通信方式;
	pDeviceObject->Flags |= DO_BUFFERED_IO;

	//关联符号;
	ntStatus = IoCreateSymbolicLink(&uLinkName, &uDeviceName);
	if (!NT_SUCCESS(ntStatus))
	{
		IoDeleteDevice(pDeviceObject);
		DbgPrint("IoCreateSymbolicLink failed: %x\n", ntStatus);
		return ntStatus;
	}

	//注册派遣函数;
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
	{
		p_DriverObject->MajorFunction[i] = DispatchCommon;//响应应用层公共消息;
	}

	p_DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;//响应应用层createfile消息;
	p_DriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;
	p_DriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWrite;
	p_DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctrl;
	p_DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DispatchClean;
	p_DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;

	//卸载函数;
	p_DriverObject->DriverUnload = DriverUnload;

	DbgPrint("Driver Load Ok;!\n");

	return STATUS_SUCCESS;
}
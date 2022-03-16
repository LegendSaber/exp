#pragma once
#include <cstdio>
#include <cstdlib>
#include <Windows.h>
#include "ntapi.h"
#pragma comment(linker, "/defaultlib:ntdll.lib")

void ShowError(char *msg, DWORD dwErrorCode);			// 打印错误信息
BOOL AllocateZeroMemory();								// 在0地址申请内存
PVOID GetHalDispatchTable();							// 获取HalDispatchTable的位置
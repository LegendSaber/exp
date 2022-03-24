#pragma once
#include <cstdio>
#include <cstdlib>
#include <Windows.h>
#include "ntapi.h"
#pragma comment(linker, "/defaultlib:ntdll.lib")

#pragma pack(1)
typedef struct _HEAD
{
	HANDLE h;
	DWORD clockObj;
}HEAD, *PHEAD;

typedef struct _THROBJHEAD
{
	HEAD h;
	PVOID pti;
}THROBJHEAD, *PTHROBJHEAD;

typedef struct _THRDESKHEAD
{
	THROBJHEAD h;
	PVOID rpdesk;
	PVOID pSelf;
}THRDESKHEAD, *PTHRDESKHEAD;
#pragma pack()

#ifdef _WIN64
typedef void* (NTAPI *lHMValidateHandle)(HWND h, int type);
#else
typedef void* (__fastcall *lHMValidateHandle)(HWND h, int type);
#endif

void ShowError(char *msg, DWORD dwErrorCode);			// 打印错误信息
BOOL AllocateZeroMemory();								// 在0地址申请内存
PVOID GetHalDispatchTable();							// 获取HalDispatchTable的位置
PVOID GetHMValidateHandle();							// 获取HMValidateHandle函数
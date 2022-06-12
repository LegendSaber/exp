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

void ShowError(char *msg, DWORD dwErrorCode);			// ��ӡ������Ϣ
BOOL AllocateZeroMemory();								// ��0��ַ�����ڴ�
PVOID GetHalQuerySystemInformation();					// ��ȡ����HalQuerySystemInformation������λ��
PVOID GetHMValidateHandle();							// ��ȡHMValidateHandle����
BOOL CallNtQueryIntervalProfile();						// ����NtQueryIntervalProfile����
BOOL CreateClipboard(DWORD dwSize);						// ͨ�����а�ʵ�ֵ�Ƭ����,�����dwSize + 0xC + 0x8���ڴ��
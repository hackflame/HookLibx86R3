// test.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "Hook.h"
#include "HookEngine.h"

typedef HMODULE (WINAPI *LoadLibraryProc)(_In_ LPCSTR lpLibFileName);

HMODULE WINAPI MyLoadLibraryA(_In_ LPCSTR lpLibFileName)
{
	printf("MyLoadLibraryA %s\r\n", lpLibFileName);
	Hook * hook =HookEngine::GetInstance()->FindHookByNewFuncAddr((ULONG)MyLoadLibraryA);
	LoadLibraryProc func = (LoadLibraryProc)hook->calloldFuncAddress;
	HMODULE hm = func(lpLibFileName);
	return hm;
}

int main()
{
	HMODULE hm = LoadLibraryA("ntdll.dll");
	auto hookengine = HookEngine::GetInstance();
	hookengine->AddHook((ULONG)LoadLibraryA, (ULONG)MyLoadLibraryA);
	hm = LoadLibraryA("ntdll.dll");
	//delete diaasm;
    return 0;
}


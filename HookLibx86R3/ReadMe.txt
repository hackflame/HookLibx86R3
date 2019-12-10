========================================================================
    静态库：HookLibx86R3 项目概述
========================================================================

环境WinAll,x86平台

小巧而强大的HOOK库，欢迎用的舒服

使用示例 在 test工程 test.cpp中 参考

作者:火哥 QQ群：1026716399 


#include "stdafx.h"
#include "Hook.h"
#include "HookEngine.h"

typedef HMODULE (WINAPI *LoadLibraryProc)(_In_ LPCSTR lpLibFileName);

HMODULE WINAPI MyLoadLibraryA(_In_ LPCSTR lpLibFileName)
{
	printf("MyLoadLibraryA %s\r\n", lpLibFileName);
	Hook * hook =HookEngine::GetInstance()->FindHookByNewFuncAddr((ULONG)MyLoadLibraryA);
	LoadLibraryProc func = (LoadLibraryProc)hook->GetCalloldFuncAddress();
	HMODULE hm = func(lpLibFileName);
	return hm;
}



ULONG __stdcall CallBack(PRegisterContext registerContext)
{
	
	printf("------------------------------------\r\n");
	return 0;
}

int main()
{
	//Hook 头部 示例
	HMODULE hm = LoadLibraryA("ntdll.dll");
	auto hookengine = HookEngine::GetInstance();
	hookengine->AddHook((ULONG)LoadLibraryA, (ULONG)MyLoadLibraryA);
	hm = LoadLibraryA("kernel32.dll");
	

	//Hook 修改寄存器示例代码
	PVOID p = GetProcAddress(hm, "LoadLibraryW");
	hookengine->AddHook((ULONG)GetProcAddress, (ULONG)CallBack, HookType::JmpHookGetRegister);
	p = GetProcAddress(hm, "LoadLibraryW");

	HookEngine::DistoryInstance();
    return 0;
}


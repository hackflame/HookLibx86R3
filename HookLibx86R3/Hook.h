#pragma once
/*
Author:火哥 QQ:471194425 群号：1026716399
*/
#include <Windows.h>
#include "HookEngine.h"

typedef struct _RegisterContext 
{
	ULONG EAX;
	ULONG ECX;
	ULONG EDX;
	ULONG EBX;
	ULONG ESP;
	ULONG EBP;
	ULONG ESI;
	ULONG EDI;
	ULONG EFLGS;
}RegisterContext,*PRegisterContext;

//JmpHookGetRegister 类型的原型
typedef ULONG(__stdcall *HookCallBack)(PRegisterContext registerContext);

class Hook
{
public:
	Hook();
	virtual ~Hook();
	//HOOK 开发者不需要调用这个函数，此函数是给引擎的
	bool InstallHook(ULONG oldFunc,ULONG newFunc, HookType type = HookType::JmpHeadHook);
	
	//是否已经HOOK
	bool isHook();

	//获取被HOOK的函数地址
	ULONG GetOldFunctionAddr();
	
	//获取新的函数地址
	ULONG GetNewFuncAddress();

	//如果是HookType::JmpHeadHook 可调用此函数 获取 被HOOK的函数地址
	/*
		typedef HMODULE (WINAPI *LoadLibraryProc)(_In_ LPCSTR lpLibFileName);

		HMODULE WINAPI MyLoadLibraryA(_In_ LPCSTR lpLibFileName)
		{
			printf("MyLoadLibraryA %s\r\n", lpLibFileName);
			Hook * hook =HookEngine::GetInstance()->FindHookByNewFuncAddr((ULONG)MyLoadLibraryA);
			//调用原来的函数
			LoadLibraryProc func = (LoadLibraryProc)hook->GetCalloldFuncAddress();
			HMODULE hm = func(lpLibFileName);
			return hm;
		}
	*/
	
	//如果是HookType::JmpHookGetRegister 此类型，那么是获得跳回的起始地址
	ULONG GetCalloldFuncAddress();


	
protected:
	
	virtual bool JmpHeadHook(ULONG oldFunc, ULONG newFunc);
	virtual bool JmpHookGetRegister(ULONG oldFunc, ULONG newFunc);
	virtual bool UnInstallHook();
	virtual int  CopyMemcpy(void * desc, void *src, size_t size);
	virtual bool UpdatePageCopyMemcpy(void * desc, void *src, size_t size);

private:
	char * GetMemory(int allocSize, bool * isAlloc);
	char * CreateDispatchFunc();
	ULONG calcResetCode(ULONG oldFunc, ULONG hookCodeSize);
private:
	char orginCode[30];
	int orginLen;
	ULONG oldFuncAddress;
	ULONG oldFuncRetAddress;
	ULONG newFuncAddress;
	ULONG calloldFuncAddress;
	HookType type;
	bool isHookSuccess;
	bool isAllocMemory;
	bool isCreateDispatchFuncAllocMemory;
	char * templateCode;
	int templateLen;
};


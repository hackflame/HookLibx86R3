#pragma once
/*
Author:»ð¸ç QQ:471194425 ÈººÅ£º1026716399
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


class Hook
{
public:
	Hook();
	virtual ~Hook();
	bool InstallHook(ULONG oldFunc,ULONG newFunc, HookType type = HookType::JmpHeadHook);
	ULONG calcResetCode(ULONG oldFunc,ULONG hookCodeSize);
protected:
	//virtual bool CallHeadHook(ULONG oldFunc, ULONG newFunc);
	//virtual bool CallNotHeadHook(ULONG oldFunc, ULONG newFunc);
	virtual bool JmpHeadHook(ULONG oldFunc, ULONG newFunc);
	virtual bool JmpNotHeadHook(ULONG oldFunc, ULONG newFunc);
	virtual bool UnInstallHook();
	virtual int  CopyMemcpy(void * desc, void *src, size_t size);
	virtual bool UpdatePageCopyMemcpy(void * desc, void *src, size_t size);
public:
	PRegisterContext reg;
	char orginCode[20];
	int orginLen;
	ULONG oldFuncAddress;
	ULONG oldFuncRetAddress;
	ULONG newFuncAddress;
	ULONG calloldFuncAddress;
	HookType type;
	bool isHookSuccess;
	
};


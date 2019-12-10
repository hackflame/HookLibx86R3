#pragma once
/*
Author:火哥 QQ:471194425 群号：1026716399
*/
#include <iostream>
#include <map>
#include <Windows.h>
enum HookType
{
	JmpHeadHook, //一般用于 Hook 头部 
	JmpHookGetRegister, //一般用于修改寄存器的HOOK
};

class Hook;

class HookEngine
{
public:
	virtual ~HookEngine();
	static HookEngine * GetInstance();
	static void  DistoryInstance();

	//添加HOOK 
	/*
	@param oldFunc  HOOK的函数地址
	@param newFunc  新的函数地址
	@param type     Hook的类型
	*/
	bool AddHook(ULONG oldFunc, ULONG newFunc, HookType type = HookType::JmpHeadHook);

	//根据替换 函数地址 查找到HOOK 对象
	Hook * FindHookByNewFuncAddr(ULONG newFunc);

	//根据HOOK 函数地址 查找到HOOK 对象
	Hook * FindHookByOldFuncAddr(ULONG oldFunc);

	//根据 替换函数地址 删除
	bool removeHook(ULONG newFunc);

	//删除所有 HOOK
	void removeAllHook();
private:
	HookEngine();
private:
	static HookEngine * hookEngine;
	std::map<ULONG, Hook*> hookMaps;
};


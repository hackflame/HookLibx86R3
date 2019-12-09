#include "stdafx.h"
#include "HookEngine.h"
#include "Hook.h"
/*
Author:»ð¸ç QQ:471194425 ÈººÅ£º1026716399
*/
HookEngine * HookEngine::hookEngine = nullptr;

HookEngine::HookEngine()
{
	hookMaps.clear();
}


HookEngine::~HookEngine()
{
	
	for (auto begin = hookMaps.begin(); begin != hookMaps.end(); begin++) 
	{
		auto hook = begin->second;
		delete hook;
	}

	hookMaps.clear();
}

HookEngine * HookEngine::GetInstance()
{
	if (!hookEngine) 
	{
		hookEngine = new HookEngine();
	}

	return hookEngine;
}

bool HookEngine::AddHook(ULONG oldFunc, ULONG newFunc, HookType type)
{
	Hook * hook = new Hook();
	bool isSuccess = hook->InstallHook(oldFunc, newFunc, type);
	if (isSuccess) 
	{
		hookMaps[newFunc] = hook;
	}
	else 
	{
		delete hook;
	}
	return isSuccess;
}

Hook * HookEngine::FindHookByNewFuncAddr(ULONG newFunc)
{
	return hookMaps[newFunc];
}

Hook * HookEngine::FindHookByOldFuncAddr(ULONG oldFunc)
{
	for (auto begin = hookMaps.begin(); begin != hookMaps.end(); begin++)
	{
		auto hook = begin->second;
		if (hook->oldFuncAddress == oldFunc) 
		{
			return hook;
		}
	}

	return nullptr;
}

void HookEngine::DistoryInstance()
{
	if (hookEngine) delete hookEngine;
	hookEngine = nullptr;
}
#include "stdafx.h"
#include "Hook.h"
#include "disasm.h"
/*
Author:火哥 QQ:471194425 群号：1026716399
*/

void __declspec(naked) HookHeadDispatch() 
{
	
}

int Hook::CopyMemcpy(void * desc, void *src, size_t size)
{
	char * tempSrc = (char *)src;
	char * tempDesc = (char *)desc;
	while (size-- != 0)
	{
		*tempDesc++ = *tempSrc++;
	}
	return 0;
} 

bool Hook::UpdatePageCopyMemcpy(void * desc, void *src, size_t size)
{
	DWORD orginProtect = 0;
	if (VirtualProtect((LPVOID)desc, size, PAGE_EXECUTE_READWRITE, &orginProtect))
	{
		this->CopyMemcpy((void*)desc, src, size);
		VirtualProtect((LPVOID)desc, size, orginProtect, &orginProtect);
		return true;
	}

	return false;
}

bool Hook::InstallHook(ULONG oldFunc, ULONG newFunc, HookType type)
{
	if (this->isHookSuccess) return true;

	bool isResult = false;
	switch(type)
	{
	/*
	case HookType::CallHeadHook:
		isResult = this->CallHeadHook(oldFunc, newFunc);
		break;
	case HookType::CallNotHeadHook:
		isResult = this->CallNotHeadHook(oldFunc, newFunc);
		break;
	*/
	case HookType::JmpHeadHook:
		isResult = this->JmpHeadHook(oldFunc, newFunc);
		break;
	case HookType::JmpNotHeadHook:
		isResult = this->JmpNotHeadHook(oldFunc, newFunc);
		break;
	}
	if (isResult) 
	{
		this->type = type;
		this->isHookSuccess = true;
		
	}
	return isResult;
}

/*
bool Hook::CallHeadHook(ULONG oldFunc, ULONG newFunc)
{
	return false;
}

bool Hook::CallNotHeadHook(ULONG oldFunc, ULONG newFunc)
{
	return false;
}
*/

ULONG Hook::calcResetCode(ULONG oldFunc, ULONG hookCodeSize)
{
	size_t sizeTotal = 0;
	//计算长度
	Disasm disasm;
	do
	{
		sizeTotal += disasm.DisasmCode((PUCHAR)oldFunc + sizeTotal, 16);
	} while (sizeTotal < hookCodeSize);
	return sizeTotal;
}

bool Hook::JmpHeadHook(ULONG oldFunc, ULONG newFunc)
{
	char bufCode[] = {0xe9,0,0,0,0};
	HMODULE module = LoadLibraryA("ntdll.dll");
	if (!module) return false;

	size_t sizeTotal = this->calcResetCode(oldFunc, sizeof(bufCode));
	this->CopyMemcpy(this->orginCode, (PUCHAR)oldFunc, sizeTotal);
	this->orginLen = sizeTotal;
	this->oldFuncAddress = oldFunc;
	this->oldFuncRetAddress = oldFunc + sizeTotal;
	this->newFuncAddress = newFunc;
	
	//修正
	*(PULONG)&bufCode[1] =(ULONG)newFunc - (oldFunc + 5);

	//查找ntdll 空白处
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((char *)module + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((char*)pNts +sizeof(pNts->Signature) + 
		sizeof(pNts->FileHeader) + pNts->FileHeader.SizeOfOptionalHeader);

	char * start = (pSection->VirtualAddress + (char *)module);
	int sc = pSection->SizeOfRawData % pNts->OptionalHeader.SectionAlignment;
	size_t sectionSize = pNts->OptionalHeader.SectionAlignment - sc + pSection->SizeOfRawData;
	
	sizeTotal = this->orginLen + 5;
	char * retCallCode = new char[sizeTotal];
	memset(retCallCode, 0, sizeTotal);
	bool isFindSpace = false;
	for (ULONG i = 0; i < sectionSize - sizeTotal; i++)
	{
		if (memcmp(retCallCode, start + i, sizeTotal) == 0)
		{
			isFindSpace = true;
			start += i;
			break;
		}
	}

	

	if (!isFindSpace) 
	{
		start = (char *)VirtualAlloc(NULL, sizeTotal, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (start == NULL) 
		{
			delete[] retCallCode;
			return false;
		}
		
	}

	

	this->CopyMemcpy(retCallCode, this->orginCode, this->orginLen);
	retCallCode[this->orginLen] = 0xE9;
	*(PULONG)&retCallCode[this->orginLen + 1] = this->oldFuncRetAddress - (ULONG)(start + this->orginLen + 5);
	bool isSuccess = this->UpdatePageCopyMemcpy(start, retCallCode, sizeTotal);

	delete[] retCallCode;
	if (!isSuccess) 
	{
		if (!isFindSpace) VirtualFree(start, sizeTotal, MEM_RELEASE);
		return isSuccess;
	}

	this->calloldFuncAddress = (ULONG)start;
	//开始HOOK
	isSuccess = this->UpdatePageCopyMemcpy((void*)this->oldFuncAddress, bufCode, sizeof(bufCode));
	return isSuccess;

}


bool Hook::JmpNotHeadHook(ULONG oldFunc, ULONG newFunc)
{
	return false;

}


Hook::Hook()
{
	this->isHookSuccess = false;
	this->orginLen = 0;
	memset(this->orginCode, 0, 20);
	this->oldFuncAddress = 0;
	this->oldFuncRetAddress = 0;
	this->newFuncAddress = 0;
	this->calloldFuncAddress = 0;
}


bool Hook::UnInstallHook()
{
	if (!this->isHookSuccess) return false;
	return this->UpdatePageCopyMemcpy((void*)this->oldFuncAddress, this->orginCode, this->orginLen);
}

Hook::~Hook()
{
	this->UnInstallHook();
}

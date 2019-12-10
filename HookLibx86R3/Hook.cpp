#include "stdafx.h"
#include "Hook.h"
#include "disasm.h"
/*
Author:火哥 QQ:471194425 群号：1026716399
*/

ULONG __stdcall HookRegisterDispatch(Hook * hook, PRegisterContext registerContext)
{

	HookCallBack callback = (HookCallBack )hook->GetNewFuncAddress();
	callback(registerContext);
	return hook->GetCalloldFuncAddress();
}

void __declspec(naked) AsmHookRegisterDispatch() 
{
	__asm 
	{
		//xchg dword ptr [esp], eax;
		//push eax;
		//lea eax, dword ptr ds : [0x12345678];
		pop ebx;
		xchg eax,dword ptr[esp];
		pushfd;
		push edi;
		push esi;
		push ebp;
		push esp;
		push ebx;
		push edx;
		push ecx;
		push eax;
		
		push esp;
		push [esp + 0x28];
		lea edx, dword ptr ds : [HookRegisterDispatch];
		call edx;
		mov [esp - 0x4], eax;
		pop eax;
		pop ecx;
		pop edx;
		pop ebx;
		pop esp;
		pop ebp;
		pop esi;
		pop edi;
		popfd;
		add esp, 4;
		jmp [esp - 0x2c];
	}
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
	
	case HookType::JmpHeadHook:
		isResult = this->JmpHeadHook(oldFunc, newFunc);
		break;
	case HookType::JmpHookGetRegister:
		isResult = this->JmpHookGetRegister(oldFunc, newFunc);
		break;
	}
	if (isResult) 
	{
		this->type = type;
		this->isHookSuccess = true;
		
	}
	return isResult;
}


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

char * Hook::GetMemory(int allocSize,bool * isAlloc)
{
	HMODULE module = LoadLibraryA("ntdll.dll");
	char * memory = nullptr;
	bool m_isAlloc = false;
	if (!module)
	{
		memory = (char *)VirtualAlloc(NULL, allocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		return memory;
	}

	//查找ntdll 空白处
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((char *)module + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((char*)pNts + sizeof(pNts->Signature) +
		sizeof(pNts->FileHeader) + pNts->FileHeader.SizeOfOptionalHeader);

	char * start = (pSection->VirtualAddress + (char *)module);
	int sc = pSection->SizeOfRawData % pNts->OptionalHeader.SectionAlignment;
	size_t sectionSize = pNts->OptionalHeader.SectionAlignment - sc + pSection->SizeOfRawData;

	
	char * retCallCode = new char[allocSize];
	memset(retCallCode, 0, allocSize);
	bool isFindSpace = false;
	for (ULONG i = 0; i < sectionSize - allocSize; i++)
	{
		if (memcmp(retCallCode, start + i, allocSize) == 0)
		{
			m_isAlloc = false;
			isFindSpace = true;
			start += i;
			break;
		}
	}
	
	delete[] retCallCode;

	if (!isFindSpace)
	{
		m_isAlloc = true;
		start = (char *)VirtualAlloc(NULL, allocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!start) m_isAlloc = false;
	}
	*isAlloc = m_isAlloc;
	memory = start;
	return memory;
}

bool Hook::JmpHeadHook(ULONG oldFunc, ULONG newFunc)
{
	char bufCode[] = {0xe9,0,0,0,0};
	size_t sizeTotal = this->calcResetCode(oldFunc, sizeof(bufCode));
	this->CopyMemcpy(this->orginCode, (PUCHAR)oldFunc, sizeTotal);
	this->orginLen = sizeTotal;
	this->oldFuncAddress = oldFunc;
	this->oldFuncRetAddress = oldFunc + sizeTotal;
	this->newFuncAddress = newFunc;
	
	//修正
	*(PULONG)&bufCode[1] =(ULONG)newFunc - (oldFunc + 5);

	sizeTotal = this->orginLen + 5;
	char * start = this->GetMemory(sizeTotal,&this->isAllocMemory);
	if (start == nullptr) return false;

	char * retCallCode = new char[sizeTotal];

	this->CopyMemcpy(retCallCode, this->orginCode, this->orginLen);
	retCallCode[this->orginLen] = 0xE9;
	*(PULONG)&retCallCode[this->orginLen + 1] = this->oldFuncRetAddress - (ULONG)(start + this->orginLen + 5);
	bool isSuccess = this->UpdatePageCopyMemcpy(start, retCallCode, sizeTotal);
	delete[] retCallCode;

	if (!isSuccess) 
	{
		if (this->isAllocMemory) VirtualFree(start, sizeTotal, MEM_RELEASE);
		return isSuccess;
	}

	this->calloldFuncAddress = (ULONG)start;
	//开始HOOK
	isSuccess = this->UpdatePageCopyMemcpy((void*)this->oldFuncAddress, bufCode, sizeof(bufCode));
	return isSuccess;

} 

char * Hook::CreateDispatchFunc()
{
	char * code  = this->GetMemory(20,&this->isCreateDispatchFuncAllocMemory);
	if (code == nullptr) return nullptr;
	char templateCode[] = 
	{
		0x50,
		0x8D,0x05,0x78,0x56,0x34,0x12,
		0x53,
		0x8D,0x1D,0x78,0x56,0x34,0x12,
		0xFF,0xE3
	};
	*(PULONG)&templateCode[3] = (ULONG)this;
	*(PULONG)&templateCode[10] = (ULONG)AsmHookRegisterDispatch;

	this->UpdatePageCopyMemcpy(code, templateCode, sizeof(templateCode));
	this->templateLen = 20;
	this->templateCode = code;

	return code;
}


bool Hook::JmpHookGetRegister(ULONG oldFunc, ULONG newFunc)
{
	char bufCode[] = {0xe9,0,0,0,0 };
	size_t sizeTotal = this->calcResetCode(oldFunc, sizeof(bufCode));
	this->CopyMemcpy(this->orginCode, (PUCHAR)oldFunc, sizeTotal);
	this->orginLen = sizeTotal;
	this->oldFuncAddress = oldFunc;
	this->oldFuncRetAddress = oldFunc + sizeTotal;
	this->newFuncAddress = newFunc;

	char * tempCode = this->CreateDispatchFunc();
	if (tempCode == nullptr) return false;
	//修正
	//*(PULONG)&bufCode[3] = (ULONG)this;
	*(PULONG)&bufCode[1] = (ULONG)tempCode - (oldFunc + sizeof(bufCode));

	sizeTotal += 5;
	char * start = this->GetMemory(sizeTotal,&this->isAllocMemory);
	if (start == nullptr) return false;

	char * retCallCode = new char[sizeTotal];
	this->CopyMemcpy(retCallCode, this->orginCode, this->orginLen);
	retCallCode[this->orginLen] = 0xE9;
	*(PULONG)&retCallCode[this->orginLen + 1] = this->oldFuncRetAddress - (ULONG)(start + this->orginLen + 5);

	bool isSuccess = this->UpdatePageCopyMemcpy(start, retCallCode, sizeTotal);
	delete[] retCallCode;

	if (!isSuccess)
	{
		if (this->isAllocMemory) VirtualFree(start, sizeTotal, MEM_RELEASE);
		return isSuccess;
	}
	this->calloldFuncAddress = (ULONG)start;
	//开始HOOK
	isSuccess = this->UpdatePageCopyMemcpy((void*)this->oldFuncAddress, bufCode, sizeof(bufCode));
	return isSuccess;

}


Hook::Hook()
{
	this->isHookSuccess = false;
	this->orginLen = 0;
	memset(this->orginCode, 0, 30);
	this->oldFuncAddress = 0;
	this->oldFuncRetAddress = 0;
	this->newFuncAddress = 0;
	this->calloldFuncAddress = 0;
	this->isAllocMemory = false;
	this->isCreateDispatchFuncAllocMemory = false;
	this->templateCode = nullptr;
	this->templateLen = 0;
}


bool Hook::UnInstallHook()
{
	if (!this->isHookSuccess) return false;
	return this->UpdatePageCopyMemcpy((void*)this->oldFuncAddress, this->orginCode, this->orginLen);
}

Hook::~Hook()
{
	this->UnInstallHook();
	if (this->isCreateDispatchFuncAllocMemory)
	{
		VirtualFree(this->templateCode, templateLen, MEM_RELEASE);
	}

	if (this->isAllocMemory)
	{
		VirtualFree((char *)this->calloldFuncAddress, this->orginLen+5, MEM_RELEASE);
	}
}


bool Hook::isHook()
{
	return this->isHookSuccess;
}

ULONG Hook::GetOldFunctionAddr()
{
	return this->oldFuncAddress;
}

ULONG Hook::GetNewFuncAddress()
{
	return this->newFuncAddress;
}

ULONG Hook::GetCalloldFuncAddress()
{
	return this->calloldFuncAddress;
}
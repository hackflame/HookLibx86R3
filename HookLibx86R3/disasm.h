#ifndef _DISASM_H
#define _DISASM_H
#endif

#pragma once
#include <Windows.h>
#include <iostream>
using namespace std;
class Disasm 
{
public:
	ULONG  cmdtype;
	ULONG  error;
	ULONG  warnings;

	ULONG  DataSize;
	ULONG  AddrSize;
	LONG   SegPrefix;
	ULONG  HasRM;
	ULONG  HasSIB;
	ULONG  DispSize;
	ULONG  ImmSize;

	PUCHAR Cmd;
	ULONG  RemainingSize;

	ULONG DisasmCode(PUCHAR Src, ULONG SrcSize);
	ULONG DisasmCodeStr(PCHAR Src, ULONG SrcSize);
private:
	VOID DecodeIM(ULONG constsize);
	VOID DecodeVX(VOID);
	void DecodeRJ(ULONG offsize);
	VOID DecodeMR(ULONG type);
	UCHAR CharToHex(UCHAR * ch);
	string StrCodeToHexStr(string code);
};



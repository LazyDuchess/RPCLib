#pragma once
#include "pch.h"
#include <string>

void MakeJMP(BYTE* pAddress, DWORD dwJumpTo, DWORD dwLen);
void Nop(BYTE* pAddress, DWORD dwLen);;
void WriteToMemory(DWORD addressToWrite, void* valueToWrite, int byteNum);
bool memory_readable(void* ptr, size_t byteCount);

char* TSGetLotXScale();
char* TSGetLotYScale();

int TSGetGameMode();

int TSGetSimBinPointer();

extern char* modBase;

extern char lotXSize[MAX_PATH];
extern char lotYSize[MAX_PATH];

static wchar_t modName[MAX_PATH];
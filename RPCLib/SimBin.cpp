#pragma once
#include "pch.h"
#include "SimBin.h"
#include "common.h"

char* jumpBackAddr;

__declspec(naked) void makeNewCharacterHook()
{
    __asm {
		call TSGetSimBinPointer
		mov ecx, eax
		mov [esp+0x70], eax
		mov eax, 0x1
		xor ebx, ebx
		cmp ecx, ebx
        jmp jumpBackAddr
    }
}

namespace SimBin
{
	void Run() {
		jumpBackAddr = modBase + 0x71AB19 + 0xA;
		MakeJMP((BYTE*)modBase + 0x71AB19, (DWORD)makeNewCharacterHook, 0xA);
	}
}
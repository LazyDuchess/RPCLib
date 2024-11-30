#include "pch.h"
#include "common.h"
#include <string>

std::string lotXSizeParam = "lotXScale";
std::string lotYSizeParam = "lotYScale";

//There has to be a better way.....
std::string* lotXSizeParamPtr = &lotXSizeParam;
std::string* lotYSizeParamPtr = &lotYSizeParam;

char* shaderBackAddr;

char* pageLocation;

//Hook floor shader stuff to send the lot size.
__declspec(naked) void shaderHook()
{
    __asm {

        push eax
        call TSGetLotXScale
        push eax
        push lotXSizeParamPtr
        mov ecx, esi
        call dword ptr [ebp + 0x34]
        call TSGetLotYScale
        push eax
        push lotYSizeParamPtr
        mov ecx, esi
        call dword ptr [ebp + 0x34]
        pop eax
        push eax
        push [pageLocation]
        jmp shaderBackAddr
    }
}

DWORD WINAPI FloorShaderThread(LPVOID param)
{
    HMODULE module = GetModuleHandleA(NULL);
    pageLocation = modBase + 0xE3696C;
    shaderBackAddr = modBase + 0x6E5281 + 0x6;
    MakeJMP((BYTE*)modBase + 0x6E5281, (DWORD)shaderHook, 0x6);
    return 0;
}
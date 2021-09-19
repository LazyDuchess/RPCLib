// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#define GAME_VERSION_JMP 0x1B3423
#define SIMANTICS_ITERATIONS_RETURN 0x52C264
#define SIMANTICS_ITERATIONS_GLOBAL 0x140b8d4
#define SIMANTICS_NEW_ITERATIONS 1000000

#define UNUSED_GLOBAL_ADDR_CMP 0x474680+4
#define UNUSED_GLOBAL_ADDR_MOV UNUSED_GLOBAL_ADDR_CMP+7

#define GROUPS_CACHE0 0x33C9F0
#define GROUPS_CACHE1 0x342A80

char version_code[] = { 0xE9, 0x25, 0x01, 0x00, 0x00, 0x90 };

char unusedGlobalReturn[] = { 0x01 };
 
//This is just ret in assembly.
char ret_code[] = { 0xC3 };

char* modBase;

DWORD newIterations = SIMANTICS_NEW_ITERATIONS;

void WriteToMemory(DWORD addressToWrite, void* valueToWrite, int byteNum)
{
    //used to change our file access type, stores the old
    //access type and restores it after memory is written
    unsigned long OldProtection;
    //give that address read and write permissions and store the old permissions at oldProtection
    VirtualProtect((LPVOID)(addressToWrite), byteNum, PAGE_EXECUTE_READWRITE, &OldProtection);

    //write the memory into the program and overwrite previous value
    memcpy((LPVOID)addressToWrite, valueToWrite, byteNum);

    //reset the permissions of the address back to oldProtection after writting memory
    VirtualProtect((LPVOID)(addressToWrite), byteNum, OldProtection, NULL);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        modBase = (char*)GetModuleHandleA(NULL);

        //Replace JE with a JMP instruction to skip Game Version attachment to TS::MainToolbar.
        WriteToMemory((DWORD)modBase + GAME_VERSION_JMP, version_code, sizeof(version_code) / sizeof(*version_code));

        //Hook SimAntics Iterations.
        WriteToMemory((DWORD)modBase + SIMANTICS_ITERATIONS_RETURN + 1, &newIterations, 4);
        WriteToMemory(SIMANTICS_ITERATIONS_GLOBAL, &newIterations, 4);

        //Make first Unused Global return 1, so modders can detect increased SimAntics primitives and perhaps other things.
        WriteToMemory((DWORD)modBase + UNUSED_GLOBAL_ADDR_CMP, unusedGlobalReturn, sizeof(unusedGlobalReturn) / sizeof(unusedGlobalReturn));
        WriteToMemory((DWORD)modBase + UNUSED_GLOBAL_ADDR_MOV, unusedGlobalReturn, sizeof(unusedGlobalReturn) / sizeof(unusedGlobalReturn));

        //Dummy Groups.cache saving and loading out cause it's buggy bullshit.
        WriteToMemory((DWORD)modBase + GROUPS_CACHE0, ret_code, sizeof(ret_code) / sizeof(ret_code));
        WriteToMemory((DWORD)modBase + GROUPS_CACHE1, ret_code, sizeof(ret_code) / sizeof(ret_code));
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


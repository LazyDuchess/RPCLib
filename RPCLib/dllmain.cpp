// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include "common.h"
#include "hotkeys.h"
#include "floorshaderhook.h"
#include "SimBin.h"

#define GAME_VERSION_JMP 0x1B3423
#define SIMANTICS_ITERATIONS_RETURN 0x52C264
#define SIMANTICS_ITERATIONS_GLOBAL 0x140b8d4
#define SIMANTICS_NEW_ITERATIONS 1000000

#define UNUSED_GLOBAL_ADDR_CMP 0x474680+4
#define UNUSED_GLOBAL_ADDR_MOV UNUSED_GLOBAL_ADDR_CMP+7

#define GROUPS_CACHE0 0x33C9F0
#define GROUPS_CACHE1 0x342A80

#define EP_OVERRIDE_ADDR 0x8F5A70

#define IMPOSTER_RES_ADDR 0x607A6D
#define IMPOSTER_UNK_ADDR 0x607A7D
#define IMPOSTER_BLUR_ADDR 0x607AA2
#define IMPOSTER_SLICE_ADDR 0x607AC8

#define SHADOW_RES_ADDR 0x693877
#define SHADOW_BLUR_ADDR 0x693855

#define DESIGN_PRICE_ADDR 0xBEA38
#define DESIGN_PRICE_ADDR1 0xBE7AD
#define DESIGN_PRICE_ADDR2 0xBE7E4

#define ZODIAC_SIGN_ADDR 0x185469

bool simBinNPCs = false;

bool untieZodiac = false;

bool oceanReflections = false;

bool customCamera = 0;

bool hotkeys = true;

int hqImposters = 0;

int shadowRes = 128;
int shadowBlur = 3;

char version_code[] = { 0xE9, 0x25, 0x01, 0x00, 0x00, 0x90 };

char jmp_code[] = { 0xEB };

char unusedGlobalReturn[] = { 0x02 };

int designToolPrice = 15;

char* designHookReturn1;
char* designHookReturn2;
char* designHookReturn3;

char* modBase;

__declspec(naked) void designHook1()
{
    __asm {
        //Only change if it doesn't equal zero
            push eax
            mov eax, [esi+0x58]
            cmp eax, 0
            pop eax
            je keep
            push [designToolPrice]
            jmp fin

            fin:
            mov ecx,esi
            jmp designHookReturn1

            keep:
            push[esi + 0x58]
            jmp fin
    }
}

__declspec(naked) void designHook2()
{
    __asm {
        //Only change if it doesn't equal zero
        push eax
        mov eax, [esi + 0x58]
        cmp eax, 0
        pop eax
        je keep
        push[designToolPrice]
        jmp fin

        fin :
        mov eax, [ecx]
            jmp designHookReturn2

            keep :
        push[esi + 0x58]
            jmp fin
    }
}

__declspec(naked) void designHook3()
{
    __asm {
        //Only change if it doesn't equal zero
        push eax
        mov eax, [esi + 0x58]
        cmp eax, 0
        pop eax
        je keep
        push[designToolPrice]
        jmp fin

        fin :
        mov ebx, [edi]
            jmp designHookReturn3

            keep :
        push[esi + 0x58]
            jmp fin
    }
}

//This is just ret in assembly.
char ret_code[] = { 0xC3 };

std::wstring folder;

DWORD newIterations = SIMANTICS_NEW_ITERATIONS;

bool selectEPs = false;
DWORD epMask = 1;

char epOverrideHook[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };

inline bool exists(const std::wstring& name) {
    struct _stat buffer;
    return (_wstat(name.c_str(), &buffer) == 0);
}

bool multiThreadedGame = true;

void LoadSettings() {
    wchar_t fullPath[MAX_PATH];
    wcscpy_s(fullPath, folder.c_str());
    wcscat_s(fullPath, L"\\RPCLib.cfg");
    if (!exists(fullPath))
    {
        wcscpy_s(fullPath, folder.c_str());
        wcscat_s(fullPath, L"\\mods\\RPCLib.cfg");
    }
    if (exists(fullPath))
    {
        std::wifstream file(fullPath);
        std::wstring str;
        while (std::getline(file, str))
        {
            str.erase(std::remove(str.begin(), str.end(), ' '), str.end());
            if (wcslen(str.c_str()) > 0)
            {
                if (wcscmp(str.substr(0, 1).c_str(), L"#"))
                {
                    std::wstring temp;
                    std::vector<std::wstring> split;
                    std::wstringstream wss(str);
                    while (std::getline(wss, temp, L'='))
                    {
                        split.push_back(temp);
                    }
                    std::wstring value = split[1];
                    int valuehex;
                    std::wstringstream ss;
                    ss << std::hex << value;
                    ss >> valuehex;
                    int intValue = std::stoi(split[1]);
                    if (!wcscmp(split[0].c_str(), L"OceanReflections"))
                    {
                        if (intValue > 0)
                            oceanReflections = true;
                    }

                    if (!wcscmp(split[0].c_str(), L"UntieSign"))
                    {
                        if (intValue > 0)
                            untieZodiac = true;
                    }

                    if (!wcscmp(split[0].c_str(), L"EPSelect"))
                    {
                        if (intValue > 0)
                            selectEPs = true;
                    }

                    if (!wcscmp(split[0].c_str(), L"Hotkeys"))
                    {
                        if (intValue <= 0)
                            hotkeys = false;
                    }

                    if (!wcscmp(split[0].c_str(), L"EPMask"))
                    {
                        epMask = static_cast<int>(valuehex);
                    }

                    if (!wcscmp(split[0].c_str(), L"DesignToolCost"))
                    {
                        designToolPrice = intValue;
                    }

                    if (!wcscmp(split[0].c_str(), L"ImposterRes"))
                    {
                        hqImposters = intValue;
                    }

                    if (!wcscmp(split[0].c_str(), L"ShadowRes"))
                    {
                        shadowRes = intValue;
                    }

                    if (!wcscmp(split[0].c_str(), L"ShadowBlur"))
                    {
                        shadowBlur = intValue;
                    }

                    if (!wcscmp(split[0].c_str(), L"SingleCoreGame"))
                    {
                        if (intValue > 0)
                            multiThreadedGame = false;
                    }

                    if (!wcscmp(split[0].c_str(), L"SimBinNPCs"))
                    {
                        if (intValue > 0)
                            simBinNPCs = true;
                    }
                }
            }
        }
        file.close();
    }
}

// From ThirteenAG's NFSU2 patch https://github.com/ThirteenAG/WidescreenFixesPack/pull/1045
static constexpr DWORD AffinityMask = 1;
HANDLE WINAPI CustomCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    HANDLE hThread = CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    if (hThread)
    {
        SetThreadAffinityMask(hThread, AffinityMask);
    }
    return hThread;
}

void Execute() {

    // From ThirteenAG's NFSU2 patch https://github.com/ThirteenAG/WidescreenFixesPack/pull/1045
    if (!multiThreadedGame)
    {
        HINSTANCE					hInstance = GetModuleHandle(nullptr);
        PIMAGE_NT_HEADERS			ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hInstance + ((PIMAGE_DOS_HEADER)hInstance)->e_lfanew);
        PIMAGE_IMPORT_DESCRIPTOR	pImports = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hInstance + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        // Find KERNEL32.DLL
        for (; pImports->Name != 0; pImports++)
        {
            if (!_stricmp((const char*)((DWORD_PTR)hInstance + pImports->Name), "KERNEL32.DLL"))
            {
                if (pImports->OriginalFirstThunk != 0)
                {
                    PIMAGE_IMPORT_BY_NAME* pFunctions = (PIMAGE_IMPORT_BY_NAME*)((DWORD_PTR)hInstance + pImports->OriginalFirstThunk);
                    for (ptrdiff_t j = 0; pFunctions[j] != nullptr; j++)
                    {
                        if (!strcmp((const char*)((DWORD_PTR)hInstance + pFunctions[j]->Name), "CreateThread"))
                        {
                            // Overwrite the address with the address to a custom CreateThread
                            DWORD dwProtect[2];
                            DWORD_PTR* pAddress = &((DWORD_PTR*)((DWORD_PTR)hInstance + pImports->FirstThunk))[j];
                            VirtualProtect(pAddress, sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &dwProtect[0]);
                            *pAddress = (DWORD_PTR)CustomCreateThread;
                            VirtualProtect(pAddress, sizeof(DWORD_PTR), dwProtect[0], &dwProtect[1]);
                            SetThreadAffinityMask(GetCurrentThread(), AffinityMask);
                            break;
                        }
                    }
                }
            }
        }
    }
    
    GetModuleFileName(NULL, modName, MAX_PATH);
    std::wstring::size_type pos = std::wstring(modName).find_last_of(L"\\/");
    folder = std::wstring(modName).substr(0, pos);

    //Replace JE with a JMP instruction to skip Game Version attachment to TS::MainToolbar.
    WriteToMemory((DWORD)modBase + GAME_VERSION_JMP, version_code, sizeof(version_code) / sizeof(*version_code));

    //Hook SimAntics Iterations.
    WriteToMemory((DWORD)modBase + SIMANTICS_ITERATIONS_RETURN + 1, &newIterations, 4);
    WriteToMemory(SIMANTICS_ITERATIONS_GLOBAL, &newIterations, 4);

    //Make first Unused Global return 1, so modders can detect increased SimAntics primitives and perhaps other things.
    //09/30/2021 - Now returns 2, with the addition of hotkeys.
    WriteToMemory((DWORD)modBase + UNUSED_GLOBAL_ADDR_CMP, unusedGlobalReturn, sizeof(unusedGlobalReturn) / sizeof(*unusedGlobalReturn));
    WriteToMemory((DWORD)modBase + UNUSED_GLOBAL_ADDR_MOV, unusedGlobalReturn, sizeof(unusedGlobalReturn) / sizeof(*unusedGlobalReturn));

    //Dummy Groups.cache saving and loading out cause it's buggy bullshit.
    WriteToMemory((DWORD)modBase + GROUPS_CACHE0, ret_code, sizeof(ret_code) / sizeof(*ret_code));
    WriteToMemory((DWORD)modBase + GROUPS_CACHE1, ret_code, sizeof(ret_code) / sizeof(*ret_code));

    LoadSettings();

    if (simBinNPCs)
    {
        SimBin::Run();
    }

    if (untieZodiac)
    {
        WriteToMemory((DWORD)modBase + ZODIAC_SIGN_ADDR, jmp_code, sizeof(jmp_code) / sizeof(*jmp_code));
    }

    if (oceanReflections)
    {
        Nop((BYTE*)modBase + 0x6808D8, 2);
        Nop((BYTE*)modBase + 0x6808E0, 2);
        Nop((BYTE*)modBase + 0x6808EA, 2);
        Nop((BYTE*)modBase + 0x6808EE, 2);
        Nop((BYTE*)modBase + 0x6808F2, 2);
    }

    //Configurable values below

    if (designToolPrice != 15)
    {
        designHookReturn1 = modBase + DESIGN_PRICE_ADDR + 0x5;
        MakeJMP((BYTE*)modBase + DESIGN_PRICE_ADDR, (DWORD)designHook1, 0x5);

        designHookReturn2 = modBase + DESIGN_PRICE_ADDR1 + 0x5;
        MakeJMP((BYTE*)modBase + DESIGN_PRICE_ADDR1, (DWORD)designHook2, 0x5);

        designHookReturn3 = modBase + DESIGN_PRICE_ADDR2 + 0x5;
        MakeJMP((BYTE*)modBase + DESIGN_PRICE_ADDR2, (DWORD)designHook3, 0x5);
    }

    if (hqImposters > 0)
    {
        int val = 1024;
        if (hqImposters == 1 || hqImposters == 3)
            val = 512;
        WriteToMemory((DWORD)modBase + IMPOSTER_RES_ADDR + 1, &val, 4);
        
        WriteToMemory((DWORD)modBase + IMPOSTER_UNK_ADDR + 6, &val, 4);
        val = 64;
        if (hqImposters == 3)
            val = 32;
        WriteToMemory((DWORD)modBase + IMPOSTER_BLUR_ADDR + 6, &val, 4);
        if (hqImposters == 3)
            val = 24;
        WriteToMemory((DWORD)modBase + IMPOSTER_SLICE_ADDR + 6, &val, 4);
    }

    if (shadowRes != 128)
        WriteToMemory((DWORD)modBase + SHADOW_RES_ADDR + 1, &shadowRes, 4);
    if (shadowBlur != 3)
        WriteToMemory((DWORD)modBase + SHADOW_BLUR_ADDR + 1, &shadowBlur, 4);

    if (selectEPs)
    {
        WriteToMemory((DWORD)modBase + EP_OVERRIDE_ADDR, epOverrideHook, sizeof(epOverrideHook) / sizeof(*epOverrideHook));
        WriteToMemory((DWORD)modBase + EP_OVERRIDE_ADDR + 1, &epMask, 4);
    }
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
        if (hotkeys)
            CreateThread(0, 0, HotkeyThread, hModule, 0, 0);
        CreateThread(0, 0, FloorShaderThread, hModule, 0, 0);
        Execute();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


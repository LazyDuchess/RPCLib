#include "pch.h"
#include <string>
#include <fstream>
#include <vector>
#include <sstream>
#include <map>
#include <iostream>
#include <Psapi.h>
#include "common.h"

//Some offsets to make stuff easier. I eventually gave up on making these defines though :(

#define GLOBAL_POINTER 0x010890C4
#define GLOBAL_POINTER_OFFSET 0x82

#define CONTROLS_OFFSET 0x10AD2C4

class sHotKey {
public:
    int decimalValue;
    bool hold;
    int gameMode;
};

//Map virtual keycodes to ints to give to SimAntics
std::map<int, sHotKey*> hotkeyMap;

int lastKey = -1;
bool consoleOpen = false;
short lastHouse = -2;

char* consoleBackAddr;

//Hook the console appearing and disappearing. Huuuge hack but seems to work ok.
__declspec(naked) void consoleHook()
{
    __asm {
        //Check a few magic bytes to make sure this is the console. Very hacky.
        cmp dword ptr[esi + 0xE4], 0x00FFFFFF
        jne back
        cmp dword ptr[esi], 0x0120C650
        jne back
        jmp truef

        back :
        //Continue the original behavior and return
        test byte ptr[esi + 0x000000D8], 0x08
            jmp consoleBackAddr

            truef :
        //3 means the console is open, 2 means it's not.
        cmp byte ptr[esi + 0x000000D8], 0x03
            je trueo
            mov consoleOpen, 0
            jmp back

            trueo :
        mov consoleOpen, 1
            jmp back
    }
}

//Thingy that changes the unused global. nop it out!
char lookup[] = { 0x66, 0x89, 0x91, 0x82, 0x00, 0x00, 0x00 };
char nopedLookup[] = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };

void WriteToMemory(DWORD addressToWrite, char* valueToWrite, int byteNum)
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

char* ScanBasic(char* pattern, int patternLen, char* begin, intptr_t size)
{

    for (int i = 0; i < size; i++)
    {
        bool found = true;
        for (int j = 0; j < patternLen; j++)
        {
            if (pattern[j] != *(char*)((intptr_t)begin + i + j))
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return (begin + i);
        }
    }
    return nullptr;
}

char* ScanInternal(char* pattern, int patternLen, char* begin, intptr_t size)
{
    char* match{ nullptr };
    MEMORY_BASIC_INFORMATION mbi{};

    for (char* curr = begin; curr < begin + size; curr += mbi.RegionSize)
    {
        if (!VirtualQuery(curr, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) continue;

        match = ScanBasic(pattern, patternLen, curr, mbi.RegionSize);

        if (match != nullptr)
        {
            break;
        }
    }
    return match;
}


//Switching lots closes the console but doesn't seem to trigger the code we are hooking, so this is just a lazy hack to consider the console closed everytime we switch lots.

short GetCurrentHouse() {
    DWORD addr = (DWORD)modBase + 0x010890C4;
    if (memory_readable((DWORD*)addr, 4))
    {
        memcpy_s(&addr, 4, (DWORD*)addr, 4);
        addr += 0x28;
        if (memory_readable((DWORD*)addr, 4))
        {
            memcpy_s(&addr, 4, (DWORD*)addr, 4);
            return addr;
        }
    }
    return -2;
}

inline bool exists(const std::wstring& name) {
    struct _stat buffer;
    return (_wstat(name.c_str(), &buffer) == 0);
}

HWND g_HWND = NULL;

BOOL CALLBACK EnumWindowsProcMy(HWND hwnd, LPARAM lParam)
{
    DWORD lpdwProcessId;
    GetWindowThreadProcessId(hwnd, &lpdwProcessId);
    if (IsWindowVisible(hwnd) && lpdwProcessId == lParam)
    {
        g_HWND = hwnd;
        return FALSE;
    }
    return TRUE;
}

void
LoadFile(std::wstring wcs) {
    std::wifstream file(wcs);
    std::wstring str;
    
    while (std::getline(file, str))
    {
        if (wcslen(str.c_str()) > 0)
        {
            
            if (wcscmp(str.substr(0, 1).c_str(), L"#"))
            {
                
                bool hold = false;
                std::wstring temp;
                std::vector<std::wstring> split;
                std::wstringstream wss(str);
            while (std::getline(wss, temp, L' '))
            {
                split.push_back(temp);
            }

                std::wstring holdValue = split[0];
                std::wstring value = split[1];
                if (!wcscmp(holdValue.c_str(), L"Hold"))
                {
                    hold = true;
                }
                
                
                

                int valuehex;
                std::wstringstream ss;
                ss << std::hex << value;
                ss >> valuehex;
                int intValue = std::stoi(split[3]);
                sHotKey* hotKey = new sHotKey();
                hotKey->decimalValue = intValue;
                hotKey->hold = hold;
                hotKey->gameMode = std::stoi(split[4]);
                hotkeyMap[static_cast<int>(valuehex)] = hotKey;
#ifdef _DEBUG
                std::cout << std::hex << valuehex << " Assigned to " << std::dec << intValue << std::endl;
#endif
            }
        }
    }
    file.close();
}

DWORD WINAPI HotkeyThread(LPVOID param)
{
#ifdef _DEBUG
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
#endif
    bool enabled = false;
    HMODULE module = GetModuleHandleA(NULL);
    consoleBackAddr = modBase + 0x2F2215 + 0x7;
    MakeJMP((BYTE*)modBase + 0x2F2215, (DWORD)consoleHook, 0x7);
    HANDLE proc = GetCurrentProcess();
    MODULEINFO modInfo;
    GetModuleInformation(proc, module, &modInfo, sizeof(MODULEINFO));
    int size = modInfo.SizeOfImage;

    DWORD addr = (DWORD)nullptr;
    while (addr == (DWORD)nullptr)
    {
        addr = (DWORD)ScanInternal(lookup, sizeof(lookup) / sizeof(*lookup), modBase, size);
        if (addr == (DWORD)nullptr)
        {
            Sleep(500);
        }
    }
    WriteToMemory(addr, nopedLookup, sizeof(nopedLookup) / sizeof(*nopedLookup));
    GetModuleFileName(NULL, modName, MAX_PATH);
    std::wstring::size_type pos = std::wstring(modName).find_last_of(L"\\/");
    auto folder = std::wstring(modName).substr(0, pos);
    wchar_t wcs[MAX_PATH];
    wchar_t pattern[MAX_PATH];

    wcscpy_s(pattern, folder.c_str());
    wcscat_s(pattern, L"\\*_hotkeys.cfg");
    //std::wstring pattern = L"Hotkeys*.cfg";
    WIN32_FIND_DATA data;
    HANDLE hFind;
    wchar_t fullPath[MAX_PATH];
    if ((hFind = FindFirstFile(pattern, &data)) != INVALID_HANDLE_VALUE) {
        do {
            wcscpy_s(fullPath, folder.c_str());
            wcscat_s(fullPath, L"\\");
            wcscat_s(fullPath, data.cFileName);
            LoadFile(fullPath);
            enabled = true;
#ifdef _DEBUG
            wprintf(fullPath);
#endif
        } while (FindNextFile(hFind, &data) != 0);
        FindClose(hFind);
    }

    wcscpy_s(pattern, folder.c_str());
    wcscat_s(pattern, L"\\mods\\*_hotkeys.cfg");
    if ((hFind = FindFirstFile(pattern, &data)) != INVALID_HANDLE_VALUE) {
        do {
            wcscpy_s(fullPath, folder.c_str());
            wcscat_s(fullPath, L"\\mods\\");
            wcscat_s(fullPath, data.cFileName);
            LoadFile(fullPath);
            enabled = true;
#ifdef _DEBUG
            wprintf(fullPath);
#endif
        } while (FindNextFile(hFind, &data) != 0);
        FindClose(hFind);
    }
    if (!enabled)
    {
        ExitThread(0);
        return 0;
    }
    int valToCopy;
    unsigned int globalAddr;
    bool kPressed = false;
    int gMode = 0;
    int pid = GetCurrentProcessId();
    while (g_HWND == NULL)
    {
        EnumWindows(EnumWindowsProcMy, pid);
    }
    while (true)
    {
        try {
            short haus = GetCurrentHouse();
            if (lastHouse != haus)
            {
#ifdef  _DEBUG
                std::cout << "House changed" << std::endl;
#endif //  _DEBUG

                consoleOpen = false;
                lastHouse = haus;
            }
            bool locked = true;
            if (memory_readable((unsigned int*)(modBase + CONTROLS_OFFSET), 4))
            {
                int val;
                memcpy(&val, (unsigned int*)(modBase + CONTROLS_OFFSET), 4);
                if (val <= 1)
                {
                    locked = false;
                }
                else
                    locked = true;
            }
            gMode = TSGetGameMode();
            if (consoleOpen)
                locked = true;
            if (GetForegroundWindow() != g_HWND)
                locked = true;
            if (memory_readable((unsigned int*)(modBase + GLOBAL_POINTER), 4))
            {
                memcpy_s(&globalAddr, 4, (unsigned int*)(modBase + GLOBAL_POINTER), 4);
                if (globalAddr != 0)
                {
                    kPressed = false;
                    for (std::map<int, sHotKey*> ::iterator it = hotkeyMap.begin(); it != hotkeyMap.end(); ++it)
                    {
                        if ((GetKeyState(it->first) & 0x800))
                        {
                            kPressed = true;
                            if (lastKey != it->first || it->second->hold == true)
                            {
                                lastKey = it->first;
                                if (it->second->gameMode != -1 && !locked)
                                {
                                    if (it->second->gameMode != gMode)
                                        locked = true;
                                }
                                if (locked == false)
                                {
                                    valToCopy = it->second->decimalValue;
                                    memcpy_s((unsigned int*)(globalAddr + GLOBAL_POINTER_OFFSET), 4, &valToCopy, 4);
                                }
                            }
                        }
                    }
                    if (!kPressed)
                        lastKey = -1;
#ifdef _DEBUG
                    int val;
                    memcpy_s(&val, 4, (unsigned int*)(globalAddr + GLOBAL_POINTER_OFFSET), 4);
                    //std::cout << "Global Value is " << std::dec << val << std::endl;
#endif
                }
            }
        }
        catch (...) {}; //This suckssss
        Sleep(16);
    }
    return 0;
}
/*
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0, MainThread, hModule, 0, 0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

*/
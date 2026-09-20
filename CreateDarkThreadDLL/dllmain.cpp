#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <array>


// ------------------ > Para funcionar tem que ser compilado em Release <------------------------------

constexpr DWORD TAM_FUNC = 17;
const std::array<BYTE, TAM_FUNC> opCodes = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x31, 0xC0, 0xE8, 00, 00, 00, 00, 0x31, 0xC0, 0xC3, 0x00, 0x00 };
const std::array<BYTE, TAM_FUNC> opCodesLoop = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x31, 0xC0, 0xE8, 00, 00, 00, 00, 0xEB, 0xF9, 0x31, 0xC0, 0xC3 };

HANDLE __stdcall CreateDarkThread(LPTHREAD_START_ROUTINE lpStartAddress, bool bLoop, LPDWORD lpThreadId)
{
    LPVOID addr = VirtualAlloc(nullptr, TAM_FUNC, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!addr) return 0;

    std::array<BYTE, TAM_FUNC> OpCodes = bLoop ? opCodesLoop : opCodes;

    MoveMemory(addr, OpCodes.data(), TAM_FUNC);

    PDWORD pRelativeDist = (PDWORD)((DWORD)addr + 0x8); //Pegando o endereço de memoria do primeiro 00 do call 
    //Estes parenteses são essenciais para ordem de procedencia se não ele faz o calculo de ponteiro com PDWORD + 0x8

    *pRelativeDist = (DWORD)lpStartAddress - ((DWORD)pRelativeDist + 0x4); //pRelativeDist + 4 pois o calculo é feito subtraindo o proximo endereço
    //de memoria depois da instrução do (call00000000) que no caso é (0xEB)

    return CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)addr, nullptr, NULL, lpThreadId);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //CreateDarkThread((LPTHREAD_START_ROUTINE)MyFunc, false, nullptr);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

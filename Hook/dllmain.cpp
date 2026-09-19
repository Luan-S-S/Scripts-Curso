#include "pch.h"
#include <Windows.h>

constexpr size_t SIZE_JMP = 0x5;
constexpr size_t NUM_BYTES = 0x6;
constexpr LPCSTR API_NAME = "LoadLibraryA";
constexpr LPCSTR MODULE_NAME = "kernel32.dll";

void WINAPI setRelativeJMP(LPVOID orig, LPVOID dest, size_t offset)
{
	DWORD d_orig = (DWORD)orig;
	DWORD addr = d_orig + offset;
	DWORD dist = ((DWORD)dest) - (d_orig + SIZE_JMP);
	(*(LPBYTE)addr) = 0xE9;
	(*(LPDWORD)(addr + 1)) = dist;
}

template <typename T>
bool WINAPI CreateDeTour(LPVOID pHKFuncAddr, LPCSTR lpFuncName, LPCSTR lpModuleName, const size_t numBytes, T myFunc, T& pTrmp, DWORD& oldProtect, BYTE oldBytes[])
{
	if (!pHKFuncAddr) pHKFuncAddr = GetProcAddress(GetModuleHandleA(lpModuleName), lpFuncName);

	DWORD newProtect = PAGE_EXECUTE_READWRITE;

	if (!pHKFuncAddr || !myFunc || numBytes < SIZE_JMP || !VirtualProtect(pHKFuncAddr, numBytes, newProtect, &oldProtect))
		return false;

	LPVOID trmp = VirtualAlloc(nullptr, numBytes + SIZE_JMP, MEM_COMMIT | MEM_RESERVE, newProtect);

	if (trmp != nullptr){
		memcpy(oldBytes, pHKFuncAddr, numBytes); //retornando bytes originais em oldBytes

		memcpy(trmp, pHKFuncAddr, numBytes);
		setRelativeJMP(trmp, pHKFuncAddr, numBytes);
		pTrmp = (T)trmp;
		memset(pHKFuncAddr, 0x90, numBytes);
		setRelativeJMP(pHKFuncAddr, myFunc, 0);
	}

	return VirtualProtect(pHKFuncAddr, numBytes, oldProtect, &newProtect);
}

typedef HMODULE(WINAPI* TLoadLibraryA) (LPCSTR lpLibFileName);

static TLoadLibraryA pTrpLoadLibaryA;

HMODULE	WINAPI MyLoadLibraryA(LPCSTR lpLibFileName)
{
	//Fazer qualquer coisa
	return pTrpLoadLibaryA(lpLibFileName);
}

static BYTE oldBytes[NUM_BYTES];
static DWORD oldProtect = 0;

DWORD WINAPI HookingLoadLibraryA(LPVOID lpThreadParameter)
{
	return CreateDeTour(nullptr, API_NAME, MODULE_NAME, NUM_BYTES, MyLoadLibraryA, pTrpLoadLibaryA, oldProtect, oldBytes);
}

//Este codigo só funciona para a arquitetura de 32 bits
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		CreateThread(nullptr, NULL, HookingLoadLibraryA, nullptr, NULL, nullptr);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


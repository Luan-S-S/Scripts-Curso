#include <iostream>
#include <Windows.h>
#include <Shlwapi.h>
#include <string.h>
#pragma comment(lib, "Shlwapi.lib") //Para não dar erro de simbolo não resolvido em Shlwapi.h

class Hook
{
private:
	Hook() = delete;
	~Hook() = delete;

	static void SetJmp(LPVOID orig, LPVOID dest, size_t offset)
	{
		DWORD d_orig = (DWORD)orig;
		DWORD addr = d_orig + offset;
		DWORD dist = ((DWORD)dest) - (d_orig + 5); //No do git nesta linha provavelmente esta errado pois não tem () em dest
		*(BYTE*)addr = 0xE9;
		*(DWORD*)(addr + 1) = dist;
	}

public:
	template <typename T>
	static bool CreateDeTour(LPVOID pHkFuncAddr, const LPCSTR lpFuncName, const LPCSTR lpModuleName, const size_t numBytes, T myFunc, T& pTrmp)
	{
		if (!pHkFuncAddr)
			pHkFuncAddr = GetProcAddress(GetModuleHandleA(lpModuleName), lpFuncName);

		DWORD oldProtect;

		if (!pHkFuncAddr || !myFunc || numBytes < 5 || !VirtualProtect(pHkFuncAddr, numBytes, PAGE_EXECUTE_READWRITE, &oldProtect))
			return false;

		LPVOID trmp = VirtualAlloc(nullptr, numBytes + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //mudei o 30 tambem trocar par 5 32 bits


		if (trmp)
		{
			memcpy(trmp, pHkFuncAddr, numBytes);
			SetJmp(trmp, pHkFuncAddr, numBytes);
			pTrmp = (T)trmp;
			memset(pHkFuncAddr, 0x90, numBytes);
			SetJmp(pHkFuncAddr, myFunc, 0);
		}

		return VirtualProtect(pHkFuncAddr, numBytes, oldProtect, nullptr) && trmp;
	}
};

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef HMODULE(WINAPI* TLoadLibraryA) (LPCSTR lpLibFileName);
typedef HMODULE(WINAPI* TLoadLibraryW) (LPCWSTR lpLibFileName);
typedef NTSTATUS(NTAPI* TLdrLoadDll) (PWCHAR pathToFile, ULONG flags, PUNICODE_STRING moduleFileName, PHANDLE moduleHandle);

TLoadLibraryA pTrpLoadA = nullptr;
TLoadLibraryW pTrpLoadW = nullptr;
TLdrLoadDll pTrpLdr = nullptr;
static LPCWSTR* blockedDlls = nullptr;
static size_t nBlockedDlls = 0;


bool ContainsBlockedDlls(LPCWSTR pszFirst, LPCWSTR exceptions[], size_t nExceptions)
{
	for (size_t i = 0; i < nExceptions; i++)
		if (StrStrIW(pszFirst, exceptions[i]) != nullptr)
			return true;

	return false;
}

bool StrAToStrW(LPCSTR strA, LPWSTR lpstrW, int cchBuffer)
{
	return MultiByteToWideChar(CP_ACP, 0, strA, -1, lpstrW, cchBuffer) > 0;
}

HMODULE WINAPI MyLoadLibraryA(LPCSTR lpLibFileName)
{
	const int tamBuffer = MAX_PATH;
	WCHAR lpwLibFileName[tamBuffer];

	if (lpLibFileName && StrAToStrW(lpLibFileName, lpwLibFileName, tamBuffer) && ContainsBlockedDlls(lpwLibFileName, blockedDlls, nBlockedDlls))
	{
		std::cout << "Dll bloqueada: " << lpLibFileName << std::endl; //Tirar depois
		SetLastError(ERROR_MOD_NOT_FOUND);
		return nullptr;
	}

	return pTrpLoadA(lpLibFileName);
}

HMODULE WINAPI MyLoadLibraryW(LPCWSTR lpLibFileName)
{

	if (lpLibFileName && ContainsBlockedDlls(lpLibFileName, blockedDlls, nBlockedDlls))
	{
		std::wcout << "Dll bloqueada: " << lpLibFileName << std::endl; //Tirar Depois
		SetLastError(ERROR_MOD_NOT_FOUND);
		return nullptr;
	}

	return pTrpLoadW(lpLibFileName);
}

NTSTATUS NTAPI MyLdrLoadDll(PWCHAR pathToFile, ULONG flags, PUNICODE_STRING moduleFileName, PHANDLE moduleHandle)
{
	//Aqui dentro quando a DLL é interceptada é retornado uma excessão "STATUS_DLL_NOT_FOUND"
	//internamente o sistema termina o processo assim que este erro é lançado
	if (moduleFileName && moduleFileName->Buffer && ContainsBlockedDlls( moduleFileName->Buffer, blockedDlls, nBlockedDlls))
	{
		std::wcout << "Dll Interceptada: " << moduleFileName->Buffer << std::endl; //Tirar Depois
		return STATUS_DLL_NOT_FOUND;
	}
	return pTrpLdr(pathToFile, flags, moduleFileName, moduleHandle);
}

bool ProtectAgainstInjections(bool loadLA, bool loadLW, bool ldrLoad, LPCWSTR lpBlockedDlls[], size_t numBlockedDlls)
{
	//Internamente tando a LoadLibararyA quanto a LoadLibraryW chamam a LdrLoadDll então
	//Se voce hookar a Ldr voce indiretamente hooka tamtem a LoadLibrarA e LoadLibraryW

	blockedDlls = lpBlockedDlls;
	nBlockedDlls = numBlockedDlls;

	bool sucessLA = true;
	bool sucessLW = true;
	bool sucessLDR = true;

	if (loadLA)
		sucessLA = Hook::CreateDeTour<TLoadLibraryA>(nullptr, "LoadLibraryA", "kernel32.dll", 5, MyLoadLibraryA, pTrpLoadA);
	if (loadLW)
		sucessLW = Hook::CreateDeTour<TLoadLibraryW>(nullptr, "LoadLibraryW", "kernel32.dll", 5, MyLoadLibraryW, pTrpLoadW);
	if (ldrLoad)
		sucessLDR = Hook::CreateDeTour<TLdrLoadDll>(nullptr, "LdrLoadDll", "ntdll.dll", 5, MyLdrLoadDll, pTrpLdr);

	return sucessLA && sucessLW && sucessLDR;
}


int main()
{
	
	LPCWSTR exceptions[] = { L"DllTeste.dll" };

	ProtectAgainstInjections(true, true, false, exceptions, 1);


	while (true)
	{
		Sleep(5000);
	}

	return 0;

}

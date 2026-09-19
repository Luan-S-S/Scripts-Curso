#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

DWORD GetPID(LPCWSTR procName)
{
    DWORD pid = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, procName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

LPVOID GetRemoteModuleBase(const DWORD pid, LPCWSTR moduleName)
{
    LPVOID modBaseAddr = nullptr;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return nullptr;

    MODULEENTRY32W mod;
    mod.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(hSnapshot, &mod)) {
        do {
            if (_wcsicmp(mod.szModule, moduleName) == 0) {
                modBaseAddr = mod.modBaseAddr;
                break;
            }
        } while (Module32NextW(hSnapshot, &mod));
    }

    CloseHandle(hSnapshot);
    return modBaseAddr;
}

LPVOID GetRemoteAPIAddress(const DWORD pid, LPCWSTR moduleName, HMODULE localModule, FARPROC localAPI)
{
    uintptr_t offset = (uintptr_t)localAPI - (uintptr_t)localModule;
    LPVOID hRemoteModule = GetRemoteModuleBase(pid, moduleName);

    return hRemoteModule != nullptr ? (LPVOID)((uintptr_t)hRemoteModule + offset) : nullptr;
}

bool UnHooking(LPCWSTR procName, LPCSTR APIname, LPCWSTR moduleName, const size_t numBytes, DWORD& oldProtect, BYTE oldBytes[])
{
    HMODULE localModule = GetModuleHandleW(moduleName);
    FARPROC localAPI = GetProcAddress(localModule, APIname);
    if (!localAPI) return false;

    DWORD pid = GetPID(procName);
    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION, false, pid);
    if (!hProcess) return false;    

    LPVOID hRemoteAPI = GetRemoteAPIAddress(pid, moduleName, localModule, localAPI);

    bool readed = false;
    bool writed = false;
    bool restoredProtection = false;
    DWORD newProtect = PAGE_EXECUTE_READWRITE;

    if (hRemoteAPI && VirtualProtectEx(hProcess, hRemoteAPI, numBytes, newProtect, &oldProtect)) {
        std::vector<BYTE> newBytes(numBytes);
        LPBYTE pNewBytes = newBytes.data();

        MoveMemory(pNewBytes, localAPI, numBytes);

        readed = ReadProcessMemory(hProcess, hRemoteAPI, oldBytes, numBytes, nullptr);
        writed = WriteProcessMemory(hProcess, hRemoteAPI, pNewBytes, numBytes, nullptr);
        restoredProtection = VirtualProtectEx(hProcess, hRemoteAPI, numBytes, oldProtect, &newProtect);
    }
    
    CloseHandle(hProcess);
    return readed && writed && restoredProtection;
}

std::string BytesToString(const BYTE bytes[], size_t length)
{
    if (length <= 0 || bytes == nullptr) return "|?|";

    std::ostringstream os;
    os << "|" << std::hex << std::uppercase;

    for (size_t i = 0; i < length; i++) {
        os << std::setw(2) << static_cast<unsigned int>(bytes[i]) << "|";
    }

    os << std::dec << std::nouppercase;
    return os.str();
}

int main()
{
    //O processo alvo e este codigo precisam ter a mesma arquitetura pois, se forem diferentes o calculo para obter
    //O endereço da API não batera.
    constexpr size_t NUM_BYTES = 0x6;
    DWORD oldProtect = 0;
    BYTE oldBytes[NUM_BYTES];

    if (!UnHooking(L"ac_client.exe", "LoadLibraryA", L"kernel32.dll", NUM_BYTES, oldProtect, oldBytes)) {
        std::cout << "Falha ao realizar UnHook no processo!" << std::endl;
        return -1;
    }

    std::cout << "UnHook Realizado com Sucesso!\n\n"
        "Bytes antigos : " << BytesToString(oldBytes, NUM_BYTES) << std::endl <<
        "Protecao Antiga: " << oldProtect << std::endl;
}

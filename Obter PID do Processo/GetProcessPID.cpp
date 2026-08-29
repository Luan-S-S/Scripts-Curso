#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

DWORD GetPid(const wchar_t* procName)
{
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

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

int main()
{
    LPCWSTR nameProcess = L"Meu Processo.exe";
    DWORD pid = GetPid(nameProcess);
    if (pid == 0) {
        std::wcout << "Nao foi possivel Obter o ID do Processo!: " << nameProcess << std::endl;
        return -1;
    }

    std::wcout << "Pid do Processo: " << nameProcess << ": " << pid << std::endl;
    return 0;
}

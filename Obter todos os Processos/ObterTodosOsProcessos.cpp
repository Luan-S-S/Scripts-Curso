#include <iostream>
#include <Windows.h>
#include <vector>
#include <TlHelp32.h>


bool GetAllProcesses(std::vector<PROCESSENTRY32>& processList)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) 
        return false;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)){
        do {
            processList.push_back(pe);
        } while (Process32Next(hSnapshot, &pe));
    }

    return CloseHandle(hSnapshot);

}

int main()
{
    std::vector<PROCESSENTRY32> processList = std::vector<PROCESSENTRY32>();

    if (!GetAllProcesses(processList)) {
        std::cout << "Falha ao Obter Processos!" << std::endl;
        return -1;
    }

    std::cout << "Processos Capturados !\n" << std::endl;
    for (PROCESSENTRY32 pe : processList){
        std::wcout <<  pe.th32ProcessID  << " --> " << pe.szExeFile << std::endl;
    }
    return 0;

}

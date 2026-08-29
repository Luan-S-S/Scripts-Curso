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

    if (Process32First(hSnapshot, &pe)) {
        do {
            processList.push_back(pe);
        } while (Process32Next(hSnapshot, &pe));
    }

    return CloseHandle(hSnapshot);

}

void ShowProcess(const std::vector<PROCESSENTRY32> processList)
{
    for (PROCESSENTRY32 pe : processList) {
        std::wcout << "ID:(" << pe.th32ProcessID << ")" << " --> " << pe.szExeFile << std::endl;
    }
}

bool IsPidInList(const std::vector<PROCESSENTRY32> processList, DWORD pid)
{
    bool contains = false;
    for (PROCESSENTRY32 pe : processList) {
        if (pe.th32ProcessID == pid) {
            contains = true;
            break;
        }
    }
    return contains;
}

int ShowReturnMessage(LPCSTR msg, int ret)
{
    std::cout << msg << std::endl;
    return ret;
}

int main()
{
    std::vector<PROCESSENTRY32> processList = std::vector<PROCESSENTRY32>();
    DWORD pid = 0;
    char resp = ' ';

    if (!GetAllProcesses(processList))
        return ShowReturnMessage("Falha ao Obter Processos!", -1);
    
    std::cout << "Processos Capturados !\n" << std::endl;
    
    ShowProcess(processList);

    std::cout << "\nDigite o ID do Processo que deseja fechar: ";
    std::cin >> pid;

    if (!IsPidInList(processList, pid)) 
        return ShowReturnMessage("\nID digitado eh invalido ou nao esta na lista\nTente Novamente!", -2);
    

    std::cout << "Deseja Fechar o processo selecionado S/N: ";
    std::cin >> resp;
    
    if (resp != 's' && resp != 'S') 
        return ShowReturnMessage("\nOK, Programa Finalizado!", -3);

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, false, pid);
    if (!hProcess)
        return ShowReturnMessage("\nFalha ao Obter HANDLE do Processo!", -4);

    bool itended = TerminateProcess(hProcess, 0);
    CloseHandle(hProcess);

    if(!itended)
        return ShowReturnMessage("\nFalha ao Fechar o processo!", -5);

    std::cout << "Processo Selecionado Fechado com sucesso!" << std::endl;
    return 0;
}


#include <iostream>
#include <iomanip>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <Psapi.h>
//#pragma comment(lib, "psapi.h") //Necessario para linkeditar Psapi.h

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation = 0,
	ThreadQuerySetWin32StartAddress = 9,
	ThreadNameInformation = 38
} THREADINFORCLASS;

typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(HANDLE ThreadHandle, THREADINFORCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

static pNtQueryInformationThread NtQueryInformationThread;

struct THREADINFO 
{
	DWORD ID = 0;
	PVOID StartAddress = nullptr;
	uintptr_t Offset = 0;
	HANDLE hThread = 0;
	std::string ModuleName = "";

	void ShowThread()
	{
		std::cout << "TID: {" << std::setw(5) << std::setfill('0') << this->ID << "}  " <<
			"Start Address: {" << this->ModuleName << "+" << std::hex << std::uppercase << this->Offset << "} " << std::dec << std::endl;
	}

	bool CloseThreadHandle() { return CloseHandle(this->hThread); }
};

bool GetProcessIDAndThreadCount(LPCWSTR procName, DWORD& id, DWORD& cntThreads)
{

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return false;

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe)) {
		do {
			if (_wcsicmp(pe.szExeFile, procName) == 0) {
				id = pe.th32ProcessID;
				cntThreads = pe.cntThreads;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	return CloseHandle(hSnapshot);

}

PVOID GetThreadStartAddress(const HANDLE hThread)
{
	PVOID startAddress = nullptr;
	if (hThread)
		NtQueryInformationThread(hThread, THREADINFORCLASS::ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), nullptr);
	
	return startAddress;
}

std::string GetThreadModuleInfo(const HANDLE hProcess, const PVOID threadStartAddr, uintptr_t& offset)
{
	HMODULE hMods[1024];
	DWORD cbNeeded = 0;

	std::string name = "???";

	if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) return name;

	int moduleCount = cbNeeded / sizeof(HMODULE);

	for (int i = 0; i < moduleCount; i++)
	{
		MODULEINFO mi;
		if (!GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) continue;

		BYTE* base = (BYTE*)mi.lpBaseOfDll;
		BYTE* end = base + mi.SizeOfImage;

		if ((BYTE*)threadStartAddr >= base && (BYTE*)threadStartAddr < end)
		{
			char modName[MAX_PATH];
			GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName));
			name = modName;

			offset = (uintptr_t)threadStartAddr - (uintptr_t)mi.lpBaseOfDll;
		}
	}
	return name;
}

bool GetAllThreadsOfProcess(const HANDLE hProcess, const DWORD pid, std::vector<THREADINFO>& threadList)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return false;

	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(hSnapshot, &te)) {
		NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
		do {
			if (te.th32OwnerProcessID == pid){
				THREADINFO ti;
				ti.ID = te.th32ThreadID;
				ti.hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_TERMINATE, false, ti.ID);
				ti.StartAddress = GetThreadStartAddress(ti.hThread);
				ti.ModuleName = GetThreadModuleInfo(hProcess, ti.StartAddress, ti.Offset);
				threadList.push_back(ti);
			}
		} while (Thread32Next(hSnapshot, &te));
	}
	return CloseHandle(hSnapshot);
}

class ProcessInfo
{
	std::wstring wname = L"";

	HANDLE hProcess = 0;
	DWORD ID = 0;
	DWORD cntThreads = 0;

public:
	std::vector<THREADINFO> Threads = std::vector<THREADINFO>();

	ProcessInfo(LPCWSTR name)
	{
		this->wname = name;

		if (GetProcessIDAndThreadCount(name, this->ID, this->cntThreads))
		{
			this->hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, this->ID);
			if (this->hProcess) 
				GetAllThreadsOfProcess(this->hProcess, this->ID, this->Threads);	
		}
	}

	bool HasFoundProcess() { return this->hProcess != 0; }

	bool CloseProcessHandle() 
	{ 
		bool released = true;
		for (THREADINFO& th : this->Threads) {
			if (!th.CloseThreadHandle())
				released = false;
		}
		return CloseHandle(this->hProcess) && released; 
	}

	void ShowProcess()
	{
		std::wcout << "================== PROCESSO SELECIONADO ===================" << std::endl << 
			"Nome: " << this->wname << std::endl <<
			"ID: " << this->ID << std::endl <<
			"Numero de Threads: " << this->cntThreads << std::endl <<
			"Handle Aberta: 0x" << this->hProcess << std::endl;

		std::cout << "=================== THREADS ===============================" << std::endl;

		size_t threadCount = this->Threads.size();

		for (size_t i = 0; i < threadCount; i++)
		{
			std::cout << "[" << i << "] -> ";
			this->Threads.at(i).ShowThread();

		}
	}
};

int ReadInt32(LPCSTR msg)
{
	int ret;
	std::cout << msg;
	std::cin >> ret;
	return ret;
}

bool IsBetwenn(int value, int min, int max) { return value >= min && value <= max; }

bool GetTHREADFromVector(std::vector<THREADINFO>& vector, int index, THREADINFO& item)
{
	bool exist = false;
	if (IsBetwenn(index, 0, vector.size() - 1)) {
		exist = true;
		item = vector.at(index);
	}
	return exist;
}

bool ControlThread(THREADINFO& th, int op)
{
	switch (op)
	{
		case 1: return ResumeThread(th.hThread) != -1;
		case 2: return SuspendThread(th.hThread) != -1;
		case 3: return TerminateThread(th.hThread,0) != 0;
		default:
			break;
	}
}

int main()
{

	std::wstring procName = L"";

	std::wcout << "Digite o nome do processo: ";
	std::getline(std::wcin, procName);

	ProcessInfo proc = ProcessInfo(procName.c_str());
	
	if (!proc.HasFoundProcess()) {
		std::cout << "Processo não encontrado";
		return -1;
	}

	THREADINFO th;

	while (true){

		system("cls");

		proc.ShowProcess();

		int indxTh = ReadInt32("\nDigite o indice da Thread que deseja manipular: ");

		while (!GetTHREADFromVector(proc.Threads, indxTh, th)){
			std::cout << "INDICE INVALIDO!" << std::endl;
			indxTh = ReadInt32("Digite novamente o indice da Thread que deseja manipular: ");
		}

		system("cls");

		std::cout << "\n==================================================== \nThread Selecionada -> ";
		th.ShowThread();
		std::cout << "======================================================\n";

		int opTh = ReadInt32("1 -> Resumir\n2 -> Suspender\n3 -> Terminar\n4 -> Cancelar\nDigite a operação que deseja realizar: ");
		while (!IsBetwenn(opTh, 1, 4)) {
			std::cout << "Opcao Invalida, Digite novamente" << std::endl;
			opTh = ReadInt32("1 -> Resumir\n2 -> Suspender\n3 -> Terminar\n4 -> Cancelar\nDigite a operação que deseja realizar: ");
		}

		if (opTh == 4) continue;

		if (!ControlThread(th, opTh)) {
			std::cout << "\nFalha ao realizar a operacao na Thread";
			Sleep(3000);
		}
		
		Sleep(100);
	}

	proc.CloseProcessHandle();

	return 0;
}
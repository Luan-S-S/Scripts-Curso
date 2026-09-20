#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

//---- ATENÇÃO ------ :
        //Para funcionar melhor o programa precisa ser executado como administrador
extern "C" __declspec(dllexport)
BOOL WINAPI EnableSeDebugPrivilege(BOOL fEnable)
{
    HANDLE TokenHandle = nullptr;

    // Obtém o HANDLE do token de acesso do processo atual.O token contém as permissões e privilégios do processo.
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
        return false;

    // Estrutura que será usada para modificar os privilégios.Inicializando como vazia ({});
    TOKEN_PRIVILEGES NewState{};
    NewState.PrivilegeCount = 1; // Vamos alterar apenas 1 privilégio

    bool changed = false;
    DWORD errorCode = ERROR_GEN_FAILURE;

    // Converte o nome do privilégio (ex: SE_DEBUG_NAME -> "SeDebugPrivileger") para o LUID correspondente no sistema.
    if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &NewState.Privileges[0].Luid))
    {
        // Define se o privilégio será habilitado ou desabilitado.
        NewState.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
        // Solicita ao sistema a alteração do privilégio.
        changed = AdjustTokenPrivileges(TokenHandle, FALSE, &NewState, sizeof(NewState), nullptr, nullptr);
        errorCode = GetLastError(); // Verificando o codigo de erro
    }

    CloseHandle(TokenHandle);

    // A operação só é considerada bem sucedida se:
    // 1. AdjustTokenPrivileges retornou TRUE
    // 2. GetLastError() retornou ERROR_SUCCESS
    return changed && errorCode == ERROR_SUCCESS;

}

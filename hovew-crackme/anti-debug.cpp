#include "anti-debug.h"

#pragma comment(lib, "ntdll.lib")

#ifdef _WIN64
PPEB pPeb = (PPEB)__readgsqword(0x60);
DWORD pNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0xBC);
#else
PPEB pPeb = (PPEB)__readfsdword(0x30);
DWORD pNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);
#endif

void checkDebug_1()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll)
    {
        auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
            hNtdll, "NtQueryInformationProcess");
        if (pfnNtQueryInformationProcess)
        {
            DWORD dwProcessDebugFlags, dwReturned;
            const DWORD ProcessDebugFlags = 0x1f;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugFlags,
                &dwProcessDebugFlags,
                sizeof(DWORD),
                &dwReturned);
            if (NT_SUCCESS(status) && (0 == dwProcessDebugFlags))
                ExitProcess(1);
        }
    }
}

void checkDebug_2()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll)
    {
        auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
            hNtdll, "NtQueryInformationProcess");
        if (pfnNtQueryInformationProcess)
        {
            DWORD dwReturned;
            HANDLE hProcessDebugObject = 0;
            const DWORD ProcessDebugObjectHandle = 0x1e;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugObjectHandle,
                &hProcessDebugObject,
                sizeof(HANDLE),
                &dwReturned);
            if (NT_SUCCESS(status) && (0 != hProcessDebugObject))
                ExitProcess(1);
        }
    }
}

void checkDebug_3()
{
    if (pPeb->BeingDebugged) {
        ExitProcess(1);
    }
}

void checkDebug_4()
{
    BOOL IsDbgPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &IsDbgPresent);
    if (IsDbgPresent) {
        ExitProcess(1);
    }
}
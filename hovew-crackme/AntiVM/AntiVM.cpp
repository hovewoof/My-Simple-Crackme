#include "pch.h"

#include "AntiVM.h"

VOID AntiVMRegOpenKeyEx() {
    HKEY rKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_15AD&DEV_0405&SUBSYS_040515AD&REV_00", 0, KEY_QUERY_VALUE, &rKey) == ERROR_SUCCESS) {
        ExitProcess(1);
    }
}

VOID AntiVMProcessName() {
    wchar_t VMwareProcessName[] = { L"vmtoolsd.exe" };
    PROCESSENTRY32 pe;
    HANDLE hSnapShot;
    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    ZeroMemory(&pe, sizeof(PROCESSENTRY32W));
    pe.dwSize = sizeof(PROCESSENTRY32W);
    Process32First(hSnapShot, &pe);
    do
    {
        if (memcmp(pe.szExeFile, VMwareProcessName, 24) == 0) {
            ExitProcess(1);
        }
    } while (Process32Next(hSnapShot, &pe));
}
#include "pch.h"

#include "SelfModifyingCode.h"

volatile VOID ModifyingFunc();

DWORD Unprotect(void* addr, size_t size) {
    DWORD oldProtect;
    if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << make_string("Error in VirtualProtect.") << std::endl;
    }
    return oldProtect;
}

VOID HackFunction() {
    size_t size = (byte*)ModifyingFunc - (byte*)HackFunction;
    DWORD oldProtect = Unprotect(HackFunction, size);
    *(byte*)ModifyingFunc = 0xC3;
    VirtualProtect(HackFunction, size, oldProtect, &oldProtect);
}

volatile VOID ModifyingFunc() {
    FLOAT x = 1.23456f;
    for (;;) {
        x = sin(x);
        x = cos(x);
        x = x * 1.38462f;
        x = x / 1.84953f;
        INT y = *(INT*)&x;
        y = y << 3;
        y = y >> 5;
        x = *(FLOAT*)&y;
        if (x < 0) {
            x *= -1;
        }
        if (x < 0.5) {
            x *= 10;
        }
        x *= 6;
        x /= 4;
        AntiDebugPEBBeingDebugged();
        if (x < 0) {
            return;
        }
    }
}

volatile VOID SelfModifyingFunc() {
    HackFunction();
    ModifyingFunc();
}

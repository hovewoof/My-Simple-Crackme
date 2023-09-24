#include <windows.h>
#include <string>
#include <vector>
#include "string_encryption.h"

typedef struct _FUNC_DATA {
    uintptr_t begin;
    uintptr_t end;
    DWORD crc;
} FUNC_DATA, * PFUNC_DATA;

char* getCorrectHash(std::string hash);
bool checkFuncValidity(FARPROC func, DWORD validCrc);
void getFunctionInfo(FARPROC func, PFUNC_DATA data);
DWORD getCrc(PUCHAR start, PUCHAR end);
bool checkCrc(PUCHAR begin, PUCHAR end, DWORD correctCrc);
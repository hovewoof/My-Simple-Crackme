#include "pch.h"

#include "FakeChecks.h"

volatile BOOL FakeCheck_1(PCHAR c, INT n) {
    srand(time(NULL));
    PCHAR hashPassword = Hash(c, n);
    PCHAR correctHash = GetCorrectHash();
    INT r1 = rand() % 256;
    INT r2 = rand() % 16;
    INT r4 = rand() % 256;
    r4 = r4 >> 7;
    UINT acc = 0;
    for (INT i = 0; i < n; i++) {
        acc ^= (hashPassword[i] << r1) >> r2;
    }
    INT r3 = rand() % 8;
    acc = acc >> r3;
    AntiDebugProcessDebugObjectHandle();
    acc &= 0xFF;
    r4 = r4 << 7;
    INT r5 = rand() % 9;
    PCHAR acc2 = correctHash + r5;
    if (!memcmp(hashPassword, correctHash, HASH_SIZE - 10)) {
        acc++;
        HANDLE hProcess = GetCurrentProcess();
        PROCESS_BASIC_INFORMATION processInfo;
        if (NtQueryInformationProcess(hProcess,
            ProcessBasicInformation,
            &processInfo,
            sizeof(processInfo),
            nullptr) == STATUS_THREAD_NOT_RUNNING) {
            return false;
        }
    }
    acc ^= r4;
    if (acc % 2 == 0)
        ++acc;
    if (acc % 2 == 0) {
        delete[] hashPassword;
        delete[] correctHash;
        return true;
    }
    else {
        delete[] hashPassword;
        delete[] correctHash;
        return false;
    }
}

volatile BOOL FakeCheck_2(PCHAR c, INT n) {
    srand(time(NULL));
    PCHAR hashPassword = Hash(c, n);
    PCHAR correctHash = GetCorrectHash();
    INT r1 = rand() % 128;
    INT r2 = rand() % 32;
    INT r4 = rand() % 128;
    r4 = r4 >> 6;
    UINT acc = 0;
    for (INT i = 0; i < n; i++) {
        acc ^= (hashPassword[i] << r1) >> r2;
    }
    INT r3 = rand() % 16;
    acc = acc << r3;
    acc &= 0xFE;
    r4 = r4 << 6;
    INT r5 = rand() % 10;
    PCHAR acc2 = correctHash + r5;
    if (!memcmp(hashPassword, correctHash, HASH_SIZE - 5)) {
        acc++;
    }
    acc ^= r4;
    if (acc % 3 == 0)
        ++acc;
    PCHAR unusedData = new CHAR[n];
    for (INT i = 0; i < n; i++) {
        unusedData[i] = hashPassword[i] ^ i;
    }
    if (acc % 3 != 0) {
        delete[] hashPassword;
        delete[] correctHash;
        delete[] unusedData;
        return true;
    }
    else {
        delete[] hashPassword;
        delete[] correctHash;
        delete[] unusedData;
        return false;
    }
}
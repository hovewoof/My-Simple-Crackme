#include "pch.h"

#include "Authentication.h"

__declspec(code_seg(".prot")) volatile BOOL Auth_1(PCHAR password, INT passwordSize) {
    srand(time(NULL));
    PCHAR hashPassword = Hash(password, passwordSize);
    AntiDisassmImpossibleDisassm();
    PCHAR correctHash = GetCorrectHash();
    INT r1 = rand() % 256;
    INT r2 = rand() % 16;
    UINT acc = 0;
    for (INT i = 0; i < passwordSize; i++) {
        acc ^= (hashPassword[i] << r1) >> r2;
    }
    INT r3 = rand() % 8;
    acc = acc >> r3;
    AntiDebugProcessDebugFlags();
    acc &= 0xFE;
    if (!memcmp(hashPassword, correctHash, HASH_SIZE)) {
        INT r4 = rand() % 256;
        r4 = r4 >> 7;
        r4 = r4 << 7;
        acc ^= r4;
        INT r5 = rand() % 4;
        PCHAR acc2 = hashPassword + r5;
        if (acc % 2 != 0) {
            ++acc;
        }
        if (!memcmp(acc2, correctHash, HASH_SIZE - 7)) {
            acc++;
        }
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

__declspec(code_seg(".prot")) volatile BOOL Auth_2(PCHAR c, INT n) {
    srand(GetTickCount());
    PCHAR hashPassword = Hash(c, n);
    PCHAR correctHash = GetCorrectHash();
    INT r1 = rand() % 64;
    INT r2 = rand() % 16;
    INT r4 = rand() % 64;
    r4 = r4 << 2;
    UINT acc = 0;
    for (INT i = 0; i < n; i++) {
        acc ^= (hashPassword[i] << r1) | (hashPassword[i] >> r2);
    }
    INT r3 = rand() % 8;
    acc = acc * r3;
    acc &= 0xC6;
    r4 = r4 >> 2;
    INT r5 = rand() % 5;
    INT flag = 4;
    if (acc % 3 == 0) {
        acc++;
    }
    if (!memcmp(hashPassword, correctHash, HASH_SIZE)) {
        acc *= 3;
    }
    else {
        acc *= 3;
        ++acc;
    }
    PCHAR acc2 = correctHash + r5;
    if (!memcmp(hashPassword, correctHash, HASH_SIZE - 5)) {
        acc2++;
    }
    if (acc % 3 == 0)
        acc *= 3;
    AntiDebugProcessDebugObjectHandle();
    PCHAR unusedData = new CHAR[n];
    for (INT i = 0; i < n; i++) {
        unusedData[i] = hashPassword[i] ^ i;
    }
    if (acc % 9 == 0) {
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
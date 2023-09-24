#include "misc.h"

char hexCharToChar(const char hexChar) {
    if (hexChar >= '0' && hexChar <= '9')
        return hexChar - '0';
    else if (hexChar >= 'A' && hexChar <= 'F')
        return hexChar - 'A' + 10;
    else if (hexChar >= 'a' && hexChar <= 'f')
        return hexChar - 'a' + 10;
    else
        return 0;
}

void hexStringToCharArray(const std::string& hexString, char* result) {
    for (std::size_t i = 0; i < hexString.length(); i += 2) {
        char highNibble = hexCharToChar(hexString[i]);
        char lowNibble = hexCharToChar(hexString[i + 1]);
        result[i / 2] = (highNibble << 4) | lowNibble;
    }
}

char* getCorrectHash(std::string hash) {
    // Calculate the length of the resulting char array
    std::size_t correctHashLength = hash.length() / 2;

    // Allocate memory for the char array (without null-terminator)
    char* correctHash = new char[correctHashLength];

    // Convert hex string to char array
    hexStringToCharArray(hash, correctHash);
    return correctHash;
}

void getFunctionInfo(FARPROC func, PFUNC_DATA data) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(func, &mbi, sizeof(mbi)) == 0) {
        return;
    }
    uintptr_t start = (uintptr_t)mbi.AllocationBase;
    uintptr_t end = start + mbi.RegionSize;
    data->begin = start;
    data->end = end;
    DWORD crc = 0;
    PUCHAR iter = reinterpret_cast<PUCHAR>(start);
    PUCHAR cycleEnd = reinterpret_cast<PUCHAR>(end);
    for (; iter < reinterpret_cast<PUCHAR>(cycleEnd); ++iter) {
        crc = _rotl(crc, 1) ^ *iter;
    }
    data->crc = crc;
}

bool checkFuncValidity(FARPROC func, DWORD validCrc) {
    FUNC_DATA funcData;
    getFunctionInfo(func, &funcData);
    return funcData.crc == validCrc;
}

DWORD getCrc(PUCHAR start, PUCHAR end) {
    uint32_t crc = 0xFFFFFFFF;  // Initial CRC value
    while (start != end) {
        crc ^= static_cast<uint32_t>(*start);

        for (int i = 0; i < 8; ++i) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;  // CRC32 polynomial
            }
            else {
                crc >>= 1;
            }
        }

        ++start;
    }

    return ~crc;  // Final XOR
}

bool checkCrc(PUCHAR begin, PUCHAR end, DWORD correctCrc) {
    DWORD calculatedCrc = getCrc(begin, end);
    return calculatedCrc == correctCrc;
}
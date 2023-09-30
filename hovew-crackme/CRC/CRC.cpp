#include "pch.h"

#include "CRC.h"

DWORD GetCrc(PUCHAR start, PUCHAR end) {
    uint32_t crc = 0xFFFFFFFF;  // Initial CRC value
    while (start != end) {
        crc ^= static_cast<uint32_t>(*start);
        for (INT i = 0; i < 8; ++i) {
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

BOOL CheckCrc(PUCHAR begin, PUCHAR end, DWORD correctCrc) {
    DWORD calculatedCrc = GetCrc(begin, end);
    return calculatedCrc == correctCrc;
}
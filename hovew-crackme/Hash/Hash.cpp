#include "pch.h"

#include "Hash.h"

std::string correctHashHex = { make_string("F83286A2E7612937EDF208AA79AD0B5EA11F06AB") };

CHAR HexCharToChar(const CHAR hexChar) {
    if (hexChar >= '0' && hexChar <= '9')
        return hexChar - '0';
    else if (hexChar >= 'A' && hexChar <= 'F')
        return hexChar - 'A' + 10;
    else if (hexChar >= 'a' && hexChar <= 'f')
        return hexChar - 'a' + 10;
    else
        return 0;
}

VOID HexStringToCharArray(const std::string& hexString, CHAR* result) {
    for (std::size_t i = 0; i < hexString.length(); i += 2) {
        CHAR highNibble = HexCharToChar(hexString[i]);
        CHAR lowNibble = HexCharToChar(hexString[i + 1]);
        result[i / 2] = (highNibble << 4) | lowNibble;
    }
}

// uses SHA1 algorithm
PCHAR Hash(const PCHAR buf, INT size) {
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0))
        return NULL;
    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return NULL;
    }
    if (!CryptHashData(hHash, (BYTE*)buf, size, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return NULL;
    }
    DWORD hashSize = HASH_SIZE;
    char* hashedPassword = new char[hashSize];
    if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)hashedPassword, &hashSize, 0)) {
        delete[] hashedPassword;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return NULL;
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return hashedPassword;
}

PCHAR GetCorrectHash() {
    std::size_t correctHashLength = correctHashHex.length() / 2;
    PCHAR correctHash = new CHAR[correctHashLength];
    HexStringToCharArray(correctHashHex, correctHash);
    return correctHash;
}
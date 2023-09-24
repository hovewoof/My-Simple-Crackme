#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdint>
#include <bit>
#include <windows.h>
#include <wincrypt.h>
#include "misc.h"

#pragma auto_inline(off)

constexpr auto HASH_SIZE = 20;
std::string correctHashHex = { make_string("F83286A2E7612937EDF208AA79AD0B5EA11F06AB") };

// uses SHA1 algorithm
char* hash(const char* buf, int size) {
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

// uses the first 8 bytes from hash of correct password hash as serial key
std::string generateSerial() {
    char* correctHash = getCorrectHash(correctHashHex);
    char* doubleHash = hash(correctHash, HASH_SIZE);
    std::string hashedPassword = doubleHash;
    delete[] correctHash;
    delete[] doubleHash;
    if (hashedPassword.empty()) {
        return "";
    }
    std::string serial = make_string("KEY$");
    std::string hashPrefix = hashedPassword.substr(0, 8);
    std::stringstream ss;
    for (char c : hashPrefix) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)c;
    }
    serial += ss.str();
    return serial;
}

#pragma runtime_checks("", off)
#pragma section(".prot", read, execute)
__declspec(code_seg(".prot")) volatile bool auth(char* password, int passwordSize) {
    char* hashPassword = hash(password, passwordSize);
    char* correctHash = getCorrectHash(correctHashHex);
    if (!memcmp(hashPassword, correctHash, HASH_SIZE)) {
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
#pragma section()
#pragma runtime_checks("", restore)

#pragma data_seg(".xDD"))
struct _CRC_DATA {
    volatile DWORD segmentSize = 0xCAFEDEAD;
    volatile DWORD correctChecksum = 0xDEADBEEF;
} CRC_DATA;
#pragma data_seg()

int main() {

    std::ifstream input(make_string("password.txt"), std::ios::binary);

    if (!checkCrc(reinterpret_cast<PUCHAR>(auth), reinterpret_cast<PUCHAR>(auth) + CRC_DATA.segmentSize, CRC_DATA.correctChecksum)) {
        std::cerr << make_string("Error: Incorrect CRC32.") << std::endl;
        return 1;
    }

    if (!input.is_open()) {
        std::cerr << make_string("Error: Can't open file password.txt.") << std::endl;
        return 1;
    }

    char password[1024] = { 0 };
    int passwordSize = static_cast<int>(input.read(password, 1024).gcount());
    char check;
    if (input.read(&check, 1).gcount() > 0) {
        std::cout << make_string("Error: Incorrect password.") << std::endl;
        return 0;
    }
    input.close();

    if (auth(password, passwordSize)) {
        std::string serial = generateSerial();
        if (serial.empty()) {
            std::cerr << make_string("Error: Can't calculate hash.") << std::endl;
            return 1;
        }

        std::ofstream output(make_string("serial.txt"));
        if (!output.is_open()) {
            std::cerr << make_string("Error: Can't open file serial.txt.") << std::endl;
            return 1;
        }

        output << serial;
        output.close();

        std::cout << make_string("Success: Serial number has been generated.") << std::endl;
    }
    else {
        std::cout << make_string("Error: Incorrect password.") << std::endl;
    }
    return 0;
}

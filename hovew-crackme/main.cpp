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
#include "anti-debug.h"

#pragma auto_inline(off)

constexpr auto HASH_SIZE = 20;
std::string correctHashHex = { make_string("F83286A2E7612937EDF208AA79AD0B5EA11F06AB") };
bool crc32_changed = false;

volatile bool fakeCheck_1(char* c, int n);
volatile bool fakeCheck_2(char* c, int n);

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

#pragma runtime_checks("", off)
#pragma section(".prot", read, execute)
__declspec(code_seg(".prot")) volatile bool auth(char* password, int passwordSize) {
    srand(time(NULL));
    char* hashPassword = hash(password, passwordSize);
    char* correctHash = getCorrectHash(correctHashHex);
    int r1 = rand() % 256;
    int r2 = rand() % 16;
    unsigned int acc = 0;
    for (int i = 0; i < passwordSize; i++) {
        acc ^= (hashPassword[i] << r1) >> r2;
    }
    int r3 = rand() % 8;
    acc = acc >> r3;
    checkDebug_1();
    acc &= 0xFE;
    if (!memcmp(hashPassword, correctHash, HASH_SIZE)) {
        int r4 = rand() % 256;
        r4 = r4 >> 7;
        r4 = r4 << 7;
        acc ^= r4;
        int r5 = rand() % 4;
        char* acc2 = hashPassword + r5;
        if (acc % 2 != 0) {
            ++acc;
        }
        if (!memcmp(acc2, correctHash, HASH_SIZE - 6)) {
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

__declspec(code_seg(".prot")) volatile bool auth2(char* c, int n) {
    srand(GetTickCount());
    char* hashPassword = hash(c, n);
    char* correctHash = getCorrectHash(correctHashHex);
    int r1 = rand() % 64;
    int r2 = rand() % 16;
    int r4 = rand() % 64;
    r4 = r4 << 2;
    unsigned int acc = 0;
    for (int i = 0; i < n; i++) {
        acc ^= (hashPassword[i] << r1) | (hashPassword[i] >> r2);
    }
    int r3 = rand() % 8;
    acc = acc * r3;
    acc &= 0xC6;
    r4 = r4 >> 2;
    int r5 = rand() % 5;
    int flag = 4;
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
    char* acc2 = correctHash + r5;
    if (!memcmp(hashPassword, correctHash, HASH_SIZE - 5)) {
        acc2++;
    }
    if (acc % 3 == 0)
        acc *= 3;
    checkDebug_2();
    char* unusedData = new char[n];
    for (int i = 0; i < n; i++) {
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
#pragma section()
#pragma runtime_checks("", restore)

// uses the first 8 bytes from hash of correct password hash as serial key
std::string generateSerial(char* password, int passwordSize) {
    char* correctHash = getCorrectHash(correctHashHex);
    if (!fakeCheck_2(password, passwordSize)) {
        std::cerr << make_string("Error: Runtime error.") << std::endl;
        exit(1);
    }
    else {
        if (!auth2(password, passwordSize)) {
            std::cerr << make_string("Error: Runtime error.") << std::endl;
            exit(1);
        }
    }
    char* doubleHash = hash(correctHash, HASH_SIZE);
    std::string hashedPassword = doubleHash;
    delete[] correctHash;
    delete[] doubleHash;
    if (hashedPassword.empty() || crc32_changed) {
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

#pragma data_seg(".xDD"))
struct _CRC_DATA {
    volatile DWORD segmentSize = 0xCAFEDEAD;
    volatile DWORD correctChecksum = 0xDEADBEEF;
} CRC_DATA;
#pragma data_seg()

volatile bool fakeCheck_1(char* c, int n) {
    srand(time(NULL));
    char* hashPassword = hash(c, n);
    char* correctHash = getCorrectHash(correctHashHex);
    int r1 = rand() % 256;
    int r2 = rand() % 16;
    int r4 = rand() % 256;
    r4 = r4 >> 7;
    unsigned int acc = 0;
    for (int i = 0; i < n; i++) {
        acc ^= (hashPassword[i] << r1) >> r2;
    }
    int r3 = rand() % 8;
    acc = acc >> r3;
    checkDebug_2();
    acc &= 0xFF;
    r4 = r4 << 7;
    int r5 = rand() % 9;
    char* acc2 = correctHash + r5;
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

volatile bool fakeCheck_2(char* c, int n) {
    srand(time(NULL));
    char* hashPassword = hash(c, n);
    char* correctHash = getCorrectHash(correctHashHex);
    int r1 = rand() % 128;
    int r2 = rand() % 32;
    int r4 = rand() % 128;
    r4 = r4 >> 6;
    unsigned int acc = 0;
    for (int i = 0; i < n; i++) {
        acc ^= (hashPassword[i] << r1) >> r2;
    }
    int r3 = rand() % 16;
    acc = acc << r3;
    acc &= 0xFE;
    r4 = r4 << 6;
    int r5 = rand() % 10;
    char* acc2 = correctHash + r5;
    if (!memcmp(hashPassword, correctHash, HASH_SIZE - 5)) {
        acc++;
    }
    acc ^= r4;
    if (acc % 3 == 0)
        ++acc;
    char* unusedData = new char[n];
    for (int i = 0; i < n; i++) {
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

int main() {
    std::ifstream input(make_string("password.txt"), std::ios::binary);
    if (!checkCrc(reinterpret_cast<PUCHAR>(auth), reinterpret_cast<PUCHAR>(auth) + CRC_DATA.segmentSize, CRC_DATA.correctChecksum)) {
        crc32_changed = true;
    }
    if (!input.is_open()) {
        std::cerr << make_string("Error: Can't open file password.txt.") << std::endl;
        return 1;
    }
    char password[1024] = { 0 };
    int passwordSize = static_cast<int>(input.read(password, 1024).gcount());
    char check;
    checkDebug_1();
    if (input.read(&check, 1).gcount() > 0) {
        std::cout << make_string("Error: Incorrect password.") << std::endl;
        return 0;
    }
    input.close();
    checkDebug_4();
    if (fakeCheck_1(password, passwordSize)) {
        std::string serial = generateSerial(password, passwordSize);
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
        checkDebug_3();
        if (auth(password, passwordSize)) {
            std::string serial = generateSerial(password, passwordSize);
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
        else
            if (!fakeCheck_2(password, passwordSize)) {
                std::string serial = generateSerial(password, passwordSize);
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
    }
    return 0;
}

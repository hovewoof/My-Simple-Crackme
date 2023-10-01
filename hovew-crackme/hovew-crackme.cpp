#include "pch.h"

BOOL crc32_changed = false;

#pragma data_seg(".xDD")
struct _CRC_DATA {
    volatile DWORD segmentSize = 0xCAFEDEAD;
    volatile DWORD correctChecksum = 0xDEADBEEF;
} CRC_DATA;
#pragma data_seg()

// uses the first 8 bytes from hash of correct password hash as serial key
std::string generateSerial(PCHAR password, INT passwordSize) {
    AntiVMRegOpenKeyEx();
    PCHAR correctHash = GetCorrectHash();
    if (!FakeCheck_2(password, passwordSize)) {
        std::cerr << make_string("Error: Runtime error.") << std::endl;
        ExitProcess(1);
    }
    else {
        AntiDisassmConstantCondition();
        if (!Auth_2(password, passwordSize)) {
            std::cerr << make_string("Error: Runtime error.") << std::endl;
            ExitProcess(1);
        }
    }
    PCHAR doubleHash = Hash(correctHash, HASH_SIZE);
    std::string hashedPassword = doubleHash;
    delete[] correctHash;
    delete[] doubleHash;
    if (hashedPassword.empty()) {
        return "";
    }
    else if (crc32_changed) {
        std::cerr << make_string("Error: Incorrect checksum.") << std::endl;
        ExitProcess(1);
    }
    std::string serial = make_string("KEY$");
    std::string hashPrefix = hashedPassword.substr(0, 8);
    std::stringstream ss;
    for (CHAR c : hashPrefix) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (INT)c;
    }
    serial += ss.str();
    return serial;
}

int main()
{
    AntiVMProcessName();
    std::ifstream input(make_string("password.txt"), std::ios::binary);
    AntiDisassmAsmJmpSameTarget();
    if (!CheckCrc(reinterpret_cast<PUCHAR>(Auth_1), reinterpret_cast<PUCHAR>(Auth_1) + CRC_DATA.segmentSize, CRC_DATA.correctChecksum)) {
        crc32_changed = true;
    }
    if (!input.is_open()) {
        std::cerr << make_string("Error: Can't open file password.txt.") << std::endl;
        return 1;
    }
    CHAR password[1024] = { 0 };
    INT passwordSize = static_cast<INT>(input.read(password, 1024).gcount());
    CHAR check;
    AntiDebugProcessDebugFlags();
    if (input.read(&check, 1).gcount() > 0) {
        std::cout << make_string("Error: Incorrect password.") << std::endl;
        return 0;
    }
    input.close();
    AntiDebugProcessDebugObjectHandle();
    if (FakeCheck_1(password, passwordSize)) {
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
        AntiDebugPEBBeingDebugged();
        try {
            if (Auth_1(password, passwordSize)) {
                if (!FakeCheck_2(password, passwordSize)) {
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
        } catch (std::exception& e) {
            SelfModifyingFunc();
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
    }
    return 0;
}

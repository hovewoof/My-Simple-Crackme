#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <windows.h>
#include <wincrypt.h>

const std::string correct_password = "5fe76f1acf6641d00945bae0f0725f6a97681ebab8806856453e299b0370a072";

std::string hashPassword(const std::string& password) {
    std::string hashedPassword;

    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        return "";
    }

    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    if (!CryptHashData(hHash, (BYTE*)password.c_str(), password.length(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    DWORD hashSize = 32;
    hashedPassword.resize(hashSize);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)hashedPassword.data(), &hashSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return hashedPassword;
}

std::string generateSerial() {
    std::string hashedPassword = hashPassword(correct_password);
    if (hashedPassword.empty()) {
        return "";
    }
    std::string serial = "KEY$";

    std::string hashPrefix = hashedPassword.substr(0, 8);

    std::stringstream ss;
    for (char c : hashPrefix) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)c;
    }

    serial += ss.str();

    return serial;
}

int main() {
    std::ifstream input("password.txt");

    if (!input.is_open()) {
        std::cerr << "Error: Can't open file password.txt." << std::endl;
        return 1;
    }

    std::string password;
    getline(input, password);
    input.close();

    if (password == correct_password) {
        std::string serial = generateSerial();
        if (serial.empty()) {
            std::cerr << "Error: Can't calculate hash." << std::endl;
            return 1;
        }

        std::ofstream output("serial.txt");
        if (!output.is_open()) {
            std::cerr << "Error: Can't open file serial.txt." << std::endl;
            return 1;
        }

        output << serial;
        output.close();

        std::cout << "Success: Serial number has been generated." << std::endl;
    }
    else {
        std::cout << "Error: Incorrect password." << std::endl;
    }

    return 0;
}

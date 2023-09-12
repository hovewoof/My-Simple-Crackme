#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <wincrypt.h>

const std::string correct_password = "5fe76f1acf6641d00945bae0f0725f6a97681ebab8806856453e299b0370a072";

std::string hashPassword(const std::string& password) {
    HCRYPTPROV hCryptProv;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "Error: CryptAcquireContext failed." << std::endl;
        return "";
    }

    HCRYPTHASH hHash;
    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "Error: CryptCreateHash failed." << std::endl;
        CryptReleaseContext(hCryptProv, 0);
        return "";
    }

    if (!CryptHashData(hHash, (const BYTE*)password.c_str(), password.length(), 0)) {
        std::cerr << "Error: CryptHashData failed." << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return "";
    }

    DWORD dwHashSize = 0;
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&dwHashSize, 0, 0)) {
        std::cerr << "Error: CryptGetHashParam failed." << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return "";
    }

    std::string result(dwHashSize, 0);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)result.data(), &dwHashSize, 0)) {
        std::cerr << "Error: CryptGetHashParam failed." << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return "";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);

    return result;
}

std::string generateSerial(const std::string& password) {
    std::string hashedPassword = hashPassword(password);
    std::string serial = "KEY$";
    serial += hashedPassword.substr(0, 5);
    if (hashedPassword.size() >= 10) {
        serial += hashedPassword.substr(hashedPassword.size() - 5, 5);
    }
    else {
        serial += hashedPassword;
    }
    serial += "$";
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
        std::string serial = generateSerial(correct_password);

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

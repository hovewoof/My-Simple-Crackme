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
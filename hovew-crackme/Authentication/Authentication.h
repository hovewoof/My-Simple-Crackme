#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

__declspec(code_seg(".prot")) volatile BOOL Auth_1(PCHAR password, INT passwordSize);
__declspec(code_seg(".prot")) volatile BOOL Auth_2(PCHAR password, INT passwordSize);

#endif //AUTHENTICATION_H

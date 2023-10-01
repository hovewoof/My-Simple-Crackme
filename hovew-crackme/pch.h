#ifndef PCH_H
#define PCH_H

#include <iostream>
#include <array>
#include <limits>
#include <iomanip>
#include <fstream>
#include <sstream>

#include <windows.h>
#include <winternl.h>
#include <Tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

/* String Encryption */
#include "StringEncryption\StringEncryption.h"

/* Hash */
#include "Hash\Hash.h"

/* Authentication */
#include "Authentication\Authentication.h"

/* Fake Checks */
#include "FakeChecks\FakeChecks.h"

/* CRC */
#include "CRC\CRC.h"

/* Anti-Debug */
#include "AntiDebug\AntiDebug.h"

/* Anti-Disassembly */
#include "AntiDisassm\AntiDisassm.h"

/* Anti-VM */
#include "AntiVM\AntiVM.h"

/* Self-modifying Code */
#include "SelfModifyingCode\SelfModifyingCode.h"

#endif //PCH_H

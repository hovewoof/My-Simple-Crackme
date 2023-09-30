#ifndef HASH_H
#define HASH_H

constexpr auto HASH_SIZE = 20;

PCHAR Hash(const PCHAR buf, INT size);
PCHAR GetCorrectHash();

#endif

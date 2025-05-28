#include <stdint.h>
#include <stddef.h>

uint32_t seed_key(const uint8_t* key) {
    uint32_t a, b;
    size_t length = 4;
    const uint8_t *k = (const uint8_t *)key;

    // Initialize the hash values
    a = b = 0x9e3779b9;

    // Handle the remaining bytes in the key
    b += length;
    if (length >= 4) {
        a += (k[0] + ((uint32_t)k[1] << 8) + ((uint32_t)k[2] << 16) + ((uint32_t)k[3] << 24));
        a -= b; a -= (b << 13); a ^= (b >> 5);
    }
    switch (length & 3) {
        case 3: b += ((uint32_t)k[2] << 16);
        case 2: b += ((uint32_t)k[1] << 8);
        case 1: b += k[0];
                a -= b; a -= (b << 13); a ^= (b >> 5);
    }

    // Final mixing
    a ^= 0x9e3779b9;
    a -= b; a -= (b << 13); a ^= (b >> 5);
    b -= a; b -= (a << 13); b ^= (a >> 5);

    return b;
}

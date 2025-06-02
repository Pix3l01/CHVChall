// gcc -shared -o test.so -fPIC lib.c -lssl -lcrypto
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

static const uint8_t AES256_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};
int session = 3;


uint64_t programming(const uint8_t *seed) {
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16] = {0};
    memcpy(plaintext, seed, 4);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, AES256_KEY, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);  // No padding, it's 4 bytes

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, 16);
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    // Take first 4 bytes and last 4 bytes of ciphertext
    uint64_t result = 0;
    result |= ((uint64_t)ciphertext[0] << 56) |
              ((uint64_t)ciphertext[1] << 48) |
              ((uint64_t)ciphertext[2] << 40) |
              ((uint64_t)ciphertext[3] << 32) |
              ((uint64_t)ciphertext[12] << 24) |
              ((uint64_t)ciphertext[13] << 16) |
              ((uint64_t)ciphertext[14] << 8)  |
              ((uint64_t)ciphertext[15]);

    return result;
}


uint64_t extended(const uint8_t* seed) {
    uint64_t a = 0xcbf29ce484222325;
    uint64_t b = 0x100000001b3;
    uint64_t result = 0;

    for(int i = 0; i < 4; ++i) {
        uint8_t value = seed[i];
        a = a ^ value;
        a *= b;
    }
    for(int i = 3; i >= 0; --i) {
        uint8_t value = seed[i];
        a = a ^ value;
        a *= b;
    }

    const char c[8] = "Drivesec";
    printf("Original : 0x%016llX\n", (unsigned long long)a);
    for (int i = 0; i < 8; i++) {
        uint8_t byte = (a >> (56 - i * 8)) & 0xFF;
        uint8_t xored = byte ^ c[i];
        result |= ((uint64_t)xored << (56 - i * 8));
        printf("XORing byte %d: %016llx\n", i, (unsigned long long)result);
    }
    return result;
}

uint64_t seed_key(const uint8_t* key){
    switch(session) {
        case 2:
            return programming(key);
        case 3:
            return extended(key);
        default:
            // exit with error code
            return -1;
    }
}

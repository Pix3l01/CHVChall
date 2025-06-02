// gcc -shared -o leak.so -fPIC leak.c -lssl -lcrypto
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

static const uint8_t AES256_KEY[32] = {
    0x62, 0x5d, 0x04, 0x57, 0xab, 0xaa, 0x22, 0x99, 0xa5, 0xb9, 0x9b, 0x64, 0xdb, 0x8e, 0x77, 0x38, 0x03, 0xa2, 0xc6,
     0x79, 0x83, 0xc2, 0x4a, 0x36, 0x4a, 0x35, 0xb6, 0x96, 0xa9, 0x5b, 0xb5, 0x1b
};

int session = 3;

uint64_t seed_key(const uint8_t* seed){
    uint64_t result = 0;

    switch(session) {
        case 2:
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

            result |= ((uint64_t)ciphertext[0] << 56) |
                      ((uint64_t)ciphertext[1] << 48) |
                      ((uint64_t)ciphertext[2] << 40) |
                      ((uint64_t)ciphertext[3] << 32) |
                      ((uint64_t)ciphertext[12] << 24) |
                      ((uint64_t)ciphertext[13] << 16) |
                      ((uint64_t)ciphertext[14] << 8)  |
                      ((uint64_t)ciphertext[15]);

            return result;
        case 3:
            uint64_t a = 0xcbf29ce484222325;
            uint64_t b = 0x100000001b3;
            const char c[8] = "Drivesec";

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

            for (int i = 0; i < 8; i++) {
                uint8_t byte = (a >> (56 - i * 8)) & 0xFF;
                uint8_t xored = byte ^ c[i];
                result |= ((uint64_t)xored << (56 - i * 8));
            }
            return result;
        default:
            return -1;
    }
}

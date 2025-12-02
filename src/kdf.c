#include "kdf.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <string.h>

int derive_key_pbkdf2(const char *password, const unsigned char *salt, size_t salt_len, uint32_t iterations, unsigned char *out_key, size_t key_len) {
    if (!password || !salt || salt_len == 0 || !out_key || key_len == 0 || iterations == 0) return 0;
    /* PKCS5_PBKDF2_HMAC expects int sizes for iterations and key_len on many platforms */
    if (!PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, (int)salt_len, (int)iterations, EVP_sha256(), (int)key_len, out_key)) {
        return 0;
    }
    return 1;
}

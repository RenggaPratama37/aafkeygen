#include "cipher.h"
#include "crypto.h"
#include <openssl/evp.h>
#include <stdlib.h>

int cipher_encrypt_cbc_stream(const unsigned char *key, const unsigned char *iv, FILE *in, FILE *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) { EVP_CIPHER_CTX_free(ctx); return 1; }
    }
    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
    if (outlen > 0) if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) { EVP_CIPHER_CTX_free(ctx); return 1; }
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int cipher_decrypt_cbc_stream(const unsigned char *key, const unsigned char *iv, FILE *in, FILE *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) { EVP_CIPHER_CTX_free(ctx); return 1; }
    }
    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
    if (outlen > 0) if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) { EVP_CIPHER_CTX_free(ctx); return 1; }
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

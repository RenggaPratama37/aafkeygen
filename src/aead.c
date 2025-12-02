#include "aead.h"
#include "crypto.h"
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

int aead_encrypt_gcm_stream(const unsigned char *key, const unsigned char *iv, size_t iv_len, FILE *in, FILE *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }

    unsigned char inbuf[4096];
    unsigned char outbuf[4128];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) { EVP_CIPHER_CTX_free(ctx); return 1; }
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
    if (outlen > 0) if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) { EVP_CIPHER_CTX_free(ctx); return 1; }

    unsigned char tag[GCM_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
    if (fwrite(tag, 1, GCM_TAG_LEN, out) != GCM_TAG_LEN) { EVP_CIPHER_CTX_free(ctx); return 1; }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int aead_decrypt_gcm_stream(const unsigned char *key, const unsigned char *iv, size_t iv_len, FILE *in, long ciphertext_len, FILE *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }

    unsigned char inbuf[1024];
    unsigned char outbuf[1040];
    int inlen, outlen;

    long long remaining = ciphertext_len;
    while (remaining > 0) {
        size_t toread = (size_t)(remaining > (long long)sizeof(inbuf) ? sizeof(inbuf) : remaining);
        inlen = fread(inbuf, 1, toread, in);
        if ((long long)inlen <= 0) break;
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) { EVP_CIPHER_CTX_free(ctx); return 1; }
        remaining -= inlen;
    }

    unsigned char tag[GCM_TAG_LEN];
    if (fread(tag, 1, GCM_TAG_LEN, in) != GCM_TAG_LEN) { EVP_CIPHER_CTX_free(ctx); return 1; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) { EVP_CIPHER_CTX_free(ctx); return 1; }
    if (outlen > 0) if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) { EVP_CIPHER_CTX_free(ctx); return 1; }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

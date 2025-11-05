#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define HEADER "AAFv1"

static void derive_key(const char *password, unsigned char *key) {
    // Derive AES key dari password (hash SHA-256)
    EVP_Digest(password, strlen(password), key, NULL, EVP_sha256(), NULL);
}

int encrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        perror("File error");
        return 1;
    }

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];
    derive_key(password, key);
    RAND_bytes(iv, AES_BLOCK_SIZE);

    // Write header + IV
    fwrite(HEADER, 1, strlen(HEADER), out);
    fwrite(iv, 1, AES_BLOCK_SIZE, out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, out);
    }

    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    return 0;
}

int decrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        perror("File error");
        return 1;
    }

    unsigned char header[6];
    fread(header, 1, strlen(HEADER), in);
    header[strlen(HEADER)] = '\0';

    if (strcmp((char *)header, HEADER) != 0) {
        fprintf(stderr, "Invalid AAF file.\n");
        return 1;
    }

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];
    derive_key(password, key);
    fread(iv, 1, AES_BLOCK_SIZE, in);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            fprintf(stderr, "Decryption failed.\n");
            return 1;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if (!EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) {
        fprintf(stderr, "Incorrect password or corrupted file.\n");
        return 1;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    return 0;
}

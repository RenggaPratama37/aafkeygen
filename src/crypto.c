#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define HEADER "AAFv1"

static void derive_key(const char *password, unsigned char *key) {
    EVP_Digest(password, strlen(password), key, NULL, EVP_sha256(), NULL);
}

int encrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        perror("File error");
        if (in) fclose(in);
        if (out) fclose(out);
        return 1;
    }

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];
    derive_key(password, key);
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        fprintf(stderr, "Random IV generation failed.\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    // ===== HEADER =====
    fwrite(HEADER, 1, strlen(HEADER), out);
    fwrite(iv, 1, AES_BLOCK_SIZE, out);

    // ===== Simpan nama file asli (tanpa path) =====
    char *filename_copy = strdup(input_file);
    const char *basename_only = basename(filename_copy);
    unsigned char name_len = (unsigned char)strlen(basename_only);

    fwrite(&name_len, 1, 1, out);
    fwrite(basename_only, 1, name_len, out);
    free(filename_copy);

    // ===== ENCRYPTION =====
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create cipher context.\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            fprintf(stderr, "Encryption failed.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if (!EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) {
        fprintf(stderr, "Final encryption step failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }

    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    printf("✅ Encrypted successfully: %s → %s\n", input_file, output_file);
    return 0;
}

int decrypt_file(const char *input_file, const char *output_placeholder, const char *password) {
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        perror("File error");
        return 1;
    }

    unsigned char header[6] = {0};
    fread(header, 1, strlen(HEADER), in);
    if (strcmp((char *)header, HEADER) != 0) {
        fprintf(stderr, "Invalid or corrupted AAF file.\n");
        fclose(in);
        return 1;
    }

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];
    derive_key(password, key);
    fread(iv, 1, AES_BLOCK_SIZE, in);

    // ===== Baca metadata nama file =====
    unsigned char name_len = 0;
    fread(&name_len, 1, 1, in);
    if (name_len == 0 || name_len > 255) {
        fprintf(stderr, "Invalid filename metadata.\n");
        fclose(in);
        return 1;
    }

    char original_name[256];
    fread(original_name, 1, name_len, in);
    original_name[name_len] = '\0';

    const char *output_name = (output_placeholder && strlen(output_placeholder) > 0)
        ? output_placeholder
        : original_name;

    FILE *out = fopen(output_name, "wb");
    if (!out) {
        perror("Output file error");
        fclose(in);
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create cipher context.\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            fprintf(stderr, "Decryption failed.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if (!EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) {
        fprintf(stderr, "❌ Incorrect password or corrupted file.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        remove(output_name); // hapus file rusak
        return 1;
    }

    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    printf("✅ Decrypted successfully: %s\n", output_name);
    return 0;
}

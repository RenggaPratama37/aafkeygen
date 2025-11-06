#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <openssl/crypto.h>

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
        fprintf(stderr, "Randomness generation failed.\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    size_t header_len = strlen(HEADER);
    if (fwrite(HEADER, 1, header_len, out) != header_len) goto write_error;
    if (fwrite(iv, 1, AES_BLOCK_SIZE, out) != AES_BLOCK_SIZE) goto write_error;

    size_t fnlen = strlen(input_file);
    if (fnlen > 255) fnlen = 255; /* limit to fit into one byte */
    uint8_t name_len = (uint8_t)fnlen;
    if (fwrite(&name_len, 1, 1, out) != 1) goto write_error;
    if (fwrite(input_file, 1, name_len, out) != name_len) goto write_error;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        goto write_error;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        goto write_error;
    }

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "Encryption update failed.\n");
            EVP_CIPHER_CTX_free(ctx);
            goto enc_fail;
        }
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
            fprintf(stderr, "Write error while writing ciphertext.\n");
            EVP_CIPHER_CTX_free(ctx);
            goto enc_fail;
        }
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "Encryption finalization failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        goto enc_fail;
    }
    if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
        fprintf(stderr, "Write error while writing final ciphertext.\n");
        EVP_CIPHER_CTX_free(ctx);
        goto enc_fail;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    OPENSSL_cleanse(key, sizeof(key));
    return 0;

write_error:
    perror("File write error");
    fclose(in);
    fclose(out);
    unlink(output_file);
    OPENSSL_cleanse(key, sizeof(key));
    return 1;

enc_fail:
    fclose(in);
    fclose(out);
    unlink(output_file);
    OPENSSL_cleanse(key, sizeof(key));
    return 1;
}

// === backward-compatible decrypt ===
int decrypt_file(const char *input_file, const char *output_placeholder, const char *password) {
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        perror("File error");
        return 1;
    }

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];
    derive_key(password, key);

    size_t header_len = strlen(HEADER);
    unsigned char header[16] = {0};
    size_t read_bytes = fread(header, 1, header_len, in);

    int legacy_mode = 0;
    char original_name[256] = {0};
    if (read_bytes < header_len || strcmp((char *)header, HEADER) != 0) {
        /* Old version (no header) */
        legacy_mode = 1;
        rewind(in);
        memset(iv, 0, AES_BLOCK_SIZE); /* default IV (old behavior) */
    } else {
        if (fread(iv, 1, AES_BLOCK_SIZE, in) != AES_BLOCK_SIZE) {
            fprintf(stderr, "Failed to read IV from file.\n");
            fclose(in);
            return 1;
        }

        uint8_t name_len = 0;
        if (fread(&name_len, 1, 1, in) != 1) {
            fprintf(stderr, "Failed to read original filename length.\n");
            fclose(in);
            return 1;
        }
        if (name_len > 0) {
            if (name_len >= sizeof(original_name)) name_len = sizeof(original_name) - 1;
            if (fread(original_name, 1, name_len, in) != name_len) {
                fprintf(stderr, "Failed to read original filename.\n");
                fclose(in);
                return 1;
            }
            original_name[name_len] = '\0';
            output_placeholder = original_name;
        }
    }

    FILE *out = fopen(output_placeholder, "wb");
    if (!out) {
        perror("Output file error");
        fclose(in);
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        fclose(in);
        fclose(out);
        return 1;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "Decryption failed.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            unlink(output_placeholder);
            OPENSSL_cleanse(key, sizeof(key));
            return 1;
        }
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
            fprintf(stderr, "Write error while writing plaintext.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            unlink(output_placeholder);
            OPENSSL_cleanse(key, sizeof(key));
            return 1;
        }
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "Incorrect password or corrupted file.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        unlink(output_placeholder);
        OPENSSL_cleanse(key, sizeof(key));
        return 1;
    }

    if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
        fprintf(stderr, "Write error while writing final plaintext.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        unlink(output_placeholder);
        OPENSSL_cleanse(key, sizeof(key));
        return 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    OPENSSL_cleanse(key, sizeof(key));

    printf("✅ Decrypted successfully: %s (mode: %s)\n",
           output_placeholder ? output_placeholder : "(unknown)",
           legacy_mode ? "legacy" : "v1.3");
    return 0;
}

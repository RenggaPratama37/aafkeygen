#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <sys/stat.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define OLD_HEADER "AAFv1"
#define NEW_MAGIC "AAF4"
#define NEW_FORMAT_VERSION 1

static void derive_key(const char *password, unsigned char *key) {
    EVP_Digest(password, strlen(password), key, NULL, EVP_sha256(), NULL);
}

/* Helper to write big-endian integers */
static int write_u16_be(FILE *f, uint16_t v) {
    unsigned char b[2];
    b[0] = (v >> 8) & 0xFF;
    b[1] = v & 0xFF;
    return fwrite(b, 1, 2, f) == 2;
}

static int write_u64_be(FILE *f, uint64_t v) {
    unsigned char b[8];
    for (int i = 0; i < 8; i++) b[7 - i] = (v >> (i * 8)) & 0xFF;
    return fwrite(b, 1, 8, f) == 8;
}

/* Helper to read big-endian integers */
static int read_u16_be(FILE *f, uint16_t *out) {
    unsigned char b[2];
    if (fread(b, 1, 2, f) != 2) return 0;
    *out = ((uint16_t)b[0] << 8) | (uint16_t)b[1];
    return 1;
}

static int read_u64_be(FILE *f, uint64_t *out) {
    unsigned char b[8];
    if (fread(b, 1, 8, f) != 8) return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | b[i];
    }
    *out = v;
    return 1;
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

    /* New format header (AAF4): magic(4) | version(1) | name_len(2) | timestamp(8) | IV(16) | name */
    if (fwrite(NEW_MAGIC, 1, 4, out) != 4) goto write_error;
    uint8_t fmt_ver = NEW_FORMAT_VERSION;
    if (fwrite(&fmt_ver, 1, 1, out) != 1) goto write_error;

    size_t fnlen = strlen(input_file);
    if (fnlen > 65535) fnlen = 65535;
    uint16_t name_len16 = (uint16_t)fnlen;
    if (!write_u16_be(out, name_len16)) goto write_error;

    uint64_t ts = (uint64_t)time(NULL);
    if (!write_u64_be(out, ts)) goto write_error;

    if (fwrite(iv, 1, AES_BLOCK_SIZE, out) != AES_BLOCK_SIZE) goto write_error;
    if (fwrite(input_file, 1, name_len16, out) != name_len16) goto write_error;

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

/* Inspect an AAF file and print header/metadata information (v1 legacy-aware).
 * This is a non-destructive helper used by the CLI `--inspect` to show basic
 * information like whether the header exists, IV bytes and original filename.
 */
int inspect_file(const char *input_file) {
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        perror("File error");
        return 1;
    }

    unsigned char header4[4] = {0};
    size_t read4 = fread(header4, 1, 4, in);
    struct stat st;
    if (stat(input_file, &st) == -1) {
        perror("stat");
        fclose(in);
        return 1;
    }

    printf("File: %s\n", input_file);
    printf("Size: %lld bytes\n", (long long)st.st_size);

    if (read4 == 4 && memcmp(header4, NEW_MAGIC, 4) == 0) {
        printf("Format: %s (new)\n", NEW_MAGIC);
        uint8_t fmt_ver = 0;
        if (fread(&fmt_ver, 1, 1, in) != 1) {
            fprintf(stderr, "Failed to read format version.\n");
            fclose(in);
            return 1;
        }
        printf("Format version: %u\n", (unsigned)fmt_ver);

        uint16_t name_len16 = 0;
        if (!read_u16_be(in, &name_len16)) {
            fprintf(stderr, "Failed to read name length.\n");
            fclose(in);
            return 1;
        }

        uint64_t ts = 0;
        if (!read_u64_be(in, &ts)) {
            fprintf(stderr, "Failed to read timestamp.\n");
            fclose(in);
            return 1;
        }
        printf("Timestamp (epoch): %llu\n", (unsigned long long)ts);

        unsigned char iv[AES_BLOCK_SIZE];
        if (fread(iv, 1, AES_BLOCK_SIZE, in) != AES_BLOCK_SIZE) {
            fprintf(stderr, "Failed to read IV.\n");
            fclose(in);
            return 1;
        }
        printf("IV: ");
        for (int i = 0; i < AES_BLOCK_SIZE; i++) printf("%02x", iv[i]);
        printf("\n");

        char original_name[256] = {0};
        if (name_len16 > 0) {
            if (name_len16 >= sizeof(original_name)) name_len16 = sizeof(original_name) - 1;
            if (fread(original_name, 1, name_len16, in) != name_len16) {
                fprintf(stderr, "Failed to read original filename.\n");
                fclose(in);
                return 1;
            }
            original_name[name_len16] = '\0';
            printf("Original filename: %s\n", original_name);
        } else {
            printf("Original filename: (none)\n");
        }

        long long header_bytes = 4 + 1 + 2 + 8 + AES_BLOCK_SIZE + name_len16;
        long long cipher_bytes = (long long)st.st_size - header_bytes;
        if (cipher_bytes < 0) cipher_bytes = 0;
        printf("Ciphertext bytes (approx): %lld\n", cipher_bytes);

        fclose(in);
        return 0;

    } else {
        /* check old header */
        unsigned char header5[6] = {0};
        memcpy(header5, header4, 4);
        if (fread(&header5[4], 1, 1, in) != 1) {
            printf("Format: legacy (no header detected)\n");
            printf("Note: legacy format uses zero IV by default or older behavior.\n");
            fclose(in);
            return 0;
        }
        if (memcmp(header5, OLD_HEADER, 5) == 0) {
            printf("Format: %s (old)\n", OLD_HEADER);
            unsigned char iv[AES_BLOCK_SIZE];
            if (fread(iv, 1, AES_BLOCK_SIZE, in) != AES_BLOCK_SIZE) {
                fprintf(stderr, "Failed to read IV.\n");
                fclose(in);
                return 1;
            }
            printf("IV: ");
            for (int i = 0; i < AES_BLOCK_SIZE; i++) printf("%02x", iv[i]);
            printf("\n");
            uint8_t name_len = 0;
            if (fread(&name_len, 1, 1, in) != 1) {
                fprintf(stderr, "Failed to read name length.\n");
                fclose(in);
                return 1;
            }
            char original_name[256] = {0};
            if (name_len > 0) {
                if (name_len >= sizeof(original_name)) name_len = sizeof(original_name) - 1;
                if (fread(original_name, 1, name_len, in) != name_len) {
                    fprintf(stderr, "Failed to read original filename.\n");
                    fclose(in);
                    return 1;
                }
                original_name[name_len] = '\0';
                printf("Original filename: %s\n", original_name);
            } else {
                printf("Original filename: (none)\n");
            }
            long long header_bytes = 5 + AES_BLOCK_SIZE + 1 + name_len;
            long long cipher_bytes = (long long)st.st_size - header_bytes;
            if (cipher_bytes < 0) cipher_bytes = 0;
            printf("Ciphertext bytes (approx): %lld\n", cipher_bytes);
            fclose(in);
            return 0;
        } else {
            printf("Format: legacy (no header detected)\n");
            printf("Note: legacy format uses zero IV by default or older behavior.\n");
            fclose(in);
            return 0;
        }
    }
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

    unsigned char header4[4] = {0};
    size_t read4 = fread(header4, 1, 4, in);

    int legacy_mode = 0;
    char original_name[256] = {0};
    if (read4 == 4 && memcmp(header4, NEW_MAGIC, 4) == 0) {
        /* New AAF4 format */
        uint8_t fmt_ver = 0;
        if (fread(&fmt_ver, 1, 1, in) != 1) {
            fprintf(stderr, "Failed to read format version.\n");
            fclose(in);
            return 1;
        }

        uint16_t name_len16 = 0;
        if (!read_u16_be(in, &name_len16)) {
            fprintf(stderr, "Failed to read name length.\n");
            fclose(in);
            return 1;
        }

        uint64_t ts = 0;
        if (!read_u64_be(in, &ts)) {
            fprintf(stderr, "Failed to read timestamp.\n");
            fclose(in);
            return 1;
        }

        if (fread(iv, 1, AES_BLOCK_SIZE, in) != AES_BLOCK_SIZE) {
            fprintf(stderr, "Failed to read IV from file.\n");
            fclose(in);
            return 1;
        }

        if (name_len16 > 0) {
            if (name_len16 >= sizeof(original_name)) name_len16 = sizeof(original_name) - 1;
            if (fread(original_name, 1, name_len16, in) != name_len16) {
                fprintf(stderr, "Failed to read original filename.\n");
                fclose(in);
                return 1;
            }
            original_name[name_len16] = '\0';
            output_placeholder = original_name;
        }
        legacy_mode = 0; /* explicit new format */

    } else {
        /* Not NEW_MAGIC; check for old HEADER (AAFv1) */
        unsigned char header5[6] = {0};
        memcpy(header5, header4, 4);
        if (fread(&header5[4], 1, 1, in) != 1) {
            /* could be legacy/no header */
            rewind(in);
            legacy_mode = 1;
            memset(iv, 0, AES_BLOCK_SIZE);
        } else if (memcmp(header5, OLD_HEADER, 5) == 0) {
            /* AAFv1 old header */
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
            legacy_mode = 0; /* parsed old header */
        } else {
            /* No recognizable header -> legacy raw file */
            rewind(in);
            legacy_mode = 1;
            memset(iv, 0, AES_BLOCK_SIZE);
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

#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define OLD_HEADER "AAFv1"
#define NEW_MAGIC "AAF4"
#define NEW_FORMAT_VERSION 2
/* KDF identifiers */
#define KDF_NONE 0
#define KDF_PBKDF2_HMAC_SHA256 1
#define DEFAULT_SALT_LEN 16
#define DEFAULT_PBKDF2_ITERS 100000
/* AEAD identifiers */
#define AEAD_NONE 0
#define AEAD_AES_256_GCM 1
#define AEAD_CHACHA20_POLY1305 2
#define DEFAULT_AEAD_ID AEAD_AES_256_GCM
#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16



/* Globals controlled by main.c */
/* Globals controlled by main.c */
unsigned int pbkdf2_iterations = 0;
int use_legacy_kdf = 0;
int selected_aead = DEFAULT_AEAD_ID; /* AEAD chosen for new encryptions */

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

    /* New format header (AAF4 v2): magic(4) | version(1) | kdf_id(1) | salt_len(1) | salt | iterations(4 BE) | name_len(2) | timestamp(8) | IV(16) | name */
    if (fwrite(NEW_MAGIC, 1, 4, out) != 4) goto write_error;
    uint8_t fmt_ver = NEW_FORMAT_VERSION;
    if (fwrite(&fmt_ver, 1, 1, out) != 1) goto write_error;

    /* KDF metadata: we'll use PBKDF2-HMAC-SHA256 with fixed salt length */
    uint8_t kdf_id = KDF_PBKDF2_HMAC_SHA256;
    if (fwrite(&kdf_id, 1, 1, out) != 1) goto write_error;
    uint8_t salt_len = DEFAULT_SALT_LEN;
    if (fwrite(&salt_len, 1, 1, out) != 1) goto write_error;

    unsigned char salt[DEFAULT_SALT_LEN];
    if (RAND_bytes(salt, DEFAULT_SALT_LEN) != 1) {
        fprintf(stderr, "Randomness generation for salt failed.\n");
        goto write_error;
    }
    if (fwrite(salt, 1, DEFAULT_SALT_LEN, out) != DEFAULT_SALT_LEN) goto write_error;

    uint32_t iterations = DEFAULT_PBKDF2_ITERS;
    /* Allow caller to override iterations via global variable set by main */
    extern uint32_t pbkdf2_iterations;
    if (pbkdf2_iterations > 0) iterations = pbkdf2_iterations;
    /* write iterations as big-endian */
    unsigned char itb[4];
    itb[0] = (iterations >> 24) & 0xFF;
    itb[1] = (iterations >> 16) & 0xFF;
    itb[2] = (iterations >> 8) & 0xFF;
    itb[3] = iterations & 0xFF;
    if (fwrite(itb, 1, 4, out) != 4) goto write_error;

    /* derive key with PBKDF2 unless legacy flag is set */
    extern int use_legacy_kdf;
    if (!use_legacy_kdf) {
        if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, DEFAULT_SALT_LEN, iterations, EVP_sha256(), AES_KEY_SIZE, key)) {
            fprintf(stderr, "PBKDF2 derivation failed.\n");
            goto write_error;
        }
        /* key derived and IV set */
    } else {
        derive_key(password, key);
    }

    /* choose AEAD and IV length and write AEAD metadata */
    extern int selected_aead;
    int aead = selected_aead;
    uint8_t iv_len = AES_BLOCK_SIZE;
    if (aead == AEAD_AES_256_GCM) iv_len = GCM_IV_LEN;
    uint8_t aead_id = (uint8_t)aead;
    if (fwrite(&aead_id, 1, 1, out) != 1) goto write_error;
    if (fwrite(&iv_len, 1, 1, out) != 1) goto write_error;
    if (RAND_bytes(iv, iv_len) != 1) goto write_error;

    size_t fnlen = strlen(input_file);
    if (fnlen > 65535) fnlen = 65535;
    uint16_t name_len16 = (uint16_t)fnlen;
    if (!write_u16_be(out, name_len16)) goto write_error;

    uint64_t ts = (uint64_t)time(NULL);
    if (!write_u64_be(out, ts)) goto write_error;

    if (fwrite(iv, 1, iv_len, out) != iv_len) goto write_error;
    if (fwrite(input_file, 1, name_len16, out) != name_len16) goto write_error;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        goto write_error;
    }

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;

    if (aead == AEAD_AES_256_GCM) {
        /* AES-GCM AEAD */
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
            fprintf(stderr, "EVP_EncryptInit_ex (gcm init) failed\n");
            EVP_CIPHER_CTX_free(ctx);
            goto write_error;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) {
            fprintf(stderr, "EVP_CIPHER_CTX_ctrl set ivlen failed\n");
            EVP_CIPHER_CTX_free(ctx);
            goto write_error;
        }
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
            fprintf(stderr, "EVP_EncryptInit_ex (gcm key/iv) failed\n");
            EVP_CIPHER_CTX_free(ctx);
            goto write_error;
        }

        while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
            if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
                fprintf(stderr, "GCM Encryption update failed.\n");
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
            fprintf(stderr, "GCM Encryption finalization failed.\n");
            EVP_CIPHER_CTX_free(ctx);
            goto enc_fail;
        }
        if (outlen > 0) {
            if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
                fprintf(stderr, "Write error while writing final ciphertext.\n");
                EVP_CIPHER_CTX_free(ctx);
                goto enc_fail;
            }
        }

        unsigned char tag[GCM_TAG_LEN];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) {
            fprintf(stderr, "Failed to get GCM tag.\n");
            EVP_CIPHER_CTX_free(ctx);
            goto enc_fail;
        }
        if (fwrite(tag, 1, GCM_TAG_LEN, out) != GCM_TAG_LEN) {
            fprintf(stderr, "Failed to write GCM tag.\n");
            EVP_CIPHER_CTX_free(ctx);
            goto enc_fail;
        }

        EVP_CIPHER_CTX_free(ctx);
    } else {
        /* fallback to AES-256-CBC for non-AEAD or legacy mode */
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
            fprintf(stderr, "EVP_EncryptInit_ex failed\n");
            EVP_CIPHER_CTX_free(ctx);
            goto write_error;
        }

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
    }
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

        /* Newer format (v2+) includes KDF metadata */
        uint8_t kdf_id = 0;
        uint8_t salt_len = 0;
        uint32_t iterations = 0;
        if (fmt_ver >= 2) {
            if (fread(&kdf_id, 1, 1, in) != 1) {
                fprintf(stderr, "Failed to read kdf id.\n");
                fclose(in);
                return 1;
            }
            if (fread(&salt_len, 1, 1, in) != 1) {
                fprintf(stderr, "Failed to read salt length.\n");
                fclose(in);
                return 1;
            }
            unsigned char saltbuf[256];
            if (salt_len > 0) {
                    if ((int)salt_len > (int)(sizeof(saltbuf) - 1)) salt_len = (uint8_t)(sizeof(saltbuf) - 1);
                if (fread(saltbuf, 1, salt_len, in) != salt_len) {
                    fprintf(stderr, "Failed to read salt.\n");
                    fclose(in);
                    return 1;
                }
                printf("KDF: %s\n", kdf_id == KDF_PBKDF2_HMAC_SHA256 ? "PBKDF2-HMAC-SHA256" : "unknown");
                printf("Salt: "); for (int i=0;i<salt_len;i++) printf("%02x", saltbuf[i]); printf("\n");
            }
            unsigned char itb[4];
            if (fread(itb, 1, 4, in) != 4) {
                fprintf(stderr, "Failed to read iterations.\n");
                fclose(in);
                return 1;
            }
            iterations = ((uint32_t)itb[0] << 24) | ((uint32_t)itb[1] << 16) | ((uint32_t)itb[2] << 8) | (uint32_t)itb[3];
            printf("Iterations: %u\n", iterations);
        }

        /* Read AEAD id and IV length (v2+) */
        uint8_t aead_id = AEAD_NONE;
        uint8_t iv_len = AES_BLOCK_SIZE;
        if (fmt_ver >= 2) {
            if (fread(&aead_id, 1, 1, in) != 1) {
                fprintf(stderr, "Failed to read AEAD id.\n");
                fclose(in);
                return 1;
            }
            if (fread(&iv_len, 1, 1, in) != 1) {
                fprintf(stderr, "Failed to read IV length.\n");
                fclose(in);
                return 1;
            }
            printf("AEAD: %s\n", aead_id == AEAD_AES_256_GCM ? "AES-256-GCM" : (aead_id == AEAD_CHACHA20_POLY1305 ? "ChaCha20-Poly1305" : "unknown"));
            printf("IV length: %u\n", (unsigned)iv_len);
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
        printf("Timestamp (epoch): %llu\n", (unsigned long long)ts);

        unsigned char ivbuf[64];
        if (iv_len > sizeof(ivbuf)) {
            fprintf(stderr, "IV length too large.\n");
            fclose(in);
            return 1;
        }
        if (fread(ivbuf, 1, iv_len, in) != iv_len) {
            fprintf(stderr, "Failed to read IV.\n");
            fclose(in);
            return 1;
        }
        printf("IV: ");
        for (unsigned i = 0; i < iv_len; i++) printf("%02x", ivbuf[i]);
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

        long long header_bytes = 4 + 1; /* magic + fmt */
        if (fmt_ver >= 2) header_bytes += 1 + 1 + (long long)salt_len + 4 + 1 + 1; /* kdf_id + salt_len + salt + iterations + aead_id + iv_len */
        header_bytes += 2 + 8 + iv_len + name_len16;
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
    /* default derive; may be replaced when parsing header v2+ */
    derive_key(password, key);

    /* globals that may be set by main */
    extern uint32_t pbkdf2_iterations;
    extern int use_legacy_kdf;

    unsigned char header4[4] = {0};
    size_t read4 = fread(header4, 1, 4, in);

    int legacy_mode = 0;
    char original_name[256] = {0};
    uint8_t aead_id = AEAD_NONE;
    uint8_t iv_len = AES_BLOCK_SIZE;
    if (read4 == 4 && memcmp(header4, NEW_MAGIC, 4) == 0) {
        /* New AAF4 format */
        uint8_t fmt_ver = 0;
        if (fread(&fmt_ver, 1, 1, in) != 1) {
            fprintf(stderr, "Failed to read format version.\n");
            fclose(in);
            return 1;
        }

        /* handle KDF metadata for version >= 2 */
        uint8_t kdf_id = KDF_NONE;
        uint8_t salt_len = 0;
        unsigned char saltbuf[256];
        uint32_t iterations = 0;
        if (fmt_ver >= 2) {
            if (fread(&kdf_id, 1, 1, in) != 1) {
                fprintf(stderr, "Failed to read kdf id.\n");
                fclose(in);
                return 1;
            }
            if (fread(&salt_len, 1, 1, in) != 1) {
                fprintf(stderr, "Failed to read salt length.\n");
                fclose(in);
                return 1;
            }
            if (salt_len > 0) {
                if ((int)salt_len > (int)(sizeof(saltbuf) - 1)) salt_len = (uint8_t)(sizeof(saltbuf) - 1);
                if (fread(saltbuf, 1, salt_len, in) != salt_len) {
                    fprintf(stderr, "Failed to read salt.\n");
                    fclose(in);
                    return 1;
                }
            }
            unsigned char itb[4];
            if (fread(itb, 1, 4, in) != 4) {
                fprintf(stderr, "Failed to read iterations.\n");
                fclose(in);
                return 1;
            }
            iterations = ((uint32_t)itb[0] << 24) | ((uint32_t)itb[1] << 16) | ((uint32_t)itb[2] << 8) | (uint32_t)itb[3];

            /* derive key now using PBKDF2 unless legacy requested */
            extern int use_legacy_kdf;
                if (!use_legacy_kdf && kdf_id == KDF_PBKDF2_HMAC_SHA256) {
                    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), saltbuf, salt_len, iterations, EVP_sha256(), AES_KEY_SIZE, key)) {
                        fprintf(stderr, "PBKDF2 derivation failed.\n");
                        fclose(in);
                        return 1;
                    }
                } else if (use_legacy_kdf) {
                derive_key(password, key);
            }
        }

        /* read AEAD id and iv length (v2+) */
        if (fmt_ver >= 2) {
            if (fread(&aead_id, 1, 1, in) != 1) {
                fprintf(stderr, "Failed to read AEAD id.\n");
                fclose(in);
                return 1;
            }
            if (fread(&iv_len, 1, 1, in) != 1) {
                fprintf(stderr, "Failed to read IV length.\n");
                fclose(in);
                return 1;
            }
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

        if (iv_len > AES_BLOCK_SIZE) {
            /* support iv_len up to our buffer size */
            if (iv_len > sizeof(iv)) {
                fprintf(stderr, "IV length too large.\n");
                fclose(in);
                return 1;
            }
        }
        if (fread(iv, 1, iv_len, in) != iv_len) {
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

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;

    if (aead_id == AEAD_AES_256_GCM) {
        /* For GCM we need to exclude the auth tag at the end of the file */
        long header_end = ftell(in);
        if (header_end == -1L) {
            fprintf(stderr, "Failed to determine file position.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        if (fseek(in, 0, SEEK_END) != 0) {
            perror("fseek");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        long total = ftell(in);
        if (total == -1L) {
            fprintf(stderr, "Failed to determine file size.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        long long tag_len = GCM_TAG_LEN;
        if (total < header_end + tag_len) {
            fprintf(stderr, "File too small for GCM tag.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        long long ciphertext_len = (long long)total - header_end - tag_len;
        if (fseek(in, header_end, SEEK_SET) != 0) {
            perror("fseek");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
            fprintf(stderr, "EVP_DecryptInit_ex (gcm init) failed\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) {
            fprintf(stderr, "EVP_CIPHER_CTX_ctrl set ivlen failed\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
            fprintf(stderr, "EVP_DecryptInit_ex (gcm key/iv) failed\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }

        long long remaining = ciphertext_len;
        while (remaining > 0) {
            size_t toread = (size_t)(remaining > (long long)sizeof(inbuf) ? sizeof(inbuf) : remaining);
            inlen = fread(inbuf, 1, toread, in);
            if ((long long)inlen <= 0) break;
            if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
                fprintf(stderr, "GCM Decryption update failed.\n");
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
            remaining -= inlen;
        }

        /* read tag */
        unsigned char tag[GCM_TAG_LEN];
        if (fread(tag, 1, GCM_TAG_LEN, in) != GCM_TAG_LEN) {
            fprintf(stderr, "Failed to read GCM tag.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            unlink(output_placeholder);
            OPENSSL_cleanse(key, sizeof(key));
            return 1;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1) {
            fprintf(stderr, "Failed to set expected GCM tag.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            unlink(output_placeholder);
            OPENSSL_cleanse(key, sizeof(key));
            return 1;
        }

        if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
            fprintf(stderr, "Incorrect password or corrupted (GCM tag mismatch).\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            unlink(output_placeholder);
            OPENSSL_cleanse(key, sizeof(key));
            return 1;
        }
        if (outlen > 0) {
            if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
                fprintf(stderr, "Write error while writing final plaintext.\n");
                EVP_CIPHER_CTX_free(ctx);
                fclose(in);
                fclose(out);
                unlink(output_placeholder);
                OPENSSL_cleanse(key, sizeof(key));
                return 1;
            }
        }

        EVP_CIPHER_CTX_free(ctx);
    } else {
        /* fallback to AES-256-CBC for non-AEAD or legacy mode */
        if (iv_len != AES_BLOCK_SIZE) {
            fprintf(stderr, "Unexpected IV length for CBC mode.\n");
            EVP_CIPHER_CTX_free(ctx);
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
    }
    fclose(in);
    fclose(out);
    OPENSSL_cleanse(key, sizeof(key));

    printf("✅ Decrypted successfully: %s (mode: %s)\n",
           output_placeholder ? output_placeholder : "(unknown)",
           legacy_mode ? "legacy" : "v1.4");
    return 0;
}

/* Encrypt helper that allows specifying the original filename stored in the header
 * (used when re-encrypting a temporary plaintext file but preserving the
 * original filename/extension in the AAF header). This duplicates some logic
 * from encrypt_file but only the header-writing part differs (we use
 * header_name instead of input_file for the original filename metadata).
 */
int encrypt_file_with_name(const char *input_file, const char *output_file, const char *password, const char *header_name) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        perror("File error");
        if (in) fclose(in);
        if (out) fclose(out);
        return 1;
    }

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];

    if (fwrite(NEW_MAGIC, 1, 4, out) != 4) goto write_error2;
    uint8_t fmt_ver = NEW_FORMAT_VERSION;
    if (fwrite(&fmt_ver, 1, 1, out) != 1) goto write_error2;

    uint8_t kdf_id = KDF_PBKDF2_HMAC_SHA256;
    if (fwrite(&kdf_id, 1, 1, out) != 1) goto write_error2;
    uint8_t salt_len = DEFAULT_SALT_LEN;
    if (fwrite(&salt_len, 1, 1, out) != 1) goto write_error2;

    unsigned char salt[DEFAULT_SALT_LEN];
    if (RAND_bytes(salt, DEFAULT_SALT_LEN) != 1) { fprintf(stderr, "Randomness generation for salt failed.\n"); goto write_error2; }
    if (fwrite(salt, 1, DEFAULT_SALT_LEN, out) != DEFAULT_SALT_LEN) goto write_error2;

    uint32_t iterations = DEFAULT_PBKDF2_ITERS;
    extern uint32_t pbkdf2_iterations;
    if (pbkdf2_iterations > 0) iterations = pbkdf2_iterations;
    unsigned char itb[4];
    itb[0] = (iterations >> 24) & 0xFF;
    itb[1] = (iterations >> 16) & 0xFF;
    itb[2] = (iterations >> 8) & 0xFF;
    itb[3] = iterations & 0xFF;
    if (fwrite(itb, 1, 4, out) != 4) goto write_error2;

    extern int use_legacy_kdf;
    if (!use_legacy_kdf) {
        if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, DEFAULT_SALT_LEN, iterations, EVP_sha256(), AES_KEY_SIZE, key)) {
            fprintf(stderr, "PBKDF2 derivation failed.\n");
            goto write_error2;
        }
    } else {
        derive_key(password, key);
    }

    extern int selected_aead;
    int aead = selected_aead;
    uint8_t iv_len = AES_BLOCK_SIZE;
    if (aead == AEAD_AES_256_GCM) iv_len = GCM_IV_LEN;
    uint8_t aead_id = (uint8_t)aead;
    if (fwrite(&aead_id, 1, 1, out) != 1) goto write_error2;
    if (fwrite(&iv_len, 1, 1, out) != 1) goto write_error2;
    if (RAND_bytes(iv, iv_len) != 1) goto write_error2;

    size_t fnlen = header_name ? strlen(header_name) : 0;
    if (fnlen > 65535) fnlen = 65535;
    uint16_t name_len16 = (uint16_t)fnlen;
    if (!write_u16_be(out, name_len16)) goto write_error2;

    uint64_t ts = (uint64_t)time(NULL);
    if (!write_u64_be(out, ts)) goto write_error2;

    if (fwrite(iv, 1, iv_len, out) != iv_len) goto write_error2;
    if (name_len16 > 0) {
        if (fwrite(header_name, 1, name_len16, out) != name_len16) goto write_error2;
    }

    /* Now perform encryption (reuse logic from encrypt_file) */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { fprintf(stderr, "EVP_CIPHER_CTX_new failed\n"); goto write_error2; }

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;

    if (aead == AEAD_AES_256_GCM) {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { fprintf(stderr, "EVP_EncryptInit_ex (gcm init) failed\n"); EVP_CIPHER_CTX_free(ctx); goto write_error2; }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) { fprintf(stderr, "EVP_CIPHER_CTX_ctrl set ivlen failed\n"); EVP_CIPHER_CTX_free(ctx); goto write_error2; }
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) { fprintf(stderr, "EVP_EncryptInit_ex (gcm key/iv) failed\n"); EVP_CIPHER_CTX_free(ctx); goto write_error2; }

        while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
            if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) { fprintf(stderr, "GCM Encryption update failed.\n"); EVP_CIPHER_CTX_free(ctx); goto enc_fail2; }
            if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) { fprintf(stderr, "Write error while writing ciphertext.\n"); EVP_CIPHER_CTX_free(ctx); goto enc_fail2; }
        }

        if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) { fprintf(stderr, "GCM Encryption finalization failed.\n"); EVP_CIPHER_CTX_free(ctx); goto enc_fail2; }
        if (outlen > 0) if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) { fprintf(stderr, "Write error while writing final ciphertext.\n"); EVP_CIPHER_CTX_free(ctx); goto enc_fail2; }

        unsigned char tag[GCM_TAG_LEN];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) { fprintf(stderr, "Failed to get GCM tag.\n"); EVP_CIPHER_CTX_free(ctx); goto enc_fail2; }
        if (fwrite(tag, 1, GCM_TAG_LEN, out) != GCM_TAG_LEN) { fprintf(stderr, "Failed to write GCM tag.\n"); EVP_CIPHER_CTX_free(ctx); goto enc_fail2; }
        EVP_CIPHER_CTX_free(ctx);
    } else {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { fprintf(stderr, "EVP_EncryptInit_ex failed\n"); EVP_CIPHER_CTX_free(ctx); goto write_error2; }
        while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
            if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) { fprintf(stderr, "Encryption update failed.\n"); EVP_CIPHER_CTX_free(ctx); goto enc_fail2; }
            if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) { fprintf(stderr, "Write error while writing ciphertext.\n"); EVP_CIPHER_CTX_free(ctx); goto enc_fail2; }
        }
        if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) { fprintf(stderr, "Encryption finalization failed.\n"); EVP_CIPHER_CTX_free(ctx); goto enc_fail2; }
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) { fprintf(stderr, "Write error while writing final ciphertext.\n"); EVP_CIPHER_CTX_free(ctx); goto enc_fail2; }
        EVP_CIPHER_CTX_free(ctx);
    }
    fclose(in);
    fclose(out);
    OPENSSL_cleanse(key, sizeof(key));
    return 0;

write_error2:
    perror("File write error");
    if (in) fclose(in);
    if (out) { fclose(out); unlink(output_file); }
    OPENSSL_cleanse(key, sizeof(key));
    return 1;

enc_fail2:
    if (in) fclose(in);
    if (out) { fclose(out); unlink(output_file); }
    OPENSSL_cleanse(key, sizeof(key));
    return 1;
}


/* temp_decrypt_and_open: simple prompt-based temporary decryption.
 * - decrypts the AAF into a secure temp file using the original filename
 *   stored in the header (if present)
 * - opens the temp file with xdg-open and prompts the user to press ENTER
 *   when done
 * - re-encrypts the temp file back into the original .aaf (overwriting)
 * - securely unlinks the temp file
 */
int temp_decrypt_and_open(const char *aaf_path, const char *password) {
    FILE *in = fopen(aaf_path, "rb");
    if (!in) { perror("File error"); return 1; }

    unsigned char header4[4] = {0};
    if (fread(header4, 1, 4, in) != 4) { fprintf(stderr, "Failed to read header\n"); fclose(in); return 1; }
    char original_name[256] = {0};
    uint8_t aead_id = AEAD_NONE;
    uint8_t iv_len = AES_BLOCK_SIZE;
    long header_end = 0;

    if (memcmp(header4, NEW_MAGIC, 4) == 0) {
        uint8_t fmt_ver = 0;
        if (fread(&fmt_ver, 1, 1, in) != 1) { fprintf(stderr, "Failed to read fmt version\n"); fclose(in); return 1; }
        if (fmt_ver >= 2) {
            uint8_t kdf_id = 0; uint8_t salt_len = 0;
            if (fread(&kdf_id,1,1,in)!=1) { fclose(in); return 1; }
            if (fread(&salt_len,1,1,in)!=1) { fclose(in); return 1; }
            if (salt_len > 0) {
                if (fseek(in, salt_len, SEEK_CUR) != 0) { fclose(in); return 1; }
            }
            if (fseek(in, 4, SEEK_CUR) != 0) { fclose(in); return 1; } /* iterations */
            if (fread(&aead_id,1,1,in) != 1) { fclose(in); return 1; }
            if (fread(&iv_len,1,1,in) != 1) { fclose(in); return 1; }
        }
        uint16_t name_len16 = 0;
        if (!read_u16_be(in, &name_len16)) { fclose(in); return 1; }
        if (!read_u64_be(in, (uint64_t*)&header_end)) { fclose(in); return 1; }
        if (fseek(in, iv_len, SEEK_CUR) != 0) { fclose(in); return 1; }
        if (name_len16 > 0) {
            if (name_len16 >= sizeof(original_name)) name_len16 = sizeof(original_name)-1;
            if (fread(original_name,1,name_len16,in) != name_len16) { fclose(in); return 1; }
            original_name[name_len16] = '\0';
        }
    } else {
        fclose(in);
        fprintf(stderr, "Unsupported or legacy format for temp-decrypt\n");
        return 1;
    }
    fclose(in);

    /* choose temp dir */
    const char *xdg = getenv("XDG_RUNTIME_DIR");
    const char *tmp = getenv("TMPDIR");
    char tmpdir_template[512];
    const char *base_tmp = xdg ? xdg : (tmp ? tmp : "/tmp");
    snprintf(tmpdir_template, sizeof(tmpdir_template), "%s/aaftmp.XXXXXX", base_tmp);
    char *tmpdir = mkdtemp(tmpdir_template);
    if (!tmpdir) { perror("mkdtemp"); return 1; }

    char temp_path[1024];
    if (original_name[0]) {
        snprintf(temp_path, sizeof(temp_path), "%s/%s", tmpdir, original_name);
    } else {
        snprintf(temp_path, sizeof(temp_path), "%s/aaftempfile", tmpdir);
    }

    /* perform decryption into temp_path by calling decrypt_file logic but
     * using our temp_path as the output. We reuse decrypt_file by calling it
     * but passing a placeholder and ensuring the function does not override
     * our chosen output. decrypt_file overrides output if header contains
     * original name, so we cannot call it safely. We'll perform a small
     * manual decryption by invoking decrypt_file with the same code path
     * duplicated here for simplicity. For brevity and to avoid duplicating
     * full logic, call decrypt_file but then move produced file if needed.
     */
    /* Call decrypt_file but direct output to a local filename so it writes the
     * original filename into that file; after success we'll move it into temp_path.
     */
    char work_output[512];
    /* use current directory as workdir output name; if original_name present use that */
    if (original_name[0]) snprintf(work_output, sizeof(work_output), "%s", original_name);
    else snprintf(work_output, sizeof(work_output), "%s/aaf_plain_%d", tmpdir, (int)getpid());

    if (decrypt_file(aaf_path, work_output, password) != 0) {
        fprintf(stderr, "Decryption failed\n");
        /* cleanup tempdir */
        rmdir(tmpdir);
        return 1;
    }

    /* move work_output into temp_path (rename) */
    if (rename(work_output, temp_path) != 0) {
        perror("rename to temp path failed");
        /* if rename fails, keep work_output as is and proceed */
        strncpy(temp_path, work_output, sizeof(temp_path)-1);
    }

    /* set secure permissions */
    chmod(temp_path, S_IRUSR | S_IWUSR);

    printf("[+] Opened temporary file: %s\n", temp_path);
    /* try to open with xdg-open (best-effort) */
    pid_t pid = fork();
    if (pid == 0) {
        execlp("xdg-open", "xdg-open", temp_path, (char *)NULL);
        /* if execlp fails, simply exit child */
        _exit(1);
    } else if (pid < 0) {
        perror("fork");
    } else {
        /* parent: do not wait on xdg-open (it usually returns quickly). Use
         * a simple prompt-based approach as requested: */
        printf("Press ENTER when you're done viewing the file to re-encrypt and remove it...");
        fflush(stdout);
        getchar();
    }

    /* re-encrypt temp_path back into the original aaf file (atomic replace) */
    char out_tmp[1024];
    snprintf(out_tmp, sizeof(out_tmp), "%s.tmp", aaf_path);
    if (encrypt_file_with_name(temp_path, out_tmp, password, original_name) != 0) {
        fprintf(stderr, "Re-encryption failed — plaintext kept at: %s\n", temp_path);
        return 1;
    }
    /* rename temporary output to final (atomic move) */
    if (rename(out_tmp, aaf_path) != 0) {
        perror("rename final aaf failed");
        return 1;
    }

    /* attempt to securely wipe the temp file by overwriting once and unlinking */
    FILE *tf = fopen(temp_path, "r+");
    if (tf) {
        if (fseek(tf, 0, SEEK_END) == 0) {
            long sz = ftell(tf);
            if (sz > 0) {
                rewind(tf);
                unsigned char *buf = calloc(1, 4096);
                long rem = sz;
                while (rem > 0) {
                    size_t w = (size_t)(rem > 4096 ? 4096 : rem);
                    fwrite(buf, 1, w, tf);
                    rem -= w;
                }
                fflush(tf);
                fsync(fileno(tf));
                free(buf);
            }
        }
        fclose(tf);
    }
    unlink(temp_path);
    /* cleanup temporary directory */
    rmdir(tmpdir);

    printf("✅ Temp view complete; file re-encrypted and plaintext removed.\n");
    return 0;
}

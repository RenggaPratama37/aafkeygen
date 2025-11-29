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

/* Silence direct printing from this module so crypto becomes a pure engine.
 * The main program (or other frontends) should handle user-facing output.
 */
#undef printf
#undef fprintf
#undef perror
#define printf(...) ((void)0)
#define fprintf(...) ((void)0)
#define perror(...) ((void)0)

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
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
int selected_aead = DEFAULT_AEAD_ID; /* AEAD chosen for new encryptions */

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

    /* derive key with PBKDF2 (legacy support removed) */
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, DEFAULT_SALT_LEN, iterations, EVP_sha256(), AES_KEY_SIZE, key)) {
        fprintf(stderr, "PBKDF2 derivation failed.\n");
        goto write_error;
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

    unsigned char inbuf[4096], outbuf[4128];
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
    OPENSSL_cleanse(iv, sizeof(iv));
    return 0;

write_error:
    perror("File write error");
    fclose(in);
    fclose(out);
    unlink(output_file);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    return 1;

enc_fail:
    fclose(in);
    fclose(out);
    unlink(output_file);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    return 1;
}


// === backward-compatible decrypt ===
int decrypt_file(const char *input_file, const char *output_placeholder, const char *password) {
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        return 1;
    }

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];
    /* globals that may be set by main */
    extern uint32_t pbkdf2_iterations;

    unsigned char header4[4] = {0};
    if (fread(header4, 1, 4, in) != 4) { fclose(in); return 1; }

    /* Only the new AAF4 format is supported in this release; legacy formats
     * are intentionally rejected so users must migrate with older tool
     * versions before upgrading.
     */
    if (memcmp(header4, NEW_MAGIC, 4) != 0) { fclose(in); return 1; }

    char original_name[256] = {0};
    uint8_t aead_id = AEAD_NONE;
    uint8_t iv_len = AES_BLOCK_SIZE;
    /* New AAF4 format */
    uint8_t fmt_ver = 0;
    if (fread(&fmt_ver, 1, 1, in) != 1) { fclose(in); return 1; }

    /* handle KDF metadata for version >= 2 */
    uint8_t kdf_id = KDF_NONE;
    uint8_t salt_len = 0;
    unsigned char saltbuf[MAX_SALT_LEN];
    uint32_t iterations = 0;
    if (fmt_ver >= 2) {
        if (fread(&kdf_id, 1, 1, in) != 1) { fclose(in); return 1; }
        if (fread(&salt_len, 1, 1, in) != 1) { fclose(in); return 1; }
        if (salt_len > 0) {
             if ((size_t)salt_len > sizeof(saltbuf)) salt_len = (uint8_t)sizeof(saltbuf);
            if (fread(saltbuf, 1, salt_len, in) != salt_len) { fclose(in); return 1; }
        }
        unsigned char itb[4];
        if (fread(itb, 1, 4, in) != 4) { fclose(in); return 1; }
        iterations = ((uint32_t)itb[0] << 24) | ((uint32_t)itb[1] << 16) | ((uint32_t)itb[2] << 8) | (uint32_t)itb[3];

        /* Only PBKDF2-HMAC-SHA256 is supported; fail otherwise. */
        if (kdf_id != KDF_PBKDF2_HMAC_SHA256) { fclose(in); return 1; }
        if (!PKCS5_PBKDF2_HMAC(password, strlen(password), saltbuf, salt_len, iterations, EVP_sha256(), AES_KEY_SIZE, key)) {
            fprintf(stderr, "PBKDF2 derivation failed.\n");
            fclose(in);
            return 1;
        }
    }

    /* read AEAD id and iv length (v2+) */
    if (fmt_ver >= 2) {
        if (fread(&aead_id, 1, 1, in) != 1) { fclose(in); return 1; }
        if (fread(&iv_len, 1, 1, in) != 1) { fclose(in); return 1; }
    }

    uint16_t name_len16 = 0;
    if (!read_u16_be(in, &name_len16)) { fclose(in); return 1; }

    uint64_t ts = 0;
    if (!read_u64_be(in, &ts)) { fclose(in); return 1; }

    if (iv_len > sizeof(iv)) { fclose(in); return 1; }

    if (fread(iv, 1, iv_len, in) != iv_len) { fclose(in); return 1; }

    if (name_len16 > 0) {
        if (name_len16 >= sizeof(original_name)) name_len16 = sizeof(original_name) - 1;
        if (fread(original_name, 1, name_len16, in) != name_len16) { fclose(in); return 1; }
        original_name[name_len16] = '\0';
    }

    /* decide final output path: prefer caller-provided, otherwise use original name from header */
    const char *final_output = output_placeholder;
    if (!final_output || final_output[0] == '\0') {
        if (original_name[0]) final_output = original_name;
        else final_output = input_file; /* fallback to input filename (without .aaf handled by caller) */
    }
    FILE *out = fopen(final_output, "wb");
    if (!out) {
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
                unlink(final_output);
                OPENSSL_cleanse(key, sizeof(key));
                OPENSSL_cleanse(iv,sizeof(iv));
                return 1;
            }
            if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
                fprintf(stderr, "Write error while writing plaintext.\n");
                EVP_CIPHER_CTX_free(ctx);
                fclose(in);
                fclose(out);
                unlink(final_output);
                OPENSSL_cleanse(key, sizeof(key));
                OPENSSL_cleanse(iv,sizeof(iv));
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
            unlink(final_output);
            OPENSSL_cleanse(key, sizeof(key));
            OPENSSL_cleanse(iv, sizeof(iv));
            return 1;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1) {
            fprintf(stderr, "Failed to set expected GCM tag.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            unlink(final_output);
            OPENSSL_cleanse(key, sizeof(key));
            OPENSSL_cleanse(iv, sizeof(iv));
            return 1;
        }

        if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
            fprintf(stderr, "Incorrect password or corrupted (GCM tag mismatch).\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            unlink(final_output);
            OPENSSL_cleanse(key, sizeof(key));
            OPENSSL_cleanse(iv, sizeof(iv));
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
                OPENSSL_cleanse(iv, sizeof(iv));
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
                OPENSSL_cleanse(iv, sizeof(iv));
                return 1;
            }
            if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
                fprintf(stderr, "Write error while writing plaintext.\n");
                EVP_CIPHER_CTX_free(ctx);
                fclose(in);
                fclose(out);
                unlink(output_placeholder);
                OPENSSL_cleanse(key, sizeof(key));
                OPENSSL_cleanse(iv, sizeof(iv));
                return 1;
            }
        }

        if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
            fprintf(stderr, "Incorrect password or corrupted file.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            unlink(final_output);
            OPENSSL_cleanse(key, sizeof(key));
            OPENSSL_cleanse(iv, sizeof(iv));
            return 1;
        }
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
            fprintf(stderr, "Write error while writing final plaintext.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            unlink(output_placeholder);
            OPENSSL_cleanse(key, sizeof(key));
            OPENSSL_cleanse(iv, sizeof(iv));
            return 1;
        }
        EVP_CIPHER_CTX_free(ctx);
    }
    fclose(in);
    fclose(out);
    OPENSSL_cleanse(key, sizeof(key));

        printf("✅ Decrypted successfully: %s\n",
            output_placeholder ? output_placeholder : "(unknown)");
    return 0;
}

/* parse_header: non-printing parser that fills aaf_header_t from an AAF file.
 * Returns 0 on success, non-zero on failure.
 */
int parse_header(const char *input_file, aaf_header_t *out) {
    if (!out) return 1;
    memset(out, 0, sizeof(*out));

    FILE *in = fopen(input_file, "rb");
    if (!in) return 1;

    unsigned char header4[4] = {0};
    if (fread(header4, 1, 4, in) != 4) { fclose(in); return 1; }

    if (memcmp(header4, NEW_MAGIC, 4) == 0) {
        memcpy(out->magic, NEW_MAGIC, 4);
        out->magic[4] = '\0';
        uint8_t fmt_ver = 0;
        if (fread(&fmt_ver, 1, 1, in) != 1) { fclose(in); return 1; }
        out->fmt_ver = fmt_ver;

        if (fmt_ver >= 2) {
            if (fread(&out->kdf_id, 1, 1, in) != 1) { fclose(in); return 1; }
            if (fread(&out->salt_len, 1, 1, in) != 1) { fclose(in); return 1; }
            if (out->salt_len > 0) {
                if (out->salt_len > MAX_SALT_LEN) {
                    /* truncate if header has larger salt than we support */
                    if (fseek(in, out->salt_len, SEEK_CUR) != 0) { fclose(in); return 1; }
                } else {
                    if (fread(out->salt, 1, out->salt_len, in) != out->salt_len) { fclose(in); return 1; }
                }
            }
            unsigned char itb[4];
            if (fread(itb, 1, 4, in) != 4) { fclose(in); return 1; }
            out->iterations = ((uint32_t)itb[0] << 24) | ((uint32_t)itb[1] << 16) | ((uint32_t)itb[2] << 8) | (uint32_t)itb[3];
        }

        if (fmt_ver >= 2) {
            if (fread(&out->aead_id, 1, 1, in) != 1) { fclose(in); return 1; }
            if (fread(&out->iv_len, 1, 1, in) != 1) { fclose(in); return 1; }
        } else {
            out->aead_id = AEAD_NONE;
            out->iv_len = AES_BLOCK_SIZE;
        }

        if (!read_u16_be(in, &out->name_len)) { fclose(in); return 1; }
        if (!read_u64_be(in, &out->timestamp)) { fclose(in); return 1; }

        /* IV length validation */
        if (out->iv_len > sizeof(out->iv)) {
            fclose(in);
            return 1; /* Invalid: IV too large */
        }
        if (out->iv_len > 0) {
            if (fread(out->iv, 1, out->iv_len, in) != out->iv_len) {
                fclose(in);
                return 1;
            }
        }

        if (out->name_len > 0) {
            uint16_t nl = out->name_len;
            if (nl >= sizeof(out->original_name)) nl = sizeof(out->original_name) - 1;
            if (fread(out->original_name, 1, nl, in) != nl) { fclose(in); return 1; }
            out->original_name[nl] = '\0';
        }

        /* compute header bytes size approximately */
        out->header_bytes = 4 + 1; /* magic + fmt */
        if (out->fmt_ver >= 2) out->header_bytes += 1 + 1 + out->salt_len + 4 + 1 + 1; /* kdf_id + salt_len + salt + iterations + aead_id + iv_len */
        out->header_bytes += 2 + 8 + out->iv_len + out->name_len;

        fclose(in);
        return 0;
    }
    /* If we reach here and the magic was not NEW_MAGIC the file is not
     * supported by this release (legacy formats removed). Return non-zero
     * so callers can handle migration with older tool versions.
     */
    fclose(in);
    return 1;
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

    /* derive key with PBKDF2 (legacy support removed) */
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, DEFAULT_SALT_LEN, iterations, EVP_sha256(), AES_KEY_SIZE, key)) {
        fprintf(stderr, "PBKDF2 derivation failed.\n");
        goto write_error2;
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
/* temp_decrypt_and_open has been moved to src/temp.c for modularity. */

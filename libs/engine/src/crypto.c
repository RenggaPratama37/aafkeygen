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
/* Local KDF wrapper */
#include "kdf.h"
/* AEAD / Cipher helpers */
#include "aead.h"
#include "cipher.h"
#include "compress.h"

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

    /* Build header metadata and write it using header module */
    unsigned char salt[DEFAULT_SALT_LEN];
    if (RAND_bytes(salt, DEFAULT_SALT_LEN) != 1) {
        fprintf(stderr, "Randomness generation for salt failed.\n");
        goto write_error;
    }
    uint32_t iterations = DEFAULT_PBKDF2_ITERS;
    extern uint32_t pbkdf2_iterations;
    if (pbkdf2_iterations > 0) iterations = pbkdf2_iterations;

    /* derive key */
    if (!derive_key_pbkdf2(password, salt, DEFAULT_SALT_LEN, iterations, key, AES_KEY_SIZE)) {
        fprintf(stderr, "PBKDF2 derivation failed.\n");
        goto write_error;
    }

    extern int selected_aead;
    int aead = selected_aead;
    uint8_t iv_len = AES_BLOCK_SIZE;
    if (aead == AEAD_AES_256_GCM) iv_len = GCM_IV_LEN;
    if (RAND_bytes(iv, iv_len) != 1) goto write_error;

    aaf_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.comp_id = 0; /* no compression by default */
    hdr.fmt_ver = NEW_FORMAT_VERSION;
    hdr.kdf_id = KDF_PBKDF2_HMAC_SHA256;
    hdr.salt_len = DEFAULT_SALT_LEN;
    memcpy(hdr.salt, salt, DEFAULT_SALT_LEN);
    hdr.iterations = iterations;
    hdr.aead_id = (uint8_t)aead;
    hdr.iv_len = iv_len;
    hdr.timestamp = (uint64_t)time(NULL);
    size_t fnlen = strlen(input_file);
    if (fnlen > 65535) fnlen = 65535;
    hdr.name_len = (uint16_t)fnlen;
    strncpy(hdr.original_name, input_file, hdr.name_len);
    memcpy(hdr.iv, iv, hdr.iv_len);
    if (write_header(out, &hdr) != 0) goto write_error;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        goto write_error;
    }

    unsigned char inbuf[4096], outbuf[4128];
    int inlen, outlen;

    if (aead == AEAD_AES_256_GCM) {
        if (aead_encrypt_gcm_stream(key, iv, iv_len, in, out) != 0) {
            goto enc_fail;
        }
    } else {
        if (cipher_encrypt_cbc_stream(key, iv, in, out) != 0) {
            goto enc_fail;
        }
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
        if (!derive_key_pbkdf2(password, saltbuf, salt_len, iterations, key, AES_KEY_SIZE)) {
            fprintf(stderr, "PBKDF2 derivation failed.\n");
            fclose(in);
            return 1;
        }
    }

    /* read AEAD id and detect optional comp_id for backwards-compat */
    uint8_t comp_id = 0;
    if (fmt_ver >= 2) {
        if (fread(&aead_id, 1, 1, in) != 1) { fclose(in); return 1; }
        unsigned char nextb = 0;
        if (fread(&nextb, 1, 1, in) != 1) { fclose(in); return 1; }
        if (nextb <= 1) {
            comp_id = nextb;
            if (fread(&iv_len, 1, 1, in) != 1) { fclose(in); return 1; }
        } else {
            /* old files: nextb was actually iv_len */
            comp_id = 0;
            iv_len = nextb;
        }
    }

    /* If the user explicitly requested an AEAD via CLI, enforce it matches the header.
     * We prefer to read the `AAF_AEAD` environment variable (set by main.c when
     * the user supplied `--aead`) rather than relying on fragile globals across
     * translation units. */
    const char *env_aead = getenv("AAF_AEAD");
    if (env_aead) {
        /* debug write to file to observe env and header values during tests */
        FILE *dbg = fopen("/tmp/aaf_dbg.txt", "a");
        if (dbg) {
            fprintf(dbg, "env_aead=%s header_aead=%u\n", env_aead, aead_id);
            fclose(dbg);
        }
        int requested = AEAD_NONE;
        if (strcmp(env_aead, "gcm") == 0) requested = AEAD_AES_256_GCM;
        else if (strcmp(env_aead, "chacha20") == 0) requested = AEAD_CHACHA20_POLY1305;
        if (requested != AEAD_NONE && requested != (int)aead_id) {
            fprintf(stderr, "AEAD mismatch: header uses id %u but requested %d\n", aead_id, requested);
            fclose(in);
            return 1;
        }
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

    /* If compressed, decrypt into a temp file then decompress into final_output. */
    FILE *out = NULL;
    char tmp_decrypt_path[1024];
    int use_temp_for_decrypt = 0;
    if (comp_id != 0) {
        const char *base_tmp = getenv("TMPDIR");
        if (!base_tmp) base_tmp = "/tmp";
        snprintf(tmp_decrypt_path, sizeof(tmp_decrypt_path), "%s/aaf_decrypt_XXXXXX", base_tmp);
        int fd = mkstemp(tmp_decrypt_path);
        if (fd == -1) { fclose(in); return 1; }
        out = fdopen(fd, "wb");
        if (!out) { close(fd); unlink(tmp_decrypt_path); fclose(in); return 1; }
        use_temp_for_decrypt = 1;
    } else {
        out = fopen(final_output, "wb");
        if (!out) { fclose(in); return 1; }
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

        if (aead_decrypt_gcm_stream(key, iv, iv_len, in, ciphertext_len, out) != 0) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            if (use_temp_for_decrypt) unlink(tmp_decrypt_path);
            OPENSSL_cleanse(key, sizeof(key));
            OPENSSL_cleanse(iv, sizeof(iv));
            return 1;
        }
    } else {
        /* fallback to AES-256-CBC for non-AEAD or legacy mode */
        if (iv_len != AES_BLOCK_SIZE) {
            fprintf(stderr, "Unexpected IV length for CBC mode.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        if (cipher_decrypt_cbc_stream(key, iv, in, out) != 0) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            if (use_temp_for_decrypt) unlink(tmp_decrypt_path);
            OPENSSL_cleanse(key, sizeof(key));
            OPENSSL_cleanse(iv, sizeof(iv));
            return 1;
        }
    }
    fclose(in);
    fclose(out);
    OPENSSL_cleanse(key, sizeof(key));

    /* If we decrypted into a temp file because payload was compressed, decompress it */
    if (use_temp_for_decrypt) {
        if (decompress_file_to(tmp_decrypt_path, final_output) != 0) {
            unlink(tmp_decrypt_path);
            fprintf(stderr, "Decompression failed\n");
            return 1;
        }
        unlink(tmp_decrypt_path);
    }

    printf("✅ Decrypted successfully: %s\n",
        final_output ? final_output : "(unknown)");
    return 0;
}

/* Header parsing moved to src/header.c (parse_header implementation).
 * crypto.c now relies on the header module for parsing/inspecting AAF headers.
 */

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

    unsigned char salt[DEFAULT_SALT_LEN];
    if (RAND_bytes(salt, DEFAULT_SALT_LEN) != 1) { fprintf(stderr, "Randomness generation for salt failed.\n"); goto write_error2; }

    uint32_t iterations = DEFAULT_PBKDF2_ITERS;
    extern uint32_t pbkdf2_iterations;
    if (pbkdf2_iterations > 0) iterations = pbkdf2_iterations;
    unsigned char itb[4];
    itb[0] = (iterations >> 24) & 0xFF;
    itb[1] = (iterations >> 16) & 0xFF;
    itb[2] = (iterations >> 8) & 0xFF;
    itb[3] = iterations & 0xFF;

    if (!derive_key_pbkdf2(password, salt, DEFAULT_SALT_LEN, iterations, key, AES_KEY_SIZE)) {
        fprintf(stderr, "PBKDF2 derivation failed.\n");
        goto write_error2;
    }

    extern int selected_aead;
    int aead = selected_aead;
    uint8_t iv_len = AES_BLOCK_SIZE;
    if (aead == AEAD_AES_256_GCM) iv_len = GCM_IV_LEN;
    if (RAND_bytes(iv, iv_len) != 1) goto write_error2;

    aaf_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.fmt_ver = NEW_FORMAT_VERSION;
    hdr.kdf_id = KDF_PBKDF2_HMAC_SHA256;
    hdr.salt_len = DEFAULT_SALT_LEN;
    memcpy(hdr.salt, salt, DEFAULT_SALT_LEN);
    hdr.iterations = iterations;
    hdr.aead_id = (uint8_t)aead;
    hdr.iv_len = iv_len;
    hdr.timestamp = (uint64_t)time(NULL);
    size_t fnlen = header_name ? strlen(header_name) : 0;
    if (fnlen > 65535) fnlen = 65535;
    hdr.name_len = (uint16_t)fnlen;
    if (hdr.name_len > 0) strncpy(hdr.original_name, header_name, hdr.name_len);
    memcpy(hdr.iv, iv, hdr.iv_len);
    if (write_header(out, &hdr) != 0) goto write_error2;

    if (aead == AEAD_AES_256_GCM) {
        if (aead_encrypt_gcm_stream(key, iv, iv_len, in, out) != 0) goto enc_fail2;
    } else {
        if (cipher_encrypt_cbc_stream(key, iv, in, out) != 0) goto enc_fail2;
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

/* New helper that allows setting a compression id in the header. */
int encrypt_file_with_opts(const char *input_file, const char *output_file, const char *password, const char *header_name, int comp_id) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        if (in) fclose(in);
        if (out) fclose(out);
        return 1;
    }

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];

    unsigned char salt[DEFAULT_SALT_LEN];
    if (RAND_bytes(salt, DEFAULT_SALT_LEN) != 1) { fprintf(stderr, "Randomness generation for salt failed.\n"); goto write_error3; }

    uint32_t iterations = DEFAULT_PBKDF2_ITERS;
    extern uint32_t pbkdf2_iterations;
    if (pbkdf2_iterations > 0) iterations = pbkdf2_iterations;

    if (!derive_key_pbkdf2(password, salt, DEFAULT_SALT_LEN, iterations, key, AES_KEY_SIZE)) {
        fprintf(stderr, "PBKDF2 derivation failed.\n");
        goto write_error3;
    }

    extern int selected_aead;
    int aead = selected_aead;
    uint8_t iv_len = AES_BLOCK_SIZE;
    if (aead == AEAD_AES_256_GCM) iv_len = GCM_IV_LEN;
    if (RAND_bytes(iv, iv_len) != 1) goto write_error3;

    aaf_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.fmt_ver = NEW_FORMAT_VERSION;
    hdr.kdf_id = KDF_PBKDF2_HMAC_SHA256;
    hdr.salt_len = DEFAULT_SALT_LEN;
    memcpy(hdr.salt, salt, DEFAULT_SALT_LEN);
    hdr.iterations = iterations;
    hdr.aead_id = (uint8_t)aead;
    hdr.comp_id = (uint8_t)comp_id;
    hdr.iv_len = iv_len;
    hdr.timestamp = (uint64_t)time(NULL);
    size_t fnlen = header_name ? strlen(header_name) : 0;
    if (fnlen > 65535) fnlen = 65535;
    hdr.name_len = (uint16_t)fnlen;
    if (hdr.name_len > 0 && header_name) strncpy(hdr.original_name, header_name, hdr.name_len);
    memcpy(hdr.iv, iv, hdr.iv_len);
    if (write_header(out, &hdr) != 0) goto write_error3;

    if (aead == AEAD_AES_256_GCM) {
        if (aead_encrypt_gcm_stream(key, iv, iv_len, in, out) != 0) goto enc_fail3;
    } else {
        if (cipher_encrypt_cbc_stream(key, iv, in, out) != 0) goto enc_fail3;
    }
    fclose(in);
    fclose(out);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    return 0;

write_error3:
    perror("File write error");
    if (in) fclose(in);
    if (out) { fclose(out); unlink(output_file); }
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    return 1;

enc_fail3:
    if (in) fclose(in);
    if (out) { fclose(out); unlink(output_file); }
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
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

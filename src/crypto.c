#include "crypto.h"
#include "kdf.h"
#include "aead.h"
#include "header.h"
#include "cipher.h"
#include "compress.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

/* Debug output control: enable with -DCRYPTO_DEBUG at compile time */
#ifdef CRYPTO_DEBUG
  #define crypto_debug(fmt, ...) fprintf(stderr, "[crypto] " fmt, ##__VA_ARGS__)
#else
  #define crypto_debug(fmt, ...) ((void)0)
#endif

/* Globals controlled by main.c */
uint32_t pbkdf2_iterations = 0;
int selected_aead = DEFAULT_AEAD_ID;

/* === Core encryption: parametrized implementation === */
static int encrypt_file_impl(const char *input_file, const char *output_file,
                            const char *password, const char *header_name, int comp_id) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        if (in) fclose(in);
        if (out) fclose(out);
        return 1;
    }

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];
    unsigned char salt[DEFAULT_SALT_LEN];
    if (RAND_bytes(salt, DEFAULT_SALT_LEN) != 1) goto cleanup;

    uint32_t iterations = DEFAULT_PBKDF2_ITERS;
    extern uint32_t pbkdf2_iterations;
    if (pbkdf2_iterations > 0) iterations = pbkdf2_iterations;

    if (!derive_key_pbkdf2(password, salt, DEFAULT_SALT_LEN, iterations, key, AES_KEY_SIZE)) {
        goto cleanup;
    }

    extern int selected_aead;
    int aead = selected_aead;
    uint8_t iv_len = AES_BLOCK_SIZE;
    if (aead == AEAD_AES_256_GCM) iv_len = GCM_IV_LEN;
    if (RAND_bytes(iv, iv_len) != 1) goto cleanup;

    aaf_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.fmt_ver = NEW_FORMAT_VERSION;  /* v3 with comp_id support */
    hdr.kdf_id = KDF_PBKDF2_HMAC_SHA256;
    hdr.salt_len = DEFAULT_SALT_LEN;
    memcpy(hdr.salt, salt, DEFAULT_SALT_LEN);
    hdr.iterations = iterations;
    hdr.aead_id = (uint8_t)aead;
    hdr.comp_id = (uint8_t)comp_id;
    hdr.iv_len = iv_len;
    hdr.timestamp = (uint64_t)time(NULL);
    
    if (header_name) {
        size_t fnlen = strlen(header_name);
        if (fnlen > 65535) fnlen = 65535;
        hdr.name_len = (uint16_t)fnlen;
        memcpy(hdr.original_name, header_name, fnlen);
    }
    memcpy(hdr.iv, iv, hdr.iv_len);
    if (write_header(out, &hdr) != 0) goto cleanup;

    int enc_ok = (aead == AEAD_AES_256_GCM)
        ? aead_encrypt_gcm_stream(key, iv, iv_len, in, out)
        : cipher_encrypt_cbc_stream(key, iv, in, out);
    
    fclose(in);
    fclose(out);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    if (enc_ok != 0) { unlink(output_file); return 1; }
    return 0;

cleanup:
    if (in) fclose(in);
    if (out) { fclose(out); unlink(output_file); }
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    return 1;
}

int encrypt_file(const char *input_file, const char *output_file, const char *password) {
    return encrypt_file_impl(input_file, output_file, password, input_file, 0);
}

int encrypt_file_with_name(const char *input_file, const char *output_file, const char *password, const char *header_name) {
    return encrypt_file_impl(input_file, output_file, password, header_name, 0);
}

int encrypt_file_with_opts(const char *input_file, const char *output_file, const char *password, const char *header_name, int comp_id) {
    return encrypt_file_impl(input_file, output_file, password, header_name, comp_id);
}

/* === Decryption (unchanged, essential logic preserved) === */
int decrypt_file(const char *input_file, const char *output_placeholder, const char *password) {
    FILE *in = fopen(input_file, "rb");
    if (!in) return 1;

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];
    extern uint32_t pbkdf2_iterations;

    unsigned char header4[4] = {0};
    if (fread(header4, 1, 4, in) != 4) { fclose(in); return 1; }

    if (memcmp(header4, NEW_MAGIC, 4) != 0) { fclose(in); return 1; }

    char original_name[256] = {0};
    uint8_t aead_id = AEAD_NONE;
    uint8_t iv_len = AES_BLOCK_SIZE;
    uint8_t fmt_ver = 0;
    if (fread(&fmt_ver, 1, 1, in) != 1) { fclose(in); return 1; }

    uint8_t kdf_id = KDF_NONE;
    uint8_t salt_len = 0;
    unsigned char saltbuf[MAX_SALT_LEN];
    uint32_t iterations = 0;
    
    if (fmt_ver >= 2) {
        if (fread(&kdf_id, 1, 1, in) != 1) { fclose(in); return 1; }
        if (fread(&salt_len, 1, 1, in) != 1) { fclose(in); return 1; }
        if (salt_len < MIN_SALT_LEN || salt_len > MAX_SALT_LEN) { fclose(in); return 1; }
        if (salt_len > 0) {
            if ((size_t)salt_len > sizeof(saltbuf)) { fclose(in); return 1; }
            if (fread(saltbuf, 1, salt_len, in) != salt_len) { fclose(in); return 1; }
        }
        unsigned char itb[4];
        if (fread(itb, 1, 4, in) != 4) { fclose(in); return 1; }
        iterations = ((uint32_t)itb[0] << 24) | ((uint32_t)itb[1] << 16) | ((uint32_t)itb[2] << 8) | (uint32_t)itb[3];

        if (iterations < MIN_PBKDF2_ITERS) { fclose(in); return 1; }
        if (kdf_id != KDF_PBKDF2_HMAC_SHA256) { fclose(in); return 1; }
        if (!derive_key_pbkdf2(password, saltbuf, salt_len, iterations, key, AES_KEY_SIZE)) {
            fclose(in);
            return 1;
        }
    }

    uint8_t comp_id = 0;
    if (fmt_ver >= 2) {
        if (fread(&aead_id, 1, 1, in) != 1) { fclose(in); return 1; }
        unsigned char nextb = 0;
        if (fread(&nextb, 1, 1, in) != 1) { fclose(in); return 1; }
        /* fmt_ver 3+ has comp_id; v2 doesn't. Disambiguate: if nextb <= 1, it's comp_id (v3+) */
        if (nextb <= 1) {
            comp_id = nextb;
            if (fread(&iv_len, 1, 1, in) != 1) { fclose(in); return 1; }
        } else {
            /* v2 format (legacy): nextb is iv_len, no comp_id */
            comp_id = 0;
            iv_len = nextb;
        }
    }

    const char *env_aead = getenv("AAF_AEAD");
    if (env_aead) {
        int requested = AEAD_NONE;
        if (strcmp(env_aead, "gcm") == 0) requested = AEAD_AES_256_GCM;
        else if (strcmp(env_aead, "chacha20") == 0) requested = AEAD_CHACHA20_POLY1305;
        if (requested != AEAD_NONE && requested != (int)aead_id) {
            fclose(in);
            return 1;
        }
    }

    uint16_t name_len16 = 0;
    unsigned char b2[2];
    if (fread(b2, 1, 2, in) != 2) { fclose(in); return 1; }
    name_len16 = ((uint16_t)b2[0] << 8) | (uint16_t)b2[1];

    uint64_t ts = 0;
    unsigned char b8[8];
    if (fread(b8, 1, 8, in) != 8) { fclose(in); return 1; }
    for (int i = 0; i < 8; i++) ts = (ts << 8) | b8[i];

    if (iv_len > sizeof(iv)) { fclose(in); return 1; }
    if (fread(iv, 1, iv_len, in) != iv_len) { fclose(in); return 1; }

    if (name_len16 > 0) {
        if (name_len16 >= sizeof(original_name)) name_len16 = sizeof(original_name) - 1;
        if (fread(original_name, 1, name_len16, in) != name_len16) { fclose(in); return 1; }
        original_name[name_len16] = '\0';
    }

    const char *final_output = output_placeholder;
    if (!final_output || final_output[0] == '\0') {
        if (original_name[0]) final_output = original_name;
        else final_output = input_file;
    }

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
        fclose(in);
        fclose(out);
        return 1;
    }

    int dec_ok = 0;
    if (aead_id == AEAD_AES_256_GCM) {
        long header_end = ftell(in);
        if (header_end == -1L || fseek(in, 0, SEEK_END) != 0) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        long total = ftell(in);
        if (total == -1L || total < header_end + (long)GCM_TAG_LEN) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        long long ciphertext_len = (long long)total - header_end - GCM_TAG_LEN;
        if (fseek(in, header_end, SEEK_SET) != 0) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        dec_ok = aead_decrypt_gcm_stream(key, iv, iv_len, in, ciphertext_len, out);
    } else {
        if (iv_len != AES_BLOCK_SIZE) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        dec_ok = cipher_decrypt_cbc_stream(key, iv, in, out);
    }
    
    fclose(in);
    fclose(out);
    OPENSSL_cleanse(key, sizeof(key));
    
    if (dec_ok != 0) {
        if (use_temp_for_decrypt) unlink(tmp_decrypt_path);
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(iv, sizeof(iv));
        return 1;
    }

    if (use_temp_for_decrypt) {
        if (decompress_file_to(tmp_decrypt_path, final_output) != 0) {
            unlink(tmp_decrypt_path);
            EVP_CIPHER_CTX_free(ctx);
            OPENSSL_cleanse(iv, sizeof(iv));
            return 1;
        }
        unlink(tmp_decrypt_path);
    }

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(iv, sizeof(iv));
    return 0;
}

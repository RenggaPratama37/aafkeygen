#ifndef HEADER_H
#define HEADER_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

/* Cryptographic constants */
#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define GCM_IV_LEN 12
#define MAX_SALT_LEN 64
#define DEFAULT_SALT_LEN 16
#define DEFAULT_PBKDF2_ITERS 600000

/* Format and magic */
#define NEW_MAGIC "AAF4"

/* KDF identifiers */
#define KDF_NONE 0
#define KDF_PBKDF2_HMAC_SHA256 1

/* AEAD identifiers */
#define AEAD_AES_256_CBC 0
#define AEAD_AES_256_GCM 1
#define AEAD_NONE 0  /* same as CBC, explicit for backward compatibility */
#define DEFAULT_AEAD_ID AEAD_AES_256_GCM

/* Validation thresholds for security */
#define MIN_PBKDF2_ITERS 10000
#define MIN_SALT_LEN 8

typedef struct {
    char magic[5];
    uint8_t fmt_ver;
    uint8_t kdf_id;
    uint8_t salt_len;
    unsigned char salt[MAX_SALT_LEN];
    uint32_t iterations;
    uint8_t aead_id;
    uint8_t comp_id; /* 0 = none, 1 = gzip (zlib/gzip) */
    uint8_t iv_len;
    uint16_t name_len;
    uint64_t timestamp;
    char original_name[256];
    uint8_t iv[16];
    size_t header_bytes;
} aaf_header_t;

/* Parse header metadata without producing any printed output. Returns 0 on
 * success and non-zero on failure. The caller may inspect errno for details.
 */
int parse_header(const char *input_file, aaf_header_t *out);

/* Write an AAF header to the given open FILE stream. The `hdr` structure
 * should have the fields populated: fmt_ver, kdf_id, salt_len, salt,
 * iterations, aead_id, iv_len, iv, name_len, original_name and timestamp.
 * Returns 0 on success, non-zero on failure.
 */
int write_header(FILE *out, const aaf_header_t *hdr);

#endif

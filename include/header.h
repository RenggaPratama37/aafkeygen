#ifndef HEADER_H
#define HEADER_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_SALT_LEN 64
#define AES_BLOCK_SIZE 16
#define NEW_MAGIC "AAF4"

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

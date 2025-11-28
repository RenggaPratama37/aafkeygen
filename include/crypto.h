#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* AEAD identifiers (shared) */
#define AEAD_NONE 0
#define AEAD_AES_256_GCM 1
#define AEAD_CHACHA20_POLY1305 2
#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16

/* Common constants exposed to other modules */
#define AES_BLOCK_SIZE 16
#define NEW_MAGIC "AAF4"
#define OLD_HEADER "AAFv1"
#define NEW_FORMAT_VERSION 2

/* Parsed header structure for callers that want to inspect metadata without
 * crypto printing anything. All fields are populated when parse_header()
 * returns 0. Salt is limited to 64 bytes here for simplicity.
 */
#define MAX_SALT_LEN 64
typedef struct {
	char magic[5];
	uint8_t fmt_ver;
	uint8_t kdf_id;
	uint8_t salt_len;
	unsigned char salt[MAX_SALT_LEN];
	uint32_t iterations;
	uint8_t aead_id;
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

int encrypt_file(const char *input_file, const char *output_file, const char *password);
int decrypt_file(const char *input_file, const char *output_file, const char *password);
int inspect_file(const char *input_file);
int encrypt_file_with_name(const char *input_file, const char *output_file, const char *password, const char *header_name);
/* Globals controlled by main.c to influence KDF behavior */
extern uint32_t pbkdf2_iterations;
extern int use_legacy_kdf;
extern int selected_aead;

#endif

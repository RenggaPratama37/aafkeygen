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

int encrypt_file(const char *input_file, const char *output_file, const char *password);
int decrypt_file(const char *input_file, const char *output_file, const char *password);
int inspect_file(const char *input_file);
/* Globals controlled by main.c to influence KDF behavior */
extern uint32_t pbkdf2_iterations;
extern int use_legacy_kdf;
extern int selected_aead;

#endif

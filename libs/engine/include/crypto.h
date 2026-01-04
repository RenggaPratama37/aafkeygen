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
#define NEW_FORMAT_VERSION 2

/* Header parsing is provided by include/header.h */
#include "header.h"

int encrypt_file(const char *input_file, const char *output_file, const char *password);
int decrypt_file(const char *input_file, const char *output_file, const char *password);
int inspect_file(const char *input_file);
int encrypt_file_with_name(const char *input_file, const char *output_file, const char *password, const char *header_name);
int encrypt_file_with_opts(const char *input_file, const char *output_file, const char *password, const char *header_name, int comp_id);
/* Globals controlled by main.c to influence KDF behavior */
extern uint32_t pbkdf2_iterations;
extern int selected_aead;
extern int aead_specified;

#endif

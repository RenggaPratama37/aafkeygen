#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int encrypt_file(const char *input_file, const char *output_file, const char *password);
int decrypt_file(const char *input_file, const char *output_file, const char *password);
int inspect_file(const char *input_file);
/* Globals controlled by main.c to influence KDF behavior */
extern uint32_t pbkdf2_iterations;
extern int use_legacy_kdf;

#endif

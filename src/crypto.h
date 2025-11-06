#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

int encrypt_file(const char *input_file, const char *output_file, const char *password);
int decrypt_file(const char *input_file, const char *output_file, const char *password);
int inspect_file(const char *input_file);

#endif

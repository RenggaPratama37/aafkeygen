/* cipher.h - CBC (non-AEAD) stream helpers */
#ifndef CIPHER_H
#define CIPHER_H

#include <stdio.h>
#include <stddef.h>

int cipher_encrypt_cbc_stream(const unsigned char *key, const unsigned char *iv, FILE *in, FILE *out);
int cipher_decrypt_cbc_stream(const unsigned char *key, const unsigned char *iv, FILE *in, FILE *out);

#endif /* CIPHER_H */

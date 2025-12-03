/* aead.h - AEAD (GCM/ChaCha20-Poly1305) stream helpers */
#ifndef AEAD_H
#define AEAD_H

#include <stdio.h>
#include <stddef.h>

int aead_encrypt_gcm_stream(const unsigned char *key, const unsigned char *iv, size_t iv_len, FILE *in, FILE *out);
int aead_decrypt_gcm_stream(const unsigned char *key, const unsigned char *iv, size_t iv_len, FILE *in, long ciphertext_len, FILE *out);

#endif /* AEAD_H */

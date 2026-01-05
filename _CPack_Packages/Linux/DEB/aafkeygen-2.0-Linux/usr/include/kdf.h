/* kdf.h - PBKDF2 KDF wrapper */
#ifndef KDF_H
#define KDF_H

#include <stddef.h>
#include <stdint.h>

/* derive_key_pbkdf2:
 * - password: null-terminated password
 * - salt: salt buffer
 * - salt_len: length of salt in bytes
 * - iterations: PBKDF2 iteration count
 * - out_key: buffer to receive derived key
 * - key_len: number of bytes to derive
 * Returns 1 on success, 0 on failure.
 */
int derive_key_pbkdf2(const char *password, const unsigned char *salt, size_t salt_len, uint32_t iterations, unsigned char *out_key, size_t key_len);

#endif /* KDF_H */

#ifndef TEMP_H
#define TEMP_H

/* Temp-view helper: decrypt to a secure temp file, open with system viewer,
 * wait for the user, then re-encrypt and securely remove the plaintext.
 */
int temp_decrypt_and_open(const char *aaf_path, const char *password);

#endif

#ifndef COMPRESS_H
#define COMPRESS_H

/* Simple gzip (zlib) file helpers used to optionally compress plaintext
 * before encryption and to decompress after decryption.
 */

int compress_file_to(const char *in_path, const char *out_path);
int decompress_file_to(const char *in_path, const char *out_path);

#endif

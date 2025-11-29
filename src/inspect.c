#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "crypto.h"
#include "inspect.h"

int inspect_file(const char *input_file) {
    aaf_header_t hdr;
    int r = parse_header(input_file, &hdr);
    if (r != 0) return 1;

    struct stat st;
    if (stat(input_file, &st) == -1) {
        perror("stat");
        return 1;
    }

    printf("File: %s\n", input_file);
    printf("Size: %lld bytes\n", (long long)st.st_size);

    if (memcmp(hdr.magic, NEW_MAGIC, 4) == 0) {
        printf("Format: %s (new)\n", NEW_MAGIC);
        printf("Format version: %u\n", (unsigned)hdr.fmt_ver);

        if (hdr.fmt_ver >= 2) {
            printf("KDF: %s\n",
                   hdr.kdf_id == 1 ? "PBKDF2-HMAC-SHA256" : "unknown");
            printf("Salt: ");
            for (int i = 0; i < hdr.salt_len; i++)
                printf("%02x", hdr.salt[i]);
            printf("\n");
            printf("Iterations: %u\n", hdr.iterations);
            printf("AEAD: %s\n",
                    hdr.aead_id == AEAD_AES_256_GCM
                        ? "AES-256-GCM"
                        : (hdr.aead_id == AEAD_CHACHA20_POLY1305
                               ? "ChaCha20-Poly1305"
                               : "unknown"));

            printf("IV length: %u\n", hdr.iv_len);
        }

        printf("Timestamp (epoch): %llu\n",
                (unsigned long long)hdr.timestamp);
        printf("IV: ");
        for (unsigned i = 0; i < hdr.iv_len; i++)
            printf("%02x", hdr.iv[i]);
        printf("\n");

        if (hdr.name_len > 0) {
            printf("Original filename: %s\n", hdr.original_name);
        } else {
            printf("Original filename: (none)\n");
        }

        long long cipher_bytes =
            (long long)st.st_size - (long long)hdr.header_bytes;
        if (cipher_bytes < 0) cipher_bytes = 0;
        printf("Ciphertext bytes (approx): %lld\n", cipher_bytes);

    } else {
        printf("Format: unsupported or legacy (not AAF4)\n");
        printf("This tool version only reads AAF4 files. Use an older release to migrate legacy files.\n");
    }

    return 0;
}

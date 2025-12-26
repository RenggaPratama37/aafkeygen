#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>

void print_usage() {
    printf("Usage:\n");
    printf("  aafkeygen --encrypt <input> <output.aaf>\n");
    printf("  aafkeygen --decrypt <input.aaf> <output>\n");
    printf("\nAliases:\n");
    printf("  aafkeygen -E <input> <output.aaf>\n");
    printf("  aafkeygen -D <input.aaf> <output>\n");
}

void print_help() {
    printf("AAFKeygen %s\n", get_version_string());
    printf("Usage:\n");
    printf("  aafkeygen -E <file> [options]\n");
    printf("  aafkeygen -D <file.aaf>  [options]\n\n");
    printf("Options:\n");
    printf("  -E, --encrypt <file>       Encrypt file\n");
    printf("  -D, --decrypt <file>       Decrypt file\n");
    printf("  -o, --output <name>        Custom output file name\n");
    printf("  -r, --random-name          Generate random output filename\n");
    printf("      --keep                 Keep original file after operation\n");
    printf("      --temp-decrypt         Decrypt to a secure temp file, open with default viewer, re-encrypt after close (prompt-based)\n");
    printf("      --compress             Compress file with gzip before encryption (saves space)\n");
    printf("  -h, --help                 Show this message\n");
}

const char* get_version_string() {
    static char ver[64];

    const char *paths[] = {
        "/usr/local/share/aafkeygen/VERSION",
        "/usr/share/aafkeygen/VERSION",
        "VERSION", // fallback untuk build dev
        NULL
    };

    FILE *f = NULL;
    for (int i = 0; paths[i]; i++) {
        f = fopen(paths[i], "r");
        if (f) break;
    }
    if (!f) {
        return "unknown-version";
    }

    if (!fgets(ver, sizeof(ver), f)) {
        fclose(f);
        return "unknown-version";
    }
    fclose(f);

    // strip newline
    ver[strcspn(ver, "\n")] = '\0';
    static char out[70];
    snprintf(out, sizeof(out), "v%s", ver);
    return out;
}

void random_string(char *buf, size_t len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    unsigned char rnd[len];
    if (len == 0) return;
    if (RAND_bytes(rnd, (int)len) != 1) {
        /* fallback to simple pseudo-randomness, unlikely */
        for (size_t i = 0; i < len - 1; i++) buf[i] = charset[rand() % (sizeof(charset) - 1)];
        buf[len - 1] = '\0';
        return;
    }
    for (size_t i = 0; i < len - 1; i++) {
        buf[i] = charset[rnd[i] % (sizeof(charset) - 1)];
    }
    buf[len - 1] = '\0';
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "crypto.h"
#include <openssl/rand.h>
#include "version.h"


void print_help() {
    printf("AAFKeygen v%s\n", VERSION);
    printf("Usage:\n");
    printf("  aafkeygen -E <file> -p <password> [options]\n");
    printf("  aafkeygen -D <file.aaf> -p <password> [options]\n\n");
    printf("Options:\n");
    printf("  -E, --encrypt <file>       Encrypt file\n");
    printf("  -D, --decrypt <file>       Decrypt file\n");
    printf("  -p, --password <pass>      Password\n");
    printf("  -o, --output <name>        Custom output file name\n");
    printf("  -r, --random-name          Generate random output filename\n");
    printf("      --keep                 Keep original file after operation\n");
    printf("  -h, --help                 Show this message\n");
}

static void random_string(char *buf, size_t len) {
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

int main(int argc, char *argv[]) {
    const char *input_file = NULL, *output_file = NULL, *password = NULL;
    int encrypt = 0, decrypt = 0, keep = 0, random_name = 0;

    if (argc < 2) {
        print_help();
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-E") || !strcmp(argv[i], "--encrypt")) {
            encrypt = 1; input_file = argv[++i];
        } else if (!strcmp(argv[i], "-D") || !strcmp(argv[i], "--decrypt")) {
            decrypt = 1; input_file = argv[++i];
        } else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--password")) {
            password = argv[++i];
        } else if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) {
            output_file = argv[++i];
        } else if (!strcmp(argv[i], "--keep")) {
            keep = 1;
        } else if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--random-name")) {
            random_name = 1;
        } else if (!strcmp(argv[i], "--inspect")) {
            /* Inspect header/metadata of a .aaf file */
            if (i + 1 >= argc) {
                print_help();
                return 1;
            }
            input_file = argv[++i];
            if (inspect_file(input_file) != 0) return 1;
            return 0;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_help();
            return 0;
        }
    }

    if (!input_file || !password || (!encrypt && !decrypt)) {
        print_help();
        return 1;
    }

    char default_output[256];

    if (encrypt) {
        if (random_name) {
            char random[12];
            random_string(random, sizeof(random));
            snprintf(default_output, sizeof(default_output), "%s.aaf", random);
            output_file = default_output;
        } else if (!output_file) {
            snprintf(default_output, sizeof(default_output), "%s.aaf", input_file);
            output_file = default_output;
        }

        printf("[+] Encrypting '%s' → '%s'\n", input_file, output_file);
        if (encrypt_file(input_file, output_file, password) == 0) {
            printf("✅ Encryption complete: %s\n", output_file);
            if (!keep) {
                remove(input_file);
                printf("[–] Original file deleted.\n");
            }
        } else {
            fprintf(stderr, "[x] Encryption failed.\n");
        }
    }

    else if (decrypt) {
        char default_output[256];
        snprintf(default_output, sizeof(default_output), "%s", input_file);

        char *dot = strstr(default_output, ".aaf");
        if (dot) *dot = '\0';
        if (!output_file) output_file = default_output;

        printf("[+] Decrypting '%s' → '%s'\n", input_file, output_file);
        if (decrypt_file(input_file, output_file, password) == 0) {
            printf("✅ Decryption complete: %s\n", output_file);
            if (!keep) {
                remove(input_file);
                printf("[–] Encrypted file deleted.\n");
            }
        } else {
            fprintf(stderr, "[x] Decryption failed.\n");
        }
    }

    return 0;
}

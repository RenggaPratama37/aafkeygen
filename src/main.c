#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "crypto.h"
#include "temp.h"
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
    printf("      --temp-decrypt         Decrypt to a secure temp file, open with default viewer, re-encrypt after close (prompt-based)\n");
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
    int legacy_flag = 0;
    uint32_t iterations_flag = 0;
    int aead_flag = 0; /* 0 = not specified -> default AEAD */
    const char *aead_name = NULL;

    /* exportable globals for crypto module (set before calling encrypt/decrypt) */
    extern uint32_t pbkdf2_iterations;
    extern int use_legacy_kdf;
    /* set defaults for crypto KDF globals */
    pbkdf2_iterations = 0;
    use_legacy_kdf = 0;

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
        } else if (!strcmp(argv[i], "--iterations")) {
            if (i + 1 >= argc) { print_help(); return 1; }
            iterations_flag = (uint32_t)atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--legacy")) {
            legacy_flag = 1;
        } else if (!strcmp(argv[i], "--aead")) {
            if (i + 1 >= argc) { print_help(); return 1; }
            aead_flag = 1;
            aead_name = argv[++i];
        } else if (!strcmp(argv[i], "--force-aead")) {
            aead_flag = 1; aead_name = "gcm"; /* force default AEAD */
        } else if (!strcmp(argv[i], "--temp-decrypt")) {
            /* temporary decrypt & open */
            decrypt = 1; /* treat as decrypt but handled specially below */
            /* mark a special flag via random_name variable to indicate temp mode */
            random_name = 2; /* 2 = temp-decrypt mode */
        }
    }

    if (!input_file || !password || (!encrypt && !decrypt)) {
        print_help();
        return 1;
    }

    char default_output[256];

    if(access(input_file, F_OK) != 0){
        fprintf(stderr, "[X] File not found %s\n", input_file);
        return 1;
    }


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
        /* export iteration, legacy and aead flags to crypto module globals */
        extern uint32_t pbkdf2_iterations;
        extern int use_legacy_kdf;
        extern int selected_aead;
        pbkdf2_iterations = iterations_flag;
        use_legacy_kdf = legacy_flag;
        if (aead_flag && aead_name) {
            if (!strcmp(aead_name, "gcm")) selected_aead = AEAD_AES_256_GCM;
            else if (!strcmp(aead_name, "chacha20")) selected_aead = AEAD_CHACHA20_POLY1305;
        }
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
        char default_output[512];
        size_t ilen = strlen(input_file);
        if (ilen > 4 && strcmp(input_file + ilen - 4, ".aaf") == 0){
            snprintf(default_output, sizeof(default_output), "%.*s", (int)(ilen - 4), input_file);
        } else {
            snprintf(default_output, sizeof(default_output),"%s.dec", input_file);
        }
        if (!output_file) output_file = default_output;

        /* temp-decrypt mode (simple prompt-based) when random_name==2 */
        if (random_name == 2) {
            printf("[+] Temp-decrypting and opening '%s'\n", input_file);
            if (temp_decrypt_and_open(input_file, password) != 0) {
                fprintf(stderr, "[x] Temp-decrypt failed.\n");
            }
        } else {
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
    }

    return 0;
}

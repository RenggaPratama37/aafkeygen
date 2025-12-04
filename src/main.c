#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "crypto.h"
#include "temp.h"
#include <openssl/rand.h>
#include "password_input.h"
#include "utils.h"

/* Whether the user explicitly requested an AEAD algorithm via CLI (--aead) */
int aead_specified = 0;

typedef struct{
    int exist;
    const char *extension;
    int is_aaf;
} CheckInput;

CheckInput check_input(const char *input_file){
    CheckInput result = {0,NULL, 0};
    FILE *f = fopen(input_file, "rb");
    if(f != NULL){
        result.exist = 1;
        fclose(f);
    }
    const char *extension = strrchr(input_file, '.');
    if (extension != NULL){
        result.extension = extension;
        if(strcmp(extension, ".aaf") == 0){
            result.is_aaf =1;
        }
    }
    return result;
}

int main(int argc, char *argv[]) {
    const char *input_file = NULL, *output_file = NULL;
    int encrypt = 0, decrypt = 0, keep = 0, random_name = 0;
    uint32_t iterations_flag = 0;
    int aead_flag = 0; /* 0 = not specified -> default AEAD */
    const char *aead_name = NULL;

    /* exportable globals for crypto module (set before calling encrypt/decrypt) */
    extern uint32_t pbkdf2_iterations;
    /* set defaults for crypto KDF globals */
    pbkdf2_iterations = 0;
    /* aead selection globals */
    extern int selected_aead;
    extern int aead_specified;
    aead_specified = 0;

    if (argc < 2) {
        print_help();
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-E") || !strcmp(argv[i], "--encrypt")) {
            encrypt = 1; input_file = argv[++i];
        } else if (!strcmp(argv[i], "-D") || !strcmp(argv[i], "--decrypt")) {
            decrypt = 1; input_file = argv[++i];
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
            fprintf(stderr, "--legacy option removed: legacy formats are no longer supported\n");
            return 1;
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
        } else if(!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            printf("AAFKeygen %s\n", get_version_string());
            return 0;

        }else {
            fprintf(stderr, "[X] Unknown argument: %s\n", argv[i]);
            return 1;
        }

    }

    char default_output[256];

    /* validate arguments presence first */
    if (!input_file || (!encrypt && !decrypt)) {
        print_help();
        return 1;
    }

    /* check file existence and extension rules before prompting for password */
    CheckInput info = check_input(input_file);
    if (!info.exist) {
        fprintf(stderr, "[X] File not found: %s\n", input_file);
        return 1;
    }

    if (encrypt) {
        if (info.is_aaf) {
            fprintf(stderr, "[X] Refusing to encrypt: '%s' already has .aaf extension\n", input_file);
            return 1;
        }
    }

    if (decrypt) {
        if (!info.is_aaf) {
            fprintf(stderr, "[X] Refusing to decrypt: '%s' is not a .aaf file\n", input_file);
            return 1;
        }
    }

    /* Do not allow explicitly selecting AEAD when decrypting: algorithm is stored in the file header */
    if (decrypt && aead_flag) {
        fprintf(stderr, "[X] --aead is only valid for encryption; when decrypting the algorithm is read from the file header\n");
        return 1;
    }

    char *password = NULL;
    char *password_confirm = NULL;

    if (encrypt) {
        password = read_password("Enter password for encryption: ");
        while (1){
            password_confirm = read_password("Confirm password: ");
            if (strcmp(password, password_confirm) == 0){
                free(password_confirm);
                break;
            }
            printf("[x] Passwords do not match. Try Again.\n");
            free(password_confirm);
        }
    } else if (decrypt) {
        password = read_password("Enter password for decryption: ");
        if (!password) {
            fprintf(stderr, "[X] Password input failed.\n");
            return 1;
        }
    }


    /* Apply AEAD selection if user provided --aead or --force-aead */
    if (aead_flag && aead_name) {
        aead_specified = 1;
        if (!strcmp(aead_name, "gcm")) selected_aead = AEAD_AES_256_GCM;
        else if (!strcmp(aead_name, "chacha20")) selected_aead = AEAD_CHACHA20_POLY1305;
        /* also export requested AEAD in environment so other translation units
         * can reliably observe the user's explicit request without depending
         * on fragile globals across objects. This avoids issues when modules
         * inspect the selection during decrypt. */
        if (!strcmp(aead_name, "gcm")) setenv("AAF_AEAD", "gcm", 1);
        else if (!strcmp(aead_name, "chacha20")) setenv("AAF_AEAD", "chacha20", 1);
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
        } else {
            // Force extension .aaf if not exist
            const char *format = strrchr(output_file, '.');
            if (!format || strcmp(format, ".aaf") !=0){
                static char forced_name[300];
                snprintf(forced_name, sizeof(forced_name),"%s.aaf", output_file);
                output_file = forced_name;
            }
        }                


        printf("[+] Encrypting '%s' → '%s'\n", input_file, output_file);
        /* export iteration flag to crypto module globals */
        extern uint32_t pbkdf2_iterations;
        pbkdf2_iterations = iterations_flag;
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
            fprintf(stderr, "%s is not .aaf file\n", input_file);
            return 1;
        }

        /* If user didn't provide -o, prefer the original filename stored in
         * the AAF header. parse_header() is non-verbose and returns metadata
         * including the original name when present. Fall back to trimming
         * the .aaf extension when header has no name. */
        if (!output_file) {
            aaf_header_t hdr;
            if (parse_header(input_file, &hdr) == 0 && hdr.name_len > 0) {
                /* use name from header */
                output_file = hdr.original_name;
            } else {
                output_file = default_output;
            }
        }

        /* temp-decrypt mode (simple prompt-based) when random_name==2 */
        if (random_name == 2) {
            printf("[+] Temp-decrypting and opening '%s'\n", input_file);
            if (temp_decrypt_and_open(input_file, password) != 0) {
                fprintf(stderr, "[x] Temp-decrypt failed.\n");
            }
        } else {
            fprintf(stderr, "DEBUG: decrypt=%d aead_flag=%d aead_name=%s aead_specified=%d selected_aead=%d\n",
                    decrypt, aead_flag, aead_name ? aead_name : "(null)", aead_specified, selected_aead);
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

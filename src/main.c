#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "crypto.h"
#include "temp.h"
#include <openssl/rand.h>
#include "password_input.h"
#include "utils.h"
#include "flags.h"
#include "compress.h"

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

    Arguments args = {0};

    if (parse_flags(argc, argv, &args) != 0){
        print_help();
        return 1;
    }
    if (args.show_help) {
        print_help();
        return 0;
    }
    
    if (args.show_version) {
        printf("AAFKeygen %s\n", get_version_string());
        return 0;
    }
    
    if (args.inspect) {
        if (inspect_file(args.inspect_file) != 0) return 1;
        return 0;
    }

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

    char default_output[256];

    /* validate arguments presence first */
    if (!args.input_file || (!args.encrypt && !args.decrypt)) {
        print_help();
        return 1;
    }

    /* check file existence and extension rules before prompting for password */
    CheckInput info = check_input(args.input_file);
    if (!info.exist) {
        fprintf(stderr, "[X] File not found: %s\n", args.input_file);
        return 1;
    }

    if (args.encrypt) {
        if (info.is_aaf) {
            fprintf(stderr, "[X] Refusing to encrypt: '%s' already has .aaf extension\n", args.input_file);
            return 1;
        }
    }

    if (args.decrypt) {
        if (!info.is_aaf) {
            fprintf(stderr, "[X] Refusing to decrypt: '%s' is not a .aaf file\n", args.input_file);
            return 1;
        }
    }

    /* Do not allow explicitly selecting AEAD when decrypting: algorithm is stored in the file header */
    if (args.decrypt && args.aead_flag) {
        fprintf(stderr, "[X] --aead is only valid for encryption; when decrypting the algorithm is read from the file header\n");
        return 1;
    }

    char *password = NULL;
    char *password_confirm = NULL;

    if (args.encrypt) {
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
    } else if (args.decrypt) {
        password = read_password("Enter password for decryption: ");
        if (!password) {
            fprintf(stderr, "[X] Password input failed.\n");
            return 1;
        }
    }

    /* Apply AEAD selection if user provided --aead or --force-aead */
    if (args.aead_flag && args.aead_name) {
        aead_specified = 1;
        if (!strcmp(args.aead_name, "gcm")) selected_aead = AEAD_AES_256_GCM;
        else if (!strcmp(args.aead_name, "chacha20")) selected_aead = AEAD_CHACHA20_POLY1305;

        if (!strcmp(args.aead_name, "gcm")) setenv("AAF_AEAD", "gcm", 1);
        else if (!strcmp(args.aead_name, "chacha20")) setenv("AAF_AEAD", "chacha20", 1);
    }

    if (args.encrypt) {
        if (args.random_name) {
            char random[12];
            random_string(random, sizeof(random));
            snprintf(default_output, sizeof(default_output), "%s.aaf", random);
            args.output_file = default_output;
        } else if (!args.output_file) {
            snprintf(default_output, sizeof(default_output), "%s.aaf", args.input_file);
            args.output_file = default_output;
        } else{
            const char *format = strrchr(args.output_file, '.');
            if (!format || strcmp(format, ".aaf") !=0){
                static char forced_name[300];
                snprintf(forced_name, sizeof(forced_name),"%s.aaf", args.output_file);
                args.output_file = forced_name;
            }
        }

        printf("[+] Encrypting '%s' → '%s'\n", args.input_file, args.output_file);
        pbkdf2_iterations = args.iterations_flag;
        int enc_ret = 1;
        if (args.compress) {
            /* compress input to temp file then encrypt with header indicating compression */
            const char *base_tmp = getenv("TMPDIR");
            if (!base_tmp) base_tmp = "/tmp";
            char tmp_template[1024];
            snprintf(tmp_template, sizeof(tmp_template), "%s/aaf_comp_XXXXXX", base_tmp);
            int fd = mkstemp(tmp_template);
            if (fd == -1) {
                fprintf(stderr, "[x] Failed to create temp file for compression\n");
                return 1;
            }
            close(fd);
            if (compress_file_to(args.input_file, tmp_template) != 0) {
                unlink(tmp_template);
                fprintf(stderr, "[x] Compression failed\n");
                return 1;
            }
            /* encrypt temp and set header original name to the real original filename */
            enc_ret = encrypt_file_with_opts(tmp_template, args.output_file, password, args.input_file, 1);
            unlink(tmp_template);
        } else {
            enc_ret = encrypt_file(args.input_file, args.output_file, password);
        }
        if (enc_ret == 0) {
            printf("✅ Encryption complete: %s\n", args.output_file);
            if (!args.keep) {
                remove(args.input_file);
                printf("[–] Original file deleted.\n");
            }
        } else {
            fprintf(stderr, "[x] Encryption failed.\n");
        }
    }

    else if (args.decrypt) {
        char default_output[512];
        size_t ilen = strlen(args.input_file);
        if (ilen > 4 && strcmp(args.input_file + ilen - 4, ".aaf") == 0){
            snprintf(default_output, sizeof(default_output), "%.*s", (int)(ilen - 4), args.input_file);
        } else {
            fprintf(stderr, "%s is not .aaf file\n", args.input_file);
            return 1;
        }

        if (!args.output_file) {
            aaf_header_t hdr;
            if (parse_header(args.input_file, &hdr) == 0 && hdr.name_len > 0) {
                args.output_file = hdr.original_name;
            } else {
                args.output_file = default_output;
            }
        }

        if (args.random_name == 2) {
            printf("[+] Temp-decrypting and opening '%s'\n", args.input_file);
            if (temp_decrypt_and_open(args.input_file, password) != 0) {
                fprintf(stderr, "[x] Temp-decrypt failed.\n");
            }
        } else {
            fprintf(stderr, "DEBUG: decrypt=%d aead_flag=%d aead_name=%s aead_specified=%d selected_aead=%d\n",
                    args.decrypt, args.aead_flag, args.aead_name ? args.aead_name : "(null)", aead_specified, selected_aead);
            printf("[+] Decrypting '%s' → '%s'\n", args.input_file, args.output_file);
            if (decrypt_file(args.input_file, args.output_file, password) == 0) {
                printf("✅ Decryption complete: %s\n", args.output_file);
                if (!args.keep) {
                    remove(args.input_file);
                    printf("[–] Encrypted file deleted.\n");
                }
            } else {
                fprintf(stderr, "[x] Decryption failed.\n");
            }
        }
    }

    return 0;
}

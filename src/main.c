#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include "crypto.h"

int main(int argc, char *argv[]) {
    int opt;
    int mode = 0; // 1 = encrypt, 2 = decrypt
    char *password = NULL;
    char *output = NULL;
    int delete_original = 0;

    static struct option long_opts[] = {
        {"encrypt", required_argument, 0, 'E'},
        {"decrypt", required_argument, 0, 'D'},
        {"password", required_argument, 0, 'p'},
        {"output", required_argument, 0, 'o'},
        {"delete-original", no_argument, 0, 'x'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    char *input = NULL;

    while ((opt = getopt_long(argc, argv, "E:D:p:o:xv", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'E': mode = 1; input = optarg; break;
            case 'D': mode = 2; input = optarg; break;
            case 'p': password = optarg; break;
            case 'o': output = optarg; break;
            case 'x': delete_original = 1; break;
            case 'v': printf("aafkeygen v1.2\n"); return 0;
            default: fprintf(stderr, "Use -E or -D with -p\n"); return 1;
        }
    }

    if (!input || !password) {
        fprintf(stderr, "Usage: aafkeygen -E|-D <file> -p <password> [-o <output>] [--delete-original]\n");
        return 1;
    }

    if (mode == 1) {
        // Encrypt
        char default_out[512];
        if (!output) snprintf(default_out, sizeof(default_out), "%s.aaf", input);
        const char *out_path = output ? output : default_out;
        printf("🔒 Encrypting: %s -> %s\n", input, out_path);
        encrypt_file(input, out_path, password);
        if (delete_original) remove(input);
    } else if (mode == 2) {
        // Decrypt
        char default_out[512];
        if (!output) {
            strcpy(default_out, input);
            char *ext = strrchr(default_out, '.');
            if (ext && strcmp(ext, ".aaf") == 0) *ext = '\0';
        }
        const char *out_path = output ? output : default_out;
        printf("🔓 Decrypting: %s -> %s\n", input, out_path);
        decrypt_file(input, out_path, password);
        if (delete_original) remove(input);
    }

    return 0;
}

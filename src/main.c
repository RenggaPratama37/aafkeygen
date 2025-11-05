#include "crypto.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 5) {
        print_usage();
        return 1;
    }

    const char *mode = NULL;
    const char *input = NULL;
    const char *output = NULL;
    const char *password = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--encrypt") == 0 || strcmp(argv[i], "-E") == 0) {
            mode = "encrypt";
            input = argv[++i];
            output = argv[++i];
        } else if (strcmp(argv[i], "--decrypt") == 0 || strcmp(argv[i], "-D") == 0) {
            mode = "decrypt";
            input = argv[++i];
            output = argv[++i];
        } else if (strcmp(argv[i], "--password") == 0 || strcmp(argv[i], "-p") == 0) {
            password = argv[++i];
        }
    }

    if (!mode || !input || !output || !password) {
        print_usage();
        return 1;
    }

    if (strcmp(mode, "encrypt") == 0)
        return encrypt_file(input, output, password);
    else
        return decrypt_file(input, output, password);
}

#include "flags.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int parse_flags(int argc, char *argv[], Arguments *args){
    if (!args) return 1;
    memset(args, 0, sizeof(*args));

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (!strcmp(arg, "-E") || !strcmp(arg, "--encrypt")) {
            if (i + 1 >= argc) return 1;
            args->encrypt = 1;
            args->input_file = argv[++i];
        } else if (!strcmp(arg, "-D") || !strcmp(arg, "--decrypt")) {
            if (i + 1 >= argc) return 1;
            args->decrypt = 1;
            args->input_file = argv[++i];
        } else if (!strcmp(arg, "-o") || !strcmp(arg, "--output")) {
            if (i + 1 >= argc) return 1;
            args->output_file = argv[++i];
        } else if (!strcmp(arg, "--keep")) {
            args->keep = 1;
        } else if (!strcmp(arg, "-r") || !strcmp(arg, "--random-name")) {
            args->random_name = 1;
        } else if (!strcmp(arg, "--inspect")) {
            if (i + 1 >= argc) return 1;
            args->inspect = 1;
            args->inspect_file = argv[++i];
        } else if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            args->show_help = 1;
            return 0;
        } else if (!strcmp(arg, "-v") || !strcmp(arg, "--version")) {
            args->show_version = 1;
            return 0;
        } else if (!strcmp(arg, "--iterations")) {
            if (i + 1 >= argc) return 1;
            args->iterations_flag = (uint32_t)atoi(argv[++i]);
        } else if (!strcmp(arg, "--legacy")) {
            fprintf(stderr, "--legacy option removed: legacy formats are no longer supported\n");
            return 1;
        } else if (!strcmp(arg, "--aead")) {
            if (i + 1 >= argc) return 1;
            args->aead_flag = 1;
            args->aead_name = argv[++i];
        } else if (!strcmp(arg, "--force-aead")) {
            args->aead_flag = 1;
            args->aead_name = "gcm";
        } else if (!strcmp(arg, "--temp-decrypt")) {
            args->decrypt = 1;
            args->random_name = 2;
        } else {
            fprintf(stderr, "[X] Unknown argument: %s\n", arg);
            return 1;
        }
    }

    return 0;
}

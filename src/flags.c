#include "flags.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Helper to validate and consume the next argv token for options that require an argument.
 * Returns pointer to the token (and advances `i`) or prints an error and returns NULL.
 */
static const char *next_arg(int argc, char *argv[], int *i, const char *opt_name)
{
    if (*i + 1 >= argc) {
        fprintf(stderr, "ERROR: Missing argument for %s\n", opt_name);
        return NULL;
    }
    if (argv[*i + 1][0] == '-') {
        fprintf(stderr, "ERROR: Missing argument for %s\n", opt_name);
        return NULL;
    }
    (*i)++;
    return argv[*i];
}

int parse_flags(int argc, char *argv[], Arguments *args){
    if (!args) return 1;
    memset(args, 0, sizeof(*args));

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (!strcmp(arg, "-E") || !strcmp(arg, "--encrypt")) {
            const char *val = next_arg(argc, argv, &i, arg);
            if (!val) return 1;
            args->encrypt = 1;
            args->input_file = val;
        } else if (!strcmp(arg, "-D") || !strcmp(arg, "--decrypt")) {
            const char *val = next_arg(argc, argv, &i, arg);
            if (!val) return 1;
            args->decrypt = 1;
            args->input_file = val;
        } else if (!strcmp(arg, "-o") || !strcmp(arg, "--output")) {
            {
                const char *val = next_arg(argc, argv, &i, arg);
                if (!val) return 1;
                args->output_file = val;
            }
        } else if (!strcmp(arg, "--keep")) {
            args->keep = 1;
        } else if (!strcmp(arg, "-r") || !strcmp(arg, "--random-name")) {
            args->random_name = 1;
        } else if (!strcmp(arg, "--inspect")) {
            {
                const char *val = next_arg(argc, argv, &i, arg);
                if (!val) return 1;
                args->inspect = 1;
                args->inspect_file = val;
            }
        } else if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            args->show_help = 1;
            return 0;
        } else if (!strcmp(arg, "-v") || !strcmp(arg, "--version")) {
            args->show_version = 1;
            return 0;
        } else if (!strcmp(arg, "--iterations")) {
            {
                const char *val = next_arg(argc, argv, &i, arg);
                if (!val) return 1;
                args->iterations_flag = (uint32_t)atoi(val);
            }
        } else if (!strcmp(arg, "--compress")) {
            args->compress = 1;
        } else if (!strcmp(arg, "--legacy")) {
            fprintf(stderr, "--legacy option removed: legacy formats are no longer supported\n");
            return 1;
        } else if (!strcmp(arg, "--aead")) {
            {
                const char *val = next_arg(argc, argv, &i, arg);
                if (!val) return 1;
                args->aead_flag = 1;
                args->aead_name = val;
            }
        } else if (!strcmp(arg, "--force-aead")) {
            args->aead_flag = 1;
            args->aead_name = "gcm";
        } else if (!strcmp(arg, "--temp-decrypt")) {
            args->decrypt = 1;
            args->random_name = 2;
        } else {
            fprintf(stderr, "ERROR: Unknown argument: %s\n", arg);
            return 1;
        }
    }

    return 0;
}

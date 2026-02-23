#include "flags.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

/* Helper to validate and consume the next argv token for options that require an argument.
 * Returns pointer to the token (and advances `i`) or prints an error and returns NULL.
 */
/* Return non-zero if `s` exactly matches a known option name. */
static int is_known_option(const char *s)
{
    static const char *opts[] = {
        "-E","--encrypt","-D","--decrypt","-o","--output",
        "--keep","-r","--random-name","--inspect","-h","--help",
        "-v","--version","--iterations","--compress","--legacy",
        "--aead","--force-aead","--temp-decrypt"
    };
    for (size_t n = 0; n < sizeof(opts)/sizeof(opts[0]); n++) {
        if (!strcmp(s, opts[n])) return 1;
    }
    return 0;
}

static const char *next_arg(int argc, char *argv[], int *i, const char *opt_name)
{
    if (*i + 1 >= argc) {
        fprintf(stderr, "ERROR: Missing argument for %s. Try --help\n", opt_name);
        return NULL;
    }
    /* Accept values that start with '-' as long as they are not known option tokens.
     * This avoids false "missing argument" for values like "-file" or negative numbers.
     */
    if (argv[*i + 1][0] == '-' && is_known_option(argv[*i + 1])) {
        fprintf(stderr, "ERROR: Missing argument for %s. Next token looks like option '%s'\n", opt_name, argv[*i + 1]);
        return NULL;
    }
    (*i)++;
    return argv[*i];
}

int parse_flags(int argc, char *argv[], Arguments *args){
    if (!args) return 1;
    memset(args, 0, sizeof(*args));
    /* Track presence of certain options to detect duplicates */
    int iterations_seen = 0;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (!strcmp(arg, "-E") || !strcmp(arg, "--encrypt")) {
            const char *val = next_arg(argc, argv, &i, arg);
            if (!val) return 1;
            if (args->input_file) {
                fprintf(stderr, "ERROR: Multiple input files specified (previous: %s, new: %s)\n", args->input_file, val);
                return 1;
            }
            args->encrypt = 1;
            args->input_file = val;
        } else if (!strcmp(arg, "-D") || !strcmp(arg, "--decrypt")) {
            const char *val = next_arg(argc, argv, &i, arg);
            if (!val) return 1;
            if (args->input_file) {
                fprintf(stderr, "ERROR: Multiple input files specified (previous: %s, new: %s)\n", args->input_file, val);
                return 1;
            }
            args->decrypt = 1;
            args->input_file = val;
        } else if (!strcmp(arg, "-o") || !strcmp(arg, "--output")) {
            {
                const char *val = next_arg(argc, argv, &i, arg);
                if (!val) return 1;
                if (args->output_file) {
                    fprintf(stderr, "ERROR: Multiple output names specified (previous: %s, new: %s)\n", args->output_file, val);
                    return 1;
                }
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
                if (args->inspect_file) {
                    fprintf(stderr, "ERROR: Multiple inspect files specified (previous: %s, new: %s)\n", args->inspect_file, val);
                    return 1;
                }
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
                if (iterations_seen) {
                    fprintf(stderr, "ERROR: Multiple --iterations values specified\n");
                    return 1;
                }
                errno = 0;
                char *endptr = NULL;
                unsigned long v = strtoul(val, &endptr, 10);
                if (endptr == val) {
                    fprintf(stderr, "ERROR: Invalid numeric value for %s: %s\n", arg, val);
                    return 1;
                }
                if (*endptr != '\0') {
                    fprintf(stderr, "ERROR: Trailing characters after number for %s: %s\n", arg, val);
                    return 1;
                }
                if (errno == ERANGE || v > UINT_MAX) {
                    fprintf(stderr, "ERROR: Numeric value out of range for %s: %s\n", arg, val);
                    return 1;
                }
                if (val[0] == '-') {
                    fprintf(stderr, "ERROR: Negative value not allowed for %s: %s\n", arg, val);
                    return 1;
                }
                args->iterations_flag = (uint32_t)v;
                iterations_seen = 1;
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
                if (args->aead_name) {
                    fprintf(stderr, "ERROR: Multiple AEAD names specified (previous: %s, new: %s)\n", args->aead_name, val);
                    return 1;
                }
                args->aead_flag = 1;
                args->aead_name = val;
            }
        } else if (!strcmp(arg, "--force-aead")) {
            if (args->aead_name) {
                fprintf(stderr, "ERROR: AEAD already specified as %s; cannot use --force-aead\n", args->aead_name);
                return 1;
            }
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

    /* Validate mutual exclusivity between primary modes: encrypt, decrypt, inspect */
    int primary = 0;
    if (args->encrypt) primary++;
    if (args->decrypt) primary++;
    if (args->inspect) primary++;
    if (primary > 1) {
        fprintf(stderr, "ERROR: Conflicting modes specified (encrypt/decrypt/inspect). Only one allowed.\n");
        return 1;
    }

    return 0;
}

#ifndef FLAGS_H
#define FLAGS_H

#include <stdint.h>

typedef struct {
    /* parsed options */
    const char *input_file;
    const char *output_file;
    int encrypt;
    int decrypt;
    int keep;
    int random_name; /* 0 = none, 1 = random name, 2 = temp-decrypt */
    uint32_t iterations_flag;
    int aead_flag;
    const char *aead_name;

    /* utility flags */
    int show_help;
    int show_version;
    int inspect;
    const char *inspect_file;
} Arguments;

int parse_flags(int argc, char *argv[], Arguments *args);

#endif
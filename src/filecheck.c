#include "filecheck.h"
#include <stdio.h>
#include <string.h>

int file_check(const char *path, FileInfo *out) {
    if (!path || !out) return 1;
    out->exist = 0;
    out->extension = NULL;
    out->is_aaf = 0;

    FILE *f = fopen(path, "rb");
    if (f) {
        out->exist = 1;
        unsigned char magic[4];
        if (fread(magic, 1, 4, f) == 4) {
            if (memcmp(magic, "AAF4", 4) == 0) {
                out->is_aaf = 1;
            }
        }
        fclose(f);
    }

    const char *ext = strrchr(path, '.');
    if (ext) out->extension = ext;

    return 0;
}

#include "compress.h"
#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK 16384

int compress_file_to(const char *in_path, const char *out_path) {
    FILE *in = fopen(in_path, "rb");
    if (!in) return 1;
    gzFile out = gzopen(out_path, "wb");
    if (!out) { fclose(in); return 1; }

    unsigned char buf[CHUNK];
    size_t read_len;
    while ((read_len = fread(buf, 1, CHUNK, in)) > 0) {
        int written = gzwrite(out, buf, (unsigned int)read_len);
        if (written == 0) {
            gzclose(out);
            fclose(in);
            return 1;
        }
    }

    gzclose(out);
    fclose(in);
    return 0;
}

int decompress_file_to(const char *in_path, const char *out_path) {
    gzFile in = gzopen(in_path, "rb");
    if (!in) return 1;
    FILE *out = fopen(out_path, "wb");
    if (!out) { gzclose(in); return 1; }

    unsigned char buf[CHUNK];
    int read_len;
    while ((read_len = gzread(in, buf, CHUNK)) > 0) {
        if (fwrite(buf, 1, read_len, out) != (size_t)read_len) {
            gzclose(in);
            fclose(out);
            return 1;
        }
    }

    gzclose(in);
    fclose(out);
    return 0;
}

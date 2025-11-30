#include "header.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Helper to write big-endian integers (reused from crypto module) */
static int read_u16_be(FILE *f, uint16_t *out) {
    unsigned char b[2];
    if (fread(b, 1, 2, f) != 2) return 0;
    *out = ((uint16_t)b[0] << 8) | (uint16_t)b[1];
    return 1;
}

static int read_u64_be(FILE *f, uint64_t *out) {
    unsigned char b[8];
    if (fread(b, 1, 8, f) != 8) return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    *out = v;
    return 1;
}

int parse_header(const char *input_file, aaf_header_t *out) {
    if (!out) return 1;
    memset(out, 0, sizeof(*out));

    FILE *in = fopen(input_file, "rb");
    if (!in) return 1;

    unsigned char header4[4] = {0};
    if (fread(header4, 1, 4, in) != 4) { fclose(in); return 1; }

    if (memcmp(header4, NEW_MAGIC, 4) == 0) {
        memcpy(out->magic, NEW_MAGIC, 4);
        out->magic[4] = '\0';
        uint8_t fmt_ver = 0;
        if (fread(&fmt_ver, 1, 1, in) != 1) { fclose(in); return 1; }
        out->fmt_ver = fmt_ver;

        if (fmt_ver >= 2) {
            if (fread(&out->kdf_id, 1, 1, in) != 1) { fclose(in); return 1; }
            if (fread(&out->salt_len, 1, 1, in) != 1) { fclose(in); return 1; }
            if (out->salt_len > 0) {
                if (out->salt_len > MAX_SALT_LEN) {
                    if (fseek(in, out->salt_len, SEEK_CUR) != 0) { fclose(in); return 1; }
                } else {
                    if (fread(out->salt, 1, out->salt_len, in) != out->salt_len) { fclose(in); return 1; }
                }
            }
            unsigned char itb[4];
            if (fread(itb, 1, 4, in) != 4) { fclose(in); return 1; }
            out->iterations = ((uint32_t)itb[0] << 24) | ((uint32_t)itb[1] << 16) | ((uint32_t)itb[2] << 8) | (uint32_t)itb[3];
        }

        if (fmt_ver >= 2) {
            if (fread(&out->aead_id, 1, 1, in) != 1) { fclose(in); return 1; }
            if (fread(&out->iv_len, 1, 1, in) != 1) { fclose(in); return 1; }
        } else {
            out->aead_id = 0;
            out->iv_len = AES_BLOCK_SIZE;
        }

        if (!read_u16_be(in, &out->name_len)) { fclose(in); return 1; }
        if (!read_u64_be(in, &out->timestamp)) { fclose(in); return 1; }

        if (out->iv_len > sizeof(out->iv)) { fclose(in); return 1; }
        if (out->iv_len > 0) {
            if (fread(out->iv, 1, out->iv_len, in) != out->iv_len) { fclose(in); return 1; }
        }

        if (out->name_len > 0) {
            uint16_t nl = out->name_len;
            if (nl >= sizeof(out->original_name)) nl = sizeof(out->original_name) - 1;
            if (fread(out->original_name, 1, nl, in) != nl) { fclose(in); return 1; }
            out->original_name[nl] = '\0';
        }

        out->header_bytes = 4 + 1;
        if (out->fmt_ver >= 2) out->header_bytes += 1 + 1 + out->salt_len + 4 + 1 + 1;
        out->header_bytes += 2 + 8 + out->iv_len + out->name_len;

        fclose(in);
        return 0;
    }

    fclose(in);
    return 1;
}

int write_header(FILE *out, const aaf_header_t *hdr) {
    if (!out || !hdr) return 1;
    /* magic */
    if (fwrite(NEW_MAGIC, 1, 4, out) != 4) return 1;
    if (fwrite(&hdr->fmt_ver, 1, 1, out) != 1) return 1;
    if (hdr->fmt_ver >= 2) {
        if (fwrite(&hdr->kdf_id, 1, 1, out) != 1) return 1;
        if (fwrite(&hdr->salt_len, 1, 1, out) != 1) return 1;
        if (hdr->salt_len > 0) {
            if (fwrite(hdr->salt, 1, hdr->salt_len, out) != hdr->salt_len) return 1;
        }
        unsigned char itb[4];
        itb[0] = (hdr->iterations >> 24) & 0xFF;
        itb[1] = (hdr->iterations >> 16) & 0xFF;
        itb[2] = (hdr->iterations >> 8) & 0xFF;
        itb[3] = hdr->iterations & 0xFF;
        if (fwrite(itb, 1, 4, out) != 4) return 1;
    }
    if (hdr->fmt_ver >= 2) {
        if (fwrite(&hdr->aead_id, 1, 1, out) != 1) return 1;
        if (fwrite(&hdr->iv_len, 1, 1, out) != 1) return 1;
    }
    /* name len and timestamp */
    unsigned char nl[2];
    nl[0] = (hdr->name_len >> 8) & 0xFF;
    nl[1] = hdr->name_len & 0xFF;
    if (fwrite(nl, 1, 2, out) != 2) return 1;
    unsigned char tsb[8];
    uint64_t ts = hdr->timestamp;
    for (int i = 0; i < 8; i++) tsb[7 - i] = (ts >> (i * 8)) & 0xFF;
    if (fwrite(tsb, 1, 8, out) != 8) return 1;

    if (hdr->iv_len > 0) {
        if (fwrite(hdr->iv, 1, hdr->iv_len, out) != hdr->iv_len) return 1;
    }
    if (hdr->name_len > 0) {
        if (fwrite(hdr->original_name, 1, hdr->name_len, out) != hdr->name_len) return 1;
    }
    return 0;
}

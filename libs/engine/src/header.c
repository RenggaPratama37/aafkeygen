#include "header.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Helper to read big-endian integers */
static int read_u16_be(FILE *f, uint16_t *out) {
    unsigned char b[2];
    if (fread(b, 1, 2, f) != 2) return 0;
    *out = ((uint16_t)b[0] << 8) | b[1];
    return 1;
}

static int read_u64_be(FILE *f, uint64_t *out) {
    unsigned char b[8];
    if (fread(b, 1, 8, f) != 8) return 0;

    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | b[i];

    *out = v;
    return 1;
}

// Parse Header
int parse_header(const char *input_file, aaf_header_t *out) {
    if (!out) return 1;
    memset(out, 0, sizeof(*out));

    FILE *in = fopen(input_file, "rb");
    if (!in) return 1;

    unsigned char magic4[4];
    if (fread(magic4, 1, 4, in) != 4) { fclose(in); return 1; }

    if (memcmp(magic4, NEW_MAGIC, 4) != 0) {
        fclose(in);
        return 1;
    }

    memcpy(out->magic, NEW_MAGIC, 4);
    out->magic[4] = '\0';

    uint8_t ver;
    if (fread(&ver, 1, 1, in) != 1) { fclose(in); return 1; }
    out->fmt_ver = ver;

    /* version ≥ 2 fields */
    if (ver >= 2) {
        if (fread(&out->kdf_id, 1, 1, in) != 1) { fclose(in); return 1; }
        if (fread(&out->salt_len, 1, 1, in) != 1) { fclose(in); return 1; }

        if (out->salt_len > MAX_SALT_LEN) {
            fseek(in, out->salt_len, SEEK_CUR);
        } else if (out->salt_len > 0) {
            if (fread(out->salt, 1, out->salt_len, in) != out->salt_len) {
                fclose(in); return 1;
            }
        }

        unsigned char itb[4];
        if (fread(itb, 1, 4, in) != 4) { fclose(in); return 1; }
        out->iterations =
            (itb[0] << 24) | (itb[1] << 16) | (itb[2] << 8) | itb[3];

        /* Backwards-compat: older v2 headers did not include comp_id. The
         * byte after aead_id may be either comp_id (0/1) or iv_len (12/16).
         * Peek and disambiguate based on plausible iv lengths.
         */
        if (fread(&out->aead_id, 1, 1, in) != 1) { fclose(in); return 1; }
        unsigned char nextb = 0;
        if (fread(&nextb, 1, 1, in) != 1) { fclose(in); return 1; }
        if (nextb <= 1) {
            /* it's a comp_id */
            out->comp_id = nextb;
            if (fread(&out->iv_len, 1, 1, in) != 1) { fclose(in); return 1; }
        } else {
            /* no comp_id present; treat nextb as iv_len and set comp_id=0 */
            out->comp_id = 0;
            out->iv_len = nextb;
        }
    } else {
        out->aead_id = 0;
        out->iv_len = AES_BLOCK_SIZE;
    }

    if (!read_u16_be(in, &out->name_len)) { fclose(in); return 1; }
    if (!read_u64_be(in, &out->timestamp)) { fclose(in); return 1; }

    if (fread(out->iv, 1, out->iv_len, in) != out->iv_len) { fclose(in); return 1; }

    if (out->name_len > 0) {
        uint16_t nl = out->name_len;
        if (nl >= sizeof(out->original_name)) nl = sizeof(out->original_name) - 1;

        if (fread(out->original_name, 1, nl, in) != nl) {
            fclose(in); return 1;
        }
        out->original_name[nl] = '\0';
    }

    fclose(in);
    return 0;
}

// write header
int write_header(FILE *out, const aaf_header_t *hdr) {
    if (!out || !hdr) return 1;

    /* magic + version */
    if (fwrite(NEW_MAGIC, 1, 4, out) != 4) return 1;
    if (fwrite(&hdr->fmt_ver, 1, 1, out) != 1) return 1;

    if (hdr->fmt_ver >= 2) {
        if (fwrite(&hdr->kdf_id, 1, 1, out) != 1) return 1;
        if (fwrite(&hdr->salt_len, 1, 1, out) != 1) return 1;

        if (hdr->salt_len > 0) {
            if (fwrite(hdr->salt, 1, hdr->salt_len, out) != hdr->salt_len)
                return 1;
        }

        unsigned char itb[4] = {
            (hdr->iterations >> 24) & 0xFF,
            (hdr->iterations >> 16) & 0xFF,
            (hdr->iterations >> 8) & 0xFF,
            hdr->iterations & 0xFF
        };
        if (fwrite(itb, 1, 4, out) != 4) return 1;

        if (fwrite(&hdr->aead_id, 1, 1, out) != 1) return 1;
        if (fwrite(&hdr->comp_id, 1, 1, out) != 1) return 1;
        if (fwrite(&hdr->iv_len, 1, 1, out) != 1) return 1;
    }

    /* name length */
    unsigned char nl[2] = {
        (hdr->name_len >> 8) & 0xFF,
        hdr->name_len & 0xFF
    };
    if (fwrite(nl, 1, 2, out) != 2) return 1;

    /* timestamp */
    unsigned char tsb[8];
    for (int i = 0; i < 8; i++)
        tsb[7 - i] = (hdr->timestamp >> (i * 8)) & 0xFF;
    if (fwrite(tsb, 1, 8, out) != 8) return 1;

    /* IV + name */
    if (fwrite(hdr->iv, 1, hdr->iv_len, out) != hdr->iv_len) return 1;

    if (hdr->name_len > 0) {
        if (fwrite(hdr->original_name, 1, hdr->name_len, out) != hdr->name_len)
            return 1;
    }

    return 0;
}

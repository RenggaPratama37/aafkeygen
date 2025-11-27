#include "temp.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

/* This file contains the prompt-based temp-decrypt helper previously embedded
 * in crypto.c. It uses decrypt_file() and encrypt_file_with_name() from
 * crypto.c to perform the work.
 s*/

int temp_decrypt_and_open(const char *aaf_path, const char *password) {
    FILE *in = fopen(aaf_path, "rb");
    if (!in) { perror("File error"); return 1; }

    unsigned char header4[4] = {0};
    if (fread(header4, 1, 4, in) != 4) { fprintf(stderr, "Failed to read header\n"); fclose(in); return 1; }
    char original_name[256] = {0};
    uint8_t aead_id = AEAD_NONE;
    uint8_t iv_len = AES_BLOCK_SIZE;
    long header_end = 0;

    if (memcmp(header4, NEW_MAGIC, 4) == 0) {
        uint8_t fmt_ver = 0;
        if (fread(&fmt_ver, 1, 1, in) != 1) { fprintf(stderr, "Failed to read fmt version\n"); fclose(in); return 1; }
        if (fmt_ver >= 2) {
            uint8_t kdf_id = 0; uint8_t salt_len = 0;
            if (fread(&kdf_id,1,1,in)!=1) { fclose(in); return 1; }
            if (fread(&salt_len,1,1,in)!=1) { fclose(in); return 1; }
            if (salt_len > 0) {
                if (fseek(in, salt_len, SEEK_CUR) != 0) { fclose(in); return 1; }
            }
            if (fseek(in, 4, SEEK_CUR) != 0) { fclose(in); return 1; } /* iterations */
            if (fread(&aead_id,1,1,in) != 1) { fclose(in); return 1; }
            if (fread(&iv_len,1,1,in) != 1) { fclose(in); return 1; }
        }
    uint16_t name_len16 = 0;
    /* read big-endian u16/u64 locally to avoid depending on crypto.c static helpers */
    unsigned char b2[2];
    if (fread(b2, 1, 2, in) != 2) { fclose(in); return 1; }
    name_len16 = ((uint16_t)b2[0] << 8) | (uint16_t)b2[1];
    unsigned char b8[8];
    if (fread(b8, 1, 8, in) != 8) { fclose(in); return 1; }
    uint64_t tmp64 = 0;
    for (int i = 0; i < 8; i++) tmp64 = (tmp64 << 8) | b8[i];
    header_end = (long)tmp64;
        if (fseek(in, iv_len, SEEK_CUR) != 0) { fclose(in); return 1; }
        if (name_len16 > 0) {
            if (name_len16 >= sizeof(original_name)) name_len16 = sizeof(original_name)-1;
            if (fread(original_name,1,name_len16,in) != name_len16) { fclose(in); return 1; }
            original_name[name_len16] = '\0';
        }
    } else {
        fclose(in);
        fprintf(stderr, "Unsupported or legacy format for temp-decrypt\n");
        return 1;
    }
    fclose(in);

    /* choose temp dir */
    const char *xdg = getenv("XDG_RUNTIME_DIR");
    const char *tmp = getenv("TMPDIR");
    char tmpdir_template[512];
    const char *base_tmp = xdg ? xdg : (tmp ? tmp : "/tmp");
    snprintf(tmpdir_template, sizeof(tmpdir_template), "%s/aaftmp.XXXXXX", base_tmp);
    char *tmpdir = mkdtemp(tmpdir_template);
    if (!tmpdir) { perror("mkdtemp"); return 1; }
    chmod(tmpdir, 0700);

    char temp_path[1024];
    if (original_name[0]) {
        snprintf(temp_path, sizeof(temp_path), "%s/%s", tmpdir, original_name);
    } else {
        snprintf(temp_path, sizeof(temp_path), "%s/aaftempfile", tmpdir);
    }

    /* decrypt into a work output name (decrypt_file tends to use header name); */
    char work_output[512];
    if (original_name[0]){
        snprintf(work_output, sizeof(work_output), "%s", original_name);
    } else {
        snprintf(work_output, sizeof(work_output), "aaf_plain_%d", (int)getpid());
    }

    /* decrypt directly into tmpdir with a controlled filename */
    char full_work_output[1024];
    snprintf(full_work_output, sizeof(full_work_output), "%s/%s", tmpdir, work_output);
    if (decrypt_file(aaf_path, full_work_output, password) != 0) {
        fprintf(stderr, "Decryption failed\n");
        (void)unlink(full_work_output);
        (void)rmdir(tmpdir);
        return 1;
    }

    /* move decrypted file to inteded temp_path*/
    if(rename(full_work_output, temp_path) != 0){
        perror("rename(temp_path) failed(cleanup and exit)");
        /* remove any plaintext left in tmpdir, then rmdir */
        (void)unlink(full_work_output);
        (void)rmdir(tmpdir);
        return 1;
    }
    /* tmpdir now empty (we moved the file out) — remove it */
    if (rmdir(tmpdir) != 0) {
        /* non-fatal, but warn — leave program flow as normal */
        perror("rmdir(tmpdir) failed");
    }

    chmod(temp_path, S_IRUSR | S_IWUSR);

    printf("[+] Opened temporary file: %s\n", temp_path);
    pid_t pid = fork();
    if (pid == 0) {
        const char *prefix = getenv("PREFIX");
        if (prefix && strstr(prefix, "com.termux")){
            execlp("termux-open", "termux-open", temp_path, (char *)NULL);
        }
        execlp("xdg-open", "xdg-open", temp_path, (char *)NULL);
        fprintf(stderr, "No suitable opener found\n");
        _exit(1);
    } else if (pid < 0) {
        perror("fork");
    } else {
        printf("Press ENTER when you're done viewing the file to re-encrypt and remove it...");
        fflush(stdout);
        getchar();
    }

    char out_tmp[1024];
    snprintf(out_tmp, sizeof(out_tmp), "%s.tmp", aaf_path);
    if (encrypt_file_with_name(temp_path, out_tmp, password, original_name) != 0) {
        fprintf(stderr, "Re-encryption failed — plaintext kept at: %s\n", temp_path);
        return 1;
    }
    if (rename(out_tmp, aaf_path) != 0) {
        perror("rename final aaf failed");
        return 1;
    }
    /* safest cleanup: unlink first, unlink only */
    unlink(temp_path);

    printf("✅ Temp view complete; file re-encrypted and plaintext removed.\n");
    return 0;
}

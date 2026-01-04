#include "temp.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <errno.h>

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
        if (fseek(in, iv_len, SEEK_CUR) != 0) { fclose(in); return 1; }
        if (name_len16 > 0) {
            if (name_len16 >= sizeof(original_name)) name_len16 = sizeof(original_name)-1;
            if (fread(original_name,1,name_len16,in) != name_len16) { fclose(in); return 1; }
            original_name[name_len16] = '\0';
        }
    } else {
        fclose(in);
        fprintf(stderr, "Unsupported or unknown format for temp-decrypt\n");
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
        /* Child: try several openers depending on environment. Prefer Termux on Android */
        int is_termux = 0;
        const char *prefix = getenv("PREFIX");
        if (prefix && strstr(prefix, "com.termux")) is_termux = 1;
        if (!is_termux) {
            if (access("/data/data/com.termux", F_OK) == 0) is_termux = 1;
        }

        char uri[1200];
        snprintf(uri, sizeof(uri), "file://%s", temp_path);

        /* helper to test command presence: use `system("command -v ...")` below */
        if (is_termux) {
            execlp("termux-open", "termux-open", temp_path, (char *)NULL);
            /* fallthrough if termux-open is missing */
        }

        /* Prefer xdg-open on desktop/proot distros */
        if (system("command -v xdg-open >/dev/null 2>&1") == 0) {
            execlp("xdg-open", "xdg-open", temp_path, (char *)NULL);
        }

        /* Try GIO */
        if (system("command -v gio >/dev/null 2>&1") == 0) {
            execlp("gio", "gio", "open", temp_path, (char *)NULL);
        }

        /* On Android (proot or Termux), try am start */
        {
            FILE *fv = fopen("/proc/version", "r");
            int is_android = 0;
            if (fv) {
                char buf[512];
                if (fgets(buf, sizeof(buf), fv)) {
                    if (strstr(buf, "Android") != NULL) is_android = 1;
                }
                fclose(fv);
            }
            if (is_android && system("command -v am >/dev/null 2>&1") == 0) {
                execlp("am", "am", "start", "-a", "android.intent.action.VIEW", "-d", uri, (char *)NULL);
            }
        }

        fprintf(stderr, "No suitable opener found (tried termux-open, xdg-open, gio, am).\n");
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

    printf("Temp view complete; file re-encrypted and plaintext removed.\n");
    return 0;
}

/* Minimal temp helper: decrypt to a secure temporary file, then re-encrypt
 * immediately and clean up. This is a non-interactive placeholder aimed at
 * resolving linker issues and providing a safe default for CI / headless use.
 */
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

int temp_decrypt_and_open(const char *aaf_path, const char *password) {
    if (!aaf_path || !password) return 1;

    /* create a secure temporary file path */
    char tmpl[] = "/tmp/aaf-temp-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return 1;
    close(fd);

    /* decrypt into temp file */
    int r = decrypt_file(aaf_path, tmpl, password);
    if (r != 0) {
        unlink(tmpl);
        return r;
    }

    /* For this minimal implementation we immediately re-encrypt the temp
     * plaintext back into the original AAF file (overwriting). We don't
     * attempt to preserve the original filename metadata here (header name)
     * — callers that need that should use a richer implementation.
     */
    r = encrypt_file_with_name(tmpl, aaf_path, password, NULL);

    /* remove the plaintext temp file regardless of encrypt outcome */
    unlink(tmpl);
    return r;
}

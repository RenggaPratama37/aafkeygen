#ifndef FILECHECK_H
#define FILECHECK_H

#include <stddef.h>

typedef struct {
    int exist;
    const char *extension; /* pointer into original path string, if any */
    int is_aaf;
} FileInfo;

/* Populate FileInfo for the given path. Returns 0 on success, non-zero on fatal error. */
int file_check(const char *path, FileInfo *out);

#endif

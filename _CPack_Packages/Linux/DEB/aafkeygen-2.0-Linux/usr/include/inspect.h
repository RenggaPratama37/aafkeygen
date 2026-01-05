#ifndef AAF_INSPECT_H
#define AAF_INSPECT_H

#include <stddef.h>

/*
 * inspect_file:
 *   Read metadata from AAF file and print human-friendly information.
 *   Returns 0 on success, 1 on failure.
 */
int inspect_file(const char *input_file);

#endif /* AAF_INSPECT_H */

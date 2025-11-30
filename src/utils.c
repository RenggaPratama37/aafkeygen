#include "utils.h"
#include <stdio.h>

void print_usage() {
    printf("Usage:\n");
    printf("  aafkeygen --encrypt <input> <output.aaf>\n");
    printf("  aafkeygen --decrypt <input.aaf> <output>\n");
    printf("\nAliases:\n");
    printf("  aafkeygen -E <input> <output.aaf>\n");
    printf("  aafkeygen -D <input.aaf> <output>\n");
}

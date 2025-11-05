#include "utils.h"
#include <stdio.h>

void print_usage() {
    printf("Usage:\n");
    printf("  aafkeygen --encrypt <input> <output.aaf> --password <pwd>\n");
    printf("  aafkeygen --decrypt <input.aaf> <output> --password <pwd>\n");
    printf("\nAliases:\n");
    printf("  aafkeygen -E <input> <output.aaf> -p <pwd>\n");
    printf("  aafkeygen -D <input.aaf> <output> -p <pwd>\n");
}

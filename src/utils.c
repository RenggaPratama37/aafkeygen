#include "utils.h"
#include <stdio.h>

void print_usage() {
    printf("Usage:\n");
    printf("  aafkeygen --encrypt <input> <output.aaf>\n");
    printf("  aafkeygen --decrypt <input.aaf> <output>\n");
    printf("\nAliases:\n");
    printf("  aafkeygen -E <input> <output.aaf> -p\n");
    printf("  aafkeygen -D <input.aaf> <output>\n");
}

void print_help() {
    printf("AAFKeygen v%s\n", VERSION);
    printf("Usage:\n");
    printf("  aafkeygen -E <file> [options]\n");
    printf("  aafkeygen -D <file.aaf>  [options]\n\n");
    printf("Options:\n");
    printf("  -E, --encrypt <file>       Encrypt file\n");
    printf("  -D, --decrypt <file>       Decrypt file\n");
    printf("  -o, --output <name>        Custom output file name\n");
    printf("  -r, --random-name          Generate random output filename\n");
    printf("      --keep                 Keep original file after operation\n");
    printf("      --temp-decrypt         Decrypt to a secure temp file, open with default viewer, re-encrypt after close (prompt-based)\n");
    printf("  -h, --help                 Show this message\n");
}

#include "password_input.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

char *read_password(const char *prompt) {
    struct termios oldt, newt;
    char *buffer = malloc(256);
    if (!buffer) return NULL;

    printf("%s", prompt);
    fflush(stdout);

    // Disable echo
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // Read password
    if (fgets(buffer, 256, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        free(buffer);
        return NULL;
    }

    // Re-enable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");

    // Remove newline
    buffer[strcspn(buffer, "\n")] = 0;
    return buffer;
}

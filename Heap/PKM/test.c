#include <stdlib.h>

int main() {
    execv("/bin/sh", NULL);
    return 0;
}
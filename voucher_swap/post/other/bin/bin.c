#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        return -1;
    }
    fprintf(stdout, "Hello, world!\n");
    fprintf(stdout, "argv[1]: %s\n", argv[1]);
    return 0;
}

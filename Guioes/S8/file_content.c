#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    FILE *file = fopen(argv[1], "r");

    char c;

    while ((c = fgetc(file)) != EOF) {
        printf("%c", c);
    }

    fclose(file);

    return 0;
}
#include <stdio.h>
#include <string.h>

void win(void) {
    puts("you win");
}

int main(int argc, char** argv) {
    if (argc >= 2 && strcmp(argv[1], "s3cr3t") == 0) {
        win();
        return 0;
    }
    puts("nope");
    return 1;
}

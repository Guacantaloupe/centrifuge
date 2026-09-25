#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    puts("you win");
}

int main(void) {
    char buf[16];
    ssize_t n = read(0, buf, 8);
    if (n >= 4 && buf[0] == 'H' && buf[1] == '4' && buf[2] == 'C' &&
        buf[3] == 'K') {
        win();
        return 0;
    }
    puts("nope");
    return 1;
}

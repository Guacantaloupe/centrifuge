#include <stdio.h>

int compute(int a, int b) {
    int x = a * 4 + b;
    if (x > 100) return x - 100;
    return x;
}

int max3(int a, int b, int c) {
    int m = a;
    if (b > m) m = b;
    if (c > m) m = c;
    return m;
}

int absdiff(int a, int b) {
    int d = a - b;
    if (d < 0) d = -d;
    return d;
}

int main(void) {
    printf("%lld\n", (long long)compute(3, 90));
    printf("%lld\n", (long long)compute(3, 95));
    printf("%lld\n", (long long)compute(1, 97));
    printf("%lld\n", (long long)compute(5, 0));
    printf("%lld\n", (long long)compute(-3, 100));
    printf("%lld\n", (long long)compute(2, 101));
    printf("%lld\n", (long long)compute(7, 80));
    printf("%lld\n", (long long)compute(0, 0));
    printf("%lld\n", (long long)max3(1, 2, 3));
    printf("%lld\n", (long long)max3(3, 2, 1));
    printf("%lld\n", (long long)max3(2, 2, 2));
    printf("%lld\n", (long long)max3(-1, -5, -3));
    printf("%lld\n", (long long)max3(5, 5, 4));
    printf("%lld\n", (long long)max3(0, -1, -2));
    printf("%lld\n", (long long)absdiff(10, 3));
    printf("%lld\n", (long long)absdiff(3, 10));
    printf("%lld\n", (long long)absdiff(0, 0));
    printf("%lld\n", (long long)absdiff(-5, 2));
    printf("%lld\n", (long long)absdiff(5, -2));
    printf("%lld\n", (long long)absdiff(-3, -8));
    return 0;
}

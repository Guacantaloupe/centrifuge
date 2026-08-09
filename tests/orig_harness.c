#include <stdio.h>

int fib(int n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

int sum_array(int* a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return s;
}


int main(void) {
    printf("%lld\n", (long long)fib(0));
    printf("%lld\n", (long long)fib(1));
    printf("%lld\n", (long long)fib(2));
    printf("%lld\n", (long long)fib(3));
    printf("%lld\n", (long long)fib(4));
    printf("%lld\n", (long long)fib(5));
    printf("%lld\n", (long long)fib(6));
    printf("%lld\n", (long long)fib(7));
    printf("%lld\n", (long long)fib(8));
    printf("%lld\n", (long long)fib(9));
    printf("%lld\n", (long long)fib(10));
    int a0[4] = {1, 2, 3, 4};
    printf("%lld\n", (long long)sum_array(a0, 4));
    int a1[1] = {5};
    printf("%lld\n", (long long)sum_array(a1, 1));
    int a2[0] = {};
    printf("%lld\n", (long long)sum_array(a2, 0));
    int a3[3] = {7, -1, 3};
    printf("%lld\n", (long long)sum_array(a3, 3));
    return 0;
}

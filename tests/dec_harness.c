#include <stdint.h>
#include <stdio.h>

int64_t compute(int64_t p0, int64_t p1) {
    int64_t zero=0, ra, sp, gp, tp, t0, t1, t2, s0, s1, a0=p0, a1=p1, a3, a4, a5, a6, a7, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, t3, t4, t5, t6;
    a0 = (int64_t)(int32_t)((uint32_t)(a0 << 2));
    a0 = (int64_t)(int32_t)((uint32_t)(a0 + a1));
    a5 = 100;
    if (a5 < a0) {
        a0 = (int64_t)(int32_t)((uint32_t)(a0 - 100));
        return a0;
    }
    return a0;
}

int64_t max3(int64_t p0, int64_t p1, int64_t p2) {
    int64_t zero=0, ra, sp, gp, tp, t0, t1, t2, s0, s1, a0=p0, a1=p1, a2=p2, a3, a4, a5, a6, a7, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, t3, t4, t5, t6;
    a5 = a1;
    if (a2 <= a1) goto L0x80000028;
    a5 = a2;
L0x80000028:
    a4 = (int64_t)(int32_t)((uint32_t)(a5));
    if (a0 <= a4) goto L0x80000034;
    a5 = a0;
L0x80000034:
    a0 = (int64_t)(int32_t)((uint32_t)(a5));
    return a0;
}

int64_t absdiff(int64_t p0, int64_t p1) {
    int64_t zero=0, ra, sp, gp, tp, t0, t1, t2, s0, s1, a0=p0, a1=p1, a3, a4, a5, a6, a7, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, t3, t4, t5, t6;
    a1 = (int64_t)(int32_t)((uint32_t)(a0 - a1));
    a0 = (int64_t)(int32_t)((uint32_t)(a1 >> 31));
    a1 = a1 ^ a0;
    a0 = (int64_t)(int32_t)((uint32_t)(a1 - a0));
    return a0;
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

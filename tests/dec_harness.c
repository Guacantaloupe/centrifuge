#include <stdint.h>
#include <stdio.h>

int64_t fib(int64_t p0, int64_t p1, int64_t p2, int64_t p3, int64_t p4, int64_t p5, int64_t p6, int64_t p7);
int64_t sum_array(int64_t p0, int64_t p1, int64_t p2, int64_t p3, int64_t p4, int64_t p5, int64_t p6, int64_t p7);

int64_t fib(int64_t p0, int64_t p1, int64_t p2, int64_t p3, int64_t p4, int64_t p5, int64_t p6, int64_t p7) {
    int64_t zero=0, ra, sp, gp, tp, t0, t1, t2, s0, s1, a0=p0, a1=p1, a2=p2, a3=p3, a4=p4, a5=p5, a6=p6, a7=p7, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, t3, t4, t5, t6;
    int64_t local_m104, local_m120, local_m128, local_m136, local_m144, local_m152, local_m16, local_m160, local_m168, local_m176, local_m184, local_m192, local_m200, local_m208, local_m216, local_m224, local_m232, local_m24, local_m240, local_m248, local_m256, local_m264, local_m272, local_m32, local_m40, local_m48, local_m56, local_m64, local_m72, local_m8, local_m80, local_m88, local_m96;
    sp = sp - 272;
    local_m64 = s6;
    local_m8 = ra;
    s6 = 1;
    if (a0 <= s6) goto L0x800003c0;
L0x80000054:
    a5 = (int64_t)(int32_t)((uint32_t)(a0 - 1));
    a4 = a5 & -2;
    local_m24 = s1;
    local_m40 = s3;
    local_m104 = s11;
    s1 = (int64_t)(int32_t)((uint32_t)(a0 - a4));
    s3 = 0;
    s11 = a5;
    if (a0 == s1) goto L0x800003b0;
L0x80000078:
    local_m48 = s4;
    s4 = (int64_t)(int32_t)((uint32_t)(a0 - 2));
    a5 = s4 & -2;
    local_m80 = s8;
    local_m88 = s9;
    local_m96 = s10;
    local_m208 = s1;
    local_m16 = s0;
    s1 = s3;
    local_m32 = s2;
    local_m56 = s5;
    local_m72 = s7;
    s9 = (int64_t)(int32_t)((uint32_t)(s11 - a5));
    s8 = 0;
    s10 = s11;
    s3 = s4;
    a5 = (int64_t)(int32_t)((uint32_t)(s10 - 1));
    if (s9 == s10) goto L0x80000368;
L0x800000c0:
    s10 = (int64_t)(int32_t)((uint32_t)(s10 - 2));
    a4 = s10 & -2;
    s11 = (int64_t)(int32_t)((uint32_t)(a5 - a4));
    s2 = 0;
    local_m200 = s8;
    s5 = s3;
    a3 = (int64_t)(int32_t)((uint32_t)(a5 - 1));
    if (s11 == a5) goto L0x800002f8;
L0x800000e0:
    a5 = (int64_t)(int32_t)((uint32_t)(a5 - 2));
    a4 = a5 & -2;
    local_m192 = s2;
    s7 = 0;
    local_m184 = s9;
    local_m176 = s11;
    s2 = (int64_t)(int32_t)((uint32_t)(a3 - a4));
    local_m168 = a5;
    a2 = (int64_t)(int32_t)((uint32_t)(a3 - 1));
    if (s2 == a3) goto L0x800002cc;
L0x80000108:
    a3 = (int64_t)(int32_t)((uint32_t)(a3 - 2));
    s3 = a3 & -2;
    s3 = (int64_t)(int32_t)((uint32_t)(a2 - s3));
    local_m160 = s1;
    local_m152 = s7;
    s11 = 0;
    local_m144 = s2;
    local_m216 = s3;
    local_m136 = s5;
    local_m128 = s10;
    local_m120 = a3;
    a5 = local_m216;
    a6 = (int64_t)(int32_t)((uint32_t)(a2 - 1));
    if (a5 == a2) goto L0x800002ac;
L0x80000140:
    s9 = (int64_t)(int32_t)((uint32_t)(a2 - 2));
    s2 = s9 & -2;
    s2 = (int64_t)(int32_t)((uint32_t)(a6 - s2));
    local_m232 = s11;
    a3 = 0;
    a1 = (int64_t)(int32_t)((uint32_t)(a2 - 4));
    local_m240 = s2;
    local_m224 = s9;
    a5 = local_m240;
    if (a6 == a5) goto L0x80000254;
L0x80000168:
    a2 = (int64_t)(int32_t)((uint32_t)(a6 - 2));
    a5 = a2 & -2;
    s3 = (int64_t)(int32_t)((uint32_t)(a6 - 3));
    s3 = (int64_t)(int32_t)((uint32_t)(s3 - a5));
    s2 = (int64_t)(int32_t)((uint32_t)(a6 - 5));
    a5 = a1 & -2;
    s2 = (int64_t)(int32_t)((uint32_t)(s2 - a5));
    s5 = a1;
    local_m264 = a3;
    local_m256 = a1;
    local_m272 = s2;
    local_m248 = a2;
    s4 = 0;
    s7 = (int64_t)(int32_t)((uint32_t)(s5 + 1));
    if (s3 == s5) goto L0x80000224;
L0x800001a4:
    s9 = (int64_t)(int32_t)((uint32_t)(s5 - 2));
    s0 = 0;
    s1 = s9;
    s8 = s5;
    if (s8 == s6) goto L0x80000208;
L0x800001b8:
    s2 = (int64_t)(int32_t)((uint32_t)(s7 - 2));
    a5 = s1 & -2;
    s7 = (int64_t)(int32_t)((uint32_t)(s7 - 4));
    s10 = (int64_t)(int32_t)((uint32_t)(s7 - a5));
    s11 = 0;
    s7 = s2;
    a0 = s7;
    ra = 2147484116;
    ra = 2147484124;
    a0 = fib(a0, a1, a2, a3, a4, a5, a6, a7);
    s7 = (int64_t)(int32_t)((uint32_t)(s7 - 2));
    s11 = (int64_t)(int32_t)((uint32_t)(a0 + s11));
    if (s10 != s7) goto L0x800001d0;
L0x800001e8:
    a5 = s1 & -2;
    s8 = (int64_t)(int32_t)((uint32_t)(s8 - 2));
    a5 = (int64_t)(int32_t)((uint32_t)(s8 - a5));
    a5 = (int64_t)(int32_t)((uint32_t)(a5 + s11));
    s0 = (int64_t)(int32_t)((uint32_t)(a5 + s0));
    s1 = (int64_t)(int32_t)((uint32_t)(s1 - 2));
    s7 = s2;
    if (s2 != s6) goto L0x800001b4;
L0x80000208:
    a5 = local_m272;
    a2 = (int64_t)(int32_t)((uint32_t)(s0 + 1));
    s4 = (int64_t)(int32_t)((uint32_t)(s4 + a2));
    if (a5 == s9) goto L0x800003d0;
L0x80000218:
    s5 = s9;
    s7 = (int64_t)(int32_t)((uint32_t)(s5 + 1));
    if (s3 != s5) goto L0x800001a4;
L0x80000224:
    a3 = local_m264;
    a1 = local_m256;
    a2 = local_m248;
    a4 = (int64_t)(int32_t)((uint32_t)(s7 + s4));
    a3 = (int64_t)(int32_t)((uint32_t)(a3 + a4));
    a1 = (int64_t)(int32_t)((uint32_t)(a1 - 2));
    a6 = a2;
    if (a2 != s6) goto L0x80000160;
L0x80000244:
    s11 = local_m232;
    s9 = local_m224;
    a4 = (int64_t)(int32_t)((uint32_t)(a3 + 1));
    goto L0x80000264;
L0x800003c0:
    ra = local_m8;
    s6 = local_m64;
    sp = sp + 272;
    return a0;
L0x800003b0:
    a0 = (int64_t)(int32_t)((uint32_t)(a5 + s3));
    s1 = local_m24;
    s3 = local_m40;
    s11 = local_m104;
goto L0x800003c0;
L0x80000368:
    s4 = s3;
    s8 = (int64_t)(int32_t)((uint32_t)(a5 + s8));
    s3 = s1;
    a0 = s4;
    s1 = local_m208;
    s3 = (int64_t)(int32_t)((uint32_t)(s3 + s8));
    if (s4 == s6) goto L0x80000328;
L0x80000384:
    a5 = (int64_t)(int32_t)((uint32_t)(s4 - 1));
    s0 = local_m16;
    s2 = local_m32;
    s4 = local_m48;
    s5 = local_m56;
    s7 = local_m72;
    s8 = local_m80;
    s9 = local_m88;
    s10 = local_m96;
    s11 = a5;
    if (a0 != s1) goto L0x80000078;
goto L0x800003b0;
L0x80000328:
    s0 = local_m16;
    ra = local_m8;
    s1 = local_m24;
    s2 = local_m32;
    s4 = local_m48;
    s5 = local_m56;
    s7 = local_m72;
    s8 = local_m80;
    s9 = local_m88;
    s10 = local_m96;
    s11 = local_m104;
    s6 = local_m64;
    a0 = (int64_t)(int32_t)((uint32_t)(s3 + 1));
    s3 = local_m40;
    sp = sp + 272;
    return a0;
L0x800002f8:
    s8 = local_m200;
    s3 = s5;
    a3 = (int64_t)(int32_t)((uint32_t)(a3 + s2));
    s8 = (int64_t)(int32_t)((uint32_t)(s8 + a3));
    if (s10 != s6) goto L0x800000b8;
L0x8000030c:
    s4 = s3;
    s8 = (int64_t)(int32_t)((uint32_t)(s8 + 1));
    s3 = s1;
    a0 = s4;
    s1 = local_m208;
    s3 = (int64_t)(int32_t)((uint32_t)(s3 + s8));
    if (s4 != s6) goto L0x80000384;
goto L0x80000328;
L0x800000b8:
    a5 = (int64_t)(int32_t)((uint32_t)(s10 - 1));
    if (s9 == s10) goto L0x80000368;
goto L0x800000c0;
L0x800002cc:
    s2 = local_m192;
    s9 = local_m184;
    s11 = local_m176;
    a5 = local_m168;
    a2 = (int64_t)(int32_t)((uint32_t)(a2 + s7));
    s2 = (int64_t)(int32_t)((uint32_t)(s2 + a2));
    if (a5 != s6) goto L0x800000d8;
L0x800002e8:
    s8 = local_m200;
    s3 = s5;
    a3 = (int64_t)(int32_t)((uint32_t)(s2 + 1));
    goto L0x80000304;
L0x800000d8:
    a3 = (int64_t)(int32_t)((uint32_t)(a5 - 1));
    if (s11 == a5) goto L0x800002f8;
goto L0x800000e0;
L0x80000304:
    s8 = (int64_t)(int32_t)((uint32_t)(s8 + a3));
    if (s10 != s6) goto L0x800000b8;
goto L0x8000030c;
L0x800002ac:
    s1 = local_m160;
    s7 = local_m152;
    s2 = local_m144;
    s5 = local_m136;
    s10 = local_m128;
    a3 = local_m120;
    a6 = (int64_t)(int32_t)((uint32_t)(a6 + s11));
    goto L0x8000028c;
L0x8000028c:
    s7 = (int64_t)(int32_t)((uint32_t)(s7 + a6));
    if (a3 != s6) goto L0x80000100;
L0x80000294:
    s2 = local_m192;
    s9 = local_m184;
    s11 = local_m176;
    a5 = local_m168;
    a2 = (int64_t)(int32_t)((uint32_t)(s7 + 1));
    goto L0x800002e0;
L0x80000100:
    a2 = (int64_t)(int32_t)((uint32_t)(a3 - 1));
    if (s2 == a3) goto L0x800002cc;
goto L0x80000108;
L0x800002e0:
    s2 = (int64_t)(int32_t)((uint32_t)(s2 + a2));
    if (a5 != s6) goto L0x800000d8;
goto L0x800002e8;
L0x80000254:
    s11 = local_m232;
    s9 = local_m224;
    a4 = (int64_t)(int32_t)((uint32_t)(a6 - 1));
    a4 = (int64_t)(int32_t)((uint32_t)(a4 + a3));
    s11 = (int64_t)(int32_t)((uint32_t)(s11 + a4));
    a2 = s9;
    if (s9 != s6) goto L0x80000134;
L0x80000270:
    s1 = local_m160;
    s7 = local_m152;
    s2 = local_m144;
    s5 = local_m136;
    s10 = local_m128;
    a3 = local_m120;
    a6 = (int64_t)(int32_t)((uint32_t)(s11 + 1));
goto L0x8000028c;
L0x80000134:
    a5 = local_m216;
    a6 = (int64_t)(int32_t)((uint32_t)(a2 - 1));
    if (a5 == a2) goto L0x800002ac;
goto L0x80000140;
L0x80000160:
    a5 = local_m240;
    if (a6 == a5) goto L0x80000254;
goto L0x80000168;
L0x80000264:
    s11 = (int64_t)(int32_t)((uint32_t)(s11 + a4));
    a2 = s9;
    if (s9 != s6) goto L0x80000134;
goto L0x80000270;
L0x800003d0:
    a3 = local_m264;
    a1 = local_m256;
    a2 = local_m248;
    a4 = (int64_t)(int32_t)((uint32_t)(s5 + s4));
    goto L0x80000234;
L0x80000234:
    a3 = (int64_t)(int32_t)((uint32_t)(a3 + a4));
    a1 = (int64_t)(int32_t)((uint32_t)(a1 - 2));
    a6 = a2;
    if (a2 != s6) goto L0x80000160;
goto L0x80000244;
L0x800001d0:
    a0 = s7;
    ra = 2147484116;
    ra = 2147484124;
    a0 = fib(a0, a1, a2, a3, a4, a5, a6, a7);
    s7 = (int64_t)(int32_t)((uint32_t)(s7 - 2));
    s11 = (int64_t)(int32_t)((uint32_t)(a0 + s11));
    if (s10 != s7) goto L0x800001d0;
goto L0x800001e8;
L0x800001b4:
    if (s8 == s6) goto L0x80000208;
goto L0x800001b8;
}

int64_t sum_array(int64_t p0, int64_t p1, int64_t p2, int64_t p3, int64_t p4, int64_t p5, int64_t p6, int64_t p7) {
    int64_t zero=0, ra, sp, gp, tp, t0, t1, t2, s0, s1, a0=p0, a1=p1, a2=p2, a3=p3, a4=p4, a5=p5, a6=p6, a7=p7, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, t3, t4, t5, t6;
    if (a1 <= 0) {
        a0 = 0;
        return a0;
    }
L0x800003e8:
    a1 = a1 << 2;
    a5 = a0;
    a1 = a0 + a1;
    a0 = 0;
    a4 = (int64_t)(int32_t)((uint32_t)(*(uint32_t *)(a5)));
    a5 = a5 + 4;
    a0 = (int64_t)(int32_t)((uint32_t)(a4 + a0));
    if (a5 != a1) goto L0x800003f8;
L0x80000408:
    return a0;
L0x8000040c:
    a0 = 0;
    return a0;
L0x800003f8:
    a4 = (int64_t)(int32_t)((uint32_t)(*(uint32_t *)(a5)));
    a5 = a5 + 4;
    a0 = (int64_t)(int32_t)((uint32_t)(a4 + a0));
    if (a5 != a1) goto L0x800003f8;
goto L0x80000408;
}

int main(void) {
    printf("%lld\n", (long long)fib(0, 0, 0, 0, 0, 0, 0, 0));
    printf("%lld\n", (long long)fib(1, 0, 0, 0, 0, 0, 0, 0));
    printf("%lld\n", (long long)fib(2, 0, 0, 0, 0, 0, 0, 0));
    printf("%lld\n", (long long)fib(3, 0, 0, 0, 0, 0, 0, 0));
    printf("%lld\n", (long long)fib(4, 0, 0, 0, 0, 0, 0, 0));
    printf("%lld\n", (long long)fib(5, 0, 0, 0, 0, 0, 0, 0));
    printf("%lld\n", (long long)fib(6, 0, 0, 0, 0, 0, 0, 0));
    printf("%lld\n", (long long)fib(7, 0, 0, 0, 0, 0, 0, 0));
    printf("%lld\n", (long long)fib(8, 0, 0, 0, 0, 0, 0, 0));
    printf("%lld\n", (long long)fib(9, 0, 0, 0, 0, 0, 0, 0));
    printf("%lld\n", (long long)fib(10, 0, 0, 0, 0, 0, 0, 0));
    int a0[4] = {1, 2, 3, 4};
    printf("%lld\n", (long long)sum_array((int64_t)a0, 4, 0, 0, 0, 0, 0, 0));
    int a1[1] = {5};
    printf("%lld\n", (long long)sum_array((int64_t)a1, 1, 0, 0, 0, 0, 0, 0));
    int a2[0] = {};
    printf("%lld\n", (long long)sum_array((int64_t)a2, 0, 0, 0, 0, 0, 0, 0));
    int a3[3] = {7, -1, 3};
    printf("%lld\n", (long long)sum_array((int64_t)a3, 3, 0, 0, 0, 0, 0, 0));
    return 0;
}

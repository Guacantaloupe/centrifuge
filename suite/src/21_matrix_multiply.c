/* 21. Matrix Multiplication family — loop-order & blocking zoo. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

#define MN 16
static double g_A[MN][MN], g_B[MN][MN], g_C[MN][MN];

TAG(mm_ijk);
void mm_ijk(int n) {
    MARK(mm_ijk);
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            double s = 0;
            for (int k = 0; k < n; k++) s += g_A[i][k] * g_B[k][j];
            g_C[i][j] = s;
        }
}
TAG(mm_ikj);
void mm_ikj(int n) {
    MARK(mm_ikj);
    for (int i = 0; i < n; i++)
        for (int k = 0; k < n; k++) {
            double a = g_A[i][k];
            for (int j = 0; j < n; j++) g_C[i][j] += a * g_B[k][j];
        }
}
TAG(mm_jik);
void mm_jik(int n) {
    MARK(mm_jik);
    for (int j = 0; j < n; j++)
        for (int i = 0; i < n; i++) {
            double s = 0;
            for (int k = 0; k < n; k++) s += g_A[i][k] * g_B[k][j];
            g_C[i][j] = s;
        }
}
TAG(mm_jki);
void mm_jki(int n) {
    MARK(mm_jki);
    for (int j = 0; j < n; j++)
        for (int k = 0; k < n; k++) {
            double b = g_B[k][j];
            for (int i = 0; i < n; i++) g_C[i][j] += g_A[i][k] * b;
        }
}
TAG(mm_kij);
void mm_kij(int n) {
    MARK(mm_kij);
    for (int k = 0; k < n; k++)
        for (int i = 0; i < n; i++) {
            double a = g_A[i][k];
            for (int j = 0; j < n; j++) g_C[i][j] += a * g_B[k][j];
        }
}
TAG(mm_kji);
void mm_kji(int n) {
    MARK(mm_kji);
    for (int k = 0; k < n; k++)
        for (int j = 0; j < n; j++) {
            double b = g_B[k][j];
            for (int i = 0; i < n; i++) g_C[i][j] += g_A[i][k] * b;
        }
}
TAG(mm_ptr_rows);
void mm_ptr_rows(int n, const double *A, const double *B, double *C) {
    MARK(mm_ptr_rows);
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            const double *a = A + i * n, *b = B + j;
            double s = 0;
            for (int k = 0; k < n; k++) s += a[k] * b[k * n];
            C[i * n + j] = s;
        }
}
TAG(mm_flattened);
void mm_flattened(int n) {
    MARK(mm_flattened);
    mm_ptr_rows(n, &g_A[0][0], &g_B[0][0], &g_C[0][0]);
}
TAG(mm_static_dims);
void mm_static_dims(void) {
    MARK(mm_static_dims);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) {
            double s = 0;
            for (int k = 0; k < 8; k++) s += g_A[i][k] * g_B[k][j];
            g_C[i][j] = s;
        }
}
TAG(mm_runtime_dims);
void mm_runtime_dims(int n) {
    MARK(mm_runtime_dims);
    mm_ijk(n);
}
TAG(mm_transpose_b);
void mm_transpose_b(int n) {
    MARK(mm_transpose_b);
    double BT[MN][MN];
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) BT[j][i] = g_B[i][j];
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            double s = 0;
            for (int k = 0; k < n; k++) s += g_A[i][k] * BT[j][k];
            g_C[i][j] = s;
        }
}
TAG(mm_scalar_accum);
double mm_scalar_accum(int n) {
    MARK(mm_scalar_accum);
    double s = 0;
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            for (int k = 0; k < n; k++) s += g_A[i][k] * g_B[k][j];
    return s;
}
TAG(mm_multi_accum);
double mm_multi_accum(int n) {
    MARK(mm_multi_accum);
    double s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            double a0 = g_A[i][j], a1 = g_A[i][(j + 1) % n],
                   a2 = g_A[i][(j + 2) % n], a3 = g_A[i][(j + 3) % n];
            s0 += a0 * g_B[j][i];
            s1 += a1 * g_B[(j + 1) % n][i];
            s2 += a2 * g_B[(j + 2) % n][i];
            s3 += a3 * g_B[(j + 3) % n][i];
        }
    return (s0 + s1) + (s2 + s3);
}
TAG(mm_blocked_4);
void mm_blocked_4(int n) {
    MARK(mm_blocked_4);
    for (int ii = 0; ii < n; ii += 4)
        for (int jj = 0; jj < n; jj += 4)
            for (int kk = 0; kk < n; kk += 4)
                for (int i = ii; i < ii + 4 && i < n; i++)
                    for (int j = jj; j < jj + 4 && j < n; j++) {
                        double s = g_C[i][j];
                        for (int k = kk; k < kk + 4 && k < n; k++)
                            s += g_A[i][k] * g_B[k][j];
                        g_C[i][j] = s;
                    }
}
TAG(mm_blocked_8);
void mm_blocked_8(int n) {
    MARK(mm_blocked_8);
    for (int ii = 0; ii < n; ii += 8)
        for (int jj = 0; jj < n; jj += 8)
            for (int kk = 0; kk < n; kk += 8)
                for (int i = ii; i < ii + 8 && i < n; i++)
                    for (int j = jj; j < jj + 8 && j < n; j++) {
                        double s = g_C[i][j];
                        for (int k = kk; k < kk + 8 && k < n; k++)
                            s += g_A[i][k] * g_B[k][j];
                        g_C[i][j] = s;
                    }
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)mm_ijk,        (variant_fn)mm_ikj,
    (variant_fn)mm_jik,        (variant_fn)mm_jki,
    (variant_fn)mm_kij,        (variant_fn)mm_kji,
    (variant_fn)mm_ptr_rows,   (variant_fn)mm_flattened,
    (variant_fn)mm_static_dims,(variant_fn)mm_runtime_dims,
    (variant_fn)mm_transpose_b,(variant_fn)mm_scalar_accum,
    (variant_fn)mm_multi_accum,(variant_fn)mm_blocked_4,
    (variant_fn)mm_blocked_8,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

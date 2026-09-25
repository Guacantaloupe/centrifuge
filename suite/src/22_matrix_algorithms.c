/* 22. Matrix Algorithms family. */
#include <stddef.h>
#include <stdint.h>
#include <math.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

#define MN 12
static double g_m[MN][MN];

TAG(ma_transpose_inplace);
void ma_transpose_inplace(int n) {
    MARK(ma_transpose_inplace);
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++) {
            double t = g_m[i][j];
            g_m[i][j] = g_m[j][i];
            g_m[j][i] = t;
        }
}
TAG(ma_transpose_outofplace);
void ma_transpose_outofplace(int n, double *dst) {
    MARK(ma_transpose_outofplace);
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) dst[j * n + i] = g_m[i][j];
}
TAG(ma_determinant);
double ma_determinant(int n) {
    MARK(ma_determinant);
    double a[MN][MN];
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) a[i][j] = g_m[i][j];
    double det = 1;
    for (int c = 0; c < n; c++) {
        int piv = c;
        for (int r = c + 1; r < n; r++)
            if (a[r][c] > a[piv][c]) piv = r;
        if (piv != c)
            for (int j = 0; j < n; j++) {
                double t = a[c][j]; a[c][j] = a[piv][j]; a[piv][j] = t;
            }
        det *= a[c][c];
        if (a[c][c] == 0) return 0;
        for (int r = c + 1; r < n; r++) {
            double f = a[r][c] / a[c][c];
            for (int j = c; j < n; j++) a[r][j] -= f * a[c][j];
        }
    }
    return det;
}
TAG(ma_gauss_no_pivot);
int ma_gauss_no_pivot(int n, double *b, double *x) {
    MARK(ma_gauss_no_pivot);
    double a[MN][MN];
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) a[i][j] = g_m[i][j];
    for (int c = 0; c < n; c++) {
        for (int r = c + 1; r < n; r++) {
            double f = a[r][c] / a[c][c];
            for (int j = c; j < n; j++) a[r][j] -= f * a[c][j];
            b[r] -= f * b[c];
        }
    }
    for (int i = n - 1; i >= 0; i--) {
        double s = b[i];
        for (int j = i + 1; j < n; j++) s -= a[i][j] * x[j];
        x[i] = s / a[i][i];
    }
    return 0;
}
TAG(ma_gauss_pivot);
int ma_gauss_pivot(int n, double *b, double *x) {
    MARK(ma_gauss_pivot);
    double a[MN][MN];
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) a[i][j] = g_m[i][j];
    for (int c = 0; c < n; c++) {
        int piv = c;
        for (int r = c + 1; r < n; r++)
            if (a[r][c] > a[piv][c]) piv = r;
        for (int j = c; j < n; j++) {
            double t = a[c][j]; a[c][j] = a[piv][j]; a[piv][j] = t;
        }
        double tb = b[c]; b[c] = b[piv]; b[piv] = tb;
        for (int r = c + 1; r < n; r++) {
            double f = a[r][c] / a[c][c];
            for (int j = c; j < n; j++) a[r][j] -= f * a[c][j];
            b[r] -= f * b[c];
        }
    }
    for (int i = n - 1; i >= 0; i--) {
        double s = b[i];
        for (int j = i + 1; j < n; j++) s -= a[i][j] * x[j];
        x[i] = s / a[i][i];
    }
    return 0;
}
TAG(ma_gauss_jordan);
int ma_gauss_jordan(int n, double *b) {
    MARK(ma_gauss_jordan);
    for (int c = 0; c < n; c++) {
        double d = g_m[c][c];
        for (int j = 0; j < n; j++) g_m[c][j] /= d;
        b[c] /= d;
        for (int r = 0; r < n; r++) {
            if (r == c) continue;
            double f = g_m[r][c];
            for (int j = 0; j < n; j++) g_m[r][j] -= f * g_m[c][j];
            b[r] -= f * b[c];
        }
    }
    return 0;
}
TAG(ma_cholesky);
int ma_cholesky(int n, double *L) {
    MARK(ma_cholesky);
    for (int i = 0; i < n; i++)
        for (int j = 0; j <= i; j++) {
            double s = g_m[i][j];
            for (int k = 0; k < j; k++) s -= L[i * n + k] * L[j * n + k];
            L[i * n + j] = i == j ? s > 0 ? sqrt(s) : 0 : s / L[j * n + j];
        }
    return 0;
}
/* sparse CSR SpMV */
struct csr { int nrows; const int *rowptr; const int *col; const double *val; };
TAG(ma_csr_spmv);
void ma_csr_spmv(const struct csr *A, const double *x, double *y) {
    MARK(ma_csr_spmv);
    for (int i = 0; i < A->nrows; i++) {
        double s = 0;
        for (int k = A->rowptr[i]; k < A->rowptr[i + 1]; k++)
            s += A->val[k] * x[A->col[k]];
        y[i] = s;
    }
}
/* sparse COO SpMV */
struct coo_entry { int row, col; double val; };
TAG(ma_coo_spmv);
void ma_coo_spmv(const struct coo_entry *e, int nnz, const double *x, double *y) {
    MARK(ma_coo_spmv);
    for (int k = 0; k < nnz; k++) y[e[k].row] += e[k].val * x[e[k].col];
}
/* matrix inverse via adjugate-free Gauss-Jordan on augmented columns */
TAG(ma_inverse);
int ma_inverse(int n) {
    MARK(ma_inverse);
    double aug[MN][2 * MN];
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            aug[i][j] = g_m[i][j];
            aug[i][n + j] = i == j ? 1.0 : 0.0;
        }
    for (int c = 0; c < n; c++) {
        double d = aug[c][c];
        for (int j = 0; j < 2 * n; j++) aug[c][j] /= d;
        for (int r = 0; r < n; r++) {
            if (r == c) continue;
            double f = aug[r][c];
            for (int j = 0; j < 2 * n; j++) aug[r][j] -= f * aug[c][j];
        }
    }
    return aug[0][2 * n - 1] > 0 ? 0 : -1;
}
TAG(ma_lu_decompose);
int ma_lu_decompose(int n) {
    MARK(ma_lu_decompose);
    for (int c = 0; c < n; c++) {
        for (int j = c; j < n; j++) {
            double s = g_m[c][j];
            for (int k = 0; k < c; k++) s -= g_m[c][k] * g_m[k][j];
            g_m[c][j] = s;
        }
        for (int r = c + 1; r < n; r++) {
            double s = g_m[r][c];
            for (int k = 0; k < c; k++) s -= g_m[r][k] * g_m[k][c];
            g_m[r][c] = s / g_m[c][c];
        }
    }
    return 0;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)ma_transpose_inplace,  (variant_fn)ma_transpose_outofplace,
    (variant_fn)ma_determinant,        (variant_fn)ma_gauss_no_pivot,
    (variant_fn)ma_gauss_pivot,        (variant_fn)ma_gauss_jordan,
    (variant_fn)ma_cholesky,           (variant_fn)ma_csr_spmv,
    (variant_fn)ma_coo_spmv,           (variant_fn)ma_inverse,
    (variant_fn)ma_lu_decompose,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

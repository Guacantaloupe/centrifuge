/* 23. FFT / DSP family. */
#include <stddef.h>
#include <stdint.h>
#include <math.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
#define FN 16

struct cplx { double re, im; };
static struct cplx g_x[FN], g_y[FN];
static const double g_bitrev4[4] = {0, 2, 1, 3};

TAG(dsp_dft);
void dsp_dft(const double *in, double *re, double *im, int n) {
    MARK(dsp_dft);
    for (int k = 0; k < n; k++) {
        double sr = 0, si = 0;
        for (int t = 0; t < n; t++) {
            double ang = -2.0 * M_PI * k * t / n;
            sr += in[t] * cos(ang);
            si += in[t] * sin(ang);
        }
        re[k] = sr;
        im[k] = si;
    }
}
static void fft_rec(struct cplx *a, int n) {
    if (n <= 1) return;
    struct cplx even[FN], odd[FN];
    for (int i = 0; i < n / 2; i++) {
        even[i] = a[2 * i];
        odd[i] = a[2 * i + 1];
    }
    fft_rec(even, n / 2);
    fft_rec(odd, n / 2);
    for (int k = 0; k < n / 2; k++) {
        double ang = -2.0 * M_PI * k / n;
        struct cplx t = {odd[k].re * cos(ang) - odd[k].im * sin(ang),
                         odd[k].re * sin(ang) + odd[k].im * cos(ang)};
        a[k].re = even[k].re + t.re;
        a[k].im = even[k].im + t.im;
        a[k + n / 2].re = even[k].re - t.re;
        a[k + n / 2].im = even[k].im - t.im;
    }
}
TAG(dsp_fft_recursive);
void dsp_fft_recursive(struct cplx *a, int n) {
    MARK(dsp_fft_recursive);
    fft_rec(a, n);
}
TAG(dsp_fft_iterative);
void dsp_fft_iterative(struct cplx *a, int n) {
    MARK(dsp_fft_iterative);
    for (int i = 1, j = 0; i < n; i++) {
        int bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) { struct cplx t = a[i]; a[i] = a[j]; a[j] = t; }
    }
    for (int len = 2; len <= n; len <<= 1) {
        double ang = -2.0 * M_PI / len;
        struct cplx wl = {cos(ang), sin(ang)};
        for (int i = 0; i < n; i += len) {
            struct cplx w = {1, 0};
            for (int j = 0; j < len / 2; j++) {
                struct cplx u = a[i + j];
                struct cplx v = {a[i + j + len / 2].re * w.re -
                                     a[i + j + len / 2].im * w.im,
                                 a[i + j + len / 2].re * w.im +
                                     a[i + j + len / 2].im * w.re};
                a[i + j].re = u.re + v.re;
                a[i + j].im = u.im + v.im;
                a[i + j + len / 2].re = u.re - v.re;
                a[i + j + len / 2].im = u.im - v.im;
                double nr = w.re * wl.re - w.im * wl.im;
                w.im = w.re * wl.im + w.im * wl.re;
                w.re = nr;
            }
        }
    }
}
TAG(dsp_bitrev_loop);
int dsp_bitrev_loop(int x, int bits) {
    MARK(dsp_bitrev_loop);
    int r = 0;
    for (int i = 0; i < bits; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}
TAG(dsp_bitrev_lut);
int dsp_bitrev_lut(int x) {
    MARK(dsp_bitrev_lut);
    return (int)g_bitrev4[x & 3];
}
TAG(dsp_conv_direct);
void dsp_conv_direct(const double *x, int nx, const double *h, int nh,
                     double *y) {
    MARK(dsp_conv_direct);
    for (int i = 0; i < nx + nh - 1; i++) {
        double s = 0;
        for (int j = 0; j < nh; j++)
            if (i - j >= 0 && i - j < nx) s += x[i - j] * h[j];
        y[i] = s;
    }
}
TAG(dsp_fir);
void dsp_fir(const double *x, const double *coef, int ncoef, double *y,
             int n) {
    MARK(dsp_fir);
    for (int i = 0; i < n; i++) {
        double s = 0;
        for (int j = 0; j < ncoef && i - j >= 0; j++) s += coef[j] * x[i - j];
        y[i] = s;
    }
}
TAG(dsp_iir);
void dsp_iir(const double *x, double *y, int n, double b0, double b1,
             double a1) {
    MARK(dsp_iir);
    for (int i = 0; i < n; i++) {
        double x1 = i > 0 ? x[i - 1] : 0;
        double y1 = i > 0 ? y[i - 1] : 0;
        y[i] = b0 * x[i] + b1 * x1 - a1 * y1;
    }
}
TAG(dsp_moving_average);
void dsp_moving_average(const double *x, double *y, int n, int w) {
    MARK(dsp_moving_average);
    double sum = 0;
    for (int i = 0; i < n; i++) {
        sum += x[i];
        if (i >= w) sum -= x[i - w];
        y[i] = sum / (i < w ? i + 1 : w);
    }
}
TAG(dsp_radix4_step);
void dsp_radix4_step(struct cplx *a, int n) {
    MARK(dsp_radix4_step);
    /* one radix-4 butterfly pass over quarter blocks */
    for (int i = 0; i < n; i += 4) {
        struct cplx s0 = a[i], s1 = a[i + 1], s2 = a[i + 2], s3 = a[i + 3];
        a[i].re = s0.re + s1.re + s2.re + s3.re;
        a[i].im = s0.im + s1.im + s2.im + s3.im;
        a[i + 2].re = s0.re - s1.re + s2.re - s3.re;
        a[i + 2].im = s0.im - s1.im + s2.im - s3.im;
        a[i + 1].re = s0.re - s2.im - s1.re + s3.im;
        a[i + 1].im = s0.im + s2.re - s1.im - s3.re;
        a[i + 3].re = s0.re + s2.im - s1.re - s3.im;
        a[i + 3].im = s0.im - s2.re - s1.im + s3.re;
    }
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)dsp_dft,           (variant_fn)dsp_fft_recursive,
    (variant_fn)dsp_fft_iterative, (variant_fn)dsp_bitrev_loop,
    (variant_fn)dsp_bitrev_lut,    (variant_fn)dsp_conv_direct,
    (variant_fn)dsp_fir,           (variant_fn)dsp_iir,
    (variant_fn)dsp_moving_average,(variant_fn)dsp_radix4_step,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)g_x; (void)g_y;
    (void)sink;
    return 0;
}

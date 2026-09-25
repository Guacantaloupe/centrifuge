/* 44. ML / SIMD-style Kernel family — dot products, GEMM, softmax, conv. */
#include <stddef.h>
#include <stdint.h>
#include <math.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(ml_dot_product);
float ml_dot_product(const float *a, const float *b, int n) {
    MARK(ml_dot_product);
    float s = 0.0f;
    for (int i = 0; i < n; i++) s += a[i] * b[i];
    return s;
}
TAG(ml_dot_unrolled4);
float ml_dot_unrolled4(const float *a, const float *b, int n) {
    MARK(ml_dot_unrolled4);
    float s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    int i = 0;
    for (; i + 4 <= n; i += 4) {
        s0 += a[i] * b[i];
        s1 += a[i + 1] * b[i + 1];
        s2 += a[i + 2] * b[i + 2];
        s3 += a[i + 3] * b[i + 3];
    }
    for (; i < n; i++) s0 += a[i] * b[i];
    return (s0 + s1) + (s2 + s3);
}
TAG(ml_gemm_naive);
void ml_gemm_naive(const float *a, const float *b, float *c, int m, int n, int k) {
    MARK(ml_gemm_naive);
    for (int i = 0; i < m; i++)
        for (int j = 0; j < n; j++) {
            float s = 0.0f;
            for (int p = 0; p < k; p++) s += a[i * k + p] * b[p * n + j];
            c[i * n + j] = s;
        }
}
TAG(ml_gemm_blocked);
void ml_gemm_blocked(const float *a, const float *b, float *c, int n, int bs) {
    MARK(ml_gemm_blocked);
    for (int bi = 0; bi < n; bi += bs)
        for (int bj = 0; bj < n; bj += bs)
            for (int bk = 0; bk < n; bk += bs)
                for (int i = bi; i < bi + bs && i < n; i++)
                    for (int j = bj; j < bj + bs && j < n; j++) {
                        float s = c[i * n + j];
                        for (int k = bk; k < bk + bs && k < n; k++)
                            s += a[i * n + k] * b[k * n + j];
                        c[i * n + j] = s;
                    }
}
TAG(ml_softmax);
void ml_softmax(float *x, int n) {
    MARK(ml_softmax);
    float mx = x[0];
    for (int i = 1; i < n; i++)
        if (x[i] > mx) mx = x[i];
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        x[i] = expf(x[i] - mx);
        sum += x[i];
    }
    for (int i = 0; i < n; i++) x[i] /= sum;
}
TAG(ml_relu_and_clip);
int ml_relu_and_clip(float *x, int n) {
    MARK(ml_relu_and_clip);
    int clipped = 0;
    for (int i = 0; i < n; i++) {
        float v = x[i];
        if (v < 0.0f) v = 0.0f;
        if (v > 6.0f) { v = 6.0f; clipped++; }
        x[i] = v;
    }
    return clipped;
}
TAG(ml_conv2d_3x3);
void ml_conv2d_3x3(const float *in, const float *ker, float *out, int w, int h) {
    MARK(ml_conv2d_3x3);
    for (int y = 1; y < h - 1; y++)
        for (int x = 1; x < w - 1; x++) {
            float s = 0.0f;
            for (int ky = 0; ky < 3; ky++)
                for (int kx = 0; kx < 3; kx++)
                    s += in[(y + ky - 1) * w + (x + kx - 1)] * ker[ky * 3 + kx];
            out[y * w + x] = s;
        }
}
TAG(ml_max_pool_2x2);
void ml_max_pool_2x2(const float *in, float *out, int w, int h) {
    MARK(ml_max_pool_2x2);
    for (int y = 0; y + 1 < h; y += 2)
        for (int x = 0; x + 1 < w; x += 2) {
            float m = in[y * w + x];
            if (in[y * w + x + 1] > m) m = in[y * w + x + 1];
            if (in[(y + 1) * w + x] > m) m = in[(y + 1) * w + x];
            if (in[(y + 1) * w + x + 1] > m) m = in[(y + 1) * w + x + 1];
            out[(y / 2) * (w / 2) + (x / 2)] = m;
        }
}
TAG(ml_layernorm);
void ml_layernorm(float *x, int n) {
    MARK(ml_layernorm);
    float mean = 0.0f;
    for (int i = 0; i < n; i++) mean += x[i];
    mean /= (float)n;
    float var = 0.0f;
    for (int i = 0; i < n; i++) {
        float d = x[i] - mean;
        var += d * d;
    }
    var /= (float)n;
    float inv = 1.0f / sqrtf(var + 1e-5f);
    for (int i = 0; i < n; i++) x[i] = (x[i] - mean) * inv;
}
TAG(ml_attention_scores);
void ml_attention_scores(const float *q, const float *k, float *s, int dim, int tokens) {
    MARK(ml_attention_scores);
    for (int t = 0; t < tokens; t++) {
        float d = 0.0f;
        for (int i = 0; i < dim; i++) d += q[i] * k[t * dim + i];
        s[t] = d / sqrtf((float)dim);
    }
}
TAG(ml_svm_hinge);
float ml_svm_hinge(const float *w, const float *x, int n, int label) {
    MARK(ml_svm_hinge);
    float margin = 0.0f;
    for (int i = 0; i < n; i++) margin += w[i] * x[i];
    margin *= (float)label;
    return margin < 1.0f ? 1.0f - margin : 0.0f;
}
TAG(ml_gradient_step);
void ml_gradient_step(float *w, const float *g, int n, float lr) {
    MARK(ml_gradient_step);
    for (int i = 0; i < n; i++) w[i] -= lr * g[i];
}
TAG(ml_kmeans_assign);
int ml_kmeans_assign(const float *x, const float *cent, int k, int dim) {
    MARK(ml_kmeans_assign);
    int best = 0;
    float best_d = 1e30f;
    for (int c = 0; c < k; c++) {
        float d = 0.0f;
        for (int i = 0; i < dim; i++) {
            float diff = x[i] - cent[c * dim + i];
            d += diff * diff;
        }
        if (d < best_d) { best_d = d; best = c; }
    }
    return best;
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    (variant_fn)ml_dot_product,    (variant_fn)ml_dot_unrolled4,
    (variant_fn)ml_gemm_naive,     (variant_fn)ml_gemm_blocked,
    (variant_fn)ml_softmax,        (variant_fn)ml_relu_and_clip,
    (variant_fn)ml_conv2d_3x3,     (variant_fn)ml_max_pool_2x2,
    (variant_fn)ml_layernorm,      (variant_fn)ml_attention_scores,
    (variant_fn)ml_svm_hinge,      (variant_fn)ml_gradient_step,
    (variant_fn)ml_kmeans_assign,
};
int main(void) {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}

/* 24. Image Algorithms family. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

#define IW 16
static uint8_t g_img[IW * IW];
static uint8_t g_img2[IW * IW];
static float g_fimg[IW * IW];

TAG(img_nearest_resize);
void img_nearest_resize(const uint8_t *src, int sw, int sh, uint8_t *dst,
                        int dw, int dh) {
    MARK(img_nearest_resize);
    for (int y = 0; y < dh; y++)
        for (int x = 0; x < dw; x++) {
            int sx = x * sw / dw, sy = y * sh / dh;
            dst[y * dw + x] = src[sy * sw + sx];
        }
}
TAG(img_bilinear_resize);
void img_bilinear_resize(const uint8_t *src, int sw, int sh, uint8_t *dst,
                         int dw, int dh) {
    MARK(img_bilinear_resize);
    for (int y = 0; y < dh; y++)
        for (int x = 0; x < dw; x++) {
            float gx = (float)x * (sw - 1) / (dw - 1);
            float gy = (float)y * (sh - 1) / (dh - 1);
            int x0 = (int)gx, y0 = (int)gy;
            int x1 = x0 + 1 < sw ? x0 + 1 : x0;
            int y1 = y0 + 1 < sh ? y0 + 1 : y0;
            float fx = gx - x0, fy = gy - y0;
            float p = (src[y0 * sw + x0] * (1 - fx) + src[y0 * sw + x1] * fx) *
                          (1 - fy) +
                      (src[y1 * sw + x0] * (1 - fx) + src[y1 * sw + x1] * fx) *
                          fy;
            dst[y * dw + x] = (uint8_t)(p + 0.5f);
        }
}
TAG(img_grayscale);
void img_grayscale(const uint8_t *rgb, uint8_t *gray, int n) {
    MARK(img_grayscale);
    for (int i = 0; i < n; i++) {
        uint8_t r = rgb[3 * i], g = rgb[3 * i + 1], b = rgb[3 * i + 2];
        gray[i] = (uint8_t)((r * 30 + g * 59 + b * 11 + 50) / 100);
    }
}
TAG(img_rgb_bgr);
void img_rgb_bgr(uint8_t *px, int n) {
    MARK(img_rgb_bgr);
    for (int i = 0; i < n; i++) {
        uint8_t t = px[3 * i];
        px[3 * i] = px[3 * i + 2];
        px[3 * i + 2] = t;
    }
}
TAG(img_threshold);
int img_threshold(uint8_t *img, int n, uint8_t t) {
    MARK(img_threshold);
    int changed = 0;
    for (int i = 0; i < n; i++) {
        uint8_t v = img[i] >= t ? 255 : 0;
        changed |= v != img[i];
        img[i] = v;
    }
    return changed;
}
TAG(img_conv3x3);
void img_conv3x3(const uint8_t *src, uint8_t *dst, int w, int h,
                 const float *k) {
    MARK(img_conv3x3);
    for (int y = 1; y < h - 1; y++)
        for (int x = 1; x < w - 1; x++) {
            float s = 0;
            for (int j = -1; j <= 1; j++)
                for (int i = -1; i <= 1; i++)
                    s += src[(y + j) * w + x + i] * k[(j + 1) * 3 + i + 1];
            dst[y * w + x] = (uint8_t)(s < 0 ? 0 : s > 255 ? 255 : s);
        }
}
TAG(img_gaussian_blur);
void img_gaussian_blur(const uint8_t *src, uint8_t *dst, int w, int h) {
    MARK(img_gaussian_blur);
    static const float k[9] = {1, 2, 1, 2, 4, 2, 1, 2, 1};
    for (int y = 1; y < h - 1; y++)
        for (int x = 1; x < w - 1; x++) {
            float s = 0;
            for (int j = -1; j <= 1; j++)
                for (int i = -1; i <= 1; i++)
                    s += src[(y + j) * w + x + i] * k[(j + 1) * 3 + i + 1];
            dst[y * w + x] = (uint8_t)(s / 16.0f);
        }
}
TAG(img_sobel);
void img_sobel(const uint8_t *src, uint8_t *dst, int w, int h) {
    MARK(img_sobel);
    static const int gx[9] = {-1, 0, 1, -2, 0, 2, -1, 0, 1};
    static const int gy[9] = {-1, -2, -1, 0, 0, 0, 1, 2, 1};
    for (int y = 1; y < h - 1; y++)
        for (int x = 1; x < w - 1; x++) {
            int sx = 0, sy = 0;
            for (int j = -1; j <= 1; j++)
                for (int i = -1; i <= 1; i++) {
                    int v = src[(y + j) * w + x + i];
                    sx += v * gx[(j + 1) * 3 + i + 1];
                    sy += v * gy[(j + 1) * 3 + i + 1];
                }
            int mag = sx < 0 ? -sx : sx;
            mag += sy < 0 ? -sy : sy;
            dst[y * w + x] = (uint8_t)(mag > 255 ? 255 : mag);
        }
}
TAG(img_histogram);
void img_histogram(const uint8_t *img, int n, int *hist) {
    MARK(img_histogram);
    for (int i = 0; i < 256; i++) hist[i] = 0;
    for (int i = 0; i < n; i++) hist[img[i]]++;
}
TAG(img_hist_equalize);
void img_hist_equalize(uint8_t *img, int n) {
    MARK(img_hist_equalize);
    int hist[256], cdf[256];
    img_histogram(img, n, hist);
    cdf[0] = hist[0];
    for (int i = 1; i < 256; i++) cdf[i] = cdf[i - 1] + hist[i];
    int cdfmin = 0;
    for (int i = 0; i < 256; i++)
        if (cdf[i]) { cdfmin = cdf[i]; break; }
    for (int i = 0; i < n; i++) {
        int v = (int)((cdf[img[i]] - cdfmin) * 255.0f / (n - cdfmin) + 0.5f);
        img[i] = (uint8_t)(v < 0 ? 0 : v > 255 ? 255 : v);
    }
}
TAG(img_flood_fill_rec);
void img_flood_fill_rec(uint8_t *img, int w, int h, int x, int y,
                        uint8_t target, uint8_t repl) {
    MARK(img_flood_fill_rec);
    if (x < 0 || x >= w || y < 0 || y >= h) return;
    if (img[y * w + x] != target) return;
    img[y * w + x] = repl;
    img_flood_fill_rec(img, w, h, x + 1, y, target, repl);
    img_flood_fill_rec(img, w, h, x - 1, y, target, repl);
    img_flood_fill_rec(img, w, h, x, y + 1, target, repl);
    img_flood_fill_rec(img, w, h, x, y - 1, target, repl);
}
TAG(img_flood_fill_queue);
void img_flood_fill_queue(uint8_t *img, int w, int h, int sx, int sy,
                          uint8_t target, uint8_t repl) {
    MARK(img_flood_fill_queue);
    int qx[256], qy[256], head = 0, tail = 0;
    qx[tail] = sx; qy[tail] = sy; tail++;
    while (head < tail) {
        int x = qx[head], y = qy[head]; head++;
        if (x < 0 || x >= w || y < 0 || y >= h) continue;
        if (img[y * w + x] != target) continue;
        img[y * w + x] = repl;
        qx[tail] = x + 1; qy[tail] = y; tail++;
        qx[tail] = x - 1; qy[tail] = y; tail++;
        qx[tail] = x; qy[tail] = y + 1; tail++;
        qx[tail] = x; qy[tail] = y - 1; tail++;
    }
}
TAG(img_connected_components);
int img_connected_components(const uint8_t *img, int w, int h, int *label) {
    MARK(img_connected_components);
    for (int i = 0; i < w * h; i++) label[i] = img[i] ? -1 : 0;
    int next = 1;
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            if (label[y * w + x] != -1) continue;
            int qx[256], qy[256], head = 0, tail = 0;
            label[y * w + x] = next;
            qx[tail] = x; qy[tail] = y; tail++;
            while (head < tail) {
                int cx = qx[head], cy = qy[head]; head++;
                static const int dx[4] = {1, -1, 0, 0};
                static const int dy[4] = {0, 0, 1, -1};
                for (int d = 0; d < 4; d++) {
                    int nx = cx + dx[d], ny = cy + dy[d];
                    if (nx >= 0 && nx < w && ny >= 0 && ny < h &&
                        label[ny * w + nx] == -1) {
                        label[ny * w + nx] = next;
                        qx[tail] = nx; qy[tail] = ny; tail++;
                    }
                }
            }
            next++;
        }
    return next - 1;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)img_nearest_resize,   (variant_fn)img_bilinear_resize,
    (variant_fn)img_grayscale,        (variant_fn)img_rgb_bgr,
    (variant_fn)img_threshold,        (variant_fn)img_conv3x3,
    (variant_fn)img_gaussian_blur,    (variant_fn)img_sobel,
    (variant_fn)img_histogram,        (variant_fn)img_hist_equalize,
    (variant_fn)img_flood_fill_rec,   (variant_fn)img_flood_fill_queue,
    (variant_fn)img_connected_components,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)g_img; (void)g_img2; (void)g_fimg;
    (void)sink;
    return 0;
}

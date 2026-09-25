/* 06. RadixSort family. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(rx_lsd_base2);
void rx_lsd_base2(uint32_t *a, size_t n) {
    MARK(rx_lsd_base2);
    uint32_t *out = (uint32_t *)malloc(n * 4);
    for (int bit = 0; bit < 32; bit++) {
        size_t cnt[2] = {0, 0};
        for (size_t i = 0; i < n; i++) cnt[(a[i] >> bit) & 1]++;
        cnt[1] += cnt[0];
        for (size_t i = n; i-- > 0;)
            out[--cnt[(a[i] >> bit) & 1]] = a[i];
        uint32_t *t = a; a = out; out = t;
    }
    free(out);
}
TAG(rx_lsd_base16);
void rx_lsd_base16(uint32_t *a, size_t n) {
    MARK(rx_lsd_base16);
    uint32_t *out = (uint32_t *)malloc(n * 4);
    for (int shift = 0; shift < 32; shift += 4) {
        size_t cnt[16] = {0};
        for (size_t i = 0; i < n; i++) cnt[(a[i] >> shift) & 15]++;
        for (int k = 1; k < 16; k++) cnt[k] += cnt[k - 1];
        for (size_t i = n; i-- > 0;)
            out[--cnt[(a[i] >> shift) & 15]] = a[i];
        uint32_t *t = a; a = out; out = t;
    }
    free(out);
}
TAG(rx_lsd_base256);
void rx_lsd_base256(uint32_t *a, size_t n) {
    MARK(rx_lsd_base256);
    uint32_t *out = (uint32_t *)malloc(n * 4);
    for (int shift = 0; shift < 32; shift += 8) {
        size_t cnt[256] = {0};
        for (size_t i = 0; i < n; i++) cnt[(a[i] >> shift) & 255]++;
        for (int k = 1; k < 256; k++) cnt[k] += cnt[k - 1];
        for (size_t i = n; i-- > 0;)
            out[--cnt[(a[i] >> shift) & 255]] = a[i];
        uint32_t *t = a; a = out; out = t;
    }
    free(out);
}
TAG(rx_lsd_base65536);
void rx_lsd_base65536(uint32_t *a, size_t n) {
    MARK(rx_lsd_base65536);
    uint32_t *out = (uint32_t *)malloc(n * 4);
    for (int shift = 0; shift < 32; shift += 16) {
        size_t *cnt = (size_t *)calloc(65536, sizeof(size_t));
        for (size_t i = 0; i < n; i++) cnt[(a[i] >> shift) & 65535]++;
        for (int k = 1; k < 65536; k++) cnt[k] += cnt[k - 1];
        for (size_t i = n; i-- > 0;)
            out[--cnt[(a[i] >> shift) & 65535]] = a[i];
        uint32_t *t = a; a = out; out = t;
        free(cnt);
    }
    free(out);
}
TAG(rx_signed);
void rx_signed(int32_t *a, size_t n) {
    MARK(rx_signed);
    for (size_t i = 0; i < n; i++) a[i] ^= 0x80000000u;
    rx_lsd_base256((uint32_t *)a, n);
    for (size_t i = 0; i < n; i++) a[i] ^= 0x80000000u;
}
TAG(rx_u64);
void rx_u64(uint64_t *a, size_t n) {
    MARK(rx_u64);
    uint64_t *out = (uint64_t *)malloc(n * 8);
    for (int shift = 0; shift < 64; shift += 8) {
        size_t cnt[256] = {0};
        for (size_t i = 0; i < n; i++) cnt[(a[i] >> shift) & 255]++;
        for (int k = 1; k < 256; k++) cnt[k] += cnt[k - 1];
        for (size_t i = n; i-- > 0;)
            out[--cnt[(a[i] >> shift) & 255]] = a[i];
        uint64_t *t = a; a = out; out = t;
    }
    free(out);
}
static void msd_rec(uint32_t *a, size_t n, int shift, uint32_t *buf) {
    if (n <= 1 || shift < 0) return;
    size_t cnt[256] = {0};
    for (size_t i = 0; i < n; i++) cnt[(a[i] >> shift) & 255]++;
    size_t sum = 0;
    for (int k = 0; k < 256; k++) { size_t c = cnt[k]; cnt[k] = sum; sum += c; }
    for (size_t i = 0; i < n; i++)
        buf[cnt[(a[i] >> shift) & 255]++] = a[i];
    memcpy(a, buf, n * 4);
    size_t start = 0;
    for (int k = 0; k < 256; k++) {
        size_t len = cnt[k] - start;
        msd_rec(a + start, len, shift - 8, buf + start);
        start = cnt[k];
    }
}
TAG(rx_msd_recursive);
void rx_msd_recursive(uint32_t *a, size_t n) {
    MARK(rx_msd_recursive);
    uint32_t *buf = (uint32_t *)malloc(n * 4);
    msd_rec(a, n, 24, buf);
    free(buf);
}
TAG(rx_msd_iterative);
void rx_msd_iterative(uint32_t *a, size_t n) {
    MARK(rx_msd_iterative);
    uint32_t *buf = (uint32_t *)malloc(n * 4);
    size_t lo[40], hi[40], sh[40], sp = 0;
    lo[sp] = 0; hi[sp] = n; sh[sp] = 24; sp++;
    while (sp > 0) {
        sp--;
        size_t l = lo[sp], h = hi[sp]; int s = (int)sh[sp];
        if (h - l <= 1 || s < 0) continue;
        size_t cnt[256] = {0};
        for (size_t i = l; i < h; i++) cnt[(a[i] >> s) & 255]++;
        size_t sum = l;
        for (int k = 0; k < 256; k++) { size_t c = cnt[k]; cnt[k] = sum; sum += c; }
        for (size_t i = l; i < h; i++) buf[cnt[(a[i] >> s) & 255]++] = a[i];
        memcpy(a + l, buf + l, (h - l) * 4);
        size_t start = l;
        for (int k = 0; k < 256; k++) {
            size_t end = cnt[k];
            if (end > start) {
                lo[sp] = start; hi[sp] = end; sh[sp] = (size_t)(s - 8); sp++;
            }
            start = end;
        }
    }
    free(buf);
}
TAG(rx_counting);
void rx_counting(uint32_t *a, size_t n, uint32_t maxv) {
    MARK(rx_counting);
    size_t *cnt = (size_t *)calloc(maxv + 1, sizeof(size_t));
    for (size_t i = 0; i < n; i++) cnt[a[i]]++;
    size_t k = 0;
    for (uint32_t v = 0; v <= maxv; v++)
        for (size_t j = 0; j < cnt[v]; j++) a[k++] = v;
    free(cnt);
}
TAG(rx_inplace);
void rx_inplace(uint32_t *a, size_t n) {
    MARK(rx_inplace);
    /* American-flag-ish in-place MSD on top byte */
    size_t cnt[256] = {0};
    for (size_t i = 0; i < n; i++) cnt[(a[i] >> 24) & 255]++;
    size_t pos[256], sum = 0;
    for (int k = 0; k < 256; k++) { pos[k] = sum; sum += cnt[k]; }
    size_t *cur = (size_t *)memcpy(malloc(256 * 8), pos, 256 * 8);
    for (int k = 0; k < 256; k++) {
        size_t i = cur[k];
        while (i < pos[k] + cnt[k]) {
            uint32_t v = a[i];
            int b = (v >> 24) & 255;
            if (b != k) { a[i] = a[cur[b]]; a[cur[b]++] = v; }
            else i++;
        }
        cur[k] = i;
    }
    for (int k = 0; k < 256; k++) {
        if (cnt[k] > 1) rx_lsd_base256(a + pos[k], cnt[k]);
    }
    free(cur);
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)rx_lsd_base2,     (variant_fn)rx_lsd_base16,
    (variant_fn)rx_lsd_base256,   (variant_fn)rx_lsd_base65536,
    (variant_fn)rx_signed,        (variant_fn)rx_u64,
    (variant_fn)rx_msd_recursive, (variant_fn)rx_msd_iterative,
    (variant_fn)rx_counting,      (variant_fn)rx_inplace,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

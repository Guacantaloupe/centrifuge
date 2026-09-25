/* 08. Linear Search family. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

static int g_arr[64];

TAG(ls_basic);
int ls_basic(const int *a, int n, int key) {
    MARK(ls_basic);
    for (int i = 0; i < n; i++) if (a[i] == key) return i;
    return -1;
}
TAG(ls_pointer_walk);
int ls_pointer_walk(const int *begin, const int *end, int key) {
    MARK(ls_pointer_walk);
    for (const int *p = begin; p < end; p++) if (*p == key) return (int)(p - begin);
    return -1;
}
TAG(ls_sentinel);
int ls_sentinel(int *a, int n, int key) {
    MARK(ls_sentinel);
    int last = a[n - 1];
    a[n - 1] = key;
    int i = 0;
    while (a[i] != key) i++;
    a[n - 1] = last;
    if (i < n - 1 || last == key) return i;
    return -1;
}
TAG(ls_unroll2);
int ls_unroll2(const int *a, int n, int key) {
    MARK(ls_unroll2);
    int i = 0;
    for (; i + 2 <= n; i += 2) {
        if (a[i] == key) return i;
        if (a[i + 1] == key) return i + 1;
    }
    for (; i < n; i++) if (a[i] == key) return i;
    return -1;
}
TAG(ls_unroll4);
int ls_unroll4(const int *a, int n, int key) {
    MARK(ls_unroll4);
    int i = 0;
    for (; i + 4 <= n; i += 4) {
        if (a[i] == key) return i;
        if (a[i + 1] == key) return i + 1;
        if (a[i + 2] == key) return i + 2;
        if (a[i + 3] == key) return i + 3;
    }
    for (; i < n; i++) if (a[i] == key) return i;
    return -1;
}
TAG(ls_unroll8);
int ls_unroll8(const int *a, int n, int key) {
    MARK(ls_unroll8);
    int i = 0;
    for (; i + 8 <= n; i += 8) {
        for (int j = 0; j < 8; j++) if (a[i + j] == key) return i + j;
    }
    for (; i < n; i++) if (a[i] == key) return i;
    return -1;
}
TAG(ls_simd_friendly);
int ls_simd_friendly(const int *a, int n, int key) {
    MARK(ls_simd_friendly);
    int i = 0, sums[4] = {0, 0, 0, 0};
    for (; i + 4 <= n; i += 4) {
        sums[0] += a[i] == key;
        sums[1] += a[i + 1] == key;
        sums[2] += a[i + 2] == key;
        sums[3] += a[i + 3] == key;
    }
    int hit = sums[0] + sums[1] + sums[2] + sums[3];
    for (; i < n; i++) hit += a[i] == key;
    return hit;
}
struct ls_rec { int id; int value; };
TAG(ls_struct);
int ls_struct(const struct ls_rec *a, int n, int id) {
    MARK(ls_struct);
    for (int i = 0; i < n; i++) if (a[i].id == id) return a[i].value;
    return -1;
}
typedef int (*ls_pred)(int);
TAG(ls_callback);
int ls_callback(const int *a, int n, ls_pred pred) {
    MARK(ls_callback);
    for (int i = 0; i < n; i++) if (pred(a[i])) return i;
    return -1;
}
static int pred_pos(int v) { return v > 0; }
TAG(ls_pred_entry);
int ls_pred_entry(const int *a, int n) {
    MARK(ls_pred_entry);
    return ls_callback(a, n, pred_pos);
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)ls_basic,       (variant_fn)ls_pointer_walk,
    (variant_fn)ls_sentinel,    (variant_fn)ls_unroll2,
    (variant_fn)ls_unroll4,     (variant_fn)ls_unroll8,
    (variant_fn)ls_simd_friendly,(variant_fn)ls_struct,
    (variant_fn)ls_pred_entry,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return g_arr[0] & 0;
}

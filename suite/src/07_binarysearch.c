/* 07. Binary Search family. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

static int g_sorted[64];

TAG(bs_classic);
int bs_classic(const int *a, int n, int key) {
    MARK(bs_classic);
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int m = (lo + hi) / 2;
        if (a[m] == key) return m;
        if (a[m] < key) lo = m + 1; else hi = m - 1;
    }
    return -1;
}
TAG(bs_halfopen);
int bs_halfopen(const int *a, int n, int key) {
    MARK(bs_halfopen);
    int lo = 0, hi = n;
    while (lo < hi) {
        int m = (lo + hi) / 2;
        if (a[m] < key) lo = m + 1; else hi = m;
    }
    return lo < n && a[lo] == key ? lo : -1;
}
TAG(bs_pointer);
int bs_pointer(const int *begin, const int *end, int key) {
    MARK(bs_pointer);
    while (begin < end) {
        const int *m = begin + (end - begin) / 2;
        if (*m < key) begin = m + 1; else end = m;
    }
    return begin < end || *begin == key ? (int)(begin - (const int *)0) : -1;
}
TAG(bs_recursive);
int bs_recursive(const int *a, int lo, int hi, int key) {
    MARK(bs_recursive);
    if (lo > hi) return -1;
    int m = (lo + hi) / 2;
    if (a[m] == key) return m;
    if (a[m] < key) return bs_recursive(a, m + 1, hi, key);
    return bs_recursive(a, lo, m - 1, key);
}
TAG(bs_iterative);
int bs_iterative(const int *a, int n, int key) {
    MARK(bs_iterative);
    return bs_classic(a, n, key);
}
TAG(bs_branchless);
int bs_branchless(const int *a, int n, int key) {
    MARK(bs_branchless);
    int pos = 0, len = n;
    while (len > 1) {
        int half = len / 2;
        pos += (a[pos + half - 1] < key) ? half : 0;
        len -= half;
    }
    return a[pos] == key ? pos : -1;
}
TAG(bs_lower_bound);
int bs_lower_bound(const int *a, int n, int key) {
    MARK(bs_lower_bound);
    int lo = 0, hi = n;
    while (lo < hi) {
        int m = (lo + hi) / 2;
        if (a[m] < key) lo = m + 1; else hi = m;
    }
    return lo;
}
TAG(bs_upper_bound);
int bs_upper_bound(const int *a, int n, int key) {
    MARK(bs_upper_bound);
    int lo = 0, hi = n;
    while (lo < hi) {
        int m = (lo + hi) / 2;
        if (a[m] <= key) lo = m + 1; else hi = m;
    }
    return lo;
}
TAG(bs_equal_range);
int bs_equal_range(const int *a, int n, int key) {
    MARK(bs_equal_range);
    int lo = 0, hi = n;
    while (lo < hi) {
        int m = (lo + hi) / 2;
        if (a[m] < key) lo = m + 1; else hi = m;
    }
    int first = lo;
    hi = n;
    while (lo < hi) {
        int m = (lo + hi) / 2;
        if (a[m] <= key) lo = m + 1; else hi = m;
    }
    return lo - first;
}
TAG(bs_first_occurrence);
int bs_first_occurrence(const int *a, int n, int key) {
    MARK(bs_first_occurrence);
    int i = bs_lower_bound(a, n, key);
    return i < n && a[i] == key ? i : -1;
}
TAG(bs_last_occurrence);
int bs_last_occurrence(const int *a, int n, int key) {
    MARK(bs_last_occurrence);
    int i = bs_upper_bound(a, n, key) - 1;
    return i >= 0 && a[i] == key ? i : -1;
}
TAG(bs_descending);
int bs_descending(const int *a, int n, int key) {
    MARK(bs_descending);
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int m = (lo + hi) / 2;
        if (a[m] == key) return m;
        if (a[m] > key) lo = m + 1; else hi = m - 1;
    }
    return -1;
}
typedef int (*bs_cmp)(int, int);
static int bs_run_cmp(const int *a, int n, int key, bs_cmp cmp) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int m = (lo + hi) / 2, c = cmp(a[m], key);
        if (c == 0) return m;
        if (c < 0) lo = m + 1; else hi = m - 1;
    }
    return -1;
}
static int cmp_int(int x, int y) { return x < y ? -1 : x > y; }
TAG(bs_cmp_fnptr);
int bs_cmp_fnptr(const int *a, int n, int key) {
    MARK(bs_cmp_fnptr);
    return bs_run_cmp(a, n, key, cmp_int);
}
TAG(bs_overflow_safe);
int bs_overflow_safe(const int *a, int lo, int hi, int key) {
    MARK(bs_overflow_safe);
    while (lo < hi) {
        int m = lo + (hi - lo) / 2;
        if (a[m] < key) lo = m + 1; else hi = m;
    }
    return a[lo] == key ? lo : -1;
}
TAG(bs_overflow_prone);
int bs_overflow_prone(const int *a, int lo, int hi, int key) {
    MARK(bs_overflow_prone);
    while (lo < hi) {
        int m = (lo + hi) >> 1;
        if (a[m] < key) lo = m + 1; else hi = m;
    }
    return a[lo] == key ? lo : -1;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)bs_classic,        (variant_fn)bs_halfopen,
    (variant_fn)bs_pointer,        (variant_fn)bs_recursive,
    (variant_fn)bs_iterative,      (variant_fn)bs_branchless,
    (variant_fn)bs_lower_bound,    (variant_fn)bs_upper_bound,
    (variant_fn)bs_equal_range,    (variant_fn)bs_first_occurrence,
    (variant_fn)bs_last_occurrence,(variant_fn)bs_descending,
    (variant_fn)bs_cmp_fnptr,      (variant_fn)bs_overflow_safe,
    (variant_fn)bs_overflow_prone,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return g_sorted[0] & 0;
}

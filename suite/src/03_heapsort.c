/* 03. HeapSort family. */
#include <stddef.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(hs_recursive_heapify);
static void hs_rec_sift(int *a, int n, int i) {
    int l = 2 * i + 1, r = 2 * i + 2, big = i;
    if (l < n && a[l] > a[big]) big = l;
    if (r < n && a[r] > a[big]) big = r;
    if (big != i) {
        int t = a[i]; a[i] = a[big]; a[big] = t;
        hs_rec_sift(a, n, big);
    }
}
void hs_recursive_heapify(int *a, int n) {
    MARK(hs_recursive_heapify);
    for (int i = n / 2 - 1; i >= 0; i--) hs_rec_sift(a, n, i);
    for (int i = n - 1; i > 0; i--) {
        int t = a[0]; a[0] = a[i]; a[i] = t;
        hs_rec_sift(a, i, 0);
    }
}

TAG(hs_iterative_heapify);
void hs_iterative_heapify(int *a, int n) {
    MARK(hs_iterative_heapify);
    for (int i = n / 2 - 1; i >= 0; i--) {
        int root = i;
        for (;;) {
            int l = 2 * root + 1;
            if (l >= n) break;
            int big = l, r = l + 1;
            if (r < n && a[r] > a[l]) big = r;
            if (a[root] >= a[big]) break;
            int t = a[root]; a[root] = a[big]; a[big] = t;
            root = big;
        }
    }
    for (int i = n - 1; i > 0; i--) {
        int t = a[0]; a[0] = a[i]; a[i] = t;
        int root = 0;
        for (;;) {
            int l = 2 * root + 1;
            if (l >= i) break;
            int big = l, r = l + 1;
            if (r < i && a[r] > a[l]) big = r;
            if (a[root] >= a[big]) break;
            t = a[root]; a[root] = a[big]; a[big] = t;
            root = big;
        }
    }
}

TAG(hs_zero_based);
void hs_zero_based(int *a, int n) { MARK(hs_zero_based); hs_iterative_heapify(a, n); }

TAG(hs_one_based);
void hs_one_based(int *a, int n) {
    MARK(hs_one_based);
    /* shift conceptual indices by +1: children of i are 2i, 2i+1 */
    for (int i = n / 2; i >= 1; i--) {
        int v = a[i - 1], k = i;
        for (;;) {
            int j = 2 * k;
            if (j > n) break;
            if (j < n && a[j - 1] > a[j]) j++;
            if (v >= a[j - 1]) break;
            a[k - 1] = a[j - 1];
            k = j;
        }
        a[k - 1] = v;
    }
    for (int i = n; i > 1; i--) {
        int t = a[0]; a[0] = a[i - 1]; a[i - 1] = t;
        int v = a[0], k = 1, lim = i - 1;
        for (;;) {
            int j = 2 * k;
            if (j > lim) break;
            if (j < lim && a[j - 1] > a[j]) j++;
            if (v >= a[j - 1]) break;
            a[k - 1] = a[j - 1];
            k = j;
        }
        a[k - 1] = v;
    }
}

typedef int (*heap_cmp)(int, int);
static void sift_cmp(int *a, int n, int i, heap_cmp cmp) {
    for (;;) {
        int l = 2 * i + 1, r = l + 1, m = i;
        if (l < n && cmp(a[l], a[m]) > 0) m = l;
        if (r < n && cmp(a[r], a[m]) > 0) m = r;
        if (m == i) break;
        int t = a[i]; a[i] = a[m]; a[m] = t;
        i = m;
    }
}
static int cmp_max(int x, int y) { return x < y ? -1 : x > y; }
static int cmp_min(int x, int y) { return x > y ? -1 : x < y; }
TAG(hs_min_heap);
void hs_min_heap(int *a, int n) {
    MARK(hs_min_heap);
    for (int i = n / 2 - 1; i >= 0; i--) sift_cmp(a, n, i, cmp_min);
    for (int i = n - 1; i > 0; i--) {
        int t = a[0]; a[0] = a[i]; a[i] = t;
        sift_cmp(a, i, 0, cmp_min);
    }
}
TAG(hs_max_heap);
void hs_max_heap(int *a, int n) {
    MARK(hs_max_heap);
    for (int i = n / 2 - 1; i >= 0; i--) sift_cmp(a, n, i, cmp_max);
    for (int i = n - 1; i > 0; i--) {
        int t = a[0]; a[0] = a[i]; a[i] = t;
        sift_cmp(a, i, 0, cmp_max);
    }
}

TAG(hs_pointer);
void hs_pointer(int *begin, int *end) {
    MARK(hs_pointer);
    int n = (int)(end - begin);
    for (int i = n / 2 - 1; i >= 0; i--) {
        int *root = begin + i;
        for (;;) {
            int *l = begin + 2 * (int)(root - begin) + 1;
            if (l >= end) break;
            int *big = l, *r = l + 1;
            if (r < end && *r > *l) big = r;
            if (*root >= *big) break;
            int t = *root; *root = *big; *big = t;
            root = big;
        }
    }
    for (int *last = end - 1; last > begin; last--) {
        int t = *begin; *begin = *last; *last = t;
        int *root = begin;
        for (;;) {
            int *l = begin + 2 * (int)(root - begin) + 1;
            if (l >= last) break;
            int *big = l, *r = l + 1;
            if (r < last && *r > *l) big = r;
            if (*root >= *big) break;
            t = *root; *root = *big; *big = t;
            root = big;
        }
    }
}

TAG(hs_branch_reduced);
void hs_branch_reduced(int *a, int n) {
    MARK(hs_branch_reduced);
    /* sift-down with branchless child select */
    for (int i = n / 2 - 1; i >= 0; i--) {
        int root = i;
        for (;;) {
            int l = 2 * root + 1;
            if (l >= n) break;
            int r = l + 1;
            int big = (r < n && a[r] > a[l]) ? r : l;
            int go = a[big] > a[root];
            int t = a[root];
            a[root] = go ? a[big] : a[root];
            a[big] = go ? t : a[big];
            if (!go) break;
            root = big;
        }
    }
    for (int i = n - 1; i > 0; i--) {
        int t = a[0]; a[0] = a[i]; a[i] = t;
        int root = 0;
        for (;;) {
            int l = 2 * root + 1;
            if (l >= i) break;
            int r = l + 1;
            int big = (r < i && a[r] > a[l]) ? r : l;
            int go = a[big] > a[root];
            t = a[root];
            a[root] = go ? a[big] : a[root];
            a[big] = go ? t : a[big];
            if (!go) break;
            root = big;
        }
    }
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)hs_recursive_heapify, (variant_fn)hs_iterative_heapify,
    (variant_fn)hs_zero_based,        (variant_fn)hs_one_based,
    (variant_fn)hs_min_heap,          (variant_fn)hs_max_heap,
    (variant_fn)hs_pointer,           (variant_fn)hs_branch_reduced,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

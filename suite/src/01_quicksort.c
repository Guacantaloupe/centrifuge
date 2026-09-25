/* 01. QuickSort family — C variants V01-V06(partial)/V08/V09/V10.
 * Every variant is a separate symbol; main references all via a volatile
 * table so linkers keep them (ICF/OPT:REF) and Centrifuge sees them all. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

static int g_arr[64];
static int g_len = 16;

/* ---------- V01 Recursive + Lomuto ---------- */
TAG(v01_lomuto_int);
void v01_lomuto_int(int *a, int lo, int hi) {
    MARK(v01_lomuto_int);
    if (lo >= hi) return;
    int pivot = a[hi], i = lo;
    for (int j = lo; j < hi; j++)
        if (a[j] < pivot) { int t = a[i]; a[i] = a[j]; a[j] = t; i++; }
    int t = a[i]; a[i] = a[hi]; a[hi] = t;
    v01_lomuto_int(a, lo, i - 1);
    v01_lomuto_int(a, i + 1, hi);
}

TAG(v01_lomuto_unsigned);
void v01_lomuto_unsigned(int *a, unsigned lo, unsigned hi) {
    MARK(v01_lomuto_unsigned);
    if (lo >= hi) return;
    int pivot = a[hi]; unsigned i = lo;
    for (unsigned j = lo; j < hi; j++)
        if (a[j] < pivot) { int t = a[i]; a[i] = a[j]; a[j] = t; i++; }
    int t = a[i]; a[i] = a[hi]; a[hi] = t;
    if (i > 0) v01_lomuto_unsigned(a, lo, i - 1);
    v01_lomuto_unsigned(a, i + 1, hi);
}

TAG(v01_lomuto_sizet);
void v01_lomuto_sizet(int *a, size_t lo, size_t hi) {
    MARK(v01_lomuto_sizet);
    if (lo >= hi) return;
    int pivot = a[hi]; size_t i = lo;
    for (size_t j = lo; j < hi; j++)
        if (a[j] < pivot) { int t = a[i]; a[i] = a[j]; a[j] = t; i++; }
    int t = a[i]; a[i] = a[hi]; a[hi] = t;
    if (i > 0) v01_lomuto_sizet(a, lo, i - 1);
    v01_lomuto_sizet(a, i + 1, hi);
}

TAG(v01_lomuto_ptr);
void v01_lomuto_ptr(int *begin, int *end) {
    MARK(v01_lomuto_ptr);
    if (end - begin <= 1) return;
    int *last = end - 1, pivot = *last, *i = begin;
    for (int *j = begin; j < last; j++)
        if (*j < pivot) { int t = *i; *i = *j; *j = t; i++; }
    int t = *i; *i = *last; *last = t;
    v01_lomuto_ptr(begin, i);
    v01_lomuto_ptr(i + 1, end);
}

/* ---------- V02 Recursive + Hoare ---------- */
static void hoare_run(int *a, int lo, int hi, int mode) {
    if (lo >= hi) return;
    int p;
    if (mode == 0) p = a[lo];
    else if (mode == 1) p = a[(lo + hi) / 2];
    else if (mode == 2) p = a[hi];
    else {
        int x = a[lo], y = a[(lo + hi) / 2], z = a[hi];
        p = x < y ? (y < z ? y : (x < z ? z : x))
                  : (x < z ? x : (y < z ? z : y));
    }
    int i = lo, j = hi;
    for (;;) {
        while (a[i] < p) i++;
        while (a[j] > p) j--;
        if (i >= j) break;
        int t = a[i]; a[i] = a[j]; a[j] = t;
        i++; j--;
    }
    hoare_run(a, lo, j, mode);
    hoare_run(a, j + 1, hi, mode);
}
TAG(v02_hoare_first);
void v02_hoare_first(int *a, int n) { MARK(v02_hoare_first); hoare_run(a, 0, n - 1, 0); }
TAG(v02_hoare_middle);
void v02_hoare_middle(int *a, int n) { MARK(v02_hoare_middle); hoare_run(a, 0, n - 1, 1); }
TAG(v02_hoare_last);
void v02_hoare_last(int *a, int n) { MARK(v02_hoare_last); hoare_run(a, 0, n - 1, 2); }
TAG(v02_hoare_median3);
void v02_hoare_median3(int *a, int n) { MARK(v02_hoare_median3); hoare_run(a, 0, n - 1, 3); }

/* ---------- V03 Tail-recursive ---------- */
TAG(v03_tail_left);
void v03_tail_left(int *a, int lo, int hi) {
    MARK(v03_tail_left);
    while (lo < hi) {
        int pivot = a[hi], i = lo;
        for (int j = lo; j < hi; j++)
            if (a[j] < pivot) { int t = a[i]; a[i] = a[j]; a[j] = t; i++; }
        int t = a[i]; a[i] = a[hi]; a[hi] = t;
        v03_tail_left(a, lo, i - 1);
        lo = i + 1;
    }
}
TAG(v03_tail_right);
void v03_tail_right(int *a, int lo, int hi) {
    MARK(v03_tail_right);
    while (lo < hi) {
        int pivot = a[lo], j = hi;
        for (int i = hi; i > lo; i--)
            if (a[i] > pivot) { int t = a[j]; a[j] = a[i]; a[i] = t; j--; }
        int t = a[j]; a[j] = a[lo]; a[lo] = t;
        v03_tail_right(a, j + 1, hi);
        hi = j - 1;
    }
}
TAG(v03_tail_smaller);
void v03_tail_smaller(int *a, int lo, int hi) {
    MARK(v03_tail_smaller);
    while (lo < hi) {
        int pivot = a[hi], i = lo;
        for (int j = lo; j < hi; j++)
            if (a[j] < pivot) { int t = a[i]; a[i] = a[j]; a[j] = t; i++; }
        int t = a[i]; a[i] = a[hi]; a[hi] = t;
        if (i - lo < hi - i) { v03_tail_smaller(a, lo, i - 1); lo = i + 1; }
        else { v03_tail_smaller(a, i + 1, hi); hi = i - 1; }
    }
}

/* ---------- V04 Iterative ---------- */
TAG(v04_iter_fixed);
void v04_iter_fixed(int *a, int n) {
    MARK(v04_iter_fixed);
    int stack_lo[64], stack_hi[64], sp = 0;
    stack_lo[sp] = 0; stack_hi[sp] = n - 1; sp++;
    while (sp > 0) {
        sp--;
        int lo = stack_lo[sp], hi = stack_hi[sp];
        if (lo >= hi) continue;
        int pivot = a[hi], i = lo;
        for (int j = lo; j < hi; j++)
            if (a[j] < pivot) { int t = a[i]; a[i] = a[j]; a[j] = t; i++; }
        int t = a[i]; a[i] = a[hi]; a[hi] = t;
        stack_lo[sp] = lo; stack_hi[sp] = i - 1; sp++;
        stack_lo[sp] = i + 1; stack_hi[sp] = hi; sp++;
    }
}
TAG(v04_iter_dynamic);
void v04_iter_dynamic(int *a, int n) {
    MARK(v04_iter_dynamic);
    int *st = (int *)malloc(2 * (size_t)n * sizeof(int));
    int sp = 0;
    st[sp] = 0; st[sp + 1] = n - 1; sp += 2;
    while (sp > 0) {
        sp -= 2;
        int lo = st[sp], hi = st[sp + 1];
        if (lo >= hi) continue;
        int pivot = a[hi], i = lo;
        for (int j = lo; j < hi; j++)
            if (a[j] < pivot) { int t = a[i]; a[i] = a[j]; a[j] = t; i++; }
        int t = a[i]; a[i] = a[hi]; a[hi] = t;
        st[sp] = lo; st[sp + 1] = i - 1; sp += 2;
        st[sp] = i + 1; st[sp + 1] = hi; sp += 2;
    }
    free(st);
}

/* ---------- V05 Hybrid (insertion cutoff) ---------- */
static void insertion_span(int *a, int lo, int hi) {
    for (int i = lo + 1; i <= hi; i++) {
        int key = a[i], j = i - 1;
        while (j >= lo && a[j] > key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
}
static void hybrid_run(int *a, int lo, int hi, int cutoff) {
    if (hi - lo + 1 <= cutoff) { insertion_span(a, lo, hi); return; }
    int pivot = a[hi], i = lo;
    for (int j = lo; j < hi; j++)
        if (a[j] < pivot) { int t = a[i]; a[i] = a[j]; a[j] = t; i++; }
    int t = a[i]; a[i] = a[hi]; a[hi] = t;
    hybrid_run(a, lo, i - 1, cutoff);
    hybrid_run(a, i + 1, hi, cutoff);
}
TAG(v05_hybrid_4);
void v05_hybrid_4(int *a, int n) { MARK(v05_hybrid_4); hybrid_run(a, 0, n - 1, 4); }
TAG(v05_hybrid_8);
void v05_hybrid_8(int *a, int n) { MARK(v05_hybrid_8); hybrid_run(a, 0, n - 1, 8); }
TAG(v05_hybrid_16);
void v05_hybrid_16(int *a, int n) { MARK(v05_hybrid_16); hybrid_run(a, 0, n - 1, 16); }
TAG(v05_hybrid_32);
void v05_hybrid_32(int *a, int n) { MARK(v05_hybrid_32); hybrid_run(a, 0, n - 1, 32); }

/* ---------- V06 Comparator (C subset) ---------- */
TAG(v06_direct);
void v06_direct(int *a, int n) {
    MARK(v06_direct);
    if (n <= 1) return;
    int pivot = a[n - 1], i = 0;
    for (int j = 0; j < n - 1; j++)
        if (a[j] < pivot) { int t = a[i]; a[i] = a[j]; a[j] = t; i++; }
    int t = a[i]; a[i] = a[n - 1]; a[n - 1] = t;
    v06_direct(a, i);
    v06_direct(a + i + 1, n - i - 1);
}
typedef int (*cmp_fn)(int, int);
static void cmp_run(int *a, int lo, int hi, cmp_fn cmp) {
    if (lo >= hi) return;
    int pivot = a[hi], i = lo;
    for (int j = lo; j < hi; j++)
        if (cmp(a[j], pivot) < 0) { int t = a[i]; a[i] = a[j]; a[j] = t; i++; }
    int t = a[i]; a[i] = a[hi]; a[hi] = t;
    cmp_run(a, lo, i - 1, cmp);
    cmp_run(a, i + 1, hi, cmp);
}
static int cmp_asc(int x, int y) { return x < y ? -1 : x > y; }
TAG(v06_fnptr);
void v06_fnptr(int *a, int n) { MARK(v06_fnptr); cmp_run(a, 0, n - 1, cmp_asc); }
typedef int (*cb_cmp)(const void *x, const void *y, void *ctx);
static void cb_run(void *base, size_t n, size_t size, cb_cmp cmp, void *ctx) {
    if (n <= 1) return;
    char *a = (char *)base;
    size_t i = 0;
    for (size_t j = 0; j < n - 1; j++)
        if (cmp(a + j * size, a + (n - 1) * size, ctx) < 0) {
            for (size_t k = 0; k < size; k++) {
                char t = a[i * size + k]; a[i * size + k] = a[j * size + k];
                a[j * size + k] = t;
            }
            i++;
        }
    for (size_t k = 0; k < size; k++) {
        char t = a[i * size + k]; a[i * size + k] = a[(n - 1) * size + k];
        a[(n - 1) * size + k] = t;
    }
    cb_run(a, i, size, cmp, ctx);
    cb_run(a + (i + 1) * size, n - i - 1, size, cmp, ctx);
}
static int cb_asc(const void *x, const void *y, void *ctx) {
    (void)ctx;
    int a = *(const int *)x, b = *(const int *)y;
    return a < b ? -1 : a > b;
}
TAG(v06_callback);
void v06_callback(int *a, size_t n) { MARK(v06_callback); cb_run(a, n, sizeof(int), cb_asc, 0); }

/* ---------- V08 Branch variants ---------- */
TAG(v08_branchless);
void v08_branchless(int *a, int n) {
    MARK(v08_branchless);
    if (n <= 1) return;
    int pivot = a[n - 1], i = 0;
    for (int j = 0; j < n - 1; j++) {
        int less = a[j] < pivot;
        int t = a[i];
        a[i] = less ? a[j] : a[i];
        a[j] = less ? t : a[j];
        i += less;
    }
    int t = a[i]; a[i] = a[n - 1]; a[n - 1] = t;
    v08_branchless(a, i);
    v08_branchless(a + i + 1, n - i - 1);
}
TAG(v08_cmov);
void v08_cmov(int *a, int n) {
    MARK(v08_cmov);
    for (int i = 1; i < n; i++) {
        int key = a[i], j = i - 1;
        while (j >= 0) {
            int mv = a[j] > key;
            a[j + 1] = mv ? a[j] : a[j + 1];
            if (!mv) break;
            j--;
        }
        a[j + 1] = key;
    }
}

/* ---------- V09 Data types ---------- */
TAG(v09_int32);
void v09_int32(int32_t *a, int n) {
    MARK(v09_int32);
    for (int i = 1; i < n; i++) {
        int32_t key = a[i]; int j = i - 1;
        while (j >= 0 && a[j] > key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
}
TAG(v09_uint32);
void v09_uint32(uint32_t *a, int n) {
    MARK(v09_uint32);
    for (int i = 1; i < n; i++) {
        uint32_t key = a[i]; int j = i - 1;
        while (j >= 0 && a[j] > key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
}
TAG(v09_int64);
void v09_int64(int64_t *a, int n) {
    MARK(v09_int64);
    for (int i = 1; i < n; i++) {
        int64_t key = a[i]; int j = i - 1;
        while (j >= 0 && a[j] > key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
}
TAG(v09_float);
void v09_float(float *a, int n) {
    MARK(v09_float);
    for (int i = 1; i < n; i++) {
        float key = a[i]; int j = i - 1;
        while (j >= 0 && a[j] > key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
}
struct rec09 { int key; int payload; };
TAG(v09_struct_key);
void v09_struct_key(struct rec09 *a, int n) {
    MARK(v09_struct_key);
    for (int i = 1; i < n; i++) {
        struct rec09 key = a[i]; int j = i - 1;
        while (j >= 0 && a[j].key > key.key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
}
TAG(v09_ptr_to_struct);
void v09_ptr_to_struct(struct rec09 **a, int n) {
    MARK(v09_ptr_to_struct);
    for (int i = 1; i < n; i++) {
        struct rec09 *key = a[i]; int j = i - 1;
        while (j >= 0 && a[j]->key > key->key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
}

/* ---------- V10 Pathological ---------- */
TAG(v10_dups);
void v10_dups(int *a, int n) {
    MARK(v10_dups);
    if (n <= 1) return;
    int pivot = a[n / 2], i = 0, j = n - 1;
    for (;;) {
        while (a[i] < pivot) i++;
        while (a[j] > pivot) j--;
        if (i >= j) break;
        int t = a[i]; a[i] = a[j]; a[j] = t;
        i++; j--;
    }
    v10_dups(a, i);
    v10_dups(a + i, n - i);
}
TAG(v10_sorted);
void v10_sorted(int *a, int lo, int hi) {
    MARK(v10_sorted);
    if (lo >= hi) return;
    int m = (lo + hi) / 2, pivot = a[m], i = lo, j = hi;
    for (;;) {
        while (a[i] < pivot) i++;
        while (a[j] > pivot) j--;
        if (i >= j) break;
        int t = a[i]; a[i] = a[j]; a[j] = t;
        i++; j--;
    }
    v10_sorted(a, lo, j);
    v10_sorted(a, j + 1, hi);
}
TAG(v10_reverse);
void v10_reverse(int *a, int lo, int hi) {
    MARK(v10_reverse);
    while (lo < hi) {
        int t = a[lo]; a[lo] = a[hi]; a[hi] = t;
        lo++; hi--;
    }
}
TAG(v10_all_equal);
int v10_all_equal(const int *a, int n) {
    MARK(v10_all_equal);
    for (int i = 1; i < n; i++)
        if (a[i] != a[0]) return 0;
    return 1;
}
TAG(v10_three_way);
void v10_three_way(int *a, int n) {
    MARK(v10_three_way);
    if (n <= 1) return;
    int pivot = a[n - 1], lt = 0, i = 0, gt = n;
    while (i < gt) {
        if (a[i] < pivot) { int t = a[lt]; a[lt] = a[i]; a[i] = t; lt++; i++; }
        else if (a[i] > pivot) { gt--; int t = a[gt]; a[gt] = a[i]; a[i] = t; }
        else i++;
    }
    v10_three_way(a, lt);
    v10_three_way(a + gt, n - gt);
}

/* ---------- keep-all dispatch ---------- */
typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)v01_lomuto_int,   (variant_fn)v01_lomuto_unsigned,
    (variant_fn)v01_lomuto_sizet, (variant_fn)v01_lomuto_ptr,
    (variant_fn)v02_hoare_first,  (variant_fn)v02_hoare_middle,
    (variant_fn)v02_hoare_last,   (variant_fn)v02_hoare_median3,
    (variant_fn)v03_tail_left,    (variant_fn)v03_tail_right,
    (variant_fn)v03_tail_smaller, (variant_fn)v04_iter_fixed,
    (variant_fn)v04_iter_dynamic, (variant_fn)v05_hybrid_4,
    (variant_fn)v05_hybrid_8,     (variant_fn)v05_hybrid_16,
    (variant_fn)v05_hybrid_32,    (variant_fn)v06_direct,
    (variant_fn)v06_fnptr,        (variant_fn)v06_callback,
    (variant_fn)v08_branchless,   (variant_fn)v08_cmov,
    (variant_fn)v09_int32,        (variant_fn)v09_uint32,
    (variant_fn)v09_int64,        (variant_fn)v09_float,
    (variant_fn)v09_struct_key,   (variant_fn)v09_ptr_to_struct,
    (variant_fn)v10_dups,         (variant_fn)v10_sorted,
    (variant_fn)v10_reverse,      (variant_fn)v10_all_equal,
    (variant_fn)v10_three_way,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (unsigned i = 0; i < g_len; i++) g_arr[i] = (int)(g_len - i);
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++) {
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    }
    (void)sink;
    return (int)g_arr[0] & 1;
}

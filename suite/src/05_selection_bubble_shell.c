/* 05. Selection / Bubble / Shell family. */
#include <stddef.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(sel_min);
void sel_min(int *a, int n) {
    MARK(sel_min);
    for (int i = 0; i < n - 1; i++) {
        int m = i;
        for (int j = i + 1; j < n; j++) if (a[j] < a[m]) m = j;
        int t = a[i]; a[i] = a[m]; a[m] = t;
    }
}
TAG(sel_max);
void sel_max(int *a, int n) {
    MARK(sel_max);
    for (int i = n - 1; i > 0; i--) {
        int m = 0;
        for (int j = 1; j <= i; j++) if (a[j] > a[m]) m = j;
        int t = a[i]; a[i] = a[m]; a[m] = t;
    }
}
TAG(sel_bidirectional);
void sel_bidirectional(int *a, int n) {
    MARK(sel_bidirectional);
    int lo = 0, hi = n - 1;
    while (lo < hi) {
        int mn = lo, mx = lo;
        for (int i = lo; i <= hi; i++) {
            if (a[i] < a[mn]) mn = i;
            if (a[i] > a[mx]) mx = i;
        }
        int t = a[lo]; a[lo] = a[mn]; a[mn] = t;
        if (mx == lo) mx = mn;
        t = a[hi]; a[hi] = a[mx]; a[mx] = t;
        lo++; hi--;
    }
}
TAG(bub_basic);
void bub_basic(int *a, int n) {
    MARK(bub_basic);
    for (int i = 0; i < n - 1; i++)
        for (int j = 0; j < n - 1 - i; j++)
            if (a[j] > a[j + 1]) { int t = a[j]; a[j] = a[j + 1]; a[j + 1] = t; }
}
TAG(bub_early_exit);
void bub_early_exit(int *a, int n) {
    MARK(bub_early_exit);
    for (int i = 0; i < n - 1; i++) {
        int swapped = 0;
        for (int j = 0; j < n - 1 - i; j++)
            if (a[j] > a[j + 1]) {
                int t = a[j]; a[j] = a[j + 1]; a[j + 1] = t;
                swapped = 1;
            }
        if (!swapped) break;
    }
}
TAG(bub_cocktail);
void bub_cocktail(int *a, int n) {
    MARK(bub_cocktail);
    int lo = 0, hi = n - 1;
    while (lo < hi) {
        int nl = hi, nh = lo;
        for (int i = lo; i < hi; i++)
            if (a[i] > a[i + 1]) { int t = a[i]; a[i] = a[i + 1]; a[i + 1] = t; nh = i; }
        hi = nh;
        for (int i = hi; i > lo; i--)
            if (a[i - 1] > a[i]) { int t = a[i]; a[i] = a[i - 1]; a[i - 1] = t; nl = i; }
        lo = nl;
    }
}
static const int g_shell_gaps[] = { 701, 301, 132, 57, 23, 10, 4, 1 };
TAG(shell_shell_gaps);
void shell_shell_gaps(int *a, int n) {
    MARK(shell_shell_gaps);
    for (int g = 0; g < 8; g++) {
        int gap = g_shell_gaps[g];
        for (int i = gap; i < n; i++) {
            int key = a[i], j = i;
            while (j >= gap && a[j - gap] > key) { a[j] = a[j - gap]; j -= gap; }
            a[j] = key;
        }
    }
}
TAG(shell_knuth);
void shell_knuth(int *a, int n) {
    MARK(shell_knuth);
    for (int gap = 1; gap * 3 + 1 < n; gap = gap * 3 + 1)
        ;
    for (; gap > 0; gap = (gap - 1) / 3)
        for (int i = gap; i < n; i++) {
            int key = a[i], j = i;
            while (j >= gap && a[j - gap] > key) { a[j] = a[j - gap]; j -= gap; }
            a[j] = key;
        }
}
TAG(shell_ciura);
void shell_ciura(int *a, int n) {
    MARK(shell_ciura);
    static const int gaps[] = { 1750, 701, 301, 132, 57, 23, 10, 4, 1 };
    for (int g = 0; g < 9; g++) {
        int gap = gaps[g];
        if (gap >= n && gap != 1) continue;
        for (int i = gap; i < n; i++) {
            int key = a[i], j = i;
            while (j >= gap && a[j - gap] > key) { a[j] = a[j - gap]; j -= gap; }
            a[j] = key;
        }
    }
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)sel_min,          (variant_fn)sel_max,
    (variant_fn)sel_bidirectional,(variant_fn)bub_basic,
    (variant_fn)bub_early_exit,   (variant_fn)bub_cocktail,
    (variant_fn)shell_shell_gaps, (variant_fn)shell_knuth,
    (variant_fn)shell_ciura,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

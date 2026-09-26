/* 04. InsertionSort family. */
#include <stdint.h>
#include <stddef.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(ins_indexed);
void ins_indexed(int *a, int n) {
    MARK(ins_indexed);
    for (int i = 1; i < n; i++) {
        int key = a[i], j = i - 1;
        while (j >= 0 && a[j] > key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
}
TAG(ins_pointer);
void ins_pointer(int *begin, int *end) {
    MARK(ins_pointer);
    for (int *i = begin + 1; i < end; i++) {
        int key = *i, *j = i - 1;
        while (j >= begin && *j > key) { j[1] = *j; j--; }
        j[1] = key;
    }
}
TAG(ins_swap_based);
void ins_swap_based(int *a, int n) {
    MARK(ins_swap_based);
    for (int i = 1; i < n; i++)
        for (int j = i; j > 0 && a[j - 1] > a[j]; j--) {
            int t = a[j]; a[j] = a[j - 1]; a[j - 1] = t;
        }
}
TAG(ins_shift_based);
void ins_shift_based(int *a, int n) {
    MARK(ins_shift_based);
    for (int i = 1; i < n; i++) {
        int key = a[i], j = i - 1;
        while (j >= 0 && a[j] > key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
}
TAG(ins_binary);
void ins_binary(int *a, int n) {
    MARK(ins_binary);
    for (int i = 1; i < n; i++) {
        int key = a[i];
        int lo = 0, hi = i;
        while (lo < hi) {
            int m = (lo + hi) / 2;
            if (a[m] <= key) lo = m + 1; else hi = m;
        }
        for (int j = i; j > lo; j--) a[j] = a[j - 1];
        a[lo] = key;
    }
}
TAG(ins_sentinel);
void ins_sentinel(int *a, int n) {
    MARK(ins_sentinel);
    int i;
    for (i = n - 1; i > 0 && a[i - 1] > a[i]; i--) {
        int t = a[i]; a[i] = a[i - 1]; a[i - 1] = t;
    }
    for (i = 2; i < n; i++) {
        int key = a[i], j = i - 1;
        while (a[j] > key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
}
TAG(ins_descending);
void ins_descending(int *a, int n) {
    MARK(ins_descending);
    for (int i = 1; i < n; i++) {
        int key = a[i], j = i - 1;
        while (j >= 0 && a[j] < key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
}
struct ins_rec { int key; int pad; };
TAG(ins_struct_key);
void ins_struct_key(struct ins_rec *a, int n) {
    MARK(ins_struct_key);
    for (int i = 1; i < n; i++) {
        struct ins_rec key = a[i]; int j = i - 1;
        while (j >= 0 && a[j].key > key.key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)ins_indexed,    (variant_fn)ins_pointer,
    (variant_fn)ins_swap_based, (variant_fn)ins_shift_based,
    (variant_fn)ins_binary,     (variant_fn)ins_sentinel,
    (variant_fn)ins_descending, (variant_fn)ins_struct_key,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

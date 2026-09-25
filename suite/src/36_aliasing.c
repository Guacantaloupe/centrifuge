/* 36. Pointer Aliasing & Memory Access family. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(al_no_alias_hint);
int al_no_alias_hint(int *__restrict a, int *__restrict b, int n) {
    MARK(al_no_alias_hint);
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i] * b[i];
    return s;
}
TAG(al_may_alias_pair);
int al_may_alias_pair(int *a, int *b, int n) {
    MARK(al_may_alias_pair);
    /* stores through b may alias a: classic vectorization blocker */
    for (int i = 1; i < n; i++) b[i] = a[i - 1] + a[i];
    return b[n - 1];
}
TAG(al_char_alias);
int al_char_alias(uint32_t *p, const char *raw, int n) {
    MARK(al_char_alias);
    /* char* may alias anything */
    for (int i = 0; i < n; i++) ((char *)p)[i] = raw[i];
    return (int)*p;
}
TAG(al_union_type_pun);
uint32_t al_union_type_pun(float f) {
    MARK(al_union_type_pun);
    union { float f; uint32_t u; } v;
    v.f = f;
    return v.u;
}
TAG(al_cast_type_pun);
float al_cast_type_pun(uint32_t u) {
    MARK(al_cast_type_pun);
    float f;
    memcpy(&f, &u, 4);
    return f;
}
TAG(al_offset_walk);
long long al_offset_walk(const char *base, size_t stride, int count) {
    MARK(al_offset_walk);
    long long acc = 0;
    for (int i = 0; i < count; i++)
        acc += *(const int *)(base + (size_t)i * stride);
    return acc;
}
TAG(al_double_indirect);
int al_double_indirect(int **pp, int n) {
    MARK(al_double_indirect);
    int s = 0;
    for (int i = 0; i < n; i++) s += *pp[i];
    return s;
}
TAG(al_struct_field_alias);
struct al_pair { int a, b; };
int al_struct_field_alias(struct al_pair *p, int n) {
    MARK(al_struct_field_alias);
    int s = 0;
    for (int i = 0; i < n; i++) {
        p[i].b = p[i].a * 2;
        s += p[i].b;
    }
    return s;
}
TAG(al_volatile_barrier);
int al_volatile_barrier(volatile int *flag, int *data, int n) {
    MARK(al_volatile_barrier);
    int s = 0;
    for (int i = 0; i < n; i++) {
        s += data[i];
        if (*flag) break;
    }
    return s;
}
TAG(al_memcpy_forward);
void al_memcpy_forward(void *dst, const void *src, size_t n) {
    MARK(al_memcpy_forward);
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}
TAG(al_overlap_backward);
void al_overlap_backward(uint8_t *dst, const uint8_t *src, size_t n) {
    MARK(al_overlap_backward);
    if (dst > src) {
        for (size_t i = n; i-- > 0;) dst[i] = src[i];
    } else {
        for (size_t i = 0; i < n; i++) dst[i] = src[i];
    }
}
TAG(al_matrix_row_col);
int al_matrix_row_col(const int *m, int rows, int cols, int row_wise) {
    MARK(al_matrix_row_col);
    int s = 0;
    if (row_wise) {
        for (int r = 0; r < rows; r++)
            for (int c = 0; c < cols; c++) s += m[r * cols + c];
    } else {
        for (int c = 0; c < cols; c++)
            for (int r = 0; r < rows; r++) s += m[r * cols + c];
    }
    return s;
}
TAG(al_fn_ptr_array);
int al_fn_ptr_array(int (*const *fns)(int), int n, int x) {
    MARK(al_fn_ptr_array);
    int acc = 0;
    for (int i = 0; i < n; i++) acc += fns[i](x + i);
    return acc;
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    (variant_fn)al_no_alias_hint,   (variant_fn)al_may_alias_pair,
    (variant_fn)al_char_alias,      (variant_fn)al_union_type_pun,
    (variant_fn)al_cast_type_pun,   (variant_fn)al_offset_walk,
    (variant_fn)al_double_indirect, (variant_fn)al_struct_field_alias,
    (variant_fn)al_volatile_barrier, (variant_fn)al_memcpy_forward,
    (variant_fn)al_overlap_backward, (variant_fn)al_matrix_row_col,
    (variant_fn)al_fn_ptr_array,
};
int main(void) {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}

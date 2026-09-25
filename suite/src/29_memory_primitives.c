/* 29. Memory Primitives family. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(mem_memcpy_byte);
void mem_memcpy_byte(void *dst, const void *src, size_t n) {
    MARK(mem_memcpy_byte);
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}
TAG(mem_memcpy_word);
void mem_memcpy_word(void *dst, const void *src, size_t n) {
    MARK(mem_memcpy_word);
    uint16_t *d = (uint16_t *)dst;
    const uint16_t *s = (const uint16_t *)src;
    n /= 2;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}
TAG(mem_memcpy_u64);
void mem_memcpy_u64(void *dst, const void *src, size_t n) {
    MARK(mem_memcpy_u64);
    uint64_t *d = (uint64_t *)dst;
    const uint64_t *s = (const uint64_t *)src;
    n /= 8;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}
TAG(mem_memcpy_unrolled);
void mem_memcpy_unrolled(void *dst, const void *src, size_t n) {
    MARK(mem_memcpy_unrolled);
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        d[i] = s[i]; d[i + 1] = s[i + 1]; d[i + 2] = s[i + 2]; d[i + 3] = s[i + 3];
        d[i + 4] = s[i + 4]; d[i + 5] = s[i + 5]; d[i + 6] = s[i + 6];
        d[i + 7] = s[i + 7];
    }
    for (; i < n; i++) d[i] = s[i];
}
TAG(mem_memmove_fwd);
void mem_memmove_fwd(void *dst, const void *src, size_t n) {
    MARK(mem_memmove_fwd);
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (d < s) for (size_t i = 0; i < n; i++) d[i] = s[i];
    else for (size_t i = n; i-- > 0;) d[i] = s[i];
}
TAG(mem_memmove_bwd);
void mem_memmove_bwd(void *dst, const void *src, size_t n) {
    MARK(mem_memmove_bwd);
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = n; i-- > 0;) d[i] = s[i];
}
TAG(mem_memset);
void mem_memset(void *dst, int c, size_t n) {
    MARK(mem_memset);
    uint8_t *d = (uint8_t *)dst;
    for (size_t i = 0; i < n; i++) d[i] = (uint8_t)c;
}
TAG(mem_memcmp);
int mem_memcmp(const void *a, const void *b, size_t n) {
    MARK(mem_memcmp);
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i]) return x[i] - y[i];
    return 0;
}
TAG(mem_strlen);
size_t mem_strlen(const char *s) {
    MARK(mem_strlen);
    size_t n = 0;
    while (s[n]) n++;
    return n;
}
TAG(mem_strcmp);
int mem_strcmp(const char *a, const char *b) {
    MARK(mem_strcmp);
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}
TAG(mem_strcpy);
void mem_strcpy(char *dst, const char *src) {
    MARK(mem_strcpy);
    while ((*dst++ = *src++))
        ;
}
TAG(mem_restrict_sum);
int mem_restrict_sum(const int *restrict a, const int *restrict b, int n) {
    MARK(mem_restrict_sum);
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i] * b[i];
    return s;
}
/* arena allocator */
struct arena { uint8_t *base; size_t cap, off; };
TAG(mem_arena_init);
void mem_arena_init(struct arena *a, void *base, size_t cap) {
    MARK(mem_arena_init);
    a->base = (uint8_t *)base;
    a->cap = cap;
    a->off = 0;
}
TAG(mem_arena_alloc);
void *mem_arena_alloc(struct arena *a, size_t n) {
    MARK(mem_arena_alloc);
    if (a->off + n > a->cap) return 0;
    void *p = a->base + a->off;
    a->off += n;
    return p;
}
TAG(mem_arena_reset);
void mem_arena_reset(struct arena *a) {
    MARK(mem_arena_reset);
    a->off = 0;
}
/* free list */
struct flnode { struct flnode *next; };
struct freelist { struct flnode *head; };
TAG(mem_freelist_push);
void mem_freelist_push(struct freelist *fl, void *p) {
    MARK(mem_freelist_push);
    struct flnode *n = (struct flnode *)p;
    n->next = fl->head;
    fl->head = n;
}
TAG(mem_freelist_pop);
void *mem_freelist_pop(struct freelist *fl) {
    MARK(mem_freelist_pop);
    struct flnode *n = fl->head;
    if (!n) return 0;
    fl->head = n->next;
    return n;
}
/* bump allocator */
TAG(mem_bump_alloc);
void *mem_bump_alloc(uint8_t **cur, uint8_t *end, size_t n) {
    MARK(mem_bump_alloc);
    if (*cur + n > end) return 0;
    void *p = *cur;
    *cur += n;
    return p;
}
/* custom malloc wrapper pair */
static uint8_t g_heap[4096];
static size_t g_heap_off;
TAG(mem_custom_malloc);
void *mem_custom_malloc(size_t n) {
    MARK(mem_custom_malloc);
    n = (n + 15) & ~(size_t)15;
    if (g_heap_off + n > sizeof(g_heap)) return 0;
    void *p = g_heap + g_heap_off;
    g_heap_off += n;
    return p;
}
TAG(mem_custom_free);
void mem_custom_free(void *p) {
    MARK(mem_custom_free);
    (void)p; /* bump heap: no-op */
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)mem_memcpy_byte,   (variant_fn)mem_memcpy_word,
    (variant_fn)mem_memcpy_u64,    (variant_fn)mem_memcpy_unrolled,
    (variant_fn)mem_memmove_fwd,   (variant_fn)mem_memmove_bwd,
    (variant_fn)mem_memset,        (variant_fn)mem_memcmp,
    (variant_fn)mem_strlen,        (variant_fn)mem_strcmp,
    (variant_fn)mem_strcpy,        (variant_fn)mem_restrict_sum,
    (variant_fn)mem_arena_init,    (variant_fn)mem_arena_alloc,
    (variant_fn)mem_arena_reset,   (variant_fn)mem_freelist_push,
    (variant_fn)mem_freelist_pop,  (variant_fn)mem_bump_alloc,
    (variant_fn)mem_custom_malloc, (variant_fn)mem_custom_free,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

/* 09. Hash Table family. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

/* open addressing - linear probing */
typedef struct { int key; int val; char used; } oa_slot;
static oa_slot g_oa[64];
TAG(ht_linear_probe);
int ht_linear_probe(int key) {
    MARK(ht_linear_probe);
    size_t i = (size_t)key & 63;
    while (g_oa[i].used) {
        if (g_oa[i].key == key) return g_oa[i].val;
        i = (i + 1) & 63;
    }
    return -1;
}
TAG(ht_quadratic_probe);
int ht_quadratic_probe(int key) {
    MARK(ht_quadratic_probe);
    size_t h = (size_t)key & 63;
    for (size_t k = 1; k <= 64; k++) {
        size_t i = (h + k * k) & 63;
        if (!g_oa[i].used) return -1;
        if (g_oa[i].key == key) return g_oa[i].val;
    }
    return -1;
}
TAG(ht_double_hash);
int ht_double_hash(int key) {
    MARK(ht_double_hash);
    size_t h1 = (size_t)key & 63, step = 1 + 2 * ((size_t)key % 31);
    size_t i = h1;
    while (g_oa[i].used) {
        if (g_oa[i].key == key) return g_oa[i].val;
        i = (i + step) & 63;
    }
    return -1;
}
/* chaining */
struct chain_node { int key, val; struct chain_node *next; };
static struct chain_node *g_buckets[64];
static struct chain_node g_pool[64];
TAG(ht_chaining);
int ht_chaining(int key) {
    MARK(ht_chaining);
    size_t h = (size_t)key & 63;
    for (struct chain_node *n = g_buckets[h]; n; n = n->next)
        if (n->key == key) return n->val;
    return -1;
}
TAG(ht_chaining_insert);
void ht_chaining_insert(int key, int val) {
    MARK(ht_chaining_insert);
    size_t h = (size_t)key & 63;
    struct chain_node *n = &g_pool[(size_t)key & 63];
    n->key = key; n->val = val; n->next = g_buckets[h];
    g_buckets[h] = n;
}
/* robin hood */
typedef struct { int key; int val; int psl; char used; } rh_slot;
static rh_slot g_rh[64];
TAG(ht_robin_hood);
int ht_robin_hood(int key) {
    MARK(ht_robin_hood);
    size_t i = (size_t)key & 63;
    for (int psl = 0; psl < 64; psl++) {
        if (!g_rh[i].used || g_rh[i].psl < psl) return -1;
        if (g_rh[i].key == key) return g_rh[i].val;
        i = (i + 1) & 63;
    }
    return -1;
}
/* cuckoo: two tables, two hashes */
static int g_ck1[64], g_ck2[64];
static char g_ck1u[64], g_ck2u[64];
static size_t h1(int k) { return (size_t)k & 63; }
static size_t h2c(int k) { return ((size_t)k * 2654435761u >> 8) & 63; }
TAG(ht_cuckoo_lookup);
int ht_cuckoo_lookup(int key) {
    MARK(ht_cuckoo_lookup);
    if (g_ck1u[h1(key)] && g_ck1[h1(key)] == key) return 1;
    if (g_ck2u[h2c(key)] && g_ck2[h2c(key)] == key) return 2;
    return 0;
}
/* tombstones: linear probing with deleted markers */
typedef struct { int key, val; int state; } tm_slot; /* 0 empty 1 used 2 tomb */
static tm_slot g_tm[64];
TAG(ht_tombstones);
int ht_tombstones(int key) {
    MARK(ht_tombstones);
    size_t i = (size_t)key & 63;
    for (;;) {
        if (g_tm[i].state == 0) return -1;
        if (g_tm[i].state == 1 && g_tm[i].key == key) return g_tm[i].val;
        i = (i + 1) & 63;
    }
}
/* string keys: FNV over bytes */
TAG(ht_string_key);
size_t ht_string_key(const char *s) {
    MARK(ht_string_key);
    size_t h = 1469598103934665603ull;
    while (*s) { h ^= (unsigned char)*s++; h *= 1099511628211ull; }
    return h & 63;
}
struct hkey { int a, b; };
TAG(ht_struct_key);
size_t ht_struct_key(struct hkey k) {
    MARK(ht_struct_key);
    return (size_t)(k.a * 31 + k.b) & 63;
}
typedef size_t (*hash_fn)(int);
static int ht_run_hash(int key, hash_fn fn) {
    size_t h = fn(key) & 63;
    return g_oa[h].used ? g_oa[h].val : -1;
}
static size_t hash_id(int k) { return (size_t)k; }
TAG(ht_fnptr_hash);
int ht_fnptr_hash(int key) {
    MARK(ht_fnptr_hash);
    return ht_run_hash(key, hash_id);
}
/* resize: grow table when load factor exceeds 3/4 */
TAG(ht_resize);
void ht_resize(oa_slot **table, size_t *cap, size_t count) {
    MARK(ht_resize);
    if (count * 4 < *cap * 3) return;
    size_t ncap = *cap * 2;
    oa_slot *nt = (oa_slot *)calloc(ncap, sizeof(oa_slot));
    for (size_t i = 0; i < *cap; i++)
        if ((*table)[i].used) {
            size_t j = (size_t)(*table)[i].key & (ncap - 1);
            while (nt[j].used) j = (j + 1) & (ncap - 1);
            nt[j] = (*table)[i];
        }
    free(*table);
    *table = nt;
    *cap = ncap;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)ht_linear_probe,  (variant_fn)ht_quadratic_probe,
    (variant_fn)ht_double_hash,   (variant_fn)ht_chaining,
    (variant_fn)ht_chaining_insert,(variant_fn)ht_robin_hood,
    (variant_fn)ht_cuckoo_lookup, (variant_fn)ht_tombstones,
    (variant_fn)ht_string_key,    (variant_fn)ht_struct_key,
    (variant_fn)ht_fnptr_hash,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return ht_linear_probe(1);
}

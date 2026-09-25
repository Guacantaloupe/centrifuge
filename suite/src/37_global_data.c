/* 37. Global Data & Cross-Module State family. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

int g_counter;
static int g_hidden_counter;
int g_table[64];
const int g_const_lut[16] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};
char g_name[32] = "centrifuge";
struct glob_state { uint32_t magic; int depth; uint64_t hits; } g_state = {0xC0FFEE, 0, 0};

TAG(gl_read_global);
int gl_read_global(void) {
    MARK(gl_read_global);
    return g_counter + g_hidden_counter;
}
TAG(gl_write_global);
void gl_write_global(int v) {
    MARK(gl_write_global);
    g_counter = v;
    g_hidden_counter = v * 2;
}
TAG(gl_increment);
int gl_increment(void) {
    MARK(gl_increment);
    return ++g_counter;
}
TAG(gl_lut_lookup);
int gl_lut_lookup(int idx) {
    MARK(gl_lut_lookup);
    return g_const_lut[idx & 15];
}
TAG(gl_table_sum);
long long gl_table_sum(int n) {
    MARK(gl_table_sum);
    long long s = 0;
    for (int i = 0; i < n && i < 64; i++) s += g_table[i];
    return s;
}
TAG(gl_table_fill);
void gl_table_fill(int seed, int n) {
    MARK(gl_table_fill);
    for (int i = 0; i < n && i < 64; i++) g_table[i] = seed * 31 + i;
}
TAG(gl_state_update);
uint64_t gl_state_update(int d) {
    MARK(gl_state_update);
    g_state.magic ^= (uint32_t)d;
    g_state.depth += d > 0 ? 1 : -1;
    g_state.hits += (uint64_t)(d > 0);
    return g_state.hits;
}
TAG(gl_name_len);
int gl_name_len(void) {
    MARK(gl_name_len);
    int n = 0;
    while (g_name[n]) n++;
    return n;
}
TAG(gl_bss_vs_data);
int gl_bss_vs_data(int n) {
    MARK(gl_bss_vs_data);
    /* g_counter is BSS (zero-init); g_const_lut is .rodata; g_state is .data */
    return g_counter + g_const_lut[n & 15] + (int)g_state.depth;
}
TAG(gl_array_of_ptrs);
const char *g_strs[4] = {"alpha", "beta", "gamma", "delta"};
int gl_array_of_ptrs(int i) {
    MARK(gl_array_of_ptrs);
    const char *s = g_strs[i & 3];
    int len = 0;
    while (s[len]) len++;
    return len;
}
TAG(gl_global_struct_ptr);
struct node { int val; struct node *next; };
struct node g_node_pool[8];
int g_pool_used;
struct node *gl_global_struct_ptr(int v) {
    MARK(gl_global_struct_ptr);
    if (g_pool_used >= 8) return 0;
    g_node_pool[g_pool_used].val = v;
    g_node_pool[g_pool_used].next = g_pool_used ? &g_node_pool[g_pool_used - 1] : 0;
    return &g_node_pool[g_pool_used++];
}
TAG(gl_walk_list);
int gl_walk_list(void) {
    MARK(gl_walk_list);
    int s = 0;
    for (struct node *p = g_pool_used ? &g_node_pool[g_pool_used - 1] : 0; p; p = p->next)
        s += p->val;
    return s;
}
TAG(gl_static_local);
int gl_static_local(void) {
    MARK(gl_static_local);
    static int tick = 100;
    tick += 7;
    return tick;
}
TAG(gl_global_pair_swap);
int g_pair[2] = {1, 2};
void gl_global_pair_swap(void) {
    MARK(gl_global_pair_swap);
    int t = g_pair[0];
    g_pair[0] = g_pair[1];
    g_pair[1] = t;
}
TAG(gl_flag_poll);
volatile int g_flag;
int gl_flag_poll(int n) {
    MARK(gl_flag_poll);
    int s = 0;
    for (int i = 0; i < n && !g_flag; i++) s += i;
    return s;
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    (variant_fn)gl_read_global,      (variant_fn)gl_write_global,
    (variant_fn)gl_increment,        (variant_fn)gl_lut_lookup,
    (variant_fn)gl_table_sum,        (variant_fn)gl_table_fill,
    (variant_fn)gl_state_update,     (variant_fn)gl_name_len,
    (variant_fn)gl_bss_vs_data,      (variant_fn)gl_array_of_ptrs,
    (variant_fn)gl_global_struct_ptr, (variant_fn)gl_walk_list,
    (variant_fn)gl_static_local,     (variant_fn)gl_global_pair_swap,
    (variant_fn)gl_flag_poll,
};
int main(void) {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}

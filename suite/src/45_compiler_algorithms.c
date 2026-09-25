/* 45. Compiler-Algorithm family — the classic passes a compiler itself uses. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

struct cfg_edge { int from, to; };
struct uf_parent { int parent, rank; };
TAG(ca_uf_find);
int ca_uf_find(struct uf_parent *uf, int x) {
    MARK(ca_uf_find);
    while (uf[x].parent != x) {
        uf[x].parent = uf[uf[x].parent].parent;
        x = uf[x].parent;
    }
    return x;
}
TAG(ca_uf_union);
int ca_uf_union(struct uf_parent *uf, int a, int b) {
    MARK(ca_uf_union);
    int ra = ca_uf_find(uf, a), rb = ca_uf_find(uf, b);
    if (ra == rb) return ra;
    if (uf[ra].rank < uf[rb].rank) {
        int t = ra; ra = rb; rb = t;
    }
    uf[rb].parent = ra;
    if (uf[ra].rank == uf[rb].rank) uf[ra].rank++;
    return ra;
}
TAG(ca_topo_sort);
int ca_topo_sort(const int *adj_flat, int n, int *out) {
    MARK(ca_topo_sort);
    /* Kahn's algorithm on flattened adjacency matrix */
    int indeg[16] = {0};
    for (int i = 0; i < n && i < 16; i++)
        for (int j = 0; j < n && j < 16; j++)
            if (adj_flat[i * 16 + j]) indeg[j]++;
    int head = 0, tail = 0;
    for (int i = 0; i < n && i < 16; i++)
        if (!indeg[i]) out[tail++] = i;
    while (head < tail) {
        int v = out[head++];
        for (int j = 0; j < n && j < 16; j++)
            if (adj_flat[v * 16 + j] && --indeg[j] == 0) out[tail++] = j;
    }
    return tail;
}
TAG(ca_liveness);
int ca_liveness(const uint32_t *use, const uint32_t *def, int n, uint32_t *live_out) {
    MARK(ca_liveness);
    /* backward dataflow: live_out[i] = use[i] | (live_in successors) approximated iteratively */
    uint32_t live[32] = {0};
    int changed = 1, iters = 0;
    while (changed && iters < 64) {
        changed = 0;
        iters++;
        for (int i = n - 1; i >= 0 && i < 32; i--) {
            uint32_t out = live[i] & ~def[i];
            uint32_t ni = out | use[i];
            if (ni != live[i]) { live[i] = ni; changed = 1; }
        }
    }
    for (int i = 0; i < n && i < 32; i++) live_out[i] = live[i];
    return iters;
}
TAG(ca_reaching_defs);
int ca_reaching_defs(const uint32_t *gen, const uint32_t *kill, int n, uint32_t *out) {
    MARK(ca_reaching_defs);
    uint32_t reach[32] = {0};
    int changed = 1, iters = 0;
    while (changed && iters < 64) {
        changed = 0;
        iters++;
        for (int i = 0; i < n && i < 32; i++) {
            uint32_t prev = reach[i];
            reach[i] |= gen[i];
            reach[i] &= ~kill[i];
            if (reach[i] != prev) changed = 1;
        }
    }
    for (int i = 0; i < n && i < 32; i++) out[i] = reach[i];
    return iters;
}
TAG(ca_dom_tree);
int ca_dom_tree(const uint32_t *succ, int n, uint32_t *idom) {
    MARK(ca_dom_tree);
    /* simple iterative dominators: idom[0]=0, others = intersect of preds */
    uint32_t dom[16];
    int nn = n < 16 ? n : 16;
    dom[0] = 1u;
    for (int i = 1; i < nn; i++) dom[i] = (1u << nn) - 1;
    int changed = 1;
    while (changed) {
        changed = 0;
        for (int i = 1; i < nn; i++) {
            uint32_t newdom = (1u << nn) - 1;
            uint32_t preds = 0;
            for (int p = 0; p < nn; p++)
                if (succ[p] & (1u << i)) preds |= 1u << p;
            for (int p = 0; p < nn; p++)
                if ((preds & (1u << p)) && dom[p])
                    newdom &= dom[p] ? dom[p] : newdom;
            newdom |= 1u << i;
            if (newdom != dom[i]) { dom[i] = newdom; changed = 1; }
        }
    }
    for (int i = 0; i < nn; i++) idom[i] = dom[i];
    return nn;
}
TAG(ca_ssa_rename);
int ca_ssa_rename(int *defs, int n, int *versions) {
    MARK(ca_ssa_rename);
    /* sequential renaming: each def gets an increasing version */
    int next_version = 0;
    for (int i = 0; i < n; i++)
        if (defs[i] >= 0) versions[defs[i]] = next_version++;
    return next_version;
}
TAG(ca_copy_prop);
int ca_copy_prop(int *values, const int *copy_of, int n) {
    MARK(ca_copy_prop);
    /* resolve copy chains: value[i] = values[root of copy chain] */
    int resolved = 0;
    for (int i = 0; i < n; i++) {
        int root = i, guard = 0;
        while (copy_of[root] >= 0 && copy_of[root] != root && guard++ < n)
            root = copy_of[root];
        if (root != i) { values[i] = values[root]; resolved++; }
    }
    return resolved;
}
TAG(ca_dead_code_sweep);
int ca_dead_code_sweep(uint32_t *live_mask, const uint32_t *defs, int n) {
    MARK(ca_dead_code_sweep);
    int removed = 0;
    for (int i = 0; i < n; i++) {
        if (!(live_mask[i] & defs[i])) { live_mask[i] = 0; removed++; }
    }
    return removed;
}
TAG(ca_gvn_hash);
uint32_t ca_gvn_hash(int op, int a, int b) {
    MARK(ca_gvn_hash);
    uint32_t h = (uint32_t)op * 0x9E3779B1u;
    h ^= (uint32_t)a * 0x85EBCA6Bu;
    h = (h << 13) | (h >> 19);
    h ^= (uint32_t)b * 0xC2B2AE35u;
    return h;
}
TAG(ca_const_fold_range);
int ca_const_fold_range(int v, int lo, int hi) {
    MARK(ca_const_fold_range);
    if (v < lo) v = lo;
    if (v > hi) v = hi;
    if (lo == hi) v = lo;
    if (lo > hi) v = 0;
    return v;
}
TAG(ca_bitfield_pack);
uint64_t ca_bitfield_pack(uint64_t a, uint64_t b, int width) {
    MARK(ca_bitfield_pack);
    uint64_t mask = width >= 64 ? ~0ull : ((1ull << width) - 1);
    return (a & mask) | ((b & mask) << width);
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    (variant_fn)ca_uf_find,      (variant_fn)ca_uf_union,
    (variant_fn)ca_topo_sort,    (variant_fn)ca_liveness,
    (variant_fn)ca_reaching_defs, (variant_fn)ca_dom_tree,
    (variant_fn)ca_ssa_rename,   (variant_fn)ca_copy_prop,
    (variant_fn)ca_dead_code_sweep, (variant_fn)ca_gvn_hash,
    (variant_fn)ca_const_fold_range, (variant_fn)ca_bitfield_pack,
};
int main(void) {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}

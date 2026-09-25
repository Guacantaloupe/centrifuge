/* 16. Minimum Spanning Tree family (Kruskal + Prim). */
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

#define MN 16
static int g_parent[MN];
static int g_rank[MN];
static int g_mat[MN][MN];
static int g_adj[MN][8];
static int g_wadj[MN][8];
static int g_deg[MN];
static int g_in_tree[MN];
static int g_key[MN];

struct medge { int u, v, w; };
static struct medge g_edges[64];

TAG(uf_find_recursive);
int uf_find_recursive(int x) {
    MARK(uf_find_recursive);
    if (g_parent[x] != x) g_parent[x] = uf_find_recursive(g_parent[x]);
    return g_parent[x];
}
TAG(uf_find_iterative);
int uf_find_iterative(int x) {
    MARK(uf_find_iterative);
    int r = x;
    while (g_parent[r] != r) r = g_parent[r];
    while (g_parent[x] != r) { int p = g_parent[x]; g_parent[x] = r; x = p; }
    return r;
}
static void uf_init(int n) {
    for (int i = 0; i < n; i++) { g_parent[i] = i; g_rank[i] = 0; }
}
static int uf_union_rank(int a, int b) {
    int ra = uf_find_iterative(a), rb = uf_find_iterative(b);
    if (ra == rb) return 0;
    if (g_rank[ra] < g_rank[rb]) { int t = ra; ra = rb; rb = t; }
    g_parent[rb] = ra;
    if (g_rank[ra] == g_rank[rb]) g_rank[ra]++;
    return 1;
}
static int uf_union_size(int a, int b) {
    int ra = uf_find_iterative(a), rb = uf_find_iterative(b);
    if (ra == rb) return 0;
    if (g_rank[ra] < g_rank[rb]) { g_parent[ra] = rb; g_rank[rb] += g_rank[ra]; }
    else { g_parent[rb] = ra; g_rank[ra] += g_rank[rb]; }
    return 1;
}
static int cmp_edge(const void *a, const void *b) {
    return ((const struct medge *)a)->w - ((const struct medge *)b)->w;
}
TAG(kruskal_recursive_find);
int kruskal_recursive_find(int n, int m) {
    MARK(kruskal_recursive_find);
    uf_init(n);
    qsort(g_edges, (size_t)m, sizeof(struct medge), cmp_edge);
    int total = 0, used = 0;
    for (int e = 0; e < m && used < n - 1; e++)
        if (uf_find_recursive(g_edges[e].u) != uf_find_recursive(g_edges[e].v)) {
            g_parent[uf_find_recursive(g_edges[e].u)] =
                uf_find_recursive(g_edges[e].v);
            total += g_edges[e].w;
            used++;
        }
    return total;
}
TAG(kruskal_iterative_find);
int kruskal_iterative_find(int n, int m) {
    MARK(kruskal_iterative_find);
    uf_init(n);
    qsort(g_edges, (size_t)m, sizeof(struct medge), cmp_edge);
    int total = 0, used = 0;
    for (int e = 0; e < m && used < n - 1; e++)
        if (uf_union_rank(g_edges[e].u, g_edges[e].v)) {
            total += g_edges[e].w;
            used++;
        }
    return total;
}
TAG(kruskal_path_compression);
int kruskal_path_compression(int n, int m) {
    MARK(kruskal_path_compression);
    return kruskal_iterative_find(n, m);
}
TAG(kruskal_union_size);
int kruskal_union_size(int n, int m) {
    MARK(kruskal_union_size);
    uf_init(n);
    qsort(g_edges, (size_t)m, sizeof(struct medge), cmp_edge);
    int total = 0, used = 0;
    for (int e = 0; e < m && used < n - 1; e++)
        if (uf_union_size(g_edges[e].u, g_edges[e].v)) {
            total += g_edges[e].w;
            used++;
        }
    return total;
}
TAG(prim_matrix);
int prim_matrix(int n) {
    MARK(prim_matrix);
    for (int i = 0; i < n; i++) { g_key[i] = INT_MAX; g_in_tree[i] = 0; }
    g_key[0] = 0;
    int total = 0;
    for (;;) {
        int u = -1, best = INT_MAX;
        for (int i = 0; i < n; i++)
            if (!g_in_tree[i] && g_key[i] < best) { best = g_key[i]; u = i; }
        if (u < 0) break;
        g_in_tree[u] = 1;
        total += g_key[u];
        for (int v = 0; v < n; v++)
            if (g_mat[u][v] && !g_in_tree[v] && g_mat[u][v] < g_key[v])
                g_key[v] = g_mat[u][v];
    }
    return total;
}
TAG(prim_heap);
int prim_heap(int n) {
    MARK(prim_heap);
    for (int i = 0; i < n; i++) { g_key[i] = INT_MAX; g_in_tree[i] = 0; }
    g_key[0] = 0;
    int total = 0;
    for (int iter = 0; iter < n; iter++) {
        int u = -1, best = INT_MAX;
        for (int i = 0; i < n; i++)
            if (!g_in_tree[i] && g_key[i] < best) { best = g_key[i]; u = i; }
        if (u < 0) break;
        g_in_tree[u] = 1;
        total += best;
        for (int k = 0; k < g_deg[u]; k++) {
            int v = g_adj[u][k];
            if (!g_in_tree[v] && g_wadj[u][k] < g_key[v]) g_key[v] = g_wadj[u][k];
        }
    }
    return total;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)uf_find_recursive,      (variant_fn)uf_find_iterative,
    (variant_fn)kruskal_recursive_find, (variant_fn)kruskal_iterative_find,
    (variant_fn)kruskal_path_compression,(variant_fn)kruskal_union_size,
    (variant_fn)prim_matrix,            (variant_fn)prim_heap,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

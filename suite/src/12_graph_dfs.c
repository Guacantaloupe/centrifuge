/* 12. Graph DFS family. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

#define GN 16
static int g_adjm[GN][GN];
static int g_adj[GN][8];
static int g_deg[GN];
static uint8_t g_visited[GN];
static uint64_t g_visit_bits;

TAG(gdfs_recursive_matrix);
void gdfs_recursive_matrix(int v, int n) {
    MARK(gdfs_recursive_matrix);
    g_visited[v] = 1;
    for (int w = 0; w < n; w++)
        if (g_adjm[v][w] && !g_visited[w]) gdfs_recursive_matrix(w, n);
}
TAG(gdfs_recursive_list);
void gdfs_recursive_list(int v) {
    MARK(gdfs_recursive_list);
    g_visited[v] = 1;
    for (int i = 0; i < g_deg[v]; i++) {
        int w = g_adj[v][i];
        if (!g_visited[w]) gdfs_recursive_list(w);
    }
}
TAG(gdfs_iterative_stack);
void gdfs_iterative_stack(int start, int n) {
    MARK(gdfs_iterative_stack);
    int st[GN], sp = 0;
    st[sp++] = start;
    while (sp > 0) {
        int v = st[--sp];
        if (g_visited[v]) continue;
        g_visited[v] = 1;
        for (int w = 0; w < n; w++)
            if (g_adjm[v][w] && !g_visited[w]) st[sp++] = w;
    }
}
TAG(gdfs_bitset_visited);
void gdfs_bitset_visited(int start, int n) {
    MARK(gdfs_bitset_visited);
    int st[GN], sp = 0;
    st[sp++] = start;
    while (sp > 0) {
        int v = st[--sp];
        if (g_visit_bits & (1ull << v)) continue;
        g_visit_bits |= 1ull << v;
        for (int i = 0; i < g_deg[v]; i++) {
            int w = g_adj[v][i];
            if (!(g_visit_bits & (1ull << w))) st[sp++] = w;
        }
    }
}
typedef void (*gvisitor)(int);
static void gdfs_visit_cb(int v, gvisitor cb) {
    g_visited[v] = 1;
    cb(v);
    for (int i = 0; i < g_deg[v]; i++) {
        int w = g_adj[v][i];
        if (!g_visited[w]) gdfs_visit_cb(w, cb);
    }
}
static void gcount_sink(int v) { (void)v; }
TAG(gdfs_callback);
void gdfs_callback(int start) {
    MARK(gdfs_callback);
    gdfs_visit_cb(start, gcount_sink);
}
TAG(gdfs_early_exit);
int gdfs_early_exit(int v, int target) {
    MARK(gdfs_early_exit);
    if (v == target) return 1;
    g_visited[v] = 1;
    for (int i = 0; i < g_deg[v]; i++) {
        int w = g_adj[v][i];
        if (!g_visited[w] && gdfs_early_exit(w, target)) return 1;
    }
    return 0;
}
TAG(gdfs_disconnected);
int gdfs_disconnected(int n) {
    MARK(gdfs_disconnected);
    for (int i = 0; i < n; i++) g_visited[i] = 0;
    int comps = 0;
    for (int v = 0; v < n; v++)
        if (!g_visited[v]) { comps++; gdfs_recursive_list(v); }
    return comps;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)gdfs_recursive_matrix, (variant_fn)gdfs_recursive_list,
    (variant_fn)gdfs_iterative_stack,  (variant_fn)gdfs_bitset_visited,
    (variant_fn)gdfs_callback,         (variant_fn)gdfs_early_exit,
    (variant_fn)gdfs_disconnected,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

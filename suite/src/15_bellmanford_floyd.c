/* 15. Bellman-Ford / Floyd-Warshall family. */
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

#define FN 16
static int g_dist[FN];
static int g_mat[FN][FN];

struct edge { int u, v, w; };
static struct edge g_edges[64];

TAG(bf_classic);
int bf_classic(int n, int m, int src) {
    MARK(bf_classic);
    for (int i = 0; i < n; i++) g_dist[i] = INT_MAX;
    g_dist[src] = 0;
    for (int iter = 0; iter < n - 1; iter++)
        for (int e = 0; e < m; e++)
            if (g_dist[g_edges[e].u] != INT_MAX &&
                g_dist[g_edges[e].u] + g_edges[e].w < g_dist[g_edges[e].v])
                g_dist[g_edges[e].v] = g_dist[g_edges[e].u] + g_edges[e].w;
    return 0;
}
TAG(bf_early_exit);
int bf_early_exit(int n, int m, int src) {
    MARK(bf_early_exit);
    for (int i = 0; i < n; i++) g_dist[i] = INT_MAX;
    g_dist[src] = 0;
    for (int iter = 0; iter < n - 1; iter++) {
        int changed = 0;
        for (int e = 0; e < m; e++)
            if (g_dist[g_edges[e].u] != INT_MAX &&
                g_dist[g_edges[e].u] + g_edges[e].w < g_dist[g_edges[e].v]) {
                g_dist[g_edges[e].v] = g_dist[g_edges[e].u] + g_edges[e].w;
                changed = 1;
            }
        if (!changed) break;
    }
    return 0;
}
TAG(bf_negative_cycle);
int bf_negative_cycle(int n, int m) {
    MARK(bf_negative_cycle);
    for (int i = 0; i < n; i++) g_dist[i] = 0;
    for (int iter = 0; iter < n; iter++)
        for (int e = 0; e < m; e++)
            if (g_dist[g_edges[e].u] + g_edges[e].w < g_dist[g_edges[e].v]) {
                g_dist[g_edges[e].v] = g_dist[g_edges[e].u] + g_edges[e].w;
                if (iter == n - 1) return 1;
            }
    return 0;
}
TAG(bf_adjacency_list);
void bf_adjacency_list(int n, int src, const int *deg, const int *adj,
                       const int *wadj) {
    MARK(bf_adjacency_list);
    for (int i = 0; i < n; i++) g_dist[i] = INT_MAX;
    g_dist[src] = 0;
    for (int iter = 0; iter < n - 1; iter++)
        for (int u = 0; u < n; u++)
            if (g_dist[u] != INT_MAX)
                for (int k = 0; k < deg[u]; k++) {
                    int v = adj[u * 8 + k];
                    int nd = g_dist[u] + wadj[u * 8 + k];
                    if (nd < g_dist[v]) g_dist[v] = nd;
                }
}
TAG(fw_triple_loop);
void fw_triple_loop(int n) {
    MARK(fw_triple_loop);
    for (int k = 0; k < n; k++)
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                if (g_mat[i][k] != INT_MAX && g_mat[k][j] != INT_MAX &&
                    g_mat[i][k] + g_mat[k][j] < g_mat[i][j])
                    g_mat[i][j] = g_mat[i][k] + g_mat[k][j];
}
TAG(fw_reordered_loops);
void fw_reordered_loops(int n) {
    MARK(fw_reordered_loops);
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            for (int k = 0; k < n; k++)
                if (g_mat[i][k] != INT_MAX && g_mat[k][j] != INT_MAX &&
                    g_mat[i][k] + g_mat[k][j] < g_mat[i][j])
                    g_mat[i][j] = g_mat[i][k] + g_mat[k][j];
}
TAG(fw_flattened);
void fw_flattened(int n) {
    MARK(fw_flattened);
    static int flat[FN * FN];
    for (int i = 0; i < n * n; i++) flat[i] = g_mat[0][i];
    for (int k = 0; k < n; k++)
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                if (flat[i * n + k] != INT_MAX && flat[k * n + j] != INT_MAX &&
                    flat[i * n + k] + flat[k * n + j] < flat[i * n + j])
                    flat[i * n + j] = flat[i * n + k] + flat[k * n + j];
    for (int i = 0; i < n * n; i++) g_mat[0][i] = flat[i];
}
TAG(fw_ptr_matrix);
void fw_ptr_matrix(int n, int **mat) {
    MARK(fw_ptr_matrix);
    for (int k = 0; k < n; k++)
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                if (mat[i][k] != INT_MAX && mat[k][j] != INT_MAX &&
                    mat[i][k] + mat[k][j] < mat[i][j])
                    mat[i][j] = mat[i][k] + mat[k][j];
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)bf_classic,       (variant_fn)bf_early_exit,
    (variant_fn)bf_negative_cycle,(variant_fn)bf_adjacency_list,
    (variant_fn)fw_triple_loop,   (variant_fn)fw_reordered_loops,
    (variant_fn)fw_flattened,     (variant_fn)fw_ptr_matrix,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

/* 14. Dijkstra family. */
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

#define DN 16
static int g_dist[DN];
static int g_parent[DN];
static int g_done[DN];
static int g_w[DN][DN];
static int g_adj[DN][8];
static int g_wadj[DN][8];
static int g_deg[DN];

TAG(dijkstra_matrix_v2);
void dijkstra_matrix_v2(int src, int n) {
    MARK(dijkstra_matrix_v2);
    for (int i = 0; i < n; i++) { g_dist[i] = INT_MAX; g_done[i] = 0; }
    g_dist[src] = 0;
    for (;;) {
        int u = -1, best = INT_MAX;
        for (int i = 0; i < n; i++)
            if (!g_done[i] && g_dist[i] < best) { best = g_dist[i]; u = i; }
        if (u < 0) break;
        g_done[u] = 1;
        for (int v = 0; v < n; v++)
            if (g_w[u][v] && !g_done[v] &&
                g_dist[u] + g_w[u][v] < g_dist[v])
                g_dist[v] = g_dist[u] + g_w[u][v];
    }
}
/* binary heap keyed by distance, storing vertex ids */
static int h_key[DN + 1], h_val[DN + 1], h_n;
static void h_push(int k, int v) {
    int i = ++h_n;
    while (i > 1 && h_key[i / 2] > k) {
        h_key[i] = h_key[i / 2]; h_val[i] = h_val[i / 2]; i /= 2;
    }
    h_key[i] = k; h_val[i] = v;
}
static int h_pop(void) {
    int top = h_val[1], last_k = h_key[h_n], last_v = h_val[h_n--];
    int i = 1;
    for (;;) {
        int c = 2 * i;
        if (c > h_n) break;
        if (c + 1 <= h_n && h_key[c + 1] < h_key[c]) c++;
        if (h_key[c] >= last_k) break;
        h_key[i] = h_key[c]; h_val[i] = h_val[c]; i = c;
    }
    h_key[i] = last_k; h_val[i] = last_v;
    return top;
}
TAG(dijkstra_binheap);
void dijkstra_binheap(int src) {
    MARK(dijkstra_binheap);
    for (int i = 0; i < DN; i++) { g_dist[i] = INT_MAX; g_done[i] = 0; }
    g_dist[src] = 0;
    h_n = 0;
    h_push(0, src);
    while (h_n > 0) {
        int u = h_pop();
        if (g_done[u]) continue;
        g_done[u] = 1;
        for (int i = 0; i < g_deg[u]; i++) {
            int v = g_adj[u][i], w = g_wadj[u][i];
            if (!g_done[v] && g_dist[u] + w < g_dist[v]) {
                g_dist[v] = g_dist[u] + w;
                h_push(g_dist[v], v);
            }
        }
    }
}
TAG(dijkstra_lazy_heap);
void dijkstra_lazy_heap(int src) {
    MARK(dijkstra_lazy_heap);
    /* lazy deletion: stale entries popped and skipped */
    for (int i = 0; i < DN; i++) g_dist[i] = INT_MAX;
    g_dist[src] = 0;
    h_n = 0;
    h_push(0, src);
    while (h_n > 0) {
        int u = h_pop();
        for (int i = 0; i < g_deg[u]; i++) {
            int v = g_adj[u][i], w = g_wadj[u][i];
            if (g_dist[u] + w < g_dist[v]) {
                g_dist[v] = g_dist[u] + w;
                h_push(g_dist[v], v);
            }
        }
    }
}
TAG(dijkstra_path_reconstruct);
void dijkstra_path_reconstruct(int src) {
    MARK(dijkstra_path_reconstruct);
    for (int i = 0; i < DN; i++) {
        g_dist[i] = INT_MAX; g_done[i] = 0; g_parent[i] = -1;
    }
    g_dist[src] = 0;
    for (;;) {
        int u = -1, best = INT_MAX;
        for (int i = 0; i < DN; i++)
            if (!g_done[i] && g_dist[i] < best) { best = g_dist[i]; u = i; }
        if (u < 0) break;
        g_done[u] = 1;
        for (int i = 0; i < g_deg[u]; i++) {
            int v = g_adj[u][i], w = g_wadj[u][i];
            if (!g_done[v] && g_dist[u] + w < g_dist[v]) {
                g_dist[v] = g_dist[u] + w;
                g_parent[v] = u;
            }
        }
    }
}
TAG(dijkstra_early_exit);
int dijkstra_early_exit(int src, int target) {
    MARK(dijkstra_early_exit);
    for (int i = 0; i < DN; i++) { g_dist[i] = INT_MAX; g_done[i] = 0; }
    g_dist[src] = 0;
    for (;;) {
        int u = -1, best = INT_MAX;
        for (int i = 0; i < DN; i++)
            if (!g_done[i] && g_dist[i] < best) { best = g_dist[i]; u = i; }
        if (u < 0 || u == target) break;
        g_done[u] = 1;
        for (int v = 0; v < DN; v++)
            if (g_w[u][v] && !g_done[v] && g_dist[u] + g_w[u][v] < g_dist[v])
                g_dist[v] = g_dist[u] + g_w[u][v];
    }
    return g_dist[target];
}
TAG(dijkstra_float_weights);
float dijkstra_float_weights(int src, int n, float *dist,
                             const float *w, const int *deg,
                             const int *adj, const int *wadj) {
    MARK(dijkstra_float_weights);
    for (int i = 0; i < n; i++) { dist[i] = 1e30f; g_done[i] = 0; }
    dist[src] = 0.0f;
    for (;;) {
        int u = -1;
        float best = 1e30f;
        for (int i = 0; i < n; i++)
            if (!g_done[i] && dist[i] < best) { best = dist[i]; u = i; }
        if (u < 0) break;
        g_done[u] = 1;
        for (int i = 0; i < deg[u]; i++) {
            int v = adj[u * 8 + i];
            float nd = dist[u] + wadj[u * 8 + i];
            if (!g_done[v] && nd < dist[v]) dist[v] = nd;
        }
    }
    return dist[src];
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)dijkstra_matrix_v2,    (variant_fn)dijkstra_binheap,
    (variant_fn)dijkstra_lazy_heap,    (variant_fn)dijkstra_path_reconstruct,
    (variant_fn)dijkstra_early_exit,   (variant_fn)dijkstra_float_weights,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

/* 13. Graph BFS family. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

#define GN 16
static int g_adjm[GN][GN];
static int g_adj[GN][8];
static int g_deg[GN];
static int g_dist[GN];
static int g_parent[GN];
static uint8_t g_visited[GN];

TAG(gbfs_queue_array);
void gbfs_queue_array(int start, int n) {
    MARK(gbfs_queue_array);
    int q[GN], head = 0, tail = 0;
    g_visited[start] = 1;
    g_dist[start] = 0;
    q[tail++] = start;
    while (head < tail) {
        int v = q[head++];
        for (int w = 0; w < n; w++)
            if (g_adjm[v][w] && !g_visited[w]) {
                g_visited[w] = 1;
                g_dist[w] = g_dist[v] + 1;
                q[tail++] = w;
            }
    }
}
TAG(gbfs_circular_queue);
void gbfs_circular_queue(int start) {
    MARK(gbfs_circular_queue);
    int q[GN], head = 0, tail = 0;
    g_visited[start] = 1;
    q[tail] = start; tail = (tail + 1) & (GN - 1);
    while (head != tail) {
        int v = q[head]; head = (head + 1) & (GN - 1);
        for (int i = 0; i < g_deg[v]; i++) {
            int w = g_adj[v][i];
            if (!g_visited[w]) {
                g_visited[w] = 1;
                q[tail] = w; tail = (tail + 1) & (GN - 1);
            }
        }
    }
}
TAG(gbfs_levels);
int gbfs_levels(int start) {
    MARK(gbfs_levels);
    int q[GN], head = 0, tail = 0, level = 0;
    for (int i = 0; i < GN; i++) g_dist[i] = -1;
    g_dist[start] = 0;
    q[tail++] = start;
    while (head < tail) {
        int v = q[head++];
        level = g_dist[v];
        for (int i = 0; i < g_deg[v]; i++) {
            int w = g_adj[v][i];
            if (g_dist[w] < 0) {
                g_dist[w] = g_dist[v] + 1;
                q[tail++] = w;
            }
        }
    }
    return level;
}
TAG(gbfs_parent_reconstruct);
void gbfs_parent_reconstruct(int start, int target) {
    MARK(gbfs_parent_reconstruct);
    int q[GN], head = 0, tail = 0;
    for (int i = 0; i < GN; i++) g_parent[i] = -1;
    g_parent[start] = start;
    q[tail++] = start;
    while (head < tail) {
        int v = q[head++];
        if (v == target) break;
        for (int i = 0; i < g_deg[v]; i++) {
            int w = g_adj[v][i];
            if (g_parent[w] < 0) {
                g_parent[w] = v;
                q[tail++] = w;
            }
        }
    }
}
TAG(gbfs_multi_source);
void gbfs_multi_source(const int *sources, int ns) {
    MARK(gbfs_multi_source);
    int q[GN], head = 0, tail = 0;
    for (int i = 0; i < ns; i++) {
        g_visited[sources[i]] = 1;
        q[tail++] = sources[i];
    }
    while (head < tail) {
        int v = q[head++];
        for (int i = 0; i < g_deg[v]; i++) {
            int w = g_adj[v][i];
            if (!g_visited[w]) {
                g_visited[w] = 1;
                q[tail++] = w;
            }
        }
    }
}
TAG(gbfs_bidirectional_probe);
int gbfs_bidirectional_probe(int a, int b) {
    MARK(gbfs_bidirectional_probe);
    /* front-wave collision check between two BFS fronts */
    uint8_t fa[GN] = {0}, fb[GN] = {0};
    int qa[GN], qb[GN], ha = 0, ta = 0, hb = 0, tb = 0;
    fa[a] = 1; qa[ta++] = a;
    fb[b] = 1; qb[tb++] = b;
    while (ha < ta && hb < tb) {
        int v = qa[ha++];
        if (fb[v]) return 1;
        for (int i = 0; i < g_deg[v]; i++)
            if (!fa[g_adj[v][i]]) { fa[g_adj[v][i]] = 1; qa[ta++] = g_adj[v][i]; }
        int w = qb[hb++];
        if (fa[w]) return 1;
        for (int i = 0; i < g_deg[w]; i++)
            if (!fb[g_adj[w][i]]) { fb[g_adj[w][i]] = 1; qb[tb++] = g_adj[w][i]; }
    }
    return 0;
}
TAG(gbfs_grid);
int gbfs_grid(int sx, int sy, int tx, int ty) {
    MARK(gbfs_grid);
    static const int dx[4] = {1, -1, 0, 0};
    static const int dy[4] = {0, 0, 1, -1};
    int qx[GN * GN], qy[GN * GN], head = 0, tail = 0;
    uint8_t seen[GN][GN] = {{0}};
    seen[sx][sy] = 1;
    qx[tail] = sx; qy[tail] = sy; tail++;
    while (head < tail) {
        int x = qx[head], y = qy[head]; head++;
        if (x == tx && y == ty) return 1;
        for (int d = 0; d < 4; d++) {
            int nx = x + dx[d], ny = y + dy[d];
            if (nx >= 0 && nx < GN && ny >= 0 && ny < GN && !seen[nx][ny]) {
                seen[nx][ny] = 1;
                qx[tail] = nx; qy[tail] = ny; tail++;
            }
        }
    }
    return 0;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)gbfs_queue_array,      (variant_fn)gbfs_circular_queue,
    (variant_fn)gbfs_levels,           (variant_fn)gbfs_parent_reconstruct,
    (variant_fn)gbfs_multi_source,     (variant_fn)gbfs_bidirectional_probe,
    (variant_fn)gbfs_grid,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

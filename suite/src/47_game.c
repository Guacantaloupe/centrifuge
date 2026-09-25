/* 47. Game / Interactive family — entity update, AABB physics, pathfinding, RNG. */
#include <stddef.h>
#include <stdint.h>
#include <math.h>
#include <stdlib.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(ga_lcg_next);
uint32_t ga_lcg_next(uint32_t *state) {
    MARK(ga_lcg_next);
    *state = *state * 1664525u + 1013904223u;
    return *state;
}
TAG(ga_xorshift32);
uint32_t ga_xorshift32(uint32_t *state) {
    MARK(ga_xorshift32);
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}
TAG(ga_rng_range);
int ga_rng_range(uint32_t *state, int lo, int hi) {
    MARK(ga_rng_range);
    return lo + (int)(ga_xorshift32(state) % (uint32_t)(hi - lo + 1));
}
struct ga_vec2 { float x, y; };
TAG(ga_vec_len);
float ga_vec_len(struct ga_vec2 v) {
    MARK(ga_vec_len);
    return sqrtf(v.x * v.x + v.y * v.y);
}
TAG(ga_vec_norm);
struct ga_vec2 ga_vec_norm(struct ga_vec2 v) {
    MARK(ga_vec_norm);
    float l = ga_vec_len(v);
    if (l > 0.0f) { v.x /= l; v.y /= l; }
    return v;
}
TAG(ga_dist_sq);
float ga_dist_sq(struct ga_vec2 a, struct ga_vec2 b) {
    MARK(ga_dist_sq);
    float dx = a.x - b.x, dy = a.y - b.y;
    return dx * dx + dy * dy;
}
TAG(ga_angle_lerp);
float ga_angle_lerp(float a, float b, float t) {
    MARK(ga_angle_lerp);
    float d = b - a;
    while (d > 3.14159265f) d -= 6.2831853f;
    while (d < -3.14159265f) d += 6.2831853f;
    return a + d * t;
}
TAG(ga_aabb_overlap);
int ga_aabb_overlap(float ax, float ay, float aw, float ah, float bx, float by, float bw, float bh) {
    MARK(ga_aabb_overlap);
    return ax < bx + bw && ax + aw > bx && ay < by + bh && ay + ah > by;
}
TAG(ga_swept_step);
struct ga_vec2 ga_swept_step(struct ga_vec2 pos, struct ga_vec2 vel, float dt) {
    MARK(ga_swept_step);
    pos.x += vel.x * dt;
    pos.y += vel.y * dt;
    return pos;
}
TAG(ga_grid_astar_manhattan);
int ga_grid_astar_manhattan(int sx, int sy, int tx, int ty, const uint8_t *walls, int w, int h) {
    MARK(ga_grid_astar_manhattan);
    /* simplified greedy best-first with manhattan heuristic, 4-dir */
    int x = sx, y = sy, steps = 0;
    while ((x != tx || y != ty) && steps < 256) {
        int dx = tx > x ? 1 : tx < x ? -1 : 0;
        int dy = ty > y ? 1 : ty < y ? -1 : 0;
        if (dx && !walls[y * w + (x + dx)]) x += dx;
        else if (dy && !walls[(y + dy) * w + x]) y += dy;
        else if (dx) x += dx;
        else if (dy) y += dy;
        else break;
        steps++;
    }
    return (x == tx && y == ty) ? steps : -1;
}
TAG(ga_bresenham);
int ga_bresenham(int x0, int y0, int x1, int y1, int *out_x, int *out_y, int max_n) {
    MARK(ga_bresenham);
    int dx = abs(x1 - x0), sx = x0 < x1 ? 1 : -1;
    int dy = -abs(y1 - y0), sy = y0 < y1 ? 1 : -1;
    int err = dx + dy, n = 0;
    for (;;) {
        if (n < max_n) { out_x[n] = x0; out_y[n] = y0; }
        n++;
        if (x0 == x1 && y0 == y1) break;
        int e2 = 2 * err;
        if (e2 >= dy) { err += dy; x0 += sx; }
        if (e2 <= dx) { err += dx; y0 += sy; }
    }
    return n;
}
TAG(ga_line_of_sight);
int ga_line_of_sight(int x0, int y0, int x1, int y1, const uint8_t *walls, int w, int h) {
    MARK(ga_line_of_sight);
    int xs[64], ys[64];
    int n = ga_bresenham(x0, y0, x1, y1, xs, ys, 64);
    for (int i = 0; i < n && i < 64; i++)
        if (xs[i] >= 0 && xs[i] < w && ys[i] >= 0 && ys[i] < h && walls[ys[i] * w + xs[i]])
            return 0;
    return 1;
}
struct ga_entity { struct ga_vec2 pos, vel; int hp; int alive; };
TAG(ga_update_entities);
int ga_update_entities(struct ga_entity *ents, int n, float dt) {
    MARK(ga_update_entities);
    int alive = 0;
    for (int i = 0; i < n; i++) {
        if (!ents[i].alive) continue;
        ents[i].pos = ga_swept_step(ents[i].pos, ents[i].vel, dt);
        if (ents[i].hp <= 0) ents[i].alive = 0;
        else alive++;
    }
    return alive;
}
TAG(ga_separation);
void ga_separation(struct ga_entity *ents, int n, float radius) {
    MARK(ga_separation);
    float r2 = radius * radius;
    for (int i = 0; i < n; i++) {
        if (!ents[i].alive) continue;
        for (int j = i + 1; j < n; j++) {
            if (!ents[j].alive) continue;
            float d2 = ga_dist_sq(ents[i].pos, ents[j].pos);
            if (d2 < r2 && d2 > 0.0f) {
                float d = sqrtf(d2);
                float push = (radius - d) * 0.5f / d;
                ents[i].pos.x += (ents[i].pos.x - ents[j].pos.x) * push;
                ents[i].pos.y += (ents[i].pos.y - ents[j].pos.y) * push;
                ents[j].pos.x -= (ents[i].pos.x - ents[j].pos.x) * push;
                ents[j].pos.y -= (ents[i].pos.y - ents[j].pos.y) * push;
            }
        }
    }
}
TAG(ga_score_combo);
int ga_score_combo(int base, int combo) {
    MARK(ga_score_combo);
    /* diminishing returns combo multiplier */
    int mult = 100;
    for (int i = 0; i < combo && i < 10; i++) mult += 25;
    return base * mult / 100;
}
TAG(ga_cooldown_ticks);
int ga_cooldown_ticks(int last_used, int now, int cooldown) {
    MARK(ga_cooldown_ticks);
    return now - last_used >= cooldown;
}
TAG(ga_frame_interp);
struct ga_vec2 ga_frame_interp(struct ga_vec2 prev, struct ga_vec2 cur, float alpha) {
    MARK(ga_frame_interp);
    struct ga_vec2 r;
    r.x = prev.x + (cur.x - prev.x) * alpha;
    r.y = prev.y + (cur.y - prev.y) * alpha;
    return r;
}
TAG(ga_spatial_hash);
uint32_t ga_spatial_hash(int x, int y) {
    MARK(ga_spatial_hash);
    return (uint32_t)(x * 73856093 ^ y * 19349663);
}
TAG(ga_fps_avg);
float ga_fps_avg(const float *deltas, int n) {
    MARK(ga_fps_avg);
    float sum = 0.0f;
    for (int i = 0; i < n; i++) sum += deltas[i];
    return sum > 0.0f ? (float)n / sum : 0.0f;
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    (variant_fn)ga_lcg_next,         (variant_fn)ga_xorshift32,
    (variant_fn)ga_rng_range,        (variant_fn)ga_vec_len,
    (variant_fn)ga_vec_norm,         (variant_fn)ga_dist_sq,
    (variant_fn)ga_angle_lerp,       (variant_fn)ga_aabb_overlap,
    (variant_fn)ga_swept_step,       (variant_fn)ga_grid_astar_manhattan,
    (variant_fn)ga_bresenham,        (variant_fn)ga_line_of_sight,
    (variant_fn)ga_update_entities,  (variant_fn)ga_separation,
    (variant_fn)ga_score_combo,      (variant_fn)ga_cooldown_ticks,
    (variant_fn)ga_frame_interp,     (variant_fn)ga_spatial_hash,
    (variant_fn)ga_fps_avg,
};
int main(void) {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}

/* 26. Physics family. */
#include <stddef.h>
#include <math.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

struct body { double x, y, vx, vy, m; };

TAG(ph_euler_explicit);
void ph_euler_explicit(struct body *b, int n, double dt) {
    MARK(ph_euler_explicit);
    for (int i = 0; i < n; i++) {
        b[i].x += b[i].vx * dt;
        b[i].y += b[i].vy * dt;
    }
}
TAG(ph_euler_semi);
void ph_euler_semi(struct body *b, int n, double dt, double ax, double ay) {
    MARK(ph_euler_semi);
    for (int i = 0; i < n; i++) {
        b[i].vx += ax * dt;
        b[i].vy += ay * dt;
        b[i].x += b[i].vx * dt;
        b[i].y += b[i].vy * dt;
    }
}
TAG(ph_verlet);
void ph_verlet(double *pos, double *acc, int n, double dt) {
    MARK(ph_verlet);
    for (int i = 1; i < n - 1; i++) {
        double next = 2 * pos[i] - pos[i - 1] + acc[i] * dt * dt;
        pos[i - 1] = pos[i];
        pos[i] = next;
    }
}
TAG(ph_rk2);
double ph_rk2(double y0, double t0, double dt, int steps) {
    MARK(ph_rk2);
    double y = y0, t = t0;
    for (int i = 0; i < steps; i++) {
        double k1 = -y;
        double k2 = -(y + dt * k1);
        y += dt * (k1 + k2) / 2;
        t += dt;
    }
    return y;
}
TAG(ph_rk4);
double ph_rk4(double y0, double dt, int steps) {
    MARK(ph_rk4);
    double y = y0;
    for (int i = 0; i < steps; i++) {
        double k1 = -y;
        double k2 = -(y + dt * k1 / 2);
        double k3 = -(y + dt * k2 / 2);
        double k4 = -(y + dt * k3);
        y += dt * (k1 + 2 * k2 + 2 * k3 + k4) / 6;
    }
    return y;
}
TAG(ph_spring);
void ph_spring(double *x, double *v, int n, double dt, double k, double damp) {
    MARK(ph_spring);
    for (int i = 0; i < n; i++) {
        double a = -k * x[i] - damp * v[i];
        v[i] += a * dt;
        x[i] += v[i] * dt;
    }
}
TAG(ph_nbody_naive);
void ph_nbody_naive(struct body *b, int n, double dt) {
    MARK(ph_nbody_naive);
    for (int i = 0; i < n; i++) {
        double ax = 0, ay = 0;
        for (int j = 0; j < n; j++) {
            if (i == j) continue;
            double dx = b[j].x - b[i].x, dy = b[j].y - b[i].y;
            double r2 = dx * dx + dy * dy + 1e-9;
            double f = b[j].m / (r2 * sqrt(r2));
            ax += f * dx;
            ay += f * dy;
        }
        b[i].vx += ax * dt;
        b[i].vy += ay * dt;
    }
    for (int i = 0; i < n; i++) {
        b[i].x += b[i].vx * dt;
        b[i].y += b[i].vy * dt;
    }
}
struct qnode {
    double cx, cy, half, mass;
    struct body *b;
    struct qnode *kids[4];
};
static struct qnode g_qnodes[256];
static int g_qnext;
TAG(ph_barnes_hut_step);
void ph_barnes_hut_step(struct qnode *node, struct body *b, double dt) {
    MARK(ph_barnes_hut_step);
    if (!node || node->mass == 0) return;
    double dx = node->cx - b->x, dy = node->cy - b->y;
    double r2 = dx * dx + dy * dy;
    double s = node->half * 2;
    if (s * s < r2 * 0.25 || !node->kids[0]) {
        double f = node->mass / (r2 * sqrt(r2) + 1e-9);
        b->vx += f * dx * dt;
        b->vy += f * dy * dt;
        return;
    }
    for (int k = 0; k < 4; k++) ph_barnes_hut_step(node->kids[k], b, dt);
}
TAG(ph_collision_response);
void ph_collision_response(struct body *a, struct body *b) {
    MARK(ph_collision_response);
    double dx = b->x - a->x, dy = b->y - a->y;
    double d = sqrt(dx * dx + dy * dy);
    if (d == 0 || d > 1.0) return;
    double nx = dx / d, ny = dy / d;
    double p = 2 * (a->vx * nx + a->vy * ny - b->vx * nx - b->vy * ny) /
               (a->m + b->m);
    a->vx -= p * b->m * nx;
    a->vy -= p * b->m * ny;
    b->vx += p * a->m * nx;
    b->vy += p * a->m * ny;
}
TAG(ph_aabb_sweep);
int ph_aabb_sweep(double x, double vx, double lo, double hi, double *t) {
    MARK(ph_aabb_sweep);
    if (vx > 0) {
        *t = (hi - x) / vx;
        return x < hi;
    }
    if (vx < 0) {
        *t = (lo - x) / vx;
        return x > lo;
    }
    *t = 1e30;
    return x >= lo && x <= hi;
}
struct quat { double w, x, y, z; };
TAG(ph_quat_mul);
struct quat ph_quat_mul(struct quat a, struct quat b) {
    MARK(ph_quat_mul);
    struct quat r = {a.w * b.w - a.x * b.x - a.y * b.y - a.z * b.z,
                     a.w * b.x + a.x * b.w + a.y * b.z - a.z * b.y,
                     a.w * b.y - a.x * b.z + a.y * b.w + a.z * b.x,
                     a.w * b.z + a.x * b.y - a.y * b.x + a.z * b.w};
    return r;
}
TAG(ph_quat_integrate);
struct quat ph_quat_integrate(struct quat q, double wx, double wy, double wz,
                              double dt) {
    MARK(ph_quat_integrate);
    q.w += 0.5 * dt * (-q.x * wx - q.y * wy - q.z * wz);
    q.x += 0.5 * dt * (q.w * wx + q.y * wz - q.z * wy);
    q.y += 0.5 * dt * (q.w * wy - q.x * wz + q.z * wx);
    q.z += 0.5 * dt * (q.w * wz + q.x * wy - q.y * wx);
    double n = sqrt(q.w * q.w + q.x * q.x + q.y * q.y + q.z * q.z);
    struct quat r = {q.w / n, q.x / n, q.y / n, q.z / n};
    return r;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)ph_euler_explicit,   (variant_fn)ph_euler_semi,
    (variant_fn)ph_verlet,           (variant_fn)ph_rk2,
    (variant_fn)ph_rk4,              (variant_fn)ph_spring,
    (variant_fn)ph_nbody_naive,      (variant_fn)ph_barnes_hut_step,
    (variant_fn)ph_collision_response,(variant_fn)ph_aabb_sweep,
    (variant_fn)ph_quat_mul,         (variant_fn)ph_quat_integrate,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)g_qnodes; (void)g_qnext;
    (void)sink;
    return 0;
}

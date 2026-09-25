/* 25. Geometry family. */
#include <stddef.h>
#include <stdlib.h>
#include <math.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

struct v2 { double x, y; };
struct v3 { double x, y, z; };

TAG(geo_dot2);
double geo_dot2(struct v2 a, struct v2 b) {
    MARK(geo_dot2);
    return a.x * b.x + a.y * b.y;
}
TAG(geo_cross3);
struct v3 geo_cross3(struct v3 a, struct v3 b) {
    MARK(geo_cross3);
    struct v3 r = {a.y * b.z - a.z * b.y,
                   a.z * b.x - a.x * b.z,
                   a.x * b.y - a.y * b.x};
    return r;
}
TAG(geo_normalize3);
struct v3 geo_normalize3(struct v3 a) {
    MARK(geo_normalize3);
    double len = sqrt(a.x * a.x + a.y * a.y + a.z * a.z);
    if (len == 0) len = 1;
    struct v3 r = {a.x / len, a.y / len, a.z / len};
    return r;
}
TAG(geo_aabb_branch);
int geo_aabb_branch(struct v3 bmin, struct v3 bmax, struct v3 ro,
                    struct v3 rd) {
    MARK(geo_aabb_branch);
    double tmin = 0, tmax = 1e30;
    int ok = 1;
    for (int i = 0; i < 3 && ok; i++) {
        double o = i == 0 ? ro.x : i == 1 ? ro.y : ro.z;
        double d = i == 0 ? rd.x : i == 1 ? rd.y : rd.z;
        double mn = i == 0 ? bmin.x : i == 1 ? bmin.y : bmin.z;
        double mx = i == 0 ? bmax.x : i == 1 ? bmax.y : bmax.z;
        if (d == 0) {
            if (o < mn || o > mx) ok = 0;
        } else {
            double t1 = (mn - o) / d, t2 = (mx - o) / d;
            if (t1 > t2) { double t = t1; t1 = t2; t2 = t; }
            tmin = t1 > tmin ? t1 : tmin;
            tmax = t2 < tmax ? t2 : tmax;
            if (tmin > tmax) ok = 0;
        }
    }
    return ok;
}
TAG(geo_aabb_slab);
int geo_aabb_slab(struct v3 bmin, struct v3 bmax, struct v3 ro, struct v3 rd) {
    MARK(geo_aabb_slab);
    double tmin = ((bmin.x - ro.x) / rd.x), tmax = ((bmax.x - ro.x) / rd.x);
    if (tmin > tmax) { double t = tmin; tmin = tmax; tmax = t; }
    double tymin = (bmin.y - ro.y) / rd.y, tymax = (bmax.y - ro.y) / rd.y;
    if (tymin > tymax) { double t = tymin; tymin = tymax; tymax = t; }
    if (tmin > tymax || tymin > tmax) return 0;
    if (tymin > tmin) tmin = tymin;
    if (tymax < tmax) tmax = tymax;
    double tzmin = (bmin.z - ro.z) / rd.z, tzmax = (bmax.z - ro.z) / rd.z;
    if (tzmin > tzmax) { double t = tzmin; tzmin = tzmax; tzmax = t; }
    return !(tmin > tzmax || tzmin > tmax);
}
TAG(geo_ray_triangle);
int geo_ray_triangle(struct v3 ro, struct v3 rd, struct v3 a, struct v3 b,
                     struct v3 c, double *t) {
    MARK(geo_ray_triangle);
    /* Moller-Trumbore */
    struct v3 e1 = {b.x - a.x, b.y - a.y, b.z - a.z};
    struct v3 e2 = {c.x - a.x, c.y - a.y, c.z - a.z};
    struct v3 pv = {rd.y * e2.z - rd.z * e2.y,
                    rd.z * e2.x - rd.x * e2.z,
                    rd.x * e2.y - rd.y * e2.x};
    double det = e1.x * pv.x + e1.y * pv.y + e1.z * pv.z;
    if (det > -1e-9 && det < 1e-9) return 0;
    double inv = 1.0 / det;
    struct v3 tv = {ro.x - a.x, ro.y - a.y, ro.z - a.z};
    double u = (tv.x * pv.x + tv.y * pv.y + tv.z * pv.z) * inv;
    if (u < 0 || u > 1) return 0;
    struct v3 qv = {tv.y * e1.z - tv.z * e1.y,
                    tv.z * e1.x - tv.x * e1.z,
                    tv.x * e1.y - tv.y * e1.x};
    double v = (rd.x * qv.x + rd.y * qv.y + rd.z * qv.z) * inv;
    if (v < 0 || u + v > 1) return 0;
    *t = (e2.x * qv.x + e2.y * qv.y + e2.z * qv.z) * inv;
    return 1;
}
TAG(geo_ray_sphere);
int geo_ray_sphere(struct v3 ro, struct v3 rd, struct v3 center, double r,
                   double *t) {
    MARK(geo_ray_sphere);
    double ox = ro.x - center.x, oy = ro.y - center.y, oz = ro.z - center.z;
    double b = ox * rd.x + oy * rd.y + oz * rd.z;
    double c = ox * ox + oy * oy + oz * oz - r * r;
    double disc = b * b - c;
    if (disc < 0) return 0;
    *t = -b - sqrt(disc);
    return *t > 0;
}
TAG(geo_segment_intersect);
int geo_segment_intersect(struct v2 p1, struct v2 p2, struct v2 p3,
                          struct v2 p4, struct v2 *out) {
    MARK(geo_segment_intersect);
    double d = (p2.x - p1.x) * (p4.y - p3.y) - (p2.y - p1.y) * (p4.x - p3.x);
    if (d == 0) return 0;
    double t = ((p3.x - p1.x) * (p4.y - p3.y) -
                (p3.y - p1.y) * (p4.x - p3.x)) / d;
    double u = ((p3.x - p1.x) * (p2.y - p1.y) -
                (p3.y - p1.y) * (p2.x - p1.x)) / d;
    if (t < 0 || t > 1 || u < 0 || u > 1) return 0;
    out->x = p1.x + t * (p2.x - p1.x);
    out->y = p1.y + t * (p2.y - p1.y);
    return 1;
}
static int cmp_angle(const void *pa, const void *pb) {
    const struct v2 *a = (const struct v2 *)pa, *b = (const struct v2 *)pb;
    return a->x * b->y - a->y * b->x < 0 ? -1 : 1;
}
TAG(geo_convex_hull_graham);
int geo_convex_hull_graham(struct v2 *pts, int n, struct v2 *out) {
    MARK(geo_convex_hull_graham);
    /* pts[0] assumed lowest point; sort rest by polar angle */
    struct v2 p0 = pts[0];
    for (int i = 1; i < n; i++) {
        pts[i].x -= p0.x;
        pts[i].y -= p0.y;
    }
    qsort(pts + 1, (size_t)(n - 1), sizeof(struct v2), cmp_angle);
    int k = 0;
    for (int i = 0; i < n; i++) {
        while (k >= 2) {
            struct v2 a = out[k - 2], b = out[k - 1], c = pts[i];
            if ((b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x) > 0)
                break;
            k--;
        }
        out[k++] = pts[i];
    }
    return k;
}
TAG(geo_convex_hull_monotonic);
int geo_convex_hull_monotonic(struct v2 *p, int n, struct v2 *out) {
    MARK(geo_convex_hull_monotonic);
    int k = 0;
    for (int i = 0; i < n; i++) {
        while (k >= 2) {
            struct v2 a = out[k - 2], b = out[k - 1], c = p[i];
            if ((b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x) > 0)
                break;
            k--;
        }
        out[k++] = p[i];
    }
    int lower = k + 1;
    for (int i = n - 2; i >= 0; i--) {
        while (k >= lower) {
            struct v2 a = out[k - 2], b = out[k - 1], c = p[i];
            if ((b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x) > 0)
                break;
            k--;
        }
        out[k++] = p[i];
    }
    return k - 1;
}
TAG(geo_point_in_polygon);
int geo_point_in_polygon(struct v2 pt, const struct v2 *poly, int n) {
    MARK(geo_point_in_polygon);
    int inside = 0;
    for (int i = 0, j = n - 1; i < n; j = i++) {
        int cross = ((poly[i].y > pt.y) != (poly[j].y > pt.y)) &&
                    (pt.x < (poly[j].x - poly[i].x) * (pt.y - poly[i].y) /
                                    (poly[j].y - poly[i].y) +
                                poly[i].x);
        if (cross) inside = !inside;
    }
    return inside;
}
TAG(geo_closest_point_segment);
struct v2 geo_closest_point_segment(struct v2 p, struct v2 a, struct v2 b) {
    MARK(geo_closest_point_segment);
    double dx = b.x - a.x, dy = b.y - a.y;
    double len2 = dx * dx + dy * dy;
    double t = len2 ? ((p.x - a.x) * dx + (p.y - a.y) * dy) / len2 : 0;
    t = t < 0 ? 0 : t > 1 ? 1 : t;
    struct v2 r = {a.x + t * dx, a.y + t * dy};
    return r;
}
TAG(geo_sat_aabb);
int geo_sat_aabb(struct v2 c1, struct v2 h1, struct v2 c2, struct v2 h2) {
    MARK(geo_sat_aabb);
    double dx = c2.x - c1.x, px = h1.x + h2.x - (dx < 0 ? -dx : dx);
    if (px <= 0) return 0;
    double dy = c2.y - c1.y, py = h1.y + h2.y - (dy < 0 ? -dy : dy);
    return py > 0;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)geo_dot2,       (variant_fn)geo_cross3,
    (variant_fn)geo_normalize3, (variant_fn)geo_aabb_branch,
    (variant_fn)geo_aabb_slab,  (variant_fn)geo_ray_triangle,
    (variant_fn)geo_ray_sphere, (variant_fn)geo_segment_intersect,
    (variant_fn)geo_convex_hull_graham, (variant_fn)geo_convex_hull_monotonic,
    (variant_fn)geo_point_in_polygon,   (variant_fn)geo_closest_point_segment,
    (variant_fn)geo_sat_aabb,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

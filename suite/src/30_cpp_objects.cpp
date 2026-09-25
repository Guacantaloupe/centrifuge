/* 30. C++ Object Recovery family — the RTTI/vtable/ctor-dtor stressor. */
#include <cstddef>
#include <cstdint>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)
TAG(b1_ctor);
TAG(b1_dtor);
TAG(b1_field);
TAG(b1_kind);
TAG(b1_use_inherit);
TAG(bo_ctor);
TAG(bo_dtor);
TAG(bo_left);
TAG(bo_right);
TAG(bt_ctor);
TAG(bt_dtor);
TAG(bt_top);
TAG(ci_area);
TAG(ci_ctor);
TAG(ci_dtor);
TAG(ci_name);
TAG(cx_add);
TAG(cx_assign_copy);
TAG(cx_assign_move);
TAG(cx_bump);
TAG(cx_ctor_copy);
TAG(cx_ctor_default);
TAG(cx_ctor_int);
TAG(cx_ctor_move);
TAG(cx_dtor);
TAG(cx_plus);
TAG(cx_total);
TAG(cx_use_counter);
TAG(cx_value);
TAG(d1_ctor);
TAG(d1_dtor);
TAG(d1_field);
TAG(d1_kind);
TAG(di_use_bottom);
TAG(ia_clone);
TAG(ia_exec);
TAG(ib_clone);
TAG(ib_exec);
TAG(id);
TAG(if_dtor);
TAG(if_use_iface);
TAG(lf_ctor);
TAG(lf_dtor);
TAG(lf_left);
TAG(mi_use_both);
TAG(ml_ctor);
TAG(ml_dtor);
TAG(ml_top);
TAG(mr_ctor);
TAG(mr_dtor);
TAG(mr_top);
TAG(rc_area);
TAG(rc_ctor);
TAG(rc_dtor);
TAG(rc_name);
TAG(rt_ctor);
TAG(rt_dtor);
TAG(rt_right);
TAG(rt_use_dynamic_cast);
TAG(sh_area);
TAG(sh_ctor);
TAG(sh_dtor);
TAG(sh_name);
TAG(sh_scale);
TAG(sh_use_shapes);
TAG(sq_ctor);
TAG(sq_dtor);
TAG(sq_name);
TAG(tp_ctor);
TAG(tp_dtor);
TAG(tp_top);

/* simple class with ctor/dtor/copy/move */
class Counter {
public:
    Counter();
    explicit Counter(int v);
    Counter(const Counter &o);
    Counter(Counter &&o) noexcept;
    Counter &operator=(const Counter &o);
    Counter &operator=(Counter &&o) noexcept;
    ~Counter();
    int value() const;
    static int total();
    Counter &add(int d);
    Counter operator+(const Counter &o) const;
    void bump();
private:
    int v_;
    static int total_;
};
int Counter::total_ = 0;
Counter::Counter() : v_(0) { MARK(cx_ctor_default); ++total_; }
Counter::Counter(int v) : v_(v) { MARK(cx_ctor_int); ++total_; }
Counter::Counter(const Counter &o) : v_(o.v_) { MARK(cx_ctor_copy); ++total_; }
Counter::Counter(Counter &&o) noexcept : v_(o.v_) { MARK(cx_ctor_move); o.v_ = 0; ++total_; }
Counter &Counter::operator=(const Counter &o) { MARK(cx_assign_copy); v_ = o.v_; return *this; }
Counter &Counter::operator=(Counter &&o) noexcept { MARK(cx_assign_move); v_ = o.v_; o.v_ = 0; return *this; }
Counter::~Counter() { MARK(cx_dtor); --total_; }
int Counter::value() const { MARK(cx_value); return v_; }
int Counter::total() { MARK(cx_total); return total_; }
Counter &Counter::add(int d) { MARK(cx_add); v_ += d; return *this; }
Counter Counter::operator+(const Counter &o) const { MARK(cx_plus); return Counter(v_ + o.v_); }
void Counter::bump() { MARK(cx_bump); ++v_; }

int cx_use_counter() {
    MARK(cx_use_counter);
    Counter a;
    Counter b(5);
    Counter c = a + b;
    c.add(3).bump();
    Counter d = c;
    Counter e = Counter(1);
    e = d;
    e = Counter(9);
    return c.value() + Counter::total();
}

/* virtual dispatch hierarchy */
class Shape {
public:
    Shape() { MARK(sh_ctor); }
    virtual ~Shape() { MARK(sh_dtor); }
    virtual double area() const { MARK(sh_area); return 0.0; }
    virtual const char *name() const { MARK(sh_name); return "shape"; }
    double scale_area(double k) const { MARK(sh_scale); return area() * k * k; }
};
class Circle : public Shape {
public:
    explicit Circle(double r) : r_(r) { MARK(ci_ctor); }
    ~Circle() override { MARK(ci_dtor); }
    double area() const override { MARK(ci_area); return 3.14159265358979323846 * r_ * r_; }
    const char *name() const override { MARK(ci_name); return "circle"; }
private:
    double r_;
};
class Rect : public Shape {
public:
    Rect(double w, double h) : w_(w), h_(h) { MARK(rc_ctor); }
    ~Rect() override { MARK(rc_dtor); }
    double area() const override { MARK(rc_area); return w_ * h_; }
    const char *name() const override { MARK(rc_name); return "rect"; }
private:
    double w_, h_;
};
class Square : public Rect {
public:
    explicit Square(double s) : Rect(s, s) { MARK(sq_ctor); }
    ~Square() override { MARK(sq_dtor); }
    const char *name() const override { MARK(sq_name); return "square"; }
};

double sh_use_shapes() {
    MARK(sh_use_shapes);
    Shape *shapes[3];
    shapes[0] = new Circle(1.0);
    shapes[1] = new Rect(2.0, 3.0);
    shapes[2] = new Square(2.5);
    double sum = 0;
    for (int i = 0; i < 3; i++) {
        sum += shapes[i]->area();
        shapes[i]->name();
        sum += shapes[i]->scale_area(0.5);
        delete shapes[i];
    }
    return sum;
}

/* single inheritance with fields */
class Base1 {
public:
    Base1() : b_(1) { MARK(b1_ctor); }
    virtual ~Base1() { MARK(b1_dtor); }
    virtual int kind() const { MARK(b1_kind); return 1; }
    int base_field() const { MARK(b1_field); return b_; }
protected:
    int b_;
};
class Derived1 : public Base1 {
public:
    Derived1() : d_(2) { MARK(d1_ctor); }
    ~Derived1() override { MARK(d1_dtor); }
    int kind() const override { MARK(d1_kind); return 2; }
    int derived_field() const { MARK(d1_field); return d_; }
private:
    int d_;
};
int b1_use_inherit() {
    MARK(b1_use_inherit);
    Base1 *p = new Derived1;
    int k = p->kind() + p->base_field();
    delete p;
    return k;
}

/* multiple inheritance */
class Left {
public:
    Left() : l_(10) { MARK(lf_ctor); }
    virtual ~Left() { MARK(lf_dtor); }
    virtual int from_left() const { MARK(lf_left); return l_; }
    int l_;
};
class Right {
public:
    Right() : r_(20) { MARK(rt_ctor); }
    virtual ~Right() { MARK(rt_dtor); }
    virtual int from_right() const { MARK(rt_right); return r_; }
    int r_;
};
class Both : public Left, public Right {
public:
    Both() { MARK(bo_ctor); }
    ~Both() override { MARK(bo_dtor); }
    int from_left() const override { MARK(bo_left); return l_ + 1; }
    int from_right() const override { MARK(bo_right); return r_ + 1; }
};
int mi_use_both() {
    MARK(mi_use_both);
    Both *b = new Both;
    int x = b->from_left() + b->from_right();
    Left *l = b;
    Right *r = b;
    x += l->from_left() + r->from_right();
    delete b;
    return x;
}

/* virtual inheritance diamond */
class Top {
public:
    Top() : t_(1) { MARK(tp_ctor); }
    virtual ~Top() { MARK(tp_dtor); }
    virtual int top() const { MARK(tp_top); return t_; }
    int t_;
};
class MidL : virtual public Top {
public:
    MidL() { MARK(ml_ctor); }
    ~MidL() override { MARK(ml_dtor); }
    int top() const override { MARK(ml_top); return t_ + 1; }
};
class MidR : virtual public Top {
public:
    MidR() { MARK(mr_ctor); }
    ~MidR() override { MARK(mr_dtor); }
    int top() const override { MARK(mr_top); return t_ + 2; }
};
class Bottom : public MidL, public MidR {
public:
    Bottom() { MARK(bt_ctor); }
    ~Bottom() override { MARK(bt_dtor); }
    int top() const override { MARK(bt_top); return t_ + 3; }
};
int di_use_bottom() {
    MARK(di_use_bottom);
    Bottom *b = new Bottom;
    int v = b->top();
    Top *t = b;
    v += t->top();
    delete b;
    return v;
}

/* pure virtual interface hierarchy + covariant-ish return */
struct Iface {
    virtual ~Iface() { MARK(if_dtor); }
    virtual int exec(int x) = 0;
    virtual Iface *clone() = 0;
};
struct ImplA : Iface {
    int exec(int x) override { MARK(ia_exec); return x + 1; }
    Iface *clone() override { MARK(ia_clone); return new ImplA(*this); }
};
struct ImplB : Iface {
    int exec(int x) override { MARK(ib_exec); return x * 2; }
    Iface *clone() override { MARK(ib_clone); return new ImplB(*this); }
};
int if_use_iface(int which, int x) {
    MARK(if_use_iface);
    Iface *p = which ? (Iface *)new ImplA : (Iface *)new ImplB;
    int r = p->exec(x);
    Iface *q = p->clone();
    r += q->exec(r);
    delete q;
    delete p;
    return r;
}

/* RTTI / dynamic_cast */
int rt_use_dynamic_cast(Shape *s) {
    MARK(rt_use_dynamic_cast);
    if (Circle *c = dynamic_cast<Circle *>(s)) return (int)c->area();
    if (Rect *r = dynamic_cast<Rect *>(s)) return (int)r->area();
    return -1;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)cx_use_counter, (variant_fn)sh_use_shapes,
    (variant_fn)b1_use_inherit, (variant_fn)mi_use_both,
    (variant_fn)di_use_bottom,  (variant_fn)if_use_iface,
    (variant_fn)rt_use_dynamic_cast,
};
int main() {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}

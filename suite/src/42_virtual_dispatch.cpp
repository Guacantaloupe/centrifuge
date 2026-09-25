/* 42. C++ Virtual Dispatch family — devirtualization, thunks, vptr chains. */
#include <cstdint>
#include <cstddef>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(vd_device_base);
TAG(vd_device_dtor);
TAG(vd_device_name);
TAG(vd_device_read);
class Device {
public:
    Device() { MARK(vd_device_base); }
    virtual ~Device() { MARK(vd_device_dtor); }
    virtual const char *name() const { MARK(vd_device_name); return "device"; }
    virtual int read(int addr) { MARK(vd_device_read); return addr & 0xff; }
};

TAG(vd_uart_ctor);
TAG(vd_uart_dtor);
TAG(vd_uart_name);
TAG(vd_uart_read);
class Uart : public Device {
public:
    Uart() { MARK(vd_uart_ctor); }
    ~Uart() override { MARK(vd_uart_dtor); }
    const char *name() const override { MARK(vd_uart_name); return "uart"; }
    int read(int addr) override { MARK(vd_uart_read); return (addr * 3 + 1) & 0xff; }
};

TAG(vd_spi_ctor);
TAG(vd_spi_dtor);
TAG(vd_spi_name);
TAG(vd_spi_read);
class Spi : public Device {
public:
    Spi() { MARK(vd_spi_ctor); }
    ~Spi() override { MARK(vd_spi_dtor); }
    const char *name() const override { MARK(vd_spi_name); return "spi"; }
    int read(int addr) override { MARK(vd_spi_read); return (addr ^ 0x5a) & 0xff; }
};

TAG(vd_i2c_ctor);
TAG(vd_i2c_dtor);
TAG(vd_i2c_name);
TAG(vd_i2c_read);
TAG(vd_i2c_extra);
class I2C : public Device {
public:
    I2C() { MARK(vd_i2c_ctor); }
    ~I2C() override { MARK(vd_i2c_dtor); }
    const char *name() const override { MARK(vd_i2c_name); return "i2c"; }
    int read(int addr) override { MARK(vd_i2c_read); return (addr + 7) & 0xff; }
    virtual int burst(int addr, int len) { MARK(vd_i2c_extra); return read(addr) * len; }
};

TAG(vd_dispatch_read);
int vd_dispatch_read(Device *d, int addr) {
    MARK(vd_dispatch_read);
    return d->read(addr);
}
TAG(vd_dispatch_name_len);
int vd_dispatch_name_len(Device *d) {
    MARK(vd_dispatch_name_len);
    const char *n = d->name();
    int l = 0;
    while (n[l]) l++;
    return l;
}
TAG(vd_loop_devices);
int vd_loop_devices(Device **devs, int n, int addr) {
    MARK(vd_loop_devices);
    int s = 0;
    for (int i = 0; i < n; i++) s += devs[i]->read(addr + i);
    return s;
}
TAG(vd_delete_device);
int vd_delete_device(Device *d) {
    MARK(vd_delete_device);
    int r = d->read(0);
    delete d;
    return r;
}
TAG(vd_static_dev_concrete);
int vd_static_dev_concrete(int addr) {
    MARK(vd_static_dev_concrete);
    Uart u; /* statically bound: devirtualization opportunity */
    return u.read(addr);
}
TAG(vd_construct_dispatch);
int vd_construct_dispatch(int which, int addr) {
    MARK(vd_construct_dispatch);
    Device *d;
    switch (which & 3) {
    case 0: d = new Uart(); break;
    case 1: d = new Spi(); break;
    case 2: d = new I2C(); break;
    default: d = new Device(); break;
    }
    int r = d->read(addr);
    delete d;
    return r;
}
TAG(vd_thunk_multi);
class VBaseL {
public:
    virtual ~VBaseL() {}
    virtual int left_id() const { return 1; }
    int l_field = 5;
};
class VBaseR {
public:
    virtual ~VBaseR() {}
    virtual int right_id() const { return 2; }
    int r_field = 6;
};
class VBoth : public VBaseL, public VBaseR {
public:
    ~VBoth() override {}
    int left_id() const override { return 11; }
    int right_id() const override { return 22; }
};
TAG(vd_multi_left);
int vd_multi_left(VBaseL *p) {
    MARK(vd_multi_left);
    return p->left_id() + p->l_field;
}
TAG(vd_multi_right);
int vd_multi_right(VBaseR *p) {
    MARK(vd_multi_right);
    return p->right_id() + p->r_field;
}
TAG(vd_multi_both);
int vd_multi_both(VBoth *p, int pick) {
    MARK(vd_multi_both);
    return pick ? vd_multi_right(p) : vd_multi_left(p); /* thunk adjustments */
}
TAG(vd_abstract_impl);
class AbstractJob {
public:
    virtual ~AbstractJob() {}
    virtual int run(int n) = 0;
    int execute(int n) { return run(n) * 2; }
};
TAG(vd_job_a);
class JobA : public AbstractJob {
public:
    int run(int n) override { MARK(vd_job_a); return n + 1; }
};
TAG(vd_job_b);
class JobB : public AbstractJob {
public:
    int run(int n) override { MARK(vd_job_b); return n * n; }
};
TAG(vd_use_abstract);
int vd_use_abstract(AbstractJob *job, int n) {
    MARK(vd_use_abstract);
    return job->execute(n);
}
TAG(vd_ctor_sees_vptr);
class VInit {
public:
    VInit() { MARK(vd_ctor_sees_vptr); id_at_ctor = name_at_ctor(); }
    virtual ~VInit() {}
    virtual int kind() const { return 1; }
    int name_at_ctor() { return kind(); }
    int id_at_ctor;
};

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    reinterpret_cast<variant_fn>(vd_dispatch_read),
    reinterpret_cast<variant_fn>(vd_dispatch_name_len),
    reinterpret_cast<variant_fn>(vd_loop_devices),
    reinterpret_cast<variant_fn>(vd_delete_device),
    reinterpret_cast<variant_fn>(vd_static_dev_concrete),
    reinterpret_cast<variant_fn>(vd_construct_dispatch),
    reinterpret_cast<variant_fn>(vd_multi_left),
    reinterpret_cast<variant_fn>(vd_multi_right),
    reinterpret_cast<variant_fn>(vd_multi_both),
    reinterpret_cast<variant_fn>(vd_use_abstract),
};
int main() {
    volatile long long sink = 0;
    Device *d = new Uart();
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    sink += vd_construct_dispatch(0, 3) + vd_multi_both(new VBoth(), 1);
    JobA ja;
    sink += vd_use_abstract(&ja, 5);
    VInit vi;
    sink += vi.id_at_ctor;
    delete d;
    (void)sink;
    return 0;
}

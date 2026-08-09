int add(int a, int b) { return a + b; }
int mul(int a, int b) { return a * b; }
int main() {
    int x = add(3, 4);
    int y = mul(x, 2);
    return y - 1;
}

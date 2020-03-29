char c1;
char c2;
char c3;
int main() {
    while (0) {
        putchar('n');
        putchar('o');
        putchar('t');
        putchar(' ');
    }

    c1 = 'o';
    c2 = 'k';
    c3 = 0;
    while (c1) {
        putchar(c1);
        c1 = c2;
        c2 = c3;
    }
}

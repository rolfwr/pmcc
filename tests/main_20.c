char x;
char y;
char xx;
char yy;
char c;
int main() {
    x = 0;
    y = 0;
    xx = 0;
    yy = 0;
    while (y < 17) {
        while (x < 17) {
            c = '\\';
            if (x < y) {
                c = '*';
            }

            if (y < x) {
                c = '.';
            }

            putchar(c);

            x = x + 1;
            xx = xx + 15;
        }
        putchar('\n');
        x = 0;
        xx = 0;
        y = y + 1;
        yy = yy + 15;
    }
}

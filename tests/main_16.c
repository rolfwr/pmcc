char remaining;
char number;
char outnum;
char huns;
char tens;
char ones;
char notoverflow;
char neg;
char needtens;
char fizz;
char buzz;
char neednum;

int main() {
    remaining = 100;
    number = 0;
    fizz = 3;
    buzz = 5;
    while (remaining) {
        remaining = remaining - 1;
        number = number - 255;
        fizz = fizz - 1;
        buzz = buzz - 1;
        neednum = 1;
        if (!fizz) {
            fizz = 3;
            putchar('F');
            putchar('i');
            putchar('z');
            putchar('z');
            neednum = 0;
        }

        if (!buzz) {
            buzz = 5;
            putchar('B');
            putchar('u');
            putchar('z');
            putchar('z');
            neednum = 0;
        }

        if (neednum) {
            outnum = number;
            huns = 0;
            tens = 0;
            ones = 0;
            while (outnum) {
                outnum = outnum - 1;

                ones = ones - 255;
                notoverflow = 10 - ones;
                if (!notoverflow) {
                    ones = 0;
                    tens = tens - 255;
                }

                notoverflow = 10 - tens;
                if (!notoverflow) {
                    tens = 0;
                    huns = huns - 255;
                }
            }

            neg = 0 - '0';

            needtens = tens;
            if (huns) {
                putchar(huns - neg);
                needtens = 1;
            }

            if (needtens) {
                putchar(tens - neg);
            }

            putchar(ones - neg);
        }
        putchar('\n');
    }
}

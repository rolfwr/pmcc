char number;
char outnum;
char huns;
char tens;
char ones;
char notoverflow;
char needtens;
char fizz;
char buzz;
char neednum;

int main() {
    number = 0;
    fizz = 3;
    buzz = 5;
    while (number - 100) {
        number = number + 1;
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

                ones = ones + 1 ;
                notoverflow = 10 - ones;
                if (!notoverflow) {
                    ones = 0;
                    tens = tens + 1;
                }

                notoverflow = 10 - tens;
                if (!notoverflow) {
                    tens = 0;
                    huns = huns + 1;
                }
            }

            needtens = tens;
            if (huns) {
                putchar('0' + huns);
                needtens = 1;
            }

            if (needtens) {
                putchar('0' + tens);
            }

            putchar('0' + ones);
        }
        putchar('\n');
    }
}

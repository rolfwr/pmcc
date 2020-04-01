char number;
char huns;
char tens;
char ones;
char needtens;
char fizz;
char buzz;
char neednum;

char acc;
char tmp;

void divide_by_ten() {
    tmp = 0;
    if (79 < acc) {
        tmp = tmp + 8;
        acc = acc - 80;
    }

    if (39 < acc) {
        tmp = tmp + 4;
        acc = acc - 40;
    }

    if (19 < acc) {
        tmp = tmp + 2;
        acc = acc - 20;
    }

    if (9 < acc) {
        tmp = tmp + 1;
        acc = acc - 10;
    }

    acc = tmp;
}

void multiply_by_ten() {
    tmp = acc + acc;
    tmp = tmp + tmp + acc;
    acc = tmp + tmp;
}

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
            ones = number;

            acc = ones;
            divide_by_ten();
            tens = acc;
            multiply_by_ten();
            ones = ones - acc;

            acc = tens;
            divide_by_ten();
            huns = acc;
            multiply_by_ten();
            tens = tens - acc;

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

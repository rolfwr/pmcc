void a() {
    putchar('a');
}

void par() {
    putchar('(');
    a();
    putchar(')');
}

void brak() {
    putchar('[');
    a();
    par();
    putchar(']');
}

void curl() {
    putchar('{');
    a();
    par();
    brak();
    putchar('}');
}


int main() {
    curl();
}
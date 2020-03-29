char false_;
char true_;
char also_false_;
char also_true_;
int main() {
    true_ = 1;
    false_ = 0;
    also_false_ = 256;
    also_true_ = 255;
    if (false_) putchar('n');
    if (true_) putchar('o');
    if (also_false_) putchar('t');
    if (false_) putchar(' ');
    if (false_) putchar('o');
    if (also_true_) putchar('k');
}

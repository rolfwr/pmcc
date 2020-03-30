char count;
char letter;
int main() {
    count = 26;
    letter = 'a';
    while (count) {
        putchar(letter);
        letter = letter - 255;
        count = count - 1;
    }

    putchar('\n');
}

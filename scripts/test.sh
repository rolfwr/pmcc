#! /bin/sh

set -e

cc -g -Wall main.c -o main

gccflags="-Wno-implicit-function-declaration -Wno-overflow"

for t in tests/test*.c; do
    echo $t
    gcc -o $t.gcc $gccflags -c $t
    ./main $t
    mv out.rw2a $t.rw2a
done

for t in tests/main*.c; do
    echo $t
    gcc -o $t.gcc $gccflags $t
    $t.gcc > $t.gcc.out
    ./main $t
    mv out.rw2a $t.rw2a
    ../rwisa-vm/src/c/vm-rwa2-4 $t.rw2a > $t.rw2a.out
    diff -u $t.gcc.out $t.rw2a.out
done
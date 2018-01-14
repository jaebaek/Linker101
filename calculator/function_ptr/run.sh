#!/usr/bin/env sh
gcc fptr.c

echo "Function pointer print in C:"
./a.out
echo ""

echo "Dump square using objdump:"
objdump -d a.out | grep 'square' -a5

/*
 * To compile this file,
 *
 *    $ gcc -o run run.c -ldl
 *    $ ./run
 */

#include <stdio.h>
#include <dlfcn.h>

int main(int argc, const char *argv[])
{
    void *handle;
    int (*mult)(int, int);

    // 1. using dlopen, open "./libcalc.so" with RTLD_LAZY flag
    //    and let |handle| keep it.
    // 2. let |mult| point out "multiply" function.

    printf("multiply test:\n");
    printf("13 * 7 = %d\n", mult(13, 7));
    return 0;
}

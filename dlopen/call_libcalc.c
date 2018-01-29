// Note that explicit dynamic linking needs the help of libdl.so.
// You must add -ldl option when building the executable.

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(int argc, const char *argv[])
{
    void *handle;
    int (*f_add)(int, int);
    int (*f_mult)(int, int);
    
    // open libcalc.so
    handle = dlopen("../calculator/libcalc.so", RTLD_LAZY);

    // get symbol "add"
    f_add = (int (*)(int, int)) dlsym(handle, "add");

    // get symbol "multiply"
    f_mult = (int (*)(int, int)) dlsym(handle, "multiply");

    printf("Test #1: 13 + 27 == %d\n", f_add(13, 27));
    printf("Test #2: 13 * 27 == %d\n", f_mult(13, 27));
    return 0;
}

#include <stdio.h>
#include "tinylinker.h"

int main(int argc, const char *argv[])
{
    void* handle0 = tlopen("./program/libcalc.so");
    void* handle1 = tlopen("./program/test");

    int (*test_main)() = (int (*)()) tlentry(handle1);
    return test_main();
}

#include <stdio.h>
#include "tinylinker.h"

int main(int argc, const char *argv[])
{
    void* handle = tlopen("./program/libcalc.so", TL_ELF_TYPE_SHARED);
    return 0;
}

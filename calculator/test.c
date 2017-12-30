#include <stdio.h>

#include "add.h"
#include "multiply.h"

int main(int argc, const char *argv[])
{
    printf("Test #1: 13 + 27 == %d\n", add(13, 27));
    printf("Test #2: 13 * 27 == %d\n", multiply(13, 27));
    return 0;
}

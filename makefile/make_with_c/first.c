#include <stdio.h>

void call_second();

int main(int argc, const char *argv[])
{
    printf("run first\n");
    call_second();
    return 0;
}

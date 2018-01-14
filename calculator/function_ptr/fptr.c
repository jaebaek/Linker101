#include <stdio.h>
#include <stdint.h>

int square(int n) { return n * n; }

int main(int argc, const char *argv[])
{
    void *ptr;
    int i;
   
    ptr = (void *)square;
    for (i = 0;i < 16; ++i) {
        printf("%02x ", ((uint8_t *)ptr)[i]);
    }
    printf("\n");

    return 0;
}

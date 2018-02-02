#include <stdio.h>

double function_add(int a, float b) {
    return (double)a + (double)b;
}

int main(int argc, const char *argv[])
{
    unsigned i;
    double (*f)(int, float) = function_add;

    /* calling a function using function pointer */
    printf("12 + 3.7 = %f\n", f(12, 3.7));
    printf("\n");

    /* print binary to compare it with the result of
     * objdump command */
    printf("Binary of function_add:\n");
    for (i = 0; i < 17; ++i) {
        printf("%02x ", ((unsigned char *)f)[i]);
        if (i == 7)
            printf("\n");
    }
    printf("\n");
    return 0;
}

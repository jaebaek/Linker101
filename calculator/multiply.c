#include "add.h"
#include "multiply.h"

int multiply(int a, int b) {
    int result = 0;
    int i = 0;

    for (i = 0; i < b; ++i) {
        result += a;
    }
    return result;
}

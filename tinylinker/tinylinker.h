#include <stdint.h>

typedef enum TL_ELF_TYPE {
    TL_ELF_TYPE_EXEC,
    TL_ELF_TYPE_SHARED,
    TL_ELF_TYPE_STATIC,
    TL_ELF_TYPE_RELOC,
} tltype_t;

void* tlopen(const char* name, tltype_t type);

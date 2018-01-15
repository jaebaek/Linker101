#include <stdint.h>
#include <stdbool.h>

#include "elf_common.h"
#include "elfstructs.h"

/* man 2 open */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* man 2 stat, read */
#include <unistd.h>

/* man 2 mmap */
#include <sys/mman.h>

#include <endian.h>
#if BYTE_ORDER == BIG_ENDIAN
# define byteorder ELFDATA2MSB
#elif BYTE_ORDER == LITTLE_ENDIAN
# define byteorder ELFDATA2LSB
#else
# error "Unknown BYTE_ORDER " BYTE_ORDER
# define byteorder ELFDATANONE
#endif

#include <stdio.h>

static Elf64_Ehdr *ehdr;

bool validate_ehdr(void)
{
    static const unsigned char expected[EI_NIDENT] =
    {
        [EI_MAG0] = ELFMAG0,
        [EI_MAG1] = ELFMAG1,
        [EI_MAG2] = ELFMAG2,
        [EI_MAG3] = ELFMAG3,
        [EI_CLASS] = ELFCLASS64,
        [EI_DATA] = byteorder,
        [EI_VERSION] = EV_CURRENT,
        [EI_OSABI] = ELFOSABI_SYSV,
        [EI_ABIVERSION] = 0
    };
    if ((ehdr = GET_OBJ(Elf64_Ehdr, 0)) == NULL) {
        dlog("%u: Ehdr size", __LINE__);
        return false;
    }
    if (memcmp(ehdr->e_ident, expected, EI_ABIVERSION)
            || ehdr->e_ident[EI_ABIVERSION] != 0
            || memcmp(&ehdr->e_ident[EI_PAD], &expected[EI_PAD],
                EI_NIDENT - EI_PAD)) {
        dlog("%u: Ehdr ident", __LINE__);
        return false;
    }
    if (ehdr->e_version != EV_CURRENT) {
        dlog("%u: Ehdr version", __LINE__);
        return false;
    }
    /* ELF format check - dynamic library */
    if (ehdr->e_type != ET_DYN) {
        dlog("%u: Ehdr not relocatable", __LINE__);
        return false;
    }
    /* check the architecture - currently only support x86_64 */
    if (ehdr->e_machine != EM_X86_64) {
        dlog("%u: Ehdr not x86_64", __LINE__);
        return false;
    }
    if (ehdr->e_shentsize != sizeof (Elf64_Shdr)) {
        dlog("%u: Shdr entry size", __LINE__);
        return false;
    }

    /* read shdr */
    if ((shdr = GET_OBJ(Elf64_Shdr, ehdr->e_shoff)) == NULL) {
        dlog("%u: no shdr", __LINE__);
        return false;
    }
    return true;
}

int main(int argc, const char *argv[])
{
    return 0;
}

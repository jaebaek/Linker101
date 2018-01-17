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

/* man 3 malloc */
#include <stdlib.h>

/* man 3 memcpy */
#include <string.h>

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

#define dlog printf

#include "tinylinker.h"
#include "tinylinker_internal.h"

uint64_t file_size(int fd) {
    struct stat buf;
    fstat(fd, &buf);
    return buf.st_size;
}

#define PAGE_SIZE 0x1000

uint64_t get_pages(uint64_t n) {
    if (n % PAGE_SIZE == 0) return n;
    return ((n / PAGE_SIZE) + 1) * PAGE_SIZE;
}

#define GET_OBJ(type, base, offset) \
     (type*) ((uint64_t)(base) + (uint64_t)(offset))

bool validate_ehdr(Elf64_Ehdr *ehdr, tltype_t type)
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
    if (ehdr->e_type != (type == TL_ELF_TYPE_SHARED ? ET_DYN : ET_EXEC)) {
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
    return true;
}

void *load(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr)
{
    /*
    size_t max_align = 0;
    for (unsigned i = 0;i < ehdr->e_phnum;++i) {
        if (phdr[i].p_type == PT_LOAD && max_align < phdr[i].p_align)
            max_align = phdr[i].p_align;
    }
    encl_base = roundup(max_align, encl_base);
    */

    unsigned i;
    uint64_t program = 0;
    uint64_t load_end = 0;
    uint64_t mem = (uint64_t) ehdr;

    for (i = 0;i < ehdr->e_phnum;++i) {
        if (phdr[i].p_type == PT_LOAD && load_end < phdr[i].p_vaddr + phdr[i].p_memsz)
            load_end = phdr[i].p_vaddr + phdr[i].p_memsz;
    }

    if (load_end) {
        program = (uint64_t) mmap(NULL, get_pages(load_end),
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    } else
        return NULL;

    for (i = 0;i < ehdr->e_phnum;++i) {
        if (phdr[i].p_type == PT_LOAD) {
            memcpy((void *)(program + phdr[i].p_vaddr),
                   (void *)(mem + phdr[i].p_offset),
                    phdr[i].p_filesz);
            if (phdr[i].p_filesz < phdr[i].p_memsz)
                bzero((void *)(program + phdr[i].p_vaddr + phdr[i].p_filesz),
                        phdr[i].p_memsz - phdr[i].p_filesz);

            /* TODO: permission setup
               mprotect(((phdr[i].p_flags & PF_R) ? PROT_EXEC : 0) |
               ((phdr[i].p_flags & PF_W) ? PROT_WRITE : 0) |
               ((phdr[i].p_flags & PF_X) ? PROT_READ : 0))
        } else if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)( encl_base + phdr[i].p_vaddr );
        }
               */
        }
    }
    return (void *) program;
}

void *tlopen(const char *name,  tltype_t type) {
    tlhandle_t *handle;
    if (type != TL_ELF_TYPE_EXEC && type != TL_ELF_TYPE_SHARED)
        return NULL;

    handle = (tlhandle_t *) malloc(sizeof(tlhandle_t));
    handle->fd = open(name, O_RDONLY);
    handle->fsz = file_size(handle->fd);
    handle->memmap = mmap(NULL, get_pages(handle->fsz),
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE, handle->fd, 0);

    handle->ehdr = (Elf64_Ehdr *) handle->memmap;
    validate_ehdr(handle->ehdr, type);

    handle->phdr = (Elf64_Phdr *) ((uint64_t) handle->memmap + (uint64_t) handle->ehdr->e_phoff);
    load(handle->ehdr, handle->phdr);
}

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

#define dlog(msg, ...) printf(msg "\n", __VA_ARGS__)
#define dlog_i

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
    unsigned i;
    uint64_t vaddr_base = 0;
    uint64_t load_end = 0;
    uint64_t file = (uint64_t) ehdr;

    for (i = 0;i < ehdr->e_phnum;++i) {
        if (phdr[i].p_type == PT_LOAD && load_end < phdr[i].p_vaddr + phdr[i].p_memsz)
            load_end = phdr[i].p_vaddr + phdr[i].p_memsz;
    }

    if (load_end) {
        vaddr_base = (uint64_t) mmap(NULL, get_pages(load_end),
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    } else
        return NULL;

    for (i = 0;i < ehdr->e_phnum;++i) {
        if (phdr[i].p_type == PT_LOAD) {
            memcpy((void *)(vaddr_base + phdr[i].p_vaddr),
                   (void *)(file + phdr[i].p_offset),
                    phdr[i].p_filesz);
            if (phdr[i].p_filesz < phdr[i].p_memsz)
                bzero((void *)(vaddr_base + phdr[i].p_vaddr + phdr[i].p_filesz),
                        phdr[i].p_memsz - phdr[i].p_filesz);

            /* TODO: permission setup
               mprotect(((phdr[i].p_flags & PF_R) ? PROT_EXEC : 0) |
               ((phdr[i].p_flags & PF_W) ? PROT_WRITE : 0) |
               ((phdr[i].p_flags & PF_X) ? PROT_READ : 0))
               */
        }
    }
    return (void *) vaddr_base;
}

uint64_t find_dynamic(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr)
{
    unsigned i;
    for (i = 0;i < ehdr->e_phnum;++i) {
        if (phdr[i].p_type == PT_DYNAMIC)
            return phdr[i].p_vaddr;
    }
    return 0;
}

uint64_t find_symbol_from_lib(tlhandle_t *handle, const char *name)
{
    unsigned i;
    Elf64_Sym *sym;
    const char *strtab;

    sym = (Elf64_Sym *)((uint64_t) handle->memmap + handle->dyn.symtab);
    strtab = (const char *)((uint64_t) handle->memmap + handle->dyn.strtab);
    for (i = 1; i < handle->symtabsz/sizeof(Elf64_Sym); ++i) {
        dlog_i("symbol %u: %s", i, &strtab[sym[i].st_name]);
        if (!strcmp(name, &strtab[sym[i].st_name])) {
            dlog_i("find symbol %u: %s", i, &strtab[sym[i].st_name]);
            return sym[i].st_value;
        }
    }
    return 0;
}

uint32_t update_dynsym(uint64_t symtabsz, Elf64_Sym *sym, uint64_t symtab, uint64_t base)
{
    unsigned i;
    uint64_t sym_vaddr;

    /* iterate .dynsym */
    for (i = 1; i < symtabsz/sizeof(Elf64_Sym); ++i) {
        if (sym[i].st_shndx == SHN_UNDEF) {
            sym_vaddr = 0;
            /* get symbol from another shared lib */
                // dlog("%u th symbol in .dynsym is not found", i);
            /* get symbol from pre-define set */
        } else {
            sym[i].st_value += base;
        }
    }
}

uint64_t get_symtab_size(Elf64_Shdr *shdr, uint32_t shnum, uint64_t symtab)
{
    unsigned i;
    for (i = 0; i < shnum; ++i)
        if (shdr[i].sh_addr == symtab)
            return shdr[i].sh_size;
    return 0;
}

//void Loader::get_symbols(extsym_t *esym, size_t nesym)
//{
//    Elf64_Sym *sym = (Elf64_Sym *)(encl_base + dinfo.symtab);
//    char *strtab = (char *)(encl_base + dinfo.strtab);
//    for (unsigned i = 1; i < dinfo.symtabsz/sizeof(Elf64_Sym); ++i) {
//        if (sym[i].st_shndx != SHN_UNDEF) {
//            for (unsigned j = 0;j < nesym;++j)
//                if (!strcmp(esym[j].name, &strtab[sym[i].st_name])) {
//                    *(esym[j].value) = sym[i].st_value;
//                    dlog("%s is %lx\n", esym[j].name, *(esym[j].value));
//                }
//        }
//    }
//}

#define GET_DT(elem) \
    dinfo->elem = (uint64_t)e->d_un.d_ptr; break
bool read_dynamic(Elf64_Dyn *dyn, dyninfo_t *dinfo)
{
    Elf64_Dyn *e;

    /* read entries of dynamic section */
    for (e = dyn;e->d_tag != DT_NULL;++e) {
        switch (e->d_tag) {
            case DT_NEEDED:
                dlog("%u: DT_NEEDED (dynamic linking) is not supported", __LINE__);
                return false;
            case DT_HASH: GET_DT(hash);

            //---- symbol and relocation tables related ----
            case DT_STRTAB: GET_DT(strtab);
            case DT_SYMTAB: GET_DT(symtab);
            case DT_STRSZ: GET_DT(strsz);
            case DT_SYMENT:
                if (e->d_un.d_val != sizeof(Elf64_Sym)) {
                    dlog("%u: SYMENT is not %lu", __LINE__, sizeof(Elf64_Sym));
                    return false;
                }
                break;
            case DT_RELA: GET_DT(rela);
            case DT_RELASZ: GET_DT(relasz);
            case DT_RELAENT:
                if (e->d_un.d_val != sizeof(Elf64_Rela)) {
                    dlog("%u: RELAENT is not %lu", __LINE__, sizeof(Elf64_Rela));
                    return false;
                }
                break;

            //---- plt, got related ----
            case DT_PLTGOT: GET_DT(pltgot);
            case DT_PLTRELSZ: GET_DT(pltrelsz);
            case DT_PLTREL: /* expected DT_RELA */ GET_DT(pltrel);
            case DT_JMPREL: GET_DT(jmprel);

            case DT_TEXTREL: break;
            case DT_RELACOUNT: GET_DT(relacount);
            default:
                dlog("%u: not supported d_tag: %ld", __LINE__, e->d_tag);
                return false;
        }
    }

    return true;
//    /* update values of special symbols in .dynsym */
//    update_dynsym(dinfo.symtab, (char *)(encl_base + dinfo.strtab),
//            spec_dsym, nspec_dsym);
}

void relocate(Elf64_Sym *symtab, Elf64_Rela *reltab, unsigned nrel, uint64_t vaddr_base)
{
    unsigned i;
    uint64_t ofs;
    uint32_t sym;
    uint32_t type;

    for (i = 0;i < nrel;++i) {
        ofs = vaddr_base + reltab[i].r_offset;
        sym = ELF64_R_SYM(reltab[i].r_info);
        type = ELF64_R_TYPE(reltab[i].r_info);

        if (type == R_X86_64_64) { /* word 64 */
            *(uint64_t *)ofs = symtab[sym].st_value + reltab[i].r_addend;
            dlog_i("%lx\n", *(uint64_t *)ofs);
        } else if (type == R_X86_64_32) { /* word 32 */
            *(uint32_t*)ofs = (uint32_t)(symtab[sym].st_value + reltab[i].r_addend);
            dlog_i("%x\n", *(uint32_t *)ofs);
        } else if (type == R_X86_64_32S) { /* word 32 */
            *(int32_t*)ofs = (int32_t)(symtab[sym].st_value + reltab[i].r_addend);
            dlog_i("%x\n", *(int32_t *)ofs);
        } else if (type == R_X86_64_PC32 || type == R_X86_64_PLT32) { /* word 32 */
            *(uint32_t*)ofs = (uint32_t)(symtab[sym].st_value - ofs
                    + reltab[i].r_addend);
            dlog_i("%x\n", *(uint32_t *)ofs);
        } else if (type == R_X86_64_GOTPCREL) { /* word 32 */
            *(uint32_t*)ofs = (uint32_t)((Elf64_Addr)&(symtab[sym].st_value)
                    - ofs + reltab[i].r_addend);
            dlog_i("%x\n", *(uint32_t *)ofs);
        } else if (type == R_X86_64_RELATIVE) { /* word 64 */
            *(uint64_t *)ofs += vaddr_base;
            dlog_i("%lx\n", *(uint64_t *)ofs);
        } else if (type == R_X86_64_JMP_SLOT || type == R_X86_64_GLOB_DAT) {
            /* word 64 */
            *(uint64_t *)ofs = symtab[sym].st_value;
            dlog_i("JMP_SLOT %lx\n", *(uint64_t *)ofs);
        } else
            dlog("%u: Relocation -- not supported type %u", __LINE__, type);
    }
}

void *tlopen(const char *name,  tltype_t type) {
    tlhandle_t *handle;
    uint64_t dynamic;
    Elf64_Dyn *dyn;
    Elf64_Sym *sym;
    Elf64_Shdr *shdr;

    if (type != TL_ELF_TYPE_EXEC && type != TL_ELF_TYPE_SHARED)
        return NULL;

    /* mmap ELF file */
    handle = (tlhandle_t *) malloc(sizeof(tlhandle_t));
    handle->fd = open(name, O_RDONLY);
    handle->fsz = file_size(handle->fd);
    handle->memmap = mmap(NULL, get_pages(handle->fsz),
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE, handle->fd, 0);

    /* check ELF header */
    handle->ehdr = (Elf64_Ehdr *) handle->memmap;
    validate_ehdr(handle->ehdr, type);

    /* load based program header */
    handle->phdr = (Elf64_Phdr *) ((uint64_t) handle->memmap + (uint64_t) handle->ehdr->e_phoff);
    handle->vaddr_base = load(handle->ehdr, handle->phdr);
    if (handle->vaddr_base == NULL) {
        dlog("%u: nothing to load", __LINE__);
        return NULL;
    }

    /* read dynamic section */
    dynamic = find_dynamic(handle->ehdr, handle->phdr);
    dyn = (Elf64_Dyn *)((uint64_t) handle->vaddr_base + dynamic);
    read_dynamic(dyn, &handle->dyn);

    /* get symbol table size */
    shdr = (Elf64_Shdr *) ((uint64_t) handle->memmap + (uint64_t) handle->ehdr->e_shoff);
    handle->symtabsz = get_symtab_size(shdr, handle->ehdr->e_shnum, handle->dyn.symtab);
    if (!handle->symtabsz) {
        dlog("%u: symbol table size is 0", __LINE__);
        return NULL;
    }

    /* update symbol table --> fill undefined symbol locations */
    sym = (Elf64_Sym *)((uint64_t) handle->memmap + handle->dyn.symtab);
    update_dynsym(handle->symtabsz, sym, handle->dyn.symtab, (uint64_t) handle->vaddr_base);

    /* relocate */
    relocate(sym, (Elf64_Rela *)((uint64_t) handle->memmap + handle->dyn.jmprel),
            handle->dyn.pltrelsz / sizeof(Elf64_Rela), (uint64_t) handle->vaddr_base);

    int (*f)(int, int) = (int (*)(int, int) ) find_symbol_from_lib(handle, "multiply");
    printf("3 X 4 = %d\n", f(3, 4));
}

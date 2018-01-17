/* data used in dynamic linking */
struct dynlink_info {
    uint64_t hash; // TODO: currently, .hash is not used .. improve performance! */
    uint64_t strtab;
    uint64_t symtab;
    size_t symtabsz;
    uint64_t strsz;
    uint64_t pltgot;
    uint64_t pltrelsz;
    uint64_t pltrel;
    uint64_t jmprel;
    uint64_t rela;
    uint64_t relasz;
    uint64_t relacount; /* I think this is meaningless .. */
};

typedef struct dynlink_info dyninfo_t;

typedef struct tl_handle {
    // for file op
    int fd;
    uint64_t fsz;
    void *memmap;

    // ELF
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;

    // load
    void *vaddr_base;
    dyninfo_t dyn;
} tlhandle_t;

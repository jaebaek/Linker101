typedef struct tl_handle {
    // for file op
    int fd;
    uint64_t fsz;
    void *memmap;

    // ELF
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;

    // load
    void *program;
} tlhandle_t;

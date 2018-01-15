#ifndef ENCL_LOADER_H
#define ENCL_LOADER_H

#define errlog printf

typedef unsigned long addr_t;

extern "C" {
extern void jump_to_program(addr_t, addr_t, addr_t, addr_t);
extern void exit_from_program(void);
}

#ifdef LD_DEBUG
#define dlog(...) printf(__VA_ARGS__)
#else
#define dlog(...)
#endif

#include "elf.h"        /* ELF */
#include <inttypes.h>
#include <vector>
#include "../capstone/include/capstone.h"

/* data used in dynamic linking */
struct dynlink_info {
    addr_t hash; // TODO: currently, .hash is not used .. improve performance! */
    addr_t strtab;
    addr_t symtab;
    size_t symtabsz;
    addr_t strsz;
    addr_t pltgot;
    addr_t pltrelsz;
    addr_t pltrel;
    addr_t jmprel;
    addr_t rela;
    addr_t relasz;
    addr_t relacount; /* Jaebaek: I think this is meaningless .. */
};

enum insn_stat {
    SANDBOX_NOT_ENFORCED,
    IN_MID_OF_BUNDLE,
    CORRECT,
};

struct dynsym_t {
    const char *name;
    addr_t value;
};

struct extsym_t {
    const char *name;
    addr_t *value;
};

class Loader {
    private:
        addr_t program;
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        Elf64_Dyn *dyn;
        Elf64_Shdr *shdr;

        uint64_t encl_base;
        dynlink_info dinfo;

        bool validate_ehdr(void);
        bool load(bool is_target);
        void update_dynsym(addr_t symtab, char *strtab,
                dynsym_t *spec_dsym, size_t nspec_dsym);
        void relocate(Elf64_Sym *symtab, Elf64_Rela *reltab, unsigned nrel);
        bool link(dynsym_t *spec_dsym, size_t nspec_dsym);

        addr_t plt;
        size_t plt_size;
        size_t plt_entsz;
        addr_t text;
        size_t text_size;
        char *shstrtab;
        addr_t got;
        size_t got_size;
        size_t got_entsz;

        addr_t get_jump_target(const char *op);
        bool is_register(const char *op);
        const char *get_reg32(const char *op);
        bool check_indirect_br(cs_insn *insn, size_t i, const char *rX,
                const char *eX);
        bool check_change_rzp(cs_insn *insn, size_t i,
                const char *eX);
        insn_stat check_bundle(csh& handle, addr_t pos, bool bundle_only);
    public:
        Loader() {}
        void init(addr_t p) {
            program = p;
            encl_base = 0;

            ehdr = NULL;
            phdr = NULL;
            dyn = NULL;
            shdr = NULL;
            bzero((void *)&dinfo, sizeof(dynlink_info));

            plt = 0;
            plt_size = 0;
            plt_entsz = 0;
            text = 0;
            text_size = 0;
            shstrtab = NULL;
            got = 0;
            got_size = 0;
            got_entsz = 0;
        }

        addr_t load_program(bool is_target,
                dynsym_t *spec_dsym, size_t nspec_dsym);
        void get_symbols(extsym_t *esym, size_t nesym);
        bool update_section();
        bool check_program();
        std::vector<unsigned> data_sections;
        void get_data_sections();
        void init_thread_region(addr_t thread_base);
};

#define NOT_LOADED ((addr_t)-1)
#define LOAD_FAIL ((addr_t)0)

#define THREAD_MEMORY_SIZE 0x100000000;
#define STACK_OFFSET 0x1000000;
extern char __enclave_base;

inline addr_t get_thread_base(unsigned tid) {
    return (addr_t)&__enclave_base + ((addr_t)tid + 1) * THREAD_MEMORY_SIZE;
}
inline addr_t get_stk(unsigned tid) {
    return get_thread_base(tid) + STACK_OFFSET;
}
extern unsigned g_num_tid;
extern addr_t entry;

#endif

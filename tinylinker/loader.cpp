#include <stdint.h>
#include <string.h>
#include <capstone.h>

#include "ocall_type.h"
typedef void (*sighandler_t)(int);
#include "Enclave.h"
#include "loader.h"
#include "Enclave_t.h"  /* print_string */
#include "sgx_trts.h"   /* sgx_read_rand */

//extern char __sgx_base;        /* defined in the linker script */
//extern char __sgx_code;        /* defined in the linker script */
//extern char __sgx_end;         /* defined in the linker script */
//
//#define ENCL_BASE ((addr_t)&__sgx_base)
//#define ENCL_CODE ((addr_t)&__sgx_code)
//#define ENCL_END ((addr_t)&__sgx_end)
extern char __enclave_base;  /* defined in the linker script */
extern char __sgx_end;         /* defined in the linker script */
#define ENCL_BASE ((((addr_t)&__enclave_base) & 0x100000000) + 0x500000000)
#define ENCL_CODE ((((addr_t)&__enclave_base) & 0x100000000) + 0x600000000)
#define ENCL_END (ENCL_CODE + 0x1000000)

#include <endian.h>
#if BYTE_ORDER == BIG_ENDIAN
# define byteorder ELFDATA2MSB
#elif BYTE_ORDER == LITTLE_ENDIAN
# define byteorder ELFDATA2LSB
#else
# error "Unknown BYTE_ORDER " BYTE_ORDER
# define byteorder ELFDATANONE
#endif

uint64_t roundup(uint64_t align, uint64_t n)
{
    if (!align) return n;
    if (n % align) return n - (n % align) + align;
    return n;
}

void cpy(char *dst, const char *src, size_t size) {
    while (size--) dst[size] = src[size];
}

static uint32_t get_rand(void)
{
    uint32_t val;
    sgx_read_rand((unsigned char *)&val, sizeof(uint32_t));
    return val;
}

const char *special_sym [] = {
    "puts",
    "abort",
    "sgx_read_rand",
    "exit",
    // "copy_to_outside", // TODO: provide this!!
};

addr_t special_sym_val [] = {
    (addr_t) ocall_print_string,
    (addr_t) abort,
    (addr_t) sgx_read_rand,
    (addr_t) exit_from_program,
    // (addr_t) copy_to_outside, // TODO: provide this!!
};

const char *reg_info[] = {
    "rax", "eax", "ax", "al",
    "rbx", "ebx", "bx", "bl",
    "rcx", "ecx", "cx", "cl",
    "rdx", "edx", "dx", "dl",
    "rsi", "esi", "si", "sil",
    "rdi", "edi", "di", "dil",
    "rbp", "ebp", "bp", "bpl",
    "rsp", "esp", "sp", "spl",
    "r8", "r8d", "r8w", "r8b",
    "r9", "r9d", "r9w", "r9b",
    "r10", "r10d", "r10w", "r10b",
    "r11", "r11d", "r11w", "r11b",
    "r12", "r12d", "r12w", "r12b",
    "r13", "r13d", "r13w", "r13b",
    "r14", "r14d", "r14w", "r14b",
    "r15", "r15d", "r15w", "r15b",
};

#define GET_OBJ(type, offset) \
     reinterpret_cast<type*>( reinterpret_cast<size_t>(program) \
            + static_cast<size_t>(offset) )
bool Loader::validate_ehdr(void)
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

bool Loader::load(bool is_target)
{
    static addr_t end_of_rwx = 0;

    if (ehdr->e_phnum > 5) {
        dlog("%u: e_phnum = %d", __LINE__, ehdr->e_phnum);
        return false;
    }

    /* read phdr */
    if ((phdr = GET_OBJ(Elf64_Phdr, ehdr->e_phoff)) == NULL) {
        dlog("%u: no phdr", __LINE__);
        return false;
    }

    /* deternmine the base of address */
#if 0 //ASLR: just turn off now
    /* randomize base address */
    size_t max_sz = 0, max_align = 0;
    for (unsigned i = 0;i < ehdr->e_phnum;++i) {
        if (phdr[i].p_type == PT_LOAD) {
            if (max_sz < phdr[i].p_memsz)
                max_sz = phdr[i].p_memsz;
            if (max_align < phdr[i].p_align)
                max_align = phdr[i].p_align;
        }
    }
    max_sz = roundup(max_align, max_sz);
    if (max_sz > ENCL_CODE - ENCL_BASE) {
        dlog("%u: max phdr > %lx - %lx", __LINE__, ENCL_CODE, ENCL_BASE);
        return false;
    }
    sgx_read_rand((unsigned char *)&encl_base, sizeof(uint64_t));
    encl_base = encl_base % (ENCL_CODE - ENCL_BASE - max_sz);
    if (max_align)
        encl_base = ((encl_base/max_align) * max_align) + ENCL_BASE;
#else
    encl_base = is_target ? ENCL_BASE : end_of_rwx;
    if (!is_target) {
        size_t max_align = 0;
        for (unsigned i = 0;i < ehdr->e_phnum;++i) {
            if (phdr[i].p_type == PT_LOAD && max_align < phdr[i].p_align)
                max_align = phdr[i].p_align;
        }
        encl_base = roundup(max_align, encl_base);
    }
#endif
    printf("ENCL_BASE = %lx, encl_base = %lx, ENCL_CODE = %lx, ENCL_END = %lx\n",
            ENCL_BASE, encl_base, ENCL_CODE, ENCL_END);

    // TODO: decrypt and copy
    /* load data */
    for (unsigned i = 0;i < ehdr->e_phnum;++i) {
        if (phdr[i].p_type == PT_LOAD) {
            memcpy((void *)(encl_base + phdr[i].p_vaddr),
                    GET_OBJ(const void, phdr[i].p_offset),
                    phdr[i].p_filesz);
            if (phdr[i].p_filesz < phdr[i].p_memsz)
                bzero((void *)(encl_base + phdr[i].p_vaddr + phdr[i].p_filesz),
                        phdr[i].p_memsz - phdr[i].p_filesz);
            /* validate RWX */
            if (!(phdr[i].p_flags & PF_X) &&
                    ENCL_CODE <= encl_base + phdr[i].p_vaddr &&
                    encl_base + phdr[i].p_vaddr + phdr[i].p_memsz < ENCL_END) {
                dlog("%u: non-executable in RWX region", __LINE__);
                return false;
            }
            if (phdr[i].p_flags & PF_X)
                end_of_rwx = roundup(phdr[i].p_align,
                        encl_base + phdr[i].p_vaddr + phdr[i].p_memsz);
        } else if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)( encl_base + phdr[i].p_vaddr );
        }
    }
    return true;
}

void Loader::update_dynsym(addr_t symtab, char *strtab,
        dynsym_t *spec_dsym, size_t nspec_dsym)
{
    Elf64_Sym *sym = (Elf64_Sym *)(encl_base + symtab);

    /* get symbol table size */
    for (unsigned i = 0; i < ehdr->e_shnum; ++i) {
        if (shdr[i].sh_addr == symtab) {
            dinfo.symtabsz = shdr[i].sh_size;
            break;
        }
    }
    if (dinfo.symtabsz == 0) {
        dlog("%u: .dynsym has 0 size", __LINE__);
        return;
    }

    /* iterate .dynsym */
    for (unsigned i = 1; i < dinfo.symtabsz/sizeof(Elf64_Sym); ++i) {
        if (sym[i].st_shndx == SHN_UNDEF) {
            unsigned found = 0;
            for (unsigned j = 0;j < sizeof(special_sym)/sizeof(const char *);++j)
                if (!strcmp(special_sym[j], &strtab[sym[i].st_name])) {
                    sym[i].st_value = special_sym_val[j];
                    found = 1;
                }
            if (!found) {
                for (unsigned j = 0;j < nspec_dsym;++j)
                    if (!strcmp(spec_dsym[j].name, &strtab[sym[i].st_name])) {
                        sym[i].st_value = spec_dsym[j].value;
                        found = 1;
                    }
            }
            if (!found)
                dlog("%u th symbol in .dynsym is not found", i);
        } else if (sym[i].st_shndx < ehdr->e_shnum && sym[i].st_shndx) {
            sym[i].st_value += encl_base;
        }
    }
}

void Loader::get_symbols(extsym_t *esym, size_t nesym)
{
    Elf64_Sym *sym = (Elf64_Sym *)(encl_base + dinfo.symtab);
    char *strtab = (char *)(encl_base + dinfo.strtab);
    for (unsigned i = 1; i < dinfo.symtabsz/sizeof(Elf64_Sym); ++i) {
        if (sym[i].st_shndx != SHN_UNDEF) {
            for (unsigned j = 0;j < nesym;++j)
                if (!strcmp(esym[j].name, &strtab[sym[i].st_name])) {
                    *(esym[j].value) = sym[i].st_value;
                    dlog("%s is %lx\n", esym[j].name, *(esym[j].value));
                }
        }
    }
}

void Loader::relocate(Elf64_Sym *symtab, Elf64_Rela *reltab, unsigned nrel)
{
    for (unsigned i = 0;i < nrel;++i) {
        unsigned long ofs = encl_base + reltab[i].r_offset;
        unsigned int sym = ELF64_R_SYM(reltab[i].r_info);
        const unsigned int type = ELF64_R_TYPE(reltab[i].r_info);
        if (type == R_X86_64_64) { /* word 64 */
            *(addr_t *)ofs = symtab[sym].st_value + reltab[i].r_addend;
            dlog("%lx\n", *(addr_t *)ofs);
        } else if (type == R_X86_64_32) { /* word 32 */
            *(uint32_t*)ofs = (uint32_t)(symtab[sym].st_value + reltab[i].r_addend);
            dlog("%x\n", *(uint32_t *)ofs);
        } else if (type == R_X86_64_32S) { /* word 32 */
            *(int32_t*)ofs = (int32_t)(symtab[sym].st_value + reltab[i].r_addend);
            dlog("%x\n", *(int32_t *)ofs);
        } else if (type == R_X86_64_PC32 || type == R_X86_64_PLT32) { /* word 32 */
            *(uint32_t*)ofs = (uint32_t)(symtab[sym].st_value - ofs
                    + reltab[i].r_addend);
            dlog("%x\n", *(uint32_t *)ofs);
        } else if (type == R_X86_64_GOTPCREL) { /* word 32 */
            *(uint32_t*)ofs = (uint32_t)((Elf64_Addr)&(symtab[sym].st_value)
                    - ofs + reltab[i].r_addend);
            dlog("%x\n", *(uint32_t *)ofs);
        } else if (type == R_X86_64_RELATIVE) { /* word 64 */
            *(addr_t *)ofs += encl_base;
            dlog("%lx\n", *(addr_t *)ofs);
        } else if (type == R_X86_64_JMP_SLOT || type == R_X86_64_GLOB_DAT) {
            /* word 64 */
            *(addr_t *)ofs = symtab[sym].st_value;
            dlog("JMP_SLOT %lx\n", *(addr_t *)ofs);
        } else
            dlog("%u: Relocation -- not supported type %u", __LINE__, type);
    }
}

#define LINK_FAIL false
#define LINK_SUCCESS true
#define GET_DT(elem) \
    dinfo.elem = (addr_t)e->d_un.d_ptr; break
bool Loader::link(dynsym_t *spec_dsym, size_t nspec_dsym)
{
    Elf64_Dyn *e;

    /* read entries of dynamic section */
    for (e = dyn;e->d_tag != DT_NULL;++e) {
        switch (e->d_tag) {
            case DT_NEEDED:
                dlog("DT_NEEDED (dynamic linking) is not supported");
                return LINK_FAIL;
            case DT_HASH: GET_DT(hash);

            //---- symbol and relocation tables related ----
            case DT_STRTAB: GET_DT(strtab);
            case DT_SYMTAB: GET_DT(symtab);
            case DT_STRSZ: GET_DT(strsz);
            case DT_SYMENT:
                if (e->d_un.d_val != sizeof(Elf64_Sym)) {
                    dlog("SYMENT is not %lu", sizeof(Elf64_Sym));
                    return LINK_FAIL;
                }
                break;
            case DT_RELA: GET_DT(rela);
            case DT_RELASZ: GET_DT(relasz);
            case DT_RELAENT:
                if (e->d_un.d_val != sizeof(Elf64_Rela)) {
                    dlog("RELAENT is not %lu", sizeof(Elf64_Rela));
                    return LINK_FAIL;
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
                dlog("Not supported d_tag: %d", e->d_tag);
                return LINK_FAIL;
        }
    }

    /* update values of special symbols in .dynsym */
    update_dynsym(dinfo.symtab, (char *)(encl_base + dinfo.strtab),
            spec_dsym, nspec_dsym);

    /* do relocation */
    relocate((Elf64_Sym *)(encl_base + dinfo.symtab),
            (Elf64_Rela *)(encl_base + dinfo.rela),
            dinfo.relasz / sizeof(Elf64_Rela));
    if (dinfo.pltrel != DT_RELA) {
        dlog("DT_PLTREL is %lu", dinfo.pltrel);
        return LINK_FAIL;
    }
    relocate((Elf64_Sym *)(encl_base + dinfo.symtab),
            (Elf64_Rela *)(encl_base + dinfo.jmprel),
            dinfo.pltrelsz / sizeof(Elf64_Rela));
    return LINK_SUCCESS;
}

#define CHK_FAIL 0
#define CHK_SUCCESS 1

#define SIGTRAP_INST 0xcc
#define CODE_ALIGNMENT 0x20

#define PLT_SECTION ".plt"
#define TEXT_SECTION ".text"
#define GOT_SECTION ".got.plt"

//------------- program validation ---------------

addr_t Loader::get_jump_target(const char *op) {
    if (op[0] != '0' || op[1] != 'x')
        return 0;
    addr_t t = 0;
    for (unsigned i = 2;op[i];++i) {
        bool tmp = ('0' <= op[i] && op[i] <= '9');
        if (!tmp && !('a' <= op[i] && op[i] <= 'f'))
            return 0;
        t = 16 * t + (tmp ? op[i]-'0' : op[i]-'a'+10);
    }
    return t;
}

bool Loader::is_register(const char *op) {
    return strlen(op) <= 3;
}

const char *Loader::get_reg32(const char *op) {
    for (unsigned i = 0;
            i < sizeof(reg_info)/sizeof(const char *);
            i += 4) {
        if (!strcmp(op, reg_info[i]))
            return reg_info[i + 1];
    }
    return NULL;
}

bool Loader::check_indirect_br(cs_insn *insn, size_t i, const char *rX,
        const char *eX) {
    const char *fail_reason = NULL;
    size_t len = strlen(eX);
    size_t j = i + 3;
    const size_t tmp = sizeof(", qword ptr [") - 1;
    if (i < 0) {
        fail_reason = "# of inst < 3";
        goto check_indirect_br_fail;
    }
    if (strcmp(insn[i].mnemonic, "and")) {
        j = i;
        fail_reason = "no and";
        goto check_indirect_br_fail;
    }
    if (strncmp(insn[i].op_str, eX, len)
            || strcmp(&(insn[i].op_str[len]), ", 0xffffffe0")) {
        j = i;
        fail_reason = "not and eX, $-32";
        goto check_indirect_br_fail;
    }
    if (strcmp(insn[i+1].mnemonic, "sub")) {
        j = i + 1;
        fail_reason = "no sub";
        goto check_indirect_br_fail;
    }
    if (strncmp(insn[i+1].op_str, eX, len)
            || strcmp(&(insn[i+1].op_str[len]), ", r15d")) {
        j = i + 1;
        fail_reason = "not sub eX, r15d";
        goto check_indirect_br_fail;
    }
    if (strcmp(insn[i+2].mnemonic, "lea")) {
        j = i + 2;
        fail_reason = "no lea";
        goto check_indirect_br_fail;
    }
    len = strlen(rX);
    if (strncmp(insn[i+2].op_str, rX, len)
            || strncmp(&(insn[i+2].op_str[len]), ", qword ptr [", tmp)
            || strncmp(&(insn[i+2].op_str[len + tmp]), rX, len)
            || strcmp(&(insn[i+2].op_str[2*len + tmp]), " + r15]")) {
        j = i + 2;
        fail_reason = "not lea rX, [rX + r15]";
        goto check_indirect_br_fail;
    }
    return true;
check_indirect_br_fail:
    errlog("0x%"PRIx64":\t%s\t\t%s // %s\n",
            insn[j].address, insn[j].mnemonic,
            insn[j].op_str, fail_reason);
    return false;
}

bool Loader::check_change_rzp(cs_insn *insn, size_t i,
        const char *eX) {
    const char *fail_reason = NULL;
    size_t j = i + 2;
    if (strcmp(insn[i].mnemonic, "sub")) {
        j = i;
        fail_reason = "no sub";
        goto check_change_rzp_fail;
    }
    if (strncmp(insn[i].op_str, eX, 3)
            || strcmp(&(insn[i].op_str[3]), ", r15d")) {
        j = i;
        fail_reason = "not sub eX, r15d";
        goto check_change_rzp_fail;
    }
    if (strcmp(insn[i+1].mnemonic, "and")) {
        j = i + 1;
        fail_reason = "no and";
        goto check_change_rzp_fail;
    }
    if (strncmp(insn[i+1].op_str, eX, 3)
            || strcmp(&(insn[i+1].op_str[3]), ", 0xffffff")) {
        j = i + 1;
        fail_reason = "not and eX, 0xffffff";
        goto check_change_rzp_fail;
    }
    return true;
check_change_rzp_fail:
    errlog("0x%"PRIx64":\t%s\t\t%s // %s\n",
            insn[j].address, insn[j].mnemonic,
            insn[j].op_str, fail_reason);
    return false;
}

insn_stat Loader::check_bundle(csh& handle, addr_t pos, bool bundle_only) {
    size_t count, j;
    const char *fail_reason = NULL;
    cs_insn *insn = NULL;
    addr_t bundle = pos & -32;
    bool start_of_ins = false; // must be TRUE at the end (not in mid of inst)
    insn_stat ret = CORRECT;
    char *substr;

    count = cs_disasm(handle, (const uint8_t *)bundle, CODE_ALIGNMENT, bundle, 0, &insn);
    if (count > 0) {
        for (j = 0; j < count; j++) {
            start_of_ins |= (pos == insn[j].address);
            // Case #0: prevent program from changing r15
            // Case #1: branch (call, jump, return) must be aligned
            // and not to API region
            if (insn[j].mnemonic[0] == 'j'
                    || !strncmp(insn[j].mnemonic, "call", sizeof("call"))) {
                addr_t target = get_jump_target(insn[j].op_str);
                if (target) { /* direct */
                    if (!bundle_only) {
                        if (insn[j].mnemonic[0] == 'j') {
                            if(check_bundle(handle, target, true) != CORRECT) {
                                fail_reason = "target in mid of inst";
                                goto check_program_fail;
                            }
                        } else {
                            if (!((target % CODE_ALIGNMENT == 0 && ENCL_CODE <= target
                                            && target < ENCL_END)
                                        || (plt <= target && target < (plt + plt_size)
                                            && (target % plt_entsz == 0)))) {
                                fail_reason = "target is weird";
                                goto check_program_fail;
                            }
                        }
                    }
                } else { /* indirect */
                    if (!bundle_only) {
                        const char *eX = get_reg32(insn[j].op_str);
                        if (!eX) {
                            fail_reason = "unknown register";
                            goto check_program_fail;
                        }
                        if (!check_indirect_br(insn, j-3, insn[j].op_str, eX)) {
                            fail_reason = "instrumentation for indirect branch";
                            goto check_program_fail;
                        }
                    }
                    for (size_t k = j-3;k <= j;++k)
                        if (pos == insn[k].address) {
                            fail_reason = "in mid of bundle";
                            ret = IN_MID_OF_BUNDLE;
                            goto check_program_fail;
                        }
                }
            } else if (!strncmp(insn[j].mnemonic, "ret", sizeof("ret"))) {
                fail_reason = "ret is not allowed";
                goto check_program_fail;

            // Case #2: RSP >= R15
            } else if ((substr = strstr(insn[j].op_str, "rsp,"))) {
                if (strcmp(insn[j].mnemonic, "mov")
                        || strcmp(insn[j].op_str, "rsp, rbp")) {
                    if (strcmp(insn[j].mnemonic, "lea")) {
                        fail_reason = "change rsp but not lea";
                        goto check_program_fail;
                    }
                    if (strncmp(insn[j].op_str, "rsp, qword ptr [rsp + r15]",
                                sizeof("rsp, qword ptr [rsp + r15]"))) {
                        fail_reason = "must be lea rsp, qword ptr [rsp + r15]";
                        goto check_program_fail;
                    }
                    if (!check_change_rzp(insn, j-2, "esp")) {
                        fail_reason = "instrumentation for rsp change";
                        goto check_program_fail;
                    }
                }

            // Case #3: [dest of store inst] >= R15
            // TODO

            // Case #4: RBP >= R15
            } else if ((substr = strstr(insn[j].op_str, "rbp,"))) {
                if (strcmp(insn[j].mnemonic, "mov")
                        || strcmp(insn[j].op_str, "rbp, rsp")) {
                    if (strcmp(insn[j].mnemonic, "lea")) {
                        fail_reason = "change rbp but not lea";
                        goto check_program_fail;
                    }
                    if (strncmp(insn[j].op_str, "rbp, qword ptr [rbp + r15]",
                                sizeof("rbp, qword ptr [rbp + r15]"))) {
                        fail_reason = "must be lea rbp, qword ptr [rbp + r15]";
                        goto check_program_fail;
                    }
                    if (!check_change_rzp(insn, j-2, "ebp")) {
                        fail_reason = "instrumentation for rbp change";
                        goto check_program_fail;
                    }
                }

            // Case #5: ENCLU
            // TODO
            }
        }
        cs_free(insn, count);
    } else {
        errlog("ERROR: Failed to disassemble given code!\n");
    }
    if (!start_of_ins) {
        errlog("%lx is in mid of instrunction\n", pos);
        ret = IN_MID_OF_BUNDLE;
        goto check_program_fail;
    }
    return CORRECT;

check_program_fail:
    if (insn) {
        errlog("0x%"PRIx64":\t%s\t\t%s // %s\n",
                insn[j].address, insn[j].mnemonic,
                insn[j].op_str, fail_reason);
        cs_free(insn, count);
    }
    return ret == CORRECT ? SANDBOX_NOT_ENFORCED : ret;
}

addr_t Loader::load_program(bool is_target,
        dynsym_t *spec_dsym, size_t nspec_dsym)
{
    if (!validate_ehdr()) return 0;
    if (!load(is_target)) return 0;
    if (!link(spec_dsym, nspec_dsym)) return 0;
    if (is_target) {
        addr_t entry = (addr_t)ehdr->e_entry + encl_base;
        dlog("main: %p\n", entry);
        return entry;
    } else {
        return (addr_t)-1;
    }
}

bool Loader::update_section() {
    // 1. fill RWX with illegal instructions
    //    except .text and .plt
    // 2. move .got.plt to read-only region
    // 3. update .plt according to the position of new .got.plt

    /* read section string table */
    if ((shstrtab = GET_OBJ(char, shdr[ehdr->e_shstrndx].sh_offset)) == NULL) {
        dlog("%u: no shstrtab (%u th sh)", __LINE__, ehdr->e_shstrndx);
        return false;
    }

    /* find .plt .text .got.plt .rodata sections */
    for (unsigned i = 0; i < ehdr->e_shnum; ++i) {
        if (!strcmp(&shstrtab[shdr[i].sh_name], PLT_SECTION)) {
            plt = (addr_t)(encl_base + shdr[i].sh_addr);
            plt_size = (size_t)shdr[i].sh_size;
            plt_entsz = (size_t)shdr[i].sh_addralign;
        } else if (!strcmp(&shstrtab[shdr[i].sh_name], TEXT_SECTION)) {
            text = (addr_t)(encl_base + shdr[i].sh_addr);
            text_size = (size_t)shdr[i].sh_size;
        } else if (!strcmp(&shstrtab[shdr[i].sh_name], GOT_SECTION)) {
            got = (addr_t)(encl_base + shdr[i].sh_addr);
            got_size = (size_t)shdr[i].sh_size;
            got_entsz = (size_t)shdr[i].sh_addralign;
        }
    }

    /* fill RWX with illegal instructions except .text and .plt */
    addr_t range[4];
    if (plt < text) {
        range[0] = plt;
        range[1] = plt + plt_size;
        range[2] = text;
        range[3] = text + text_size;
    } else {
        range[0] = text;
        range[1] = text + text_size;
        range[2] = plt;
        range[3] = plt + plt_size;
    }
    for (addr_t ptr = ENCL_CODE;ptr < range[0];++ptr)
        *(uint8_t *)ptr = SIGTRAP_INST;
    for (addr_t ptr = range[1];ptr < range[2];++ptr)
        *(uint8_t *)ptr = SIGTRAP_INST;
    for (addr_t ptr = range[3];ptr < ENCL_END;++ptr)
        *(uint8_t *)ptr = SIGTRAP_INST;

    /* fill plt[0] with illegal instructions */
    for (int i = 0; i < plt_entsz; ++i) {
        ((uint8_t *)plt)[i] = SIGTRAP_INST;
    }

    /* move .got.plt to read-only region */
    void *new_got = memalign(got_entsz, got_size);
    int32_t delta_got = (int32_t)((addr_t)new_got - got);
    memcpy(new_got, (const void *)got, got_size);

    /* update .plt according to the position of new .got.plt */
    for (addr_t i = plt_entsz; i < plt_size; i += plt_entsz) {
        int32_t *ptr = (int32_t *)&((uint8_t *)plt)[i + 2];
        dlog("%x --> ", *ptr);
        *ptr = *ptr + delta_got;
        dlog("%x\n", *ptr);
    }
    return true;
}

bool Loader::check_program() {
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        errlog("capstone open fail");
        return false;
    }
    for (size_t i = 0; i < text_size; i += CODE_ALIGNMENT) {
        if (check_bundle(handle, text + i, false) != CORRECT)
            return false;
    }
    cs_close(&handle);
    return true;
}

void Loader::get_data_sections() {
    /* find .bss .data sections */
    for (unsigned i = 0; i < ehdr->e_shnum; ++i) {
        if (shdr[i].sh_flags == (SHF_WRITE | SHF_ALLOC)) {
            if (shdr[i].sh_type != SHT_DYNAMIC
                    && strcmp(&shstrtab[shdr[i].sh_name], GOT_SECTION)) {
                data_sections.push_back(i);
            }
        }
    }
}

void Loader::init_thread_region(addr_t thread_base) {
    for (unsigned i = 0; i < data_sections.size(); ++i) {
        unsigned idx = data_sections[i];
        if (shdr[idx].sh_type == SHT_NOBITS)
            bzero((void *)(thread_base + shdr[idx].sh_addr),
                    (size_t)shdr[idx].sh_size);
        else
            memcpy((void *)(thread_base + shdr[idx].sh_addr),
                    (void *)(encl_base + shdr[idx].sh_addr),
                    (size_t)shdr[idx].sh_size);
    }
}

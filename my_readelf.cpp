//
// Created by Yuehi on 2021-12-01.
//
#include <iostream>
#include <cstdlib>
#include <getopt.h>
#include <elf.h>
#include <iomanip>
#include <bitset>

typedef enum print_type{
    ERROR,
    USAGE,
    VERSION,
    DATA_ERROR,
    FOPEN_ERROR,
    NOSECTIONS,
    NOSECTIONS_ERROR
}print_type;

static struct option options[] = {
        {"help",            no_argument, nullptr, 'H'},
        {"file-header",     no_argument, nullptr, 'h'},
        {"section-headers", no_argument, nullptr, 'S'},
        {"sections",        no_argument, nullptr, 'S'},
        {"symbols",         no_argument, nullptr, 's'},
        {"syms",            no_argument, nullptr, 's'},
        {"version",         no_argument, nullptr, 'v'},
        {nullptr,           no_argument, nullptr, 0}
};

static bool do_header = false;
static bool do_syms = false;
static bool do_sections = false;

static bool print_info(print_type type, void *content = nullptr){
    switch (type) {
        case ERROR:
            std::cout << "my-readelf: Invalid option '-" << (char *)content << "'\n";
        case USAGE:
            std::cout << "Usage: readelf <option(s)> elf-file(s)\n";
            std::cout << " Display information about the contents of ELF format files\n";
            std::cout << " Options are:\n";
            std::cout << "  -h --file-header       Display the ELF file header\n";
            std::cout << "  -S --section-headers   Display the sections' header\n";
            std::cout << "  -s --syms              Display the symbol table\n";
            std::cout << "  -H --help              Display this information\n";
            std::cout << "  -v --version           Display the version number of readelf\n";
            exit(0);
        case VERSION:
            std::cout << "Fake version written by Yuehi.\n";
            std::cout << "Use this program or Watch source code, help yourself.\n";
            break;
        case DATA_ERROR:
            std::cout << "Unhandled data length.\n";
            break;
        case FOPEN_ERROR:
            std::cout << "my-readelf: Error: '" << (char *)content << "': No such file\n";
            return false;
        case NOSECTIONS_ERROR:
            std::cout << "possibly corrupt ELF file header - it has a non-zero section header offset, but no section headers\n";
            return false;
        case NOSECTIONS:
            std::cout << "\nThere are no sections in this file.\n";
            return true;
    }
    return true;
}

static void parse_args(int argc, char **argv){
    if (argc < 2) print_info(USAGE);
    opterr = 0;
    int c;
    while ((c = getopt_long(argc, argv, "HShsv", options, nullptr)) != EOF){
        switch (c) {
            case 0:
            case 'H': print_info(USAGE);
            case 'h':
                do_header = true;
                break;
            case 'S':
                do_sections = true;
                break;
            case 's':
                do_syms = true;
                break;
            case 'v':
                print_info(VERSION);
                break;
            case '?': print_info(ERROR, &optopt);
            default: print_info(USAGE);
        }
    }
    if (do_header || do_sections || do_syms) return;
    print_info(USAGE);
}

static const char *get_elf_class(unsigned int i){
    switch (i) {
        case ELFCLASS32: return "ELF32";
        case ELFCLASS64: return "ELF64";
        default: return "Invalid class";
    }
}

static const char *get_data_encoding(unsigned int i){
    switch (i) {
        case ELFDATA2LSB: return "2's complement, little endian";
        case ELFDATA2MSB: return "2's complement, big endian";
        default: return "Invalid data encoding";
    }
}

static const char *get_osabi_name(unsigned int i){
    switch (i) {
        case ELFOSABI_NONE: return "UNIX System V ABI";
        case ELFOSABI_HPUX: return "HP-UX.";
        case ELFOSABI_NETBSD: return "NetBSD.";
        case ELFOSABI_GNU: return "Object uses GNU ELF extensions.";
        case ELFOSABI_SOLARIS: return "Sun Solaris.";
        case ELFOSABI_AIX: return "IBM AIX.";
        case ELFOSABI_IRIX: return "SGI Irix.";
        case ELFOSABI_FREEBSD: return "FreeBSD.";
        case ELFOSABI_TRU64: return "Compaq TRU64 UNIX.";
        case ELFOSABI_MODESTO: return "Novell Modesto.";
        case ELFOSABI_OPENBSD: return "OpenBSD.";
        case ELFOSABI_ARM_AEABI: return "ARM EABI";
        case ELFOSABI_ARM: return "ARM";
        case ELFOSABI_STANDALONE: return "Standalone (embedded) application";
        default: return "Unknown OS ABI";
    }
}

static const char *get_file_type(unsigned int i){
    switch (i) {
        case ET_NONE: return "No file type";
        case ET_REL: return "Relocatable file";
        case ET_EXEC: return "Executable file";
        case ET_DYN: return "Shared object file";
        case ET_CORE: return "Core file";
        default: return "Unknown file type";
    }
}

static const char *get_machine_name(unsigned int i){
    static char other[2];
    switch (i) {
        case EM_X86_64: return "AMD x86-64 architecture";
        default:
            sprintf(other, "%d", i);
            return other;
    }
}

static const char *get_symbol_type(unsigned char i){
    static char other[4];
    switch (ELF64_ST_TYPE(i)) {
        case STT_NOTYPE: return "NOTYPE";
        case STT_SECTION: return "SECTION";
        case STT_OBJECT: return "OBJECT";
        case STT_FUNC: return "FUNC";
        case STT_FILE: return "FILE";
        default:
            sprintf(other, "%d", ELF64_ST_TYPE(i));
            return other;
    }
}

static const char *get_symbol_bind(unsigned char i){
    static char other[4];
    switch (ELF64_ST_BIND(i)) {
        case STB_LOCAL: return "LOCAL";
        case STB_GLOBAL: return "GLOBAL";
        case STB_WEAK: return "WEAK";
        default:
            sprintf(other, "%d", ELF64_ST_BIND(i));
            return other;
    }
}

static const char *get_symbol_vis(unsigned char i){
    static char other[4];
    switch (ELF64_ST_VISIBILITY(i)) {
        case STV_DEFAULT: return "DEFAULT";
        case STV_INTERNAL: return "INTERNAL";
        case STV_HIDDEN: return "HIDDEN";
        case STV_PROTECTED: return "PROTECTED";
        default: return "Invaild";
    }
}

static const char *get_symbol_index(unsigned short i){
    static char other[4];
    switch (i) {
        case SHN_UNDEF: return "UND";
        case SHN_ABS: return "ABS";
        default:
            sprintf(other, "%d", i);
            return other;
    }
}

static const char *get_section_type(unsigned int i){
    static char other[4];
    switch (i) {
        case SHT_NULL: return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_NOTE: return "NOTE";
        case SHT_GNU_HASH: return "GNU_HASH";
        case SHT_DYNSYM: return "DYNSYM";
        case SHT_STRTAB: return "STRTAB";
        case SHT_GNU_versym: return "GNU_versym";
        case SHT_GNU_verneed: return "GNU_verneed";
        case SHT_RELA: return "RELA";
        case SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
        case SHT_GROUP: return "GROUP";
        case SHT_DYNAMIC: return "DYNAMIC";
        case SHT_NOBITS: return "NOBITS";
        case SHT_SYMTAB: return "SYMTAB";
        case SHT_FINI_ARRAY: return "FINI_ARRAY";
        case SHT_INIT_ARRAY: return "INIT_ARRAY";
        default:
            sprintf(other, "%x", i);
            return other;
    }
}

static const char *get_section_flags(unsigned long int i){
    static char flags[8];
    char *p = flags;
    if (i & SHF_WRITE) *p++ = 'W';
    if (i & SHF_ALLOC) *p++ = 'A';
    if (i & SHF_EXECINSTR) *p++ = 'X';
    if (i & SHF_MERGE) *p++ = 'M';
    if (i & SHF_STRINGS) *p++ = 'S';
    if (i & SHF_INFO_LINK) *p++ = 'I';
    return flags;
}

static bool process_file_header(Elf64_Ehdr *elf_header){
    if (elf_header->e_ident[EI_MAG0] != ELFMAG0
        || elf_header->e_ident[EI_MAG1] != ELFMAG1
        || elf_header->e_ident[EI_MAG2] != ELFMAG2
        || elf_header->e_ident[EI_MAG3] != ELFMAG3)
        return true;

    std::cout << "\nELF Header:\n";
    std::cout << "  Magic:   ";
    std::cout.fill('0');
    for (unsigned int i : elf_header->e_ident) {
        std::cout.width(2);
        std::cout << std::hex << i << " ";
    }
    std::cout << "\n  Class:                             " << get_elf_class(elf_header->e_ident[EI_CLASS]);
    std::cout << "\n  Data:                              " << get_data_encoding(elf_header->e_ident[EI_DATA]);
    std::cout << "\n  Version:                           " << (unsigned int)elf_header->e_ident[EI_VERSION]
              << (elf_header->e_ident[EI_VERSION] == EV_CURRENT ? " (current)" : (elf_header->e_ident[EI_VERSION] != EV_NONE
                                                                                  ? " <unknown>" : ""));
    std::cout << "\n  OS/ABI:                            " << get_osabi_name(elf_header->e_ident[EI_OSABI]);
    std::cout << "\n  ABI Version:                       " << (unsigned int)elf_header->e_ident[EI_ABIVERSION];
    std::cout << "\n  Type:                              " << get_file_type(elf_header->e_type);
    std::cout << "\n  Machine:                           " << get_machine_name(elf_header->e_machine);
    std::cout << "\n  Version:                           0x" << std::hex << elf_header->e_version;
    std::cout << "\n  Entry point address:               0x" << std::hex << elf_header->e_entry;
    std::cout << "\n  Start of program headers:          " <<  std::dec << elf_header->e_phoff;
    std::cout << " (bytes into file)\n  Start of section headers:          " <<  std::dec << elf_header->e_shoff;
    std::cout << " (bytes into file)";
    std::cout << "\n  Flags:                             0x" << std::hex << elf_header->e_flags;
    std::cout << "\n  Size of this header:               " << std::dec << elf_header->e_ehsize;
    std::cout << " (bytes)\n  Size of program headers:           " << std::dec << elf_header->e_phentsize;
    std::cout << " (bytes)\n  Number of program headers:         " << std::dec <<elf_header->e_phnum;
    std::cout << "\n  Size of section headers:           " << std::dec << elf_header->e_shentsize;
    std::cout << " (bytes)\n  Number of section headers:         " << std::dec << elf_header->e_shnum;
    std::cout << "\n  Section header string table index: " << std::dec << elf_header->e_shstrndx;
    std::cout << "\n";
    return false;
}

static bool process_section_headers(FILE *elf_file, Elf64_Ehdr *elf_header){
    unsigned int header_size = sizeof(Elf64_Shdr);
    unsigned int header_num = elf_header->e_shnum;
    unsigned int header_index = 0;
    unsigned int string_table_index = elf_header->e_shstrndx;
    Elf64_Shdr section_headers[header_num];
    Elf64_Shdr string_table_header;
    if (fseek(elf_file, elf_header->e_shoff+string_table_index*header_size, 0)) return true;
    if (fread(&string_table_header, header_size, 1, elf_file) != 1) return true;
    char string_table[string_table_header.sh_size];
    if (fseek(elf_file, string_table_header.sh_offset, 0)) return true;
    if (fread(&string_table, string_table_header.sh_size, 1, elf_file) != 1) return true;
    if (fseek(elf_file, elf_header->e_shoff, 0)) return true;
    std::cout << "\nSection Headers:\n";
    std::cout << "  [Nr]\tName\t\t\tType\t\t\tAddress\t\t\tOffset\t\tSize\tEntSize\tFlags\tLink\tInfo\tAlign\n";
    for (Elf64_Shdr header: section_headers) {
        if (fread(&header, header_size, 1, elf_file) != 1) return true;
        std::cout << "  [" << header_index++ << "]\t";
        std::cout << std::setw(16) << std::setiosflags(std::ios::left) << std::setfill(' ') << &string_table[header.sh_name] << "\t";
        std::cout << std::setw(16) << std::setiosflags(std::ios::left) << std::setfill(' ') << get_section_type(header.sh_type) << " \t";
        std::cout << std::setw(16) << std::resetiosflags(std::ios::left) << std::setfill('0') << std::hex << header.sh_addr << "\t";
        std::cout << std::setw(8) << header.sh_offset << "\t";
        std::cout << std::dec << header.sh_size << "\t";
        std::cout << header.sh_entsize << "\t";
        std::cout << get_section_flags(header.sh_flags) << "\t";
        std::cout << header.sh_link << "\t";
        std::cout << header.sh_info << "\t";
        std::cout << header.sh_addralign;
        std::cout << "\n";
    }
    return false;
}

static bool process_symbol_table(FILE *elf_file, Elf64_Ehdr *elf_header){
    bool done = false;
    unsigned int symbol_size = sizeof(Elf64_Sym);
    unsigned int symbol_index = 0;
    Elf64_Shdr section_header;
    Elf64_Shdr symtab_section_header;
    Elf64_Shdr dynsym_section_header;
    if (fseek(elf_file, elf_header->e_shoff, 0)) return true;
    for (int i=0; i<elf_header->e_shnum; ++i) {
        if (fread(&section_header, sizeof(Elf64_Shdr), 1, elf_file) != 1) return true;
        if (section_header.sh_type == SHT_SYMTAB){
            symtab_section_header = section_header;
            if (done) break;
            done = true;
        } else if (section_header.sh_type == SHT_DYNSYM){
            dynsym_section_header = section_header;
            if (done) break;
            done = true;
        }
    }

/* 打印symbol的name字符串：
 *  读取symbol获得字符串索引
 *  读取section header获取section headers
 *  对比section headers的name字符串：
 *      读取elf header的section name字符串的section索引
 *      按索引找到section name的section header
 *      拿到对应section offset
 *      按offset找到section
 *      按section header的name索引找到对应name字符串
 *  找到名为.strtab的section header
 *  拿到对应section offset
 *  按offset找到section
 *  按symbol的name索引找到对应name字符串
    */

    unsigned int sym_num = symtab_section_header.sh_size / symbol_size;
    unsigned int dynsym_num = dynsym_section_header.sh_size / symbol_size;
    Elf64_Sym symbol_table[sym_num];
    Elf64_Sym dynsym_table[dynsym_num];

    if (fseek(elf_file, dynsym_section_header.sh_offset, 0)) return true;
    std::cout << "\nSymbol table '.dynsym' contains " << dynsym_num << ngettext(" entry:\n", " entries:\n", dynsym_num);
    std::cout << "   Num:\tValue\t\t\tSize\tType\tBind\tVis\tNdx\tName\n";
    for (Elf64_Sym symbol: dynsym_table) {
        if (fread(&symbol, symbol_size, 1, elf_file) != 1) return true;
        std::cout << std::setw(6) << std::setfill(' ') << std::dec << symbol_index++ << ":\t";
        std::cout << std::setw(16) << std::setfill('0') << std::hex << symbol.st_value << "\t";
        std::cout << std::dec << symbol.st_size << "\t";
        std::cout << get_symbol_type(symbol.st_info) << "\t";
        std::cout << get_symbol_bind(symbol.st_info) << "\t";
        std::cout << get_symbol_vis(symbol.st_other) << "\t";
        std::cout << get_symbol_index(symbol.st_shndx) << "\t";
        std::cout << std::hex << symbol.st_name << "\t";
        std::cout << "\n";
    }

    if (fseek(elf_file, symtab_section_header.sh_offset, 0)) return true;
    std::cout << "\nSymbol table '.symtab' contains " << sym_num << ngettext(" entry:\n", " entries:\n", sym_num);
    std::cout << "   Num:\tValue\t\t\tSize\tType\tBind\tVis\tNdx\tName\n";
    for (Elf64_Sym symbol: symbol_table) {
        if (fread(&symbol, symbol_size, 1, elf_file) != 1) return true;
        std::cout << std::setw(6) << std::setfill(' ') << std::dec << symbol_index++ << ":\t";
        std::cout << std::setw(16) << std::setfill('0') << std::hex << symbol.st_value << "\t";
        std::cout << std::dec << symbol.st_size << "\t";
        std::cout << get_symbol_type(symbol.st_info) << "\t";
        std::cout << get_symbol_bind(symbol.st_info) << "\t";
        std::cout << get_symbol_vis(symbol.st_other) << "\t";
        std::cout << get_symbol_index(symbol.st_shndx) << "\t";
        std::cout << std::hex << symbol.st_name << "\t";
        std::cout << "\n";
    }

    return false;
}

static bool process_file(char *filename){
    bool err = false;
    FILE *elf_file;
    Elf64_Ehdr elf_header;
    if (!(elf_file = fopen(filename, "rb"))) return print_info(FOPEN_ERROR, filename);
    if (fread(&elf_header, sizeof(Elf64_Ehdr), 1, elf_file) != 1) return false;
    if (do_header) err = process_file_header(&elf_header) || err;
    if (do_sections) err = process_section_headers(elf_file, &elf_header) || err;
    if (do_syms) err = process_symbol_table(elf_file, &elf_header) || err;
    return err;
}

int main(int argc, char ** argv) {
    bool err = false;
    // 检查&保存参数
    parse_args(argc, argv);
    if (do_header || do_sections || do_syms)
        while (optind < argc)
            err = process_file(argv[optind++]) || err;

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

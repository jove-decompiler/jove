#include <llvm/Object/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>
#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> Input(cl::Positional, cl::desc("vdso.bin"),
                                  cl::Required, cl::value_desc("filename"),
                                  cl::cat(JoveCategory));
}

static bool verify_arch(const obj::ObjectFile &);

namespace jove {
static int ReadVDSO(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::ParseCommandLineOptions(argc, argv, "read-vdso\n");

  if (!fs::exists(opts::Input)) {
    WithColor::error() << "input does not exist\n";
    return 1;
  }

  return jove::ReadVDSO();
}

namespace jove {

#if defined(__x86_64__) || defined(__aarch64__)
typedef typename obj::ELF64LE ELFT;
#elif defined(__i386__)
typedef typename obj::ELF32LE ELFT;
#endif

typedef typename obj::ELFObjectFile<ELFT> ELFO;
typedef typename obj::ELFFile<ELFT> ELFF;

typedef typename ELFF::Elf_Ehdr Elf_Ehdr;
typedef typename ELFF::Elf_Phdr_Range Elf_Phdr_Range;
typedef typename ELFF::Elf_Phdr Elf_Phdr;

static int printFileHeaders(const ELFF &, llvm::formatted_raw_ostream &);
static int printProgramHeaders(const ELFF &, llvm::formatted_raw_ostream &);

int ReadVDSO(void) {
  // Initialize targets and assembly printers/parsers.
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetDisassembler();

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> FileOrErr =
      llvm::MemoryBuffer::getFileOrSTDIN(opts::Input);

  if (std::error_code EC = FileOrErr.getError()) {
    WithColor::error() << "failed to open " << opts::Input << '\n';
    return 1;
  }

  std::unique_ptr<llvm::MemoryBuffer> &Buffer = FileOrErr.get();

  llvm::Expected<ELFF> ELFOrErr = ELFF::create(Buffer->getBuffer());

  if (!ELFOrErr) {
    WithColor::error() << "failed to create binary from " << opts::Input << ": "
                       << toString(ELFOrErr.takeError()) << '\n';
    return 1;
  }

  const ELFF &E = ELFOrErr.get();

  llvm::ScopedPrinter Writer(llvm::outs());
  llvm::formatted_raw_ostream OS(Writer.getOStream());

  if (int ret = printFileHeaders(E, OS))
    return ret;

  OS << "\n";

  if (int ret = printProgramHeaders(E, OS))
    return ret;

  llvm::Expected<Elf_Phdr_Range> ProgHdrsOrErr = E.program_headers();
  if (!ProgHdrsOrErr) {
    WithColor::error() << "failed to get program headers\n";
    return 1;
  }

  for (const Elf_Phdr &Phdr : ProgHdrsOrErr.get()) {
    ;
  }

  return 0;
}

static void printFields(llvm::formatted_raw_ostream &,
                        llvm::StringRef,
                        llvm::StringRef);

static const llvm::EnumEntry<unsigned> ElfClass[] = {
    {"None", "none", llvm::ELF::ELFCLASSNONE},
    {"32-bit", "ELF32", llvm::ELF::ELFCLASS32},
    {"64-bit", "ELF64", llvm::ELF::ELFCLASS64},
};

static const llvm::EnumEntry<unsigned> ElfDataEncoding[] = {
    {"None",         "none",                          llvm::ELF::ELFDATANONE},
    {"LittleEndian", "2's complement, little endian", llvm::ELF::ELFDATA2LSB},
    {"BigEndian",    "2's complement, big endian",    llvm::ELF::ELFDATA2MSB},
};

static const llvm::EnumEntry<unsigned> ElfOSABI[] = {
    {"SystemV",      "UNIX - System V",      llvm::ELF::ELFOSABI_NONE},
    {"HPUX",         "UNIX - HP-UX",         llvm::ELF::ELFOSABI_HPUX},
    {"NetBSD",       "UNIX - NetBSD",        llvm::ELF::ELFOSABI_NETBSD},
    {"GNU/Linux",    "UNIX - GNU",           llvm::ELF::ELFOSABI_LINUX},
    {"GNU/Hurd",     "GNU/Hurd",             llvm::ELF::ELFOSABI_HURD},
    {"Solaris",      "UNIX - Solaris",       llvm::ELF::ELFOSABI_SOLARIS},
    {"AIX",          "UNIX - AIX",           llvm::ELF::ELFOSABI_AIX},
    {"IRIX",         "UNIX - IRIX",          llvm::ELF::ELFOSABI_IRIX},
    {"FreeBSD",      "UNIX - FreeBSD",       llvm::ELF::ELFOSABI_FREEBSD},
    {"TRU64",        "UNIX - TRU64",         llvm::ELF::ELFOSABI_TRU64},
    {"Modesto",      "Novell - Modesto",     llvm::ELF::ELFOSABI_MODESTO},
    {"OpenBSD",      "UNIX - OpenBSD",       llvm::ELF::ELFOSABI_OPENBSD},
    {"OpenVMS",      "VMS - OpenVMS",        llvm::ELF::ELFOSABI_OPENVMS},
    {"NSK",          "HP - Non-Stop Kernel", llvm::ELF::ELFOSABI_NSK},
    {"AROS",         "AROS",                 llvm::ELF::ELFOSABI_AROS},
    {"FenixOS",      "FenixOS",              llvm::ELF::ELFOSABI_FENIXOS},
    {"CloudABI",     "CloudABI",             llvm::ELF::ELFOSABI_CLOUDABI},
    {"Standalone",   "Standalone App",       llvm::ELF::ELFOSABI_STANDALONE}
};

static const llvm::EnumEntry<unsigned> ElfObjectFileType[] = {
    {"None",         "NONE (none)",              llvm::ELF::ET_NONE},
    {"Relocatable",  "REL (Relocatable file)",   llvm::ELF::ET_REL},
    {"Executable",   "EXEC (Executable file)",   llvm::ELF::ET_EXEC},
    {"SharedObject", "DYN (Shared object file)", llvm::ELF::ET_DYN},
    {"Core",         "CORE (Core file)",         llvm::ELF::ET_CORE},
};

#define ENUM_ENT(enum, altName) \
  { #enum, altName, llvm::ELF::enum }

static const llvm::EnumEntry<unsigned> ElfMachineType[] = {
  ENUM_ENT(EM_NONE,          "None"),
  ENUM_ENT(EM_M32,           "WE32100"),
  ENUM_ENT(EM_SPARC,         "Sparc"),
  ENUM_ENT(EM_386,           "Intel 80386"),
  ENUM_ENT(EM_68K,           "MC68000"),
  ENUM_ENT(EM_88K,           "MC88000"),
  ENUM_ENT(EM_IAMCU,         "EM_IAMCU"),
  ENUM_ENT(EM_860,           "Intel 80860"),
  ENUM_ENT(EM_MIPS,          "MIPS R3000"),
  ENUM_ENT(EM_S370,          "IBM System/370"),
  ENUM_ENT(EM_MIPS_RS3_LE,   "MIPS R3000 little-endian"),
  ENUM_ENT(EM_PARISC,        "HPPA"),
  ENUM_ENT(EM_VPP500,        "Fujitsu VPP500"),
  ENUM_ENT(EM_SPARC32PLUS,   "Sparc v8+"),
  ENUM_ENT(EM_960,           "Intel 80960"),
  ENUM_ENT(EM_PPC,           "PowerPC"),
  ENUM_ENT(EM_PPC64,         "PowerPC64"),
  ENUM_ENT(EM_S390,          "IBM S/390"),
  ENUM_ENT(EM_SPU,           "SPU"),
  ENUM_ENT(EM_V800,          "NEC V800 series"),
  ENUM_ENT(EM_FR20,          "Fujistsu FR20"),
  ENUM_ENT(EM_RH32,          "TRW RH-32"),
  ENUM_ENT(EM_RCE,           "Motorola RCE"),
  ENUM_ENT(EM_ARM,           "ARM"),
  ENUM_ENT(EM_ALPHA,         "EM_ALPHA"),
  ENUM_ENT(EM_SH,            "Hitachi SH"),
  ENUM_ENT(EM_SPARCV9,       "Sparc v9"),
  ENUM_ENT(EM_TRICORE,       "Siemens Tricore"),
  ENUM_ENT(EM_ARC,           "ARC"),
  ENUM_ENT(EM_H8_300,        "Hitachi H8/300"),
  ENUM_ENT(EM_H8_300H,       "Hitachi H8/300H"),
  ENUM_ENT(EM_H8S,           "Hitachi H8S"),
  ENUM_ENT(EM_H8_500,        "Hitachi H8/500"),
  ENUM_ENT(EM_IA_64,         "Intel IA-64"),
  ENUM_ENT(EM_MIPS_X,        "Stanford MIPS-X"),
  ENUM_ENT(EM_COLDFIRE,      "Motorola Coldfire"),
  ENUM_ENT(EM_68HC12,        "Motorola MC68HC12 Microcontroller"),
  ENUM_ENT(EM_MMA,           "Fujitsu Multimedia Accelerator"),
  ENUM_ENT(EM_PCP,           "Siemens PCP"),
  ENUM_ENT(EM_NCPU,          "Sony nCPU embedded RISC processor"),
  ENUM_ENT(EM_NDR1,          "Denso NDR1 microprocesspr"),
  ENUM_ENT(EM_STARCORE,      "Motorola Star*Core processor"),
  ENUM_ENT(EM_ME16,          "Toyota ME16 processor"),
  ENUM_ENT(EM_ST100,         "STMicroelectronics ST100 processor"),
  ENUM_ENT(EM_TINYJ,         "Advanced Logic Corp. TinyJ embedded processor"),
  ENUM_ENT(EM_X86_64,        "Advanced Micro Devices X86-64"),
  ENUM_ENT(EM_PDSP,          "Sony DSP processor"),
  ENUM_ENT(EM_PDP10,         "Digital Equipment Corp. PDP-10"),
  ENUM_ENT(EM_PDP11,         "Digital Equipment Corp. PDP-11"),
  ENUM_ENT(EM_FX66,          "Siemens FX66 microcontroller"),
  ENUM_ENT(EM_ST9PLUS,       "STMicroelectronics ST9+ 8/16 bit microcontroller"),
  ENUM_ENT(EM_ST7,           "STMicroelectronics ST7 8-bit microcontroller"),
  ENUM_ENT(EM_68HC16,        "Motorola MC68HC16 Microcontroller"),
  ENUM_ENT(EM_68HC11,        "Motorola MC68HC11 Microcontroller"),
  ENUM_ENT(EM_68HC08,        "Motorola MC68HC08 Microcontroller"),
  ENUM_ENT(EM_68HC05,        "Motorola MC68HC05 Microcontroller"),
  ENUM_ENT(EM_SVX,           "Silicon Graphics SVx"),
  ENUM_ENT(EM_ST19,          "STMicroelectronics ST19 8-bit microcontroller"),
  ENUM_ENT(EM_VAX,           "Digital VAX"),
  ENUM_ENT(EM_CRIS,          "Axis Communications 32-bit embedded processor"),
  ENUM_ENT(EM_JAVELIN,       "Infineon Technologies 32-bit embedded cpu"),
  ENUM_ENT(EM_FIREPATH,      "Element 14 64-bit DSP processor"),
  ENUM_ENT(EM_ZSP,           "LSI Logic's 16-bit DSP processor"),
  ENUM_ENT(EM_MMIX,          "Donald Knuth's educational 64-bit processor"),
  ENUM_ENT(EM_HUANY,         "Harvard Universitys's machine-independent object format"),
  ENUM_ENT(EM_PRISM,         "Vitesse Prism"),
  ENUM_ENT(EM_AVR,           "Atmel AVR 8-bit microcontroller"),
  ENUM_ENT(EM_FR30,          "Fujitsu FR30"),
  ENUM_ENT(EM_D10V,          "Mitsubishi D10V"),
  ENUM_ENT(EM_D30V,          "Mitsubishi D30V"),
  ENUM_ENT(EM_V850,          "NEC v850"),
  ENUM_ENT(EM_M32R,          "Renesas M32R (formerly Mitsubishi M32r)"),
  ENUM_ENT(EM_MN10300,       "Matsushita MN10300"),
  ENUM_ENT(EM_MN10200,       "Matsushita MN10200"),
  ENUM_ENT(EM_PJ,            "picoJava"),
  ENUM_ENT(EM_OPENRISC,      "OpenRISC 32-bit embedded processor"),
  ENUM_ENT(EM_ARC_COMPACT,   "EM_ARC_COMPACT"),
  ENUM_ENT(EM_XTENSA,        "Tensilica Xtensa Processor"),
  ENUM_ENT(EM_VIDEOCORE,     "Alphamosaic VideoCore processor"),
  ENUM_ENT(EM_TMM_GPP,       "Thompson Multimedia General Purpose Processor"),
  ENUM_ENT(EM_NS32K,         "National Semiconductor 32000 series"),
  ENUM_ENT(EM_TPC,           "Tenor Network TPC processor"),
  ENUM_ENT(EM_SNP1K,         "EM_SNP1K"),
  ENUM_ENT(EM_ST200,         "STMicroelectronics ST200 microcontroller"),
  ENUM_ENT(EM_IP2K,          "Ubicom IP2xxx 8-bit microcontrollers"),
  ENUM_ENT(EM_MAX,           "MAX Processor"),
  ENUM_ENT(EM_CR,            "National Semiconductor CompactRISC"),
  ENUM_ENT(EM_F2MC16,        "Fujitsu F2MC16"),
  ENUM_ENT(EM_MSP430,        "Texas Instruments msp430 microcontroller"),
  ENUM_ENT(EM_BLACKFIN,      "Analog Devices Blackfin"),
  ENUM_ENT(EM_SE_C33,        "S1C33 Family of Seiko Epson processors"),
  ENUM_ENT(EM_SEP,           "Sharp embedded microprocessor"),
  ENUM_ENT(EM_ARCA,          "Arca RISC microprocessor"),
  ENUM_ENT(EM_UNICORE,       "Unicore"),
  ENUM_ENT(EM_EXCESS,        "eXcess 16/32/64-bit configurable embedded CPU"),
  ENUM_ENT(EM_DXP,           "Icera Semiconductor Inc. Deep Execution Processor"),
  ENUM_ENT(EM_ALTERA_NIOS2,  "Altera Nios"),
  ENUM_ENT(EM_CRX,           "National Semiconductor CRX microprocessor"),
  ENUM_ENT(EM_XGATE,         "Motorola XGATE embedded processor"),
  ENUM_ENT(EM_C166,          "Infineon Technologies xc16x"),
  ENUM_ENT(EM_M16C,          "Renesas M16C"),
  ENUM_ENT(EM_DSPIC30F,      "Microchip Technology dsPIC30F Digital Signal Controller"),
  ENUM_ENT(EM_CE,            "Freescale Communication Engine RISC core"),
  ENUM_ENT(EM_M32C,          "Renesas M32C"),
  ENUM_ENT(EM_TSK3000,       "Altium TSK3000 core"),
  ENUM_ENT(EM_RS08,          "Freescale RS08 embedded processor"),
  ENUM_ENT(EM_SHARC,         "EM_SHARC"),
  ENUM_ENT(EM_ECOG2,         "Cyan Technology eCOG2 microprocessor"),
  ENUM_ENT(EM_SCORE7,        "SUNPLUS S+Core"),
  ENUM_ENT(EM_DSP24,         "New Japan Radio (NJR) 24-bit DSP Processor"),
  ENUM_ENT(EM_VIDEOCORE3,    "Broadcom VideoCore III processor"),
  ENUM_ENT(EM_LATTICEMICO32, "Lattice Mico32"),
  ENUM_ENT(EM_SE_C17,        "Seiko Epson C17 family"),
  ENUM_ENT(EM_TI_C6000,      "Texas Instruments TMS320C6000 DSP family"),
  ENUM_ENT(EM_TI_C2000,      "Texas Instruments TMS320C2000 DSP family"),
  ENUM_ENT(EM_TI_C5500,      "Texas Instruments TMS320C55x DSP family"),
  ENUM_ENT(EM_MMDSP_PLUS,    "STMicroelectronics 64bit VLIW Data Signal Processor"),
  ENUM_ENT(EM_CYPRESS_M8C,   "Cypress M8C microprocessor"),
  ENUM_ENT(EM_R32C,          "Renesas R32C series microprocessors"),
  ENUM_ENT(EM_TRIMEDIA,      "NXP Semiconductors TriMedia architecture family"),
  ENUM_ENT(EM_HEXAGON,       "Qualcomm Hexagon"),
  ENUM_ENT(EM_8051,          "Intel 8051 and variants"),
  ENUM_ENT(EM_STXP7X,        "STMicroelectronics STxP7x family"),
  ENUM_ENT(EM_NDS32,         "Andes Technology compact code size embedded RISC processor family"),
  ENUM_ENT(EM_ECOG1,         "Cyan Technology eCOG1 microprocessor"),
  ENUM_ENT(EM_ECOG1X,        "Cyan Technology eCOG1X family"),
  ENUM_ENT(EM_MAXQ30,        "Dallas Semiconductor MAXQ30 Core microcontrollers"),
  ENUM_ENT(EM_XIMO16,        "New Japan Radio (NJR) 16-bit DSP Processor"),
  ENUM_ENT(EM_MANIK,         "M2000 Reconfigurable RISC Microprocessor"),
  ENUM_ENT(EM_CRAYNV2,       "Cray Inc. NV2 vector architecture"),
  ENUM_ENT(EM_RX,            "Renesas RX"),
  ENUM_ENT(EM_METAG,         "Imagination Technologies Meta processor architecture"),
  ENUM_ENT(EM_MCST_ELBRUS,   "MCST Elbrus general purpose hardware architecture"),
  ENUM_ENT(EM_ECOG16,        "Cyan Technology eCOG16 family"),
  ENUM_ENT(EM_CR16,          "Xilinx MicroBlaze"),
  ENUM_ENT(EM_ETPU,          "Freescale Extended Time Processing Unit"),
  ENUM_ENT(EM_SLE9X,         "Infineon Technologies SLE9X core"),
  ENUM_ENT(EM_L10M,          "EM_L10M"),
  ENUM_ENT(EM_K10M,          "EM_K10M"),
  ENUM_ENT(EM_AARCH64,       "AArch64"),
  ENUM_ENT(EM_AVR32,         "Atmel Corporation 32-bit microprocessor family"),
  ENUM_ENT(EM_STM8,          "STMicroeletronics STM8 8-bit microcontroller"),
  ENUM_ENT(EM_TILE64,        "Tilera TILE64 multicore architecture family"),
  ENUM_ENT(EM_TILEPRO,       "Tilera TILEPro multicore architecture family"),
  ENUM_ENT(EM_CUDA,          "NVIDIA CUDA architecture"),
  ENUM_ENT(EM_TILEGX,        "Tilera TILE-Gx multicore architecture family"),
  ENUM_ENT(EM_CLOUDSHIELD,   "EM_CLOUDSHIELD"),
  ENUM_ENT(EM_COREA_1ST,     "EM_COREA_1ST"),
  ENUM_ENT(EM_COREA_2ND,     "EM_COREA_2ND"),
  ENUM_ENT(EM_ARC_COMPACT2,  "EM_ARC_COMPACT2"),
  ENUM_ENT(EM_OPEN8,         "EM_OPEN8"),
  ENUM_ENT(EM_RL78,          "Renesas RL78"),
  ENUM_ENT(EM_VIDEOCORE5,    "Broadcom VideoCore V processor"),
  ENUM_ENT(EM_78KOR,         "EM_78KOR"),
  ENUM_ENT(EM_56800EX,       "EM_56800EX"),
  ENUM_ENT(EM_AMDGPU,        "EM_AMDGPU"),
  ENUM_ENT(EM_RISCV,         "RISC-V"),
  ENUM_ENT(EM_LANAI,         "EM_LANAI"),
  ENUM_ENT(EM_BPF,           "EM_BPF"),
};

template <typename T, typename TEnum>
static std::string
printEnum(T Value, llvm::ArrayRef<llvm::EnumEntry<TEnum>> EnumValues) {
  for (const auto &EnumItem : EnumValues)
    if (EnumItem.Value == Value)
      return EnumItem.AltName;
  return llvm::to_hexString(Value, false);
}

int printFileHeaders(const ELFF &E, llvm::formatted_raw_ostream &OS) {
  const Elf_Ehdr *e = E.getHeader();

  OS << "ELF Header:\n";
  OS << "  Magic:  ";
  for (unsigned i = 0; i < llvm::ELF::EI_NIDENT; ++i)
    OS << llvm::format(" %02x", static_cast<int>(e->e_ident[i]));
  OS << "\n";

  std::string Str;

  Str = printEnum(e->e_ident[llvm::ELF::EI_CLASS],
                  llvm::makeArrayRef(ElfClass));
  printFields(OS, "Class:", Str);

  Str = printEnum(e->e_ident[llvm::ELF::EI_DATA],
                  llvm::makeArrayRef(ElfDataEncoding));
  printFields(OS, "Data:", Str);
  OS.PadToColumn(2u);
  OS << "Version:";
  OS.PadToColumn(37u);
  OS << llvm::to_hexString(e->e_ident[llvm::ELF::EI_VERSION]);
  if (e->e_version == llvm::ELF::EV_CURRENT)
    OS << " (current)";
  OS << "\n";

  Str = printEnum(e->e_ident[llvm::ELF::EI_OSABI], llvm::makeArrayRef(ElfOSABI));
  printFields(OS, "OS/ABI:", Str);

  Str = "0x" + llvm::to_hexString(e->e_ident[llvm::ELF::EI_ABIVERSION]);
  printFields(OS, "ABI Version:", Str);

  Str = printEnum(e->e_type, llvm::makeArrayRef(ElfObjectFileType));
  printFields(OS, "Type:", Str);

  Str = printEnum(e->e_machine, llvm::makeArrayRef(ElfMachineType));
  printFields(OS, "Machine:", Str);

  Str = "0x" + llvm::to_hexString(e->e_version);
  printFields(OS, "Version:", Str);

  Str = "0x" + llvm::to_hexString(e->e_entry);
  printFields(OS, "Entry point address:", Str);

  Str = llvm::to_string(e->e_phoff) + " (bytes into file)";
  printFields(OS, "Start of program headers:", Str);

  Str = llvm::to_string(e->e_shoff) + " (bytes into file)";
  printFields(OS, "Start of section headers:", Str);

  Str = "0x" + llvm::to_hexString(e->e_flags);
  printFields(OS, "Flags:", Str);

  Str = llvm::to_string(e->e_ehsize) + " (bytes)";
  printFields(OS, "Size of this header:", Str);

  Str = llvm::to_string(e->e_phentsize) + " (bytes)";
  printFields(OS, "Size of program headers:", Str);

  Str = llvm::to_string(e->e_phnum);
  printFields(OS, "Number of program headers:", Str);

  Str = llvm::to_string(e->e_shentsize) + " (bytes)";
  printFields(OS, "Size of section headers:", Str);

  return 0;
}

static std::string printPhdrFlags(unsigned Flag);

struct Field {
  llvm::StringRef Str;
  unsigned Column;

  Field(llvm::StringRef S, unsigned Col) : Str(S), Column(Col) {}
  Field(unsigned Col) : Str(""), Column(Col) {}
};

static void printField(llvm::formatted_raw_ostream &OS, struct Field F);
static std::string getElfPtType(unsigned Arch, unsigned Type);

int printProgramHeaders(const ELFF &E, llvm::formatted_raw_ostream &OS) {
  OS << "ELF Program Headers:\n";

  unsigned Bias = ELFT::Is64Bits ? 8 : 0;
  unsigned Width = ELFT::Is64Bits ? 18 : 10;
  unsigned SizeWidth = ELFT::Is64Bits ? 8 : 7;
  std::string Type, Offset, VMA, LMA, FileSz, MemSz, Flag, Align;

  const Elf_Ehdr *Header = E.getHeader();
  Field Fields[8] = {2,         17,        26,        37 + Bias,
                     48 + Bias, 56 + Bias, 64 + Bias, 68 + Bias};

  if (ELFT::Is64Bits)
    OS << "  Type           Offset   VirtAddr           PhysAddr         "
       << "  FileSiz  MemSiz   Flg Align\n";
  else
    OS << "  Type           Offset   VirtAddr   PhysAddr   FileSiz "
       << "MemSiz  Flg Align\n";

  llvm::Expected<Elf_Phdr_Range> ProgHdrsOrErr = E.program_headers();
  if (!ProgHdrsOrErr) {
    WithColor::error() << "failed to get program headers\n";
    return 1;
  }

  for (const Elf_Phdr &Phdr : ProgHdrsOrErr.get()) {
    Type = getElfPtType(Header->e_machine, Phdr.p_type);
    Offset = llvm::to_string(llvm::format_hex(Phdr.p_offset, 8));
    VMA = llvm::to_string(llvm::format_hex(Phdr.p_vaddr, Width));
    LMA = llvm::to_string(llvm::format_hex(Phdr.p_paddr, Width));
    FileSz = llvm::to_string(llvm::format_hex(Phdr.p_filesz, SizeWidth));
    MemSz = llvm::to_string(llvm::format_hex(Phdr.p_memsz, SizeWidth));
    Flag = printPhdrFlags(Phdr.p_flags);
    Align = llvm::to_string(llvm::format_hex(Phdr.p_align, 1));
    Fields[0].Str = Type;
    Fields[1].Str = Offset;
    Fields[2].Str = VMA;
    Fields[3].Str = LMA;
    Fields[4].Str = FileSz;
    Fields[5].Str = MemSz;
    Fields[6].Str = Flag;
    Fields[7].Str = Align;
    for (auto Field : Fields)
      printField(OS, Field);
    if (Phdr.p_type == llvm::ELF::PT_INTERP) {
      OS << "\n      [Requesting program interpreter: ";
      OS << reinterpret_cast<const char *>(E.base()) + Phdr.p_offset << "]";
    }
    OS << "\n";
  }

  return 0;
}

#define LLVM_READOBJ_PHDR_ENUM(ns, enum)                                       \
  case ns::enum:                                                               \
    return std::string(#enum).substr(3);

std::string getElfPtType(unsigned Arch, unsigned Type) {
  switch (Type) {
    LLVM_READOBJ_PHDR_ENUM(llvm::ELF, PT_NULL)
    LLVM_READOBJ_PHDR_ENUM(llvm::ELF, PT_LOAD)
    LLVM_READOBJ_PHDR_ENUM(llvm::ELF, PT_DYNAMIC)
    LLVM_READOBJ_PHDR_ENUM(llvm::ELF, PT_INTERP)
    LLVM_READOBJ_PHDR_ENUM(llvm::ELF, PT_NOTE)
    LLVM_READOBJ_PHDR_ENUM(llvm::ELF, PT_SHLIB)
    LLVM_READOBJ_PHDR_ENUM(llvm::ELF, PT_PHDR)
    LLVM_READOBJ_PHDR_ENUM(llvm::ELF, PT_TLS)
    LLVM_READOBJ_PHDR_ENUM(llvm::ELF, PT_GNU_EH_FRAME)
    LLVM_READOBJ_PHDR_ENUM(llvm::ELF, PT_SUNW_UNWIND)
    LLVM_READOBJ_PHDR_ENUM(llvm::ELF, PT_GNU_STACK)
    LLVM_READOBJ_PHDR_ENUM(llvm::ELF, PT_GNU_RELRO)
  default:
    // All machine specific PT_* types
    switch (Arch) {
    case llvm::ELF::EM_ARM:
      if (Type == llvm::ELF::PT_ARM_EXIDX)
        return "EXIDX";
      break;
    case llvm::ELF::EM_MIPS:
    case llvm::ELF::EM_MIPS_RS3_LE:
      switch (Type) {
      case llvm::ELF::PT_MIPS_REGINFO:
        return "REGINFO";
      case llvm::ELF::PT_MIPS_RTPROC:
        return "RTPROC";
      case llvm::ELF::PT_MIPS_OPTIONS:
        return "OPTIONS";
      case llvm::ELF::PT_MIPS_ABIFLAGS:
        return "ABIFLAGS";
      }
      break;
    }
  }
  return std::string("<unknown>: ") +
         llvm::to_string(llvm::format_hex(Type, 1));
}

std::string printPhdrFlags(unsigned Flag) {
  std::string Str;
  Str = (Flag & llvm::ELF::PF_R) ? "R" : " ";
  Str += (Flag & llvm::ELF::PF_W) ? "W" : " ";
  Str += (Flag & llvm::ELF::PF_X) ? "E" : " ";
  return Str;
}

void printField(llvm::formatted_raw_ostream &OS, struct Field F) {
  if (F.Column != 0)
    OS.PadToColumn(F.Column);
  OS << F.Str;
  OS.flush();
}

void printFields(llvm::formatted_raw_ostream &OS,
                 llvm::StringRef Str1,
                 llvm::StringRef Str2) {
  OS.PadToColumn(2u);
  OS << Str1;
  OS.PadToColumn(37u);
  OS << Str2 << "\n";
  OS.flush();
}
}

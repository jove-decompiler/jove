#include "tcgcommon.hpp"

#include <tuple>
#include <memory>
#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Support/FileSystem.h>

#include "jove/jove.h"
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>

namespace fs = boost::filesystem;
namespace po = boost::program_options;
namespace obj = llvm::object;

namespace jove {

static int parse_command_line_arguments(int argc, char **argv);
static int initialize_decompilation(void);

}

int main(int argc, char **argv) {
  llvm::StringRef ToolName = argv[0];
  llvm::sys::PrintStackTraceOnErrorSignal(ToolName);
  llvm::PrettyStackTraceProgram X(argc, argv);
  llvm::llvm_shutdown_obj Y;

  return jove::parse_command_line_arguments(argc, argv) ||
         jove::initialize_decompilation();
}

namespace jove {

static bool verify_arch(const obj::ObjectFile &);

static struct {
  fs::path input;
  fs::path output;
  bool verbose;
} cmdline;

typedef std::tuple<llvm::MCDisassembler &,
                   const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &> disas_t;

static llvm::ArrayRef<uint8_t> SecContents;

static bool translate_function(binary_t &,
                               tiny_code_generator_t &,
                               disas_t,
                               target_ulong Addr);

int initialize_decompilation(void) {
  tiny_code_generator_t tcg;

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> FileOrErr =
      llvm::MemoryBuffer::getFileOrSTDIN(cmdline.input.string());

  if (std::error_code EC = FileOrErr.getError()) {
    fprintf(stderr, "failed to open %s\n",
            cmdline.input.string().c_str());
    return 1;
  }

  std::unique_ptr<llvm::MemoryBuffer> &Buffer = FileOrErr.get();

  llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
      obj::createBinary(Buffer->getMemBufferRef());

  if (!BinOrErr) {
    fprintf(stderr, "failed to open %s\n", cmdline.input.string().c_str());
    return 1;
  }

  std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

  typedef typename obj::ELF64LEObjectFile ELFO;
  typedef typename obj::ELF64LEFile ELFT;

  if (!llvm::isa<ELFO>(Bin.get())) {
    fprintf(stderr, "%s is not ELF64LEObjectFile\n",
            cmdline.input.string().c_str());
    return 1;
  }

  ELFO &O = *llvm::cast<ELFO>(Bin.get());

  if (!verify_arch(O)) {
    fprintf(stderr, "architecture mismatch of input\n");
    return 1;
  }

  std::string ArchName;
  llvm::Triple TheTriple = O.makeTriple();
  std::string Error;

  const llvm::Target *TheTarget =
      llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    fprintf(stderr, "failed to lookup target: %s\n", Error.c_str());
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;
  llvm::SubtargetFeatures Features = O.getFeatures();

  std::unique_ptr<const llvm::MCRegisterInfo> MRI(
      TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    fprintf(stderr, "no register info for target\n");
    return 1;
  }

  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName));
  if (!AsmInfo) {
    fprintf(stderr, "no assembly info\n");
    return 1;
  }

  std::unique_ptr<const llvm::MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI) {
    fprintf(stderr, "no subtarget info\n");
    return 1;
  }

  std::unique_ptr<const llvm::MCInstrInfo> MII(TheTarget->createMCInstrInfo());
  if (!MII) {
    fprintf(stderr, "no instruction info\n");
    return 1;
  }

  llvm::MCObjectFileInfo MOFI;
  llvm::MCContext Ctx(AsmInfo.get(), MRI.get(), &MOFI);
  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI.InitMCObjectFileInfo(llvm::Triple(TripleName), false, Ctx);

  std::unique_ptr<llvm::MCDisassembler> DisAsm(
      TheTarget->createMCDisassembler(*STI, Ctx));
  if (!DisAsm) {
    fprintf(stderr, "no disassembler for target\n");
    return 1;
  }

  int AsmPrinterVariant = AsmInfo->getAssemblerDialect();
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    fprintf(stderr, "no instruction printer\n");
    return 1;
  }

  //
  // initialize the decompilation of the given binary by exploring every defined
  // exported function
  //
  decompilation_t decompilation;
  binary_t &binary =
      decompilation.Binaries[fs::canonical(cmdline.input).string()];

  binary.Data.resize(Buffer->getBufferSize());
  memcpy(&binary.Data[0], Buffer->getBufferStart(), binary.Data.size());

  auto write_decompilation = [&](void) -> void {
    std::ofstream ofs(cmdline.output.string());

    boost::archive::text_oarchive oa(ofs);
    oa << decompilation;
  };

  // XXX I don't like the fact that this is a macro.
#define unwrapOrBail(__ExpectedVal)                                            \
  ({                                                                           \
    auto __E = (__ExpectedVal);                                                \
    if (!__E) {                                                                \
      fprintf(stderr, "error (%s)\n", #__ExpectedVal);                         \
      return 1;                                                                \
    }                                                                          \
                                                                               \
    *__E;                                                                      \
  })

  const ELFT &E = *O.getELFFile();

  typedef typename ELFT::Elf_Shdr Elf_Shdr;
  typedef typename ELFT::Elf_Sym Elf_Sym;
  typedef typename ELFT::Elf_Sym_Range Elf_Sym_Range;
  typedef typename ELFT::Elf_Word Elf_Word;

  //
  // get the extended symbol table index section, if it exists
  //
  struct {
    llvm::ArrayRef<Elf_Word> Table;

    bool Found;
  } Shndx;

  Shndx.Found = false;
  for (const Elf_Shdr &Sec : unwrapOrBail(E.sections())) {
    if (Sec.sh_type != llvm::ELF::SHT_SYMTAB_SHNDX)
      continue;

    if (Shndx.Found) {
      fprintf(stderr, "invalid ELF: multiple SHT_SYMTAB_SHNDX sections\n");
      return 1;
    }

    Shndx.Table = unwrapOrBail(E.getSHNDXTable(Sec));

    Shndx.Found = true;
  }

  //
  // get the dynamic symbols (those are the ones that matter to the dynamic
  // linker)
  //
  struct {
    llvm::StringRef StringTable;
    Elf_Sym_Range Symbols;

    bool Found;
  } Dyn;

  Dyn.Found = false;
  for (const Elf_Shdr &Sec : unwrapOrBail(E.sections())) {
    if (Sec.sh_type != llvm::ELF::SHT_DYNSYM)
      continue;

    if (Dyn.Found) {
      fprintf(stderr, "malformed ELF: multiple SHT_DYNSYM sections\n");
      return 1;
    }

    Dyn.StringTable = unwrapOrBail(E.getStringTableForSymtab(Sec));
    Dyn.Symbols = Elf_Sym_Range(
        reinterpret_cast<const Elf_Sym *>(E.base() + Sec.sh_offset),
        reinterpret_cast<const Elf_Sym *>(E.base() + Sec.sh_offset +
                                          Sec.sh_size));

    Dyn.Found = true;
  }

  if (!Dyn.Found) {
    fprintf(stderr, "malformed ELF: failed to find SHT_DYNSYM section\n");
    return 1;
  }

  if (Dyn.Symbols.empty()) {
    write_decompilation();
    return 0;
  }

  //
  // iterate dynamic (!undefined) functions
  //
  for (const Elf_Sym &Sym : Dyn.Symbols) {
    if (Sym.getType() != llvm::ELF::STT_FUNC)
      continue;

    if (Sym.isUndefined())
      continue;

    //
    // get section
    //
    unsigned SectIndex = Sym.st_shndx;
    if (SectIndex == llvm::ELF::SHN_XINDEX) {
      if (!Shndx.Found) {
        fprintf(stderr, "malformed ELF: no extended symbol table index\n");
        return 1;
      }

      SectIndex = unwrapOrBail(obj::getExtendedSymbolTableIndex<obj::ELF64LE>(
          &Sym, Dyn.Symbols.begin(), Shndx.Table));
    }
    const Elf_Shdr &Sec = *unwrapOrBail(E.getSection(SectIndex));
    const std::uintptr_t SectBase = Sec.sh_addr;
    SecContents = unwrapOrBail(E.getSectionContents(&Sec));

    //
    // print function
    //
    llvm::StringRef Nm = unwrapOrBail(Sym.getName(Dyn.StringTable));
    const std::uintptr_t Addr = Sym.st_value;
    std::ptrdiff_t Offset = Addr - SectBase;
    assert(Offset >= 0);
    llvm::StringRef SectNm = unwrapOrBail(E.getSectionName(&Sec));
    if (cmdline.verbose)
      printf("%s @ %s+%#lx\n", Nm.str().c_str(), SectNm.str().c_str(),
             static_cast<std::uintptr_t>(Offset));

    //
    // prepare TCG
    //
    tcg.set_section(SectBase, SecContents.data());

    //
    // translate function
    //
    if (!translate_function(binary, tcg, disas_t(*DisAsm, std::cref(*STI), *IP),
                            Addr))
      fprintf(stderr, "failed to translate %s @ %s+%#lx\n", Nm.str().c_str(),
              SectNm.str().c_str(), static_cast<std::uintptr_t>(Offset));
  }

  write_decompilation();

  return 0;
}

static basic_block_t translate_basic_block(function_t &,
                                           tiny_code_generator_t &,
                                           disas_t,
                                           const target_ulong Addr);

static std::unordered_map<std::uintptr_t, basic_block_t> BBMap;

static bool translate_function(binary_t &binary,
                               tiny_code_generator_t &tcg,
                               disas_t dis,
                               target_ulong Addr) {
  if (binary.Analysis.Functions.find(Addr) != binary.Analysis.Functions.end()) {
    return true;
  }

  BBMap.clear();

  basic_block_t entry;
  {
    function_t &fn = binary.Analysis.Functions[Addr];
    entry = translate_basic_block(fn, tcg, dis, Addr);
  }

  if (entry == boost::graph_traits<function_t>::null_vertex()) {
    binary.Analysis.Functions.erase(binary.Analysis.Functions.find(Addr));
    return false;
  }

  return true;
}

basic_block_t translate_basic_block(function_t &f,
                                    tiny_code_generator_t &tcg,
                                    disas_t dis,
                                    const target_ulong Addr) {
  unsigned Size;
  jove::terminator_info_t T;
  std::tie(Size, T) = tcg.translate(Addr);

#if 0
  fprintf(stdout, "%s\n", string_of_terminator(T.Type));
  tcg.dump_operations();
  fputc('\n', stdout);
#endif

  if (T.Type == TERMINATOR::UNKNOWN) {
    fprintf(stderr, "unknown terminator @ %#lx\n", Addr);

    llvm::MCDisassembler &DisAsm = std::get<0>(dis);
    const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
    llvm::MCInstPrinter &IP = std::get<2>(dis);

    uint64_t InstLen;
    for (target_ulong A = Addr; A < Addr + Size; A += InstLen) {
      std::ptrdiff_t Offset = A - guest_base_addr /* XXX */;

      llvm::MCInst Inst;
      bool Disassembled =
          DisAsm.getInstruction(Inst, InstLen, SecContents.slice(Offset), A,
                                llvm::nulls(), llvm::nulls());

      if (!Disassembled) {
        fprintf(stderr, "failed to disassemble %p\n",
                reinterpret_cast<void *>(Addr));
        break;
      }

      std::string str;
      {
        llvm::raw_string_ostream StrStream(str);
        IP.printInst(&Inst, StrStream, "", STI);
      }
      puts(str.c_str());
    }

    tcg.dump_operations();
    fputc('\n', stdout);

    return boost::graph_traits<function_t>::null_vertex();
  }

  basic_block_t bb = boost::add_vertex(f);
  basic_block_properties_t& bbprop = f[bb];
  bbprop.Addr = Addr;
  bbprop.Size = Size;
  bbprop.Term.Type = T.Type;
  bbprop.Term.Addr = T.Addr;

  BBMap[Addr] = bb;

  //
  // conduct analysis of last instruction (the terminator of the block) and
  // (recursively) descend into branch targets, translating basic blocks
  //
  auto control_flow = [&](std::uintptr_t Target) -> void {
    if (!Target) {
      fprintf(stderr, "what the hell happened @ 0x%lx (%s)\n", Addr,
              string_of_terminator(bbprop.Term.Type));
      return;
    }

    auto it = BBMap.find(Target);
    if (it != BBMap.end()) {
      boost::add_edge(bb, (*it).second, f);
      return;
    }

    basic_block_t succ = translate_basic_block(f, tcg, dis, Target);
    if (succ != boost::graph_traits<function_t>::null_vertex())
      boost::add_edge(bb, succ, f);
  };

  switch (T.Type) {
  case TERMINATOR::UNCONDITIONAL_JUMP:
    control_flow(T._unconditional_jump.Target);
    break;

  case TERMINATOR::CONDITIONAL_JUMP:
    control_flow(T._conditional_jump.Target);
    control_flow(T._conditional_jump.NextPC);
    break;

  case TERMINATOR::CALL:
    bbprop.Term.Callees.Local.insert(T._call.Target);
    control_flow(T._call.NextPC);
    break;

  case TERMINATOR::INDIRECT_CALL:
    control_flow(T._indirect_call.NextPC);
    break;

  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::RETURN:
  case TERMINATOR::UNREACHABLE:
    break;

  default:
    abort();
  }

  return bb;
}

int parse_command_line_arguments(int argc, char **argv) {
  fs::path &ifp = cmdline.input;
  fs::path &ofp = cmdline.output;
  bool &verbose = cmdline.verbose;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
      ("help,h", "produce help message")

      ("input,i", po::value<fs::path>(&ifp),
       "input binary")

      ("output,o", po::value<fs::path>(&ofp),
       "output file path")

      ("verbose,v", po::value<bool>(&verbose)->default_value(false),
       "be verbose");

    po::positional_options_description p;
    p.add("input", -1);

    po::variables_map vm;
    po::store(
        po::command_line_parser(argc, argv).options(desc).positional(p).run(),
        vm);
    po::notify(vm);

    if (vm.count("help") || !vm.count("input") || !vm.count("output")) {
      printf("Usage: %s [-o output] binary\n", argv[0]);
      std::string desc_s;
      {
        std::ostringstream oss(desc_s);
        oss << desc;
      }
      printf("%s", desc_s.c_str());
      return 1;
    }

    if (!fs::exists(ifp)) {
      fprintf(stderr, "given input %s does not exist\n", ifp.string().c_str());
      return 1;
    }

    if (!vm.count("output")) {
      ofp = ifp;
      ofp.replace_extension("jv");
      ofp = ofp.filename();
    }
  } catch (std::exception &e) {
    fprintf(stderr, "%s\n", e.what());
    return 1;
  }

  return 0;
}

bool verify_arch(const obj::ObjectFile &Obj) {
#if defined(TARGET_X86_64)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::x86_64;
#elif defined(TARGET_AARCH64)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::aarch64;
#else
#error "unknown architecture"
#endif

  return Obj.getArch() == archty;
}

}

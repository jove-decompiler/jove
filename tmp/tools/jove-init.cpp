#include "tcgcommon.hpp"

#include <memory>
#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
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
static struct {
  fs::path input;
  fs::path output;
} cmdline;

int parse_command_line_arguments(int argc, char **argv);

static bool verify_arch(const obj::ObjectFile &);
static void print_obj_info(const obj::ObjectFile &);
static int initialize_decompilation(void);
}

int main(int argc, char** argv) {
  llvm::StringRef ToolName = argv[0];
  llvm::sys::PrintStackTraceOnErrorSignal(ToolName);
  llvm::PrettyStackTraceProgram X(argc, argv);
  llvm::llvm_shutdown_obj Y;

  return jove::parse_command_line_arguments(argc, argv) ||
         jove::initialize_decompilation();
}

namespace jove {

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

  print_obj_info(O);

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

#define unwrapOrBail(ExpectedVal)                                              \
  ({                                                                           \
    auto E = (ExpectedVal);                                                    \
    if (!E) {                                                                  \
      fprintf(stderr, "error (%s)\n", #ExpectedVal);                           \
      return 1;                                                                \
    }                                                                          \
    *E;                                                                        \
  })

  const ELFT &ELF = *O.getELFFile();

  typedef typename ELFT::Elf_Shdr Elf_Shdr;
  typedef typename ELFT::Elf_Sym Elf_Sym;
  typedef typename ELFT::Elf_Sym_Range Elf_Sym_Range;

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
  for (const Elf_Shdr &Sec : unwrapOrBail(ELF.sections())) {
    if (Sec.sh_type != llvm::ELF::SHT_DYNSYM)
      continue;

    if (Dyn.Found) {
      fprintf(stderr, "multiple SHT_DYNSYM sections\n");
      return 1;
    }

    Dyn.StringTable = unwrapOrBail(ELF.getStringTableForSymtab(Sec));
    Dyn.Symbols = Elf_Sym_Range(
        reinterpret_cast<const Elf_Sym *>(ELF.base() + Sec.sh_offset),
        reinterpret_cast<const Elf_Sym *>(ELF.base() + Sec.sh_offset +
                                          Sec.sh_size));

    Dyn.Found = true;
  }

  if (!Dyn.Found) {
    fprintf(stderr, "failed to find SHT_DYNSYM section\n");
    return 1;
  }

  for (Elf_Sym Sym : Dyn.Symbols) {
    if (Sym.getType() != llvm::ELF::STT_FUNC)
      continue;

    if (Sym.isUndefined())
      continue;

    llvm::StringRef Nm = unwrapOrBail(Sym.getName(Dyn.StringTable));
    fprintf(stderr, "Symbol %s\n", Nm.str().c_str());
  }

  decompilation_t decompilation;
  binary_t &binary =
      decompilation.Binaries[fs::canonical(cmdline.input).string()];
  binary.Data.resize(Buffer->getBufferSize());
  memcpy(&binary.Data[0], Buffer->getBufferStart(), binary.Data.size());

  {
    std::ofstream ofs(cmdline.output.string());

    boost::archive::text_oarchive oa(ofs);
    oa << decompilation;
  }

  return 0;
}

int parse_command_line_arguments(int argc, char **argv) {
  fs::path &ifp = cmdline.input;
  fs::path &ofp = cmdline.output;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
      ("help,h", "produce help message")

      ("input,i", po::value<fs::path>(&ifp),
       "input binary")

      ("output,o", po::value<fs::path>(&ofp),
       "output file path");

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

void print_obj_info(const obj::ObjectFile &Obj) {
  printf("File: %s\n"
         "Format: %s\n"
         "Arch: %s\n"
         "AddressSize: %ubit\n",
         Obj.getFileName().str().c_str(), Obj.getFileFormatName().str().c_str(),
         llvm::Triple::getArchTypeName(Obj.getArch()).str().c_str(),
         8 * Obj.getBytesInAddress());
}

}

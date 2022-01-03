#define JOVE_EXTRA_BIN_PROPERTIES                                              \
  std::unique_ptr<llvm::object::Binary> ObjectFile;

#include "tcgcommon.hpp"

#include <memory>
#include <boost/filesystem.hpp>
#include <cinttypes>
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
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>
#include <sys/wait.h>

#include <boost/icl/split_interval_map.hpp>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> Binary(cl::Positional, cl::desc("<binary>"),
                                   cl::Required, cl::cat(JoveCategory));

static cl::opt<bool> DoTCGOpt("do-tcg-opt",
                              cl::desc("Run QEMU TCG optimizations"),
                              cl::cat(JoveCategory));

static cl::opt<std::string> BreakOnAddr(
    "break-on-addr",
    cl::desc(
        "Allow user to set a debugger breakpoint on TCGDumpUserBreakPoint, "
        "and triggered when basic block address matches given address"),
    cl::cat(JoveCategory));

static cl::opt<std::string>
    StartingFrom("starting-from",
                 cl::desc("Provide file address to disassemble"),
                 cl::cat(JoveCategory));
}

namespace jove {
static int tcgdump(void);

static int await_process_completion(pid_t);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "TCG Dump\n");

  if (opts::DoTCGOpt)
    jove::do_tcg_optimization = true;

  return jove::tcgdump();
}

extern "C" {
void __attribute__((noinline))
     __attribute__((visibility("default")))
TCGDumpUserBreakPoint(void) {
  puts(__func__);
}
}

namespace jove {

int await_process_completion(pid_t pid) {
  int wstatus;
  do {
    if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0)
      abort();

    if (WIFEXITED(wstatus)) {
      //printf("exited, status=%d\n", WEXITSTATUS(wstatus));
      return WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
      //printf("killed by signal %d\n", WTERMSIG(wstatus));
      return 1;
    } else if (WIFSTOPPED(wstatus)) {
      //printf("stopped by signal %d\n", WSTOPSIG(wstatus));
      return 1;
    } else if (WIFCONTINUED(wstatus)) {
      //printf("continued\n");
    }
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  abort();
}

#include "elf.hpp"

int tcgdump(void) {
  struct {
    target_ulong Addr;
    bool Active;
  } BreakOn = { .Active = false };

  if (!opts::BreakOnAddr.empty()) {
    BreakOn.Active = true;
    BreakOn.Addr = std::stoi(opts::BreakOnAddr.c_str(), 0, 16);
  }

  if (!fs::exists(opts::Binary)) {
    llvm::errs() << "given binary " << opts::Binary << " does not exist\n";
    return 1;
  }

  jove::tiny_code_generator_t tcg;

  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  llvm::Expected<obj::OwningBinary<obj::Binary>> BinaryOrErr =
      obj::createBinary(opts::Binary);

  if (!BinaryOrErr) {
    fprintf(stderr, "failed to open %s\n", opts::Binary.c_str());
    return 1;
  }

  obj::Binary *B = BinaryOrErr.get().getBinary();
  if (!llvm::isa<ELFO>(B)) {
    fprintf(stderr, "invalid binary\n");
    return 1;
  }

  const ELFO &O = *llvm::cast<ELFO>(B);
  const ELFF &E = *O.getELFFile();

  DynRegionInfo DynamicTable(O.getFileName());
  loadDynamicTable(&E, &O, DynamicTable);

  if (!DynamicTable.Addr) {
    fprintf(stderr, "no dynamic table for given binary\n");
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

  llvm::MCTargetOptions Options;
  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
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
  llvm::MCContext Ctx(AsmInfo.get(), MRI.get(), &MOFI); // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI.InitMCObjectFileInfo(llvm::Triple(TripleName), false, Ctx);

  std::unique_ptr<llvm::MCDisassembler> DisAsm(
      TheTarget->createMCDisassembler(*STI, Ctx));
  if (!DisAsm) {
    fprintf(stderr, "no disassembler for target\n");
    return 1;
  }

  int AsmPrinterVariant =
#if defined(TARGET_X86_64) || defined(TARGET_I386)
      1 /* intel */
#else
      AsmInfo->getAssemblerDialect()
#endif
      ;
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    fprintf(stderr, "no instruction printer\n");
    return 1;
  }

  llvm::StringRef DynamicStringTable;
  const Elf_Shdr *SymbolVersionSection;
  std::vector<VersionMapEntry> VersionMap;
  llvm::Optional<DynRegionInfo> OptionalDynSymRegion =
      loadDynamicSymbols(&E, &O,
                         DynamicTable,
                         DynamicStringTable,
                         SymbolVersionSection,
                         VersionMap);

  auto linear_scan_disassemble = [&](target_ulong Addr, target_ulong End = 0) -> bool {
    if (!End)
      End = Addr + 32;

    tcg.set_elf(&E);

    printf("0x%" PRIx64 "\n", Addr);

    unsigned BBSize;
    for (target_ulong A = Addr; A < End; A += BBSize) {
      if (BreakOn.Active) {
        if (A == BreakOn.Addr) {
          ::TCGDumpUserBreakPoint();
        }
      }

      jove::terminator_info_t T;
      std::tie(BBSize, T) = tcg.translate(A);

      //
      // print machine code
      //
      uint64_t InstLen;
      for (uint64_t _A = A; _A < A + BBSize; _A += InstLen) {
        llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(_A);
        if (!ExpectedPtr) {
          WithColor::error()
              << llvm::formatv("failed to get binary contents for {0:x}\n", A);
          return invalid_basic_block_index;
        }

        llvm::MCInst Inst;

        bool Disassembled = DisAsm->getInstruction(
            Inst, InstLen, llvm::ArrayRef<uint8_t>(*ExpectedPtr, BBSize), _A,
            llvm::nulls());
        if (!Disassembled) {
          fprintf(stderr, "failed to disassemble %" PRIx64 "\n", _A);
          break;
        }

        std::string inst_str;
        {
          llvm::raw_string_ostream StrStream(inst_str);
          IP->printInst(&Inst, _A, "", *STI, StrStream);
        }

        printf("%" PRIx64 "%s\n", static_cast<uint64_t>(_A), inst_str.c_str());
      }
      fputc('\n', stdout);

      //
      // print TCG
      //
      tcg.dump_operations();
      fputc('\n', stdout);

      //
      // print basic block terminator
      //
      printf("%s @ 0x%" PRIx64 "\n",
             description_of_terminator(T.Type), static_cast<uint64_t>(T.Addr));

      switch (T.Type) {
      case jove::TERMINATOR::UNCONDITIONAL_JUMP:
        printf("Target: 0x%" PRIx64 "\n", static_cast<uint64_t>(T._unconditional_jump.Target));
        break;

      case jove::TERMINATOR::CONDITIONAL_JUMP:
        printf("Target: 0x%" PRIx64 "\n", static_cast<uint64_t>(T._conditional_jump.Target));
        printf("NextPC: 0x%" PRIx64 "\n", static_cast<uint64_t>(T._conditional_jump.NextPC));
        break;

      case jove::TERMINATOR::INDIRECT_CALL:
        printf("NextPC: 0x%" PRIx64 "\n", static_cast<uint64_t>(T._indirect_call.NextPC));
        break;

      case jove::TERMINATOR::CALL:
        printf("Target: 0x%" PRIx64 "\n", static_cast<uint64_t>(T._call.Target));
        printf("NextPC: 0x%" PRIx64 "\n", static_cast<uint64_t>(T._call.NextPC));
        break;

      case jove::TERMINATOR::NONE:
        printf("NextPC: 0x%" PRIx64 "\n", static_cast<uint64_t>(T._none.NextPC));
        break;

      default:
        break;
      }

      fputc('\n', stdout);
    }

    return true;
  };

  struct {
    target_ulong Addr;
  } StartingFrom = {0};

  if (!opts::StartingFrom.empty()) {
    StartingFrom.Addr = std::stoi(opts::StartingFrom.c_str(), 0, 16);
  }

  if (!opts::StartingFrom.empty()) {
    linear_scan_disassemble(StartingFrom.Addr);
  } else if (OptionalDynSymRegion) {
    auto DynSyms = OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();

    for_each_if(DynSyms.begin(),
                DynSyms.end(),
                [](const Elf_Sym &Sym) -> bool {
                  return !Sym.isUndefined() &&
                          Sym.getType() == llvm::ELF::STT_FUNC &&
                          Sym.st_size > 0;
                },
                [&](const Elf_Sym &Sym) {
                  auto ExpectedSymName = Sym.getName(DynamicStringTable);
                  if (!ExpectedSymName)
                    return;

                  uintptr_t Addr = Sym.st_value;

                  printf("//\n"
                         "// %s\n"
                         "//\n", (*ExpectedSymName).c_str());
                  linear_scan_disassemble(Addr, Addr + Sym.st_size);
                });
  } else {
    fprintf(stderr, "no dynamic symbols for given binary\n");
    return 1;
  }

  return 0;
}

void _qemu_log(const char *cstr) {
  fputs(cstr, stdout);
}

}

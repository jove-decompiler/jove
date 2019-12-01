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

#include <boost/icl/split_interval_map.hpp>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

namespace opts {
  static cl::OptionCategory JoveCategory("Specific Options");

  static cl::opt<std::string> Binary(cl::Positional, cl::desc("<binary>"),
                                     cl::Required, cl::cat(JoveCategory));

  static cl::opt<bool> DoTCGOpt("do-tcg-opt",
                                cl::desc("Run QEMU TCG optimizations"),
                                cl::cat(JoveCategory));

  static cl::opt<std::string> BreakOnAddr(
      "break-on-addr",
      cl::desc("Allow user to set a debugger breakpoint on TCGDumpBreakPoint, "
               "and triggered when basic block address matches given address"),
      cl::cat(JoveCategory));
}

namespace jove {
static int tcgdump(void);
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

#if defined(__x86_64__) || defined(__aarch64__)
typedef typename obj::ELF64LEObjectFile ELFO;
typedef typename obj::ELF64LEFile ELFT;
#elif defined(__i386__)
typedef typename obj::ELF32LEObjectFile ELFO;
typedef typename obj::ELF32LEFile ELFT;
#endif

typedef typename ELFT::Elf_Dyn Elf_Dyn;
typedef typename ELFT::Elf_Dyn_Range Elf_Dyn_Range;
typedef typename ELFT::Elf_Phdr Elf_Phdr;
typedef typename ELFT::Elf_Phdr_Range Elf_Phdr_Range;
typedef typename ELFT::Elf_Rela Elf_Rela;
typedef typename ELFT::Elf_Shdr Elf_Shdr;
typedef typename ELFT::Elf_Shdr_Range Elf_Shdr_Range;
typedef typename ELFT::Elf_Sym Elf_Sym;
typedef typename ELFT::Elf_Sym_Range Elf_Sym_Range;

template <class T>
static T unwrapOrError(llvm::Expected<T> EO) {
  if (EO)
    return *EO;

  std::string Buf;
  {
    llvm::raw_string_ostream OS(Buf);
    llvm::logAllUnhandledErrors(EO.takeError(), OS, "");
  }
  fprintf(stderr, "%s\n", Buf.c_str());
  exit(1);
}

int tcgdump(void) {
  struct {
    uintptr_t Addr;
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

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetDisassembler();

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
  const ELFT &E = *O.getELFFile();

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

  int AsmPrinterVariant =
#if defined(__x86_64__) || defined(__i386__)
      1
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

  //
  // build section map
  //
  struct section_properties_t {
    llvm::StringRef name;
    llvm::ArrayRef<uint8_t> contents;

    bool operator==(const section_properties_t &sect) const {
      return name == sect.name;
    }

    bool operator<(const section_properties_t &sect) const {
      return name < sect.name;
    }
  };

  typedef std::set<section_properties_t> section_properties_set_t;
  boost::icl::split_interval_map<std::uintptr_t, section_properties_set_t>
      SectMap;

  for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
    if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
      continue;

    llvm::Expected<llvm::ArrayRef<uint8_t>> contents =
        E.getSectionContents(&Sec);

    if (!contents)
      continue;

    llvm::Expected<llvm::StringRef> name = E.getSectionName(&Sec);

    if (!name)
      continue;

    boost::icl::interval<std::uintptr_t>::type intervl =
        boost::icl::interval<std::uintptr_t>::right_open(
            Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

    section_properties_t sectprop;
    sectprop.name = *name;
    sectprop.contents = *contents;

    SectMap.add({intervl, {sectprop}});
  }

  //
  // examine defined symbols which are functions and have a nonzero size
  //
  llvm::StringRef StrTable;
  const Elf_Shdr *DotSymtabSec = nullptr;

  for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
    if (Sec.sh_type == llvm::ELF::SHT_SYMTAB) {
      assert(!DotSymtabSec);
      DotSymtabSec = &Sec;
    }
  }

  if (!DotSymtabSec)
    return 0;

  StrTable = unwrapOrError(E.getStringTableForSymtab(*DotSymtabSec));

  auto symbols = [&](void) -> Elf_Sym_Range {
    return unwrapOrError(E.symbols(DotSymtabSec));
  };

  for (const Elf_Sym &Sym : symbols()) {
    if (Sym.getType() != llvm::ELF::STT_FUNC)
      continue;
    if (Sym.isUndefined())
      continue;
    if (!Sym.st_size)
      continue;

    llvm::StringRef SymName = unwrapOrError(Sym.getName(StrTable));
    uintptr_t Addr = Sym.st_value;

    auto it = SectMap.find(Addr);
    if (it == SectMap.end()) {
      fprintf(stderr, "warning: no section for symbol %s @ %" PRIxPTR "\n",
              SymName.str().c_str(), Addr);
      continue;
    }

    const auto &SectProp = *(*it).second.begin();

    const uintptr_t SectBase = (*it).first.lower();

    printf("%s @ %s+0x%" PRIxPTR " <%u>\n",
           SymName.str().c_str(),
           SectProp.name.str().c_str(),
           static_cast<std::uintptr_t>(Addr - SectBase),
           static_cast<unsigned>(Sym.st_size));

    //
    // linear scan translation
    //
    tcg.set_section(SectBase, SectProp.contents.data());

    unsigned BBSize;
    for (uintptr_t A = Addr; A < Addr + Sym.st_size; A += BBSize) {
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
      for (uintptr_t _A = A; _A < A + BBSize; _A += InstLen) {
        llvm::MCInst Inst;
        llvm::raw_ostream &DebugOut = llvm::nulls();
        llvm::raw_ostream &CommentStream = llvm::nulls();

        ptrdiff_t Offset = _A - SectBase;
        bool Disassembled = DisAsm->getInstruction(
            Inst, InstLen, SectProp.contents.slice(Offset), _A, DebugOut,
            CommentStream);
        if (!Disassembled) {
          fprintf(stderr, "failed to disassemble %" PRIxPTR "\n", _A);
          break;
        }

        std::string str;
        {
          llvm::raw_string_ostream StrStream(str);
          IP->printInst(&Inst, StrStream, "", *STI);
        }
        puts(str.c_str());
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
      printf("%s @ 0x%" PRIxPTR "\n",
             description_of_terminator(T.Type), T.Addr);

      switch (T.Type) {
      case jove::TERMINATOR::UNCONDITIONAL_JUMP:
        printf("Target: 0x%" PRIxPTR "\n", T._unconditional_jump.Target);
        break;

      case jove::TERMINATOR::CONDITIONAL_JUMP:
        printf("Target: 0x%" PRIxPTR "\n", T._conditional_jump.Target);
        printf("NextPC: 0x%" PRIxPTR "\n", T._conditional_jump.NextPC);
        break;

      case jove::TERMINATOR::INDIRECT_CALL:
        printf("NextPC: 0x%" PRIxPTR "\n", T._indirect_call.NextPC);
        break;

      case jove::TERMINATOR::CALL:
        printf("Target: 0x%" PRIxPTR "\n", T._call.Target);
        printf("NextPC: 0x%" PRIxPTR "\n", T._call.NextPC);
        break;

      case jove::TERMINATOR::NONE:
        printf("NextPC: 0x%" PRIxPTR "\n", T._none.NextPC);
        break;

      default:
        break;
      }

      fputc('\n', stdout);
    }
  }

  return 0;
}

void _qemu_log(const char *cstr) {
  fputs(cstr, stdout);
}

}

#include "tcgcommon.hpp"

#include <memory>
#include <boost/filesystem.hpp>
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

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

namespace opts {
  static cl::opt<std::string> Binary(cl::Positional,
    cl::desc("<binary>"),
    cl::Required);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "TCG Dump\n");

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

  if (!BinaryOrErr ||
      !llvm::isa<obj::ObjectFile>(BinaryOrErr.get().getBinary())) {
    fprintf(stderr, "failed to open %s\n", argv[1]);
    return 1;
  }

  obj::ObjectFile &O =
      *llvm::cast<obj::ObjectFile>(BinaryOrErr.get().getBinary());

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
#if defined(__x86_64__)
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

  llvm::StringRef SectNm;
  for (obj::SymbolRef Sym : O.symbols()) {
    if (!Sym.getName() || Sym.getName()->empty() ||
        !Sym.getType() || Sym.getType().get() != obj::SymbolRef::ST_Function ||
        !Sym.getSection() || Sym.getSection().get() == O.section_end() ||
        !Sym.getAddress() ||
        !(Sym.getAddress().get() >= Sym.getSection().get()->getAddress()) ||
        Sym.getSection().get()->getName(SectNm))
      continue;

    obj::SectionRef Sect = *Sym.getSection().get();

    const std::uintptr_t Addr = Sym.getAddress().get();
    const std::uintptr_t Base = Sect.getAddress();

    llvm::StringRef SecContentsStr;
    Sect.getContents(SecContentsStr);

    //
    // translate machine code to TCG
    //
    tcg.set_section(Base, SecContentsStr.bytes_begin());

    unsigned BBSize;
    jove::terminator_info_t T;
    std::tie(BBSize, T) = tcg.translate(Addr);

    //
    // print machine code which was translated
    //
    std::ptrdiff_t Offset = Addr - Base;
    assert(Offset >= 0);
    printf("%s @ %s+%#lx\n", Sym.getName()->str().c_str(), SectNm.str().c_str(),
           static_cast<std::uintptr_t>(Offset));

    uint64_t InstLen;
    for (std::uintptr_t A = Addr; A < Addr + BBSize; A += InstLen) {
      llvm::MCInst Inst;
      llvm::raw_ostream &DebugOut = llvm::nulls();
      llvm::raw_ostream &CommentStream = llvm::nulls();
      llvm::ArrayRef<uint8_t> SecContents(
          reinterpret_cast<const uint8_t *>(SecContentsStr.data()),
          SecContentsStr.size());

      Offset = A - Base;
      bool Disassembled =
          DisAsm->getInstruction(Inst, InstLen, SecContents.slice(Offset), Addr,
                                 DebugOut, CommentStream);
      if (!Disassembled) {
        fprintf(stderr, "failed to disassemble %p\n",
                reinterpret_cast<void *>(Addr));
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

    printf("live:");
    for (int i = 0; i < tcg._ctx.nb_globals; ++i) {
      const TCGTemp &ts = tcg._ctx.temps[i];
      if (ts.state & TS_DEAD)
        continue;

      printf(" %s", ts.name);
    }
    fputc('\n', stdout);

    printf("%s @ %#lx\n", description_of_terminator(T.Type), T.Addr);
    switch (T.Type) {
    case jove::TERMINATOR::UNCONDITIONAL_JUMP:
      printf("Target: %#lx\n", T._unconditional_jump.Target);
      break;

    case jove::TERMINATOR::CONDITIONAL_JUMP:
      printf("Target: %#lx\n", T._conditional_jump.Target);
      printf("NextPC: %#lx\n", T._conditional_jump.NextPC);
      break;

    case jove::TERMINATOR::INDIRECT_CALL:
      printf("NextPC: %#lx\n", T._indirect_call.NextPC);
      break;

    case jove::TERMINATOR::CALL:
      printf("Target: %#lx\n", T._call.Target);
      printf("NextPC: %#lx\n", T._call.NextPC);
      break;

    default:
      break;
    }
    fputc('\n', stdout);
  }

  return 0;
}

#include "tool.h"
#include "tcg.h"
#include "elf.h"
#include "disas.h"

#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>

#include <cinttypes>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

extern "C" {
void __attribute__((noinline))
     __attribute__((visibility("default")))
TCGDumpUserBreakPoint(void) {
  puts(__func__);
}
}

namespace jove {

namespace {

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> ObjectFile;
};

}

class TCGDumpTool : public TransformerTool<binary_state_t> {
  struct Cmdline {
    cl::opt<std::string> Binary;
    cl::opt<bool> DoTCGOpt;
    cl::opt<std::string> BreakOnAddr;
    cl::opt<std::string> StartingFrom;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Binary(cl::Positional, cl::desc("<binary>"), cl::Required,
                 cl::cat(JoveCategory)),

          DoTCGOpt("do-tcg-opt", cl::desc("Run QEMU TCG optimizations"),
                   cl::cat(JoveCategory)),

          BreakOnAddr("break-on-addr",
                      cl::desc("Allow user to set a debugger breakpoint on "
                               "TCGDumpUserBreakPoint, "
                               "and triggered when basic block address matches "
                               "given address"),
                      cl::cat(JoveCategory)),

          StartingFrom("starting-from",
                       cl::desc("Provide file address to disassemble"),
                       cl::cat(JoveCategory)) {}
  } opts;

public:
  TCGDumpTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("tcgdump", TCGDumpTool);

typedef boost::format fmt;

int TCGDumpTool::Run(void) {
#if 0
  if (opts.DoTCGOpt)
    do_tcg_optimization = true;
#endif

  struct {
    tcg_uintptr_t Addr = 0;
    bool Active = false;
  } BreakOn;

  if (!opts.BreakOnAddr.empty()) {
    BreakOn.Active = true;
    BreakOn.Addr = std::stoi(opts.BreakOnAddr.c_str(), 0, 16);
  }

  if (!fs::exists(opts.Binary)) {
    HumanOut() << llvm::formatv("given binary {0} does not exist\n", opts.Binary);
    return 1;
  }

  jove::tiny_code_generator_t tcg;
  disas_t disas;

  auto BinPair = CreateBinaryFromFile(opts.Binary.c_str());

  obj::Binary *B = BinPair.getBinary();
  if (!llvm::isa<ELFO>(B)) {
    HumanOut() << "invalid binary\n";
    return 1;
  }

  const ELFO &O = *llvm::cast<ELFO>(B);
  const ELFF &E = *O.getELFFile();

  DynRegionInfo DynamicTable(O.getFileName());
  loadDynamicTable(&E, &O, DynamicTable);

  if (!DynamicTable.Addr) {
    HumanOut() << "no dynamic table for given binary\n";
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

  auto linear_scan_disassemble = [&](tcg_uintptr_t Addr, tcg_uintptr_t End = 0) -> bool {
    if (!End)
      End = Addr + 32;

    tcg.set_binary(*B);

    HumanOut() << llvm::formatv("{0:x}\n", Addr);

    unsigned BBSize;
    for (tcg_uintptr_t A = Addr; A < End; A += BBSize) {
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

        bool Disassembled = disas.DisAsm->getInstruction(
            Inst, InstLen, llvm::ArrayRef<uint8_t>(*ExpectedPtr, BBSize), _A,
            llvm::nulls());
        if (!Disassembled) {
          HumanOut() << llvm::formatv("failed to disassemble {0:x}\n", _A);
          break;
        }

        std::string inst_str;
        {
          llvm::raw_string_ostream StrStream(inst_str);
          disas.IP->printInst(&Inst, _A, "", *disas.STI, StrStream);
        }

        HumanOut() << llvm::formatv("{0:x} {1}\n", _A, inst_str);
      }
      HumanOut() << '\n';

      //
      // print TCG
      //
      tcg.dump_operations();
      HumanOut() << '\n';

      //
      // print basic block terminator
      //
      HumanOut() << llvm::formatv("{0} @ {1:x}\n",
                                  description_of_terminator(T.Type),
                                  T.Addr);

      switch (T.Type) {
      case jove::TERMINATOR::UNCONDITIONAL_JUMP:
        HumanOut() << llvm::formatv("Target: {0:x}\n", T._unconditional_jump.Target);
        break;

      case jove::TERMINATOR::CONDITIONAL_JUMP:
        HumanOut() << llvm::formatv("Target: {0:x}\n", T._conditional_jump.Target);
        HumanOut() << llvm::formatv("NextPC: {0:x}\n", T._conditional_jump.NextPC);
        break;

      case jove::TERMINATOR::INDIRECT_CALL:
        HumanOut() << llvm::formatv("NextPC: {0:x}\n", T._indirect_call.NextPC);
        break;

      case jove::TERMINATOR::CALL:
        HumanOut() << llvm::formatv("Target: {0:x}\n", T._call.Target);
        HumanOut() << llvm::formatv("NextPC: {0:x}\n", T._call.NextPC);
        break;

      case jove::TERMINATOR::NONE:
        HumanOut() << llvm::formatv("NextPC: {0:x}\n", T._none.NextPC);
        break;

      default:
        break;
      }

      HumanOut() << '\n';
    }

    return true;
  };

  struct {
    tcg_uintptr_t Addr = 0;
  } StartingFrom;

  if (!opts.StartingFrom.empty())
    StartingFrom.Addr = std::stoi(opts.StartingFrom.c_str(), 0, 16);

  if (!opts.StartingFrom.empty()) {
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

                  HumanOut() << (fmt("//\n"
                                     "// %s\n"
                                     "//\n") % (*ExpectedSymName).data()).str();
                  linear_scan_disassemble(Addr, Addr + Sym.st_size);
                });
  } else {
    HumanOut() << "no dynamic symbols for given binary\n";
    return 1;
  }

  return 0;
}

}

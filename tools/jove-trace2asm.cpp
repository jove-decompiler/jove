#include "tool.h"
#include "elf.h"
#include <boost/algorithm/string.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <cstdlib>
#include <llvm/ADT/PointerIntPair.h>
#include <llvm/DebugInfo/Symbolize/Symbolize.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataExtractor.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Target/TargetMachine.h>
#include <memory>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <linux/magic.h>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

struct binary_state_t {
  std::unique_ptr<llvm::object::Binary> ObjectFile;
};

class Trace2AsmTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> TracePath;
    cl::opt<std::string> jv;
    cl::alias jvAlias;
    cl::list<unsigned> ExcludeBinaries;
    cl::opt<bool> SkipRepeated;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : TracePath(cl::Positional, cl::desc("trace.txt"), cl::Required,
                    cl::value_desc("filename"), cl::cat(JoveCategory)),

          jv("decompilation", cl::desc("Jove decompilation"), cl::Required,
             cl::value_desc("filename"), cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -decompilation."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)),

          ExcludeBinaries("exclude-bins", cl::CommaSeparated,
                          cl::value_desc("bidx_1,bidx_2,...,bidx_n"),
                          cl::desc("Indices of binaries to exclude"),
                          cl::cat(JoveCategory)),

          SkipRepeated("skip-repeated", cl::desc("Skip repeated blocks"),
                       cl::cat(JoveCategory)) {}
  } opts;

public:
  Trace2AsmTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("trace2asm", Trace2AsmTool);

typedef boost::format fmt;

int Trace2AsmTool::Run(void) {
  if (!fs::exists(opts.TracePath)) {
    WithColor::error() << "trace does not exist\n";
    return 1;
  }

  if (!fs::exists(opts.jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  //
  // parse trace.txt
  //
  std::vector<std::pair<binary_index_t, basic_block_index_t>> trace;

  {
    std::ifstream trace_ifs(opts.TracePath.c_str());

    if (!trace_ifs) {
      WithColor::error() << llvm::formatv("failed to open trace file '{0}'\n",
                                          opts.TracePath.c_str());
      return 1;
    }

    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } Last;

    Last.BIdx = invalid_binary_index;
    Last.BBIdx = invalid_basic_block_index;

    std::string line;
    while (std::getline(trace_ifs, line)) {
      if (line.size() < sizeof("JV_") || line[0] != 'J' || line[1] != 'V' ||
          line[2] != '_') {
        WithColor::error()
            << llvm::formatv("bad input line: '{0}'\n", line.c_str());
        return 1;
      }

      uint32_t BIdx, BBIdx;
      int fields =
          sscanf(line.c_str(), "JV_%" PRIu32 "_%" PRIu32, &BIdx, &BBIdx);

      if (fields != 2)
        break;

      if (opts.SkipRepeated) {
        if (Last.BIdx == BIdx && Last.BBIdx == BBIdx)
          continue;
      }

      trace.push_back({BIdx, BBIdx});

      Last.BIdx = BIdx;
      Last.BBIdx = BBIdx;
    }
  }

  //
  // parse the existing decompilation file
  //
  decompilation_t decompilation;
  bool git = fs::is_directory(opts.jv);
  std::string jvfp = git ? (opts.jv + "/decompilation.jv") : opts.jv;
  ReadDecompilationFromFile(jvfp, decompilation);

  llvm::InitializeAllTargets();

  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  llvm::Triple TheTriple;
  llvm::SubtargetFeatures Features;

  //
  // init state for binaries
  //
  for (binary_index_t BIdx = 0; BIdx < decompilation.Binaries.size(); ++BIdx) {
    auto &binary = decompilation.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;

    //
    // parse the ELF
    //
    llvm::StringRef Buffer(reinterpret_cast<const char *>(&binary.Data[0]),
                           binary.Data.size());
    llvm::StringRef Identifier(binary.Path);
    llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(MemBuffRef);
    if (!BinOrErr) {
      WithColor::error() << "failed to create binary from " << binary.Path
                         << '\n';
    } else {
      std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

      state_for_binary(binary).ObjectFile = std::move(BinRef);
    }
  }

  const llvm::Target *TheTarget;
  std::unique_ptr<const llvm::MCRegisterInfo> MRI;
  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo;
  std::unique_ptr<const llvm::MCSubtargetInfo> STI;
  std::unique_ptr<const llvm::MCInstrInfo> MII;
  std::unique_ptr<llvm::MCObjectFileInfo> MOFI;
  std::unique_ptr<llvm::MCContext> MCCtx;
  std::unique_ptr<llvm::MCDisassembler> DisAsm;
  std::unique_ptr<llvm::MCInstPrinter> IP;
  std::unique_ptr<llvm::TargetMachine> TM;

  //
  // TheTarget
  //
  std::string ArchName;
  std::string Error;

  TheTarget = llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    WithColor::error() << llvm::formatv("failed to lookup target: {0}\n",
                                        Error.c_str());
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;

  MRI.reset(TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    fprintf(stderr, "no register info for target\n");
    return 1;
  }

  {
    llvm::MCTargetOptions Options;
    AsmInfo.reset(
	TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
  }
  if (!AsmInfo) {
    fprintf(stderr, "no assembly info\n");
    return 1;
  }

  STI.reset(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI) {
    fprintf(stderr, "no subtarget info\n");
    return 1;
  }

  MII.reset(TheTarget->createMCInstrInfo());
  if (!MII) {
    fprintf(stderr, "no instruction info\n");
    return 1;
  }

  MOFI.reset(new llvm::MCObjectFileInfo);
  MCCtx.reset(new llvm::MCContext(AsmInfo.get(), MRI.get(), MOFI.get()));

  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI->InitMCObjectFileInfo(TheTriple, false, *MCCtx);

  DisAsm.reset(TheTarget->createMCDisassembler(*STI, *MCCtx));
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
  IP.reset(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    fprintf(stderr, "no instruction printer\n");
    return 1;
  }

  auto disassemble_basic_block = [&](binary_index_t BIdx,
                                     basic_block_index_t BBIdx) -> std::string {
    auto &binary = decompilation.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;
    basic_block_t bb = boost::vertex(BBIdx, ICFG);

    const ELFF &E = *llvm::cast<ELFO>(state_for_binary(binary).ObjectFile.get())->getELFFile();

    tcg_uintptr_t Addr = ICFG[bb].Addr;
    unsigned Size = ICFG[bb].Size;

    //std::string res = (fmt("%08x [%u]\n\n") % ICFG[bb].Addr % ICFG[bb].Size).str();
    std::string res;

    tcg_uintptr_t End = Addr + Size;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    if (ICFG[bb].Term.Type != TERMINATOR::NONE)
      End += 4; /* delay slot */
#endif

    uint64_t InstLen = 0;
    for (uintptr_t A = Addr; A < End; A += InstLen) {
      llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(A);
      if (!ExpectedPtr)
        abort();

      llvm::MCInst Inst;

      std::string errmsg;
      bool Disassembled;
      {
        llvm::raw_string_ostream ErrorStrStream(errmsg);

        Disassembled = DisAsm->getInstruction(
            Inst, InstLen, llvm::ArrayRef<uint8_t>(*ExpectedPtr, End - Addr), A,
            ErrorStrStream);
      }

      if (!Disassembled) {
        res.append("failed to disassemble");
        if (!errmsg.empty()) {
          res.append(": ");
          res.append(errmsg);
        }
        res.push_back('\n');
        break;
      }

      std::string line;
      {
        llvm::raw_string_ostream StrStream(line);
        IP->printInst(&Inst, A, "", *STI, StrStream);
      }
      boost::trim(line);

      res.append((fmt("%08x   ") % A).str());
      res.append(line);
      res.push_back('\n');
    }

    return res;
  };

  //
  // disassemble every block in the trace
  //
  for (const auto &pair : trace) {
    binary_index_t BIdx;
    basic_block_index_t BBIdx;

    std::tie(BIdx, BBIdx) = pair;

    if (std::find(opts.ExcludeBinaries.begin(),
                  opts.ExcludeBinaries.end(), BIdx) != opts.ExcludeBinaries.end())
      continue;

    llvm::outs() << '\n' << disassemble_basic_block(BIdx, BBIdx) << '\n';
  }

  return 0;
}

}

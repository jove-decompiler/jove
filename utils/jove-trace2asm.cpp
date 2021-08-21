#include <boost/icl/split_interval_map.hpp>
#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/ArrayRef.h>
#include <set>

struct section_properties_t {
  llvm::StringRef name;
  llvm::ArrayRef<uint8_t> contents;

  bool w, x;
  bool initArray;
  bool finiArray;

  bool operator==(const section_properties_t &sect) const {
    return name == sect.name;
  }

  bool operator<(const section_properties_t &sect) const {
    return name < sect.name;
  }
};
typedef std::set<section_properties_t> section_properties_set_t;

//
// forward decls
//
namespace llvm {
namespace object {
class Binary;
}
}

#define JOVE_EXTRA_BIN_PROPERTIES                                              \
  std::unique_ptr<llvm::object::Binary> ObjectFile;                            \
  boost::icl::split_interval_map<tcg_uintptr_t, section_properties_set_t> SectMap; \

#include "tcgcommon.hpp"

#include <memory>
#include <cstdlib>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/DebugInfo/Symbolize/Symbolize.h>
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
#include <llvm/Target/TargetMachine.h>
#include <boost/format.hpp>
#include <boost/filesystem.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/algorithm/string.hpp>
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

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> TracePath(cl::Positional, cl::desc("trace.txt"),
                                      cl::Required, cl::value_desc("filename"),
                                      cl::cat(JoveCategory));

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

static cl::list<unsigned>
    ExcludeBinaries("exclude-bins", cl::CommaSeparated,
                    cl::value_desc("bidx_1,bidx_2,...,bidx_n"),
                    cl::desc("Indices of binaries to exclude"),
                    cl::cat(JoveCategory));

static cl::opt<bool> SkipRepeated("skip-repeated",
                                  cl::desc("Skip repeated blocks"),
                                  cl::cat(JoveCategory));

static cl::opt<bool> tcg("tcg",
                         cl::desc("Translate to TCG"),
                         cl::cat(JoveCategory));

} // namespace opts

namespace jove {
static int trace2asm(void);
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove Trace\n");

  if (!fs::exists(opts::TracePath)) {
    WithColor::error() << "trace does not exist\n";
    return 1;
  }

  if (!fs::exists(opts::jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  return jove::trace2asm();
}

namespace jove {

typedef boost::format fmt;

#include "elf.hpp"

static int await_process_completion(pid_t);

static bool is_dumping_ops = false;

static std::string dumped_ops; /* XXX hack */

int trace2asm(void) {
  //
  // parse trace.txt
  //
  std::vector<std::pair<binary_index_t, basic_block_index_t>> trace;

  {
    std::ifstream trace_ifs(opts::TracePath.c_str());

    if (!trace_ifs) {
      WithColor::error() << llvm::formatv("failed to open trace file '{0}'\n",
                                          opts::TracePath.c_str());
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

      if (opts::SkipRepeated) {
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
  bool git = fs::is_directory(opts::jv);
  {
    std::ifstream ifs(git ? (opts::jv + "/decompilation.jv") : opts::jv);

    boost::archive::text_iarchive ia(ifs);
    ia >> decompilation;
  }

  jove::tiny_code_generator_t tcg;

#if 0
  llvm::InitializeAllTargets();
#else
  //LLVMInitializeAArch64TargetInfo();
  //LLVMInitializeAMDGPUTargetInfo();
  //LLVMInitializeARMTargetInfo();
  //LLVMInitializeBPFTargetInfo();
  //LLVMInitializeHexagonTargetInfo();
  //LLVMInitializeLanaiTargetInfo();
  //LLVMInitializeMipsTargetInfo();
  //LLVMInitializeMSP430TargetInfo();
  //LLVMInitializeNVPTXTargetInfo();
  //LLVMInitializePowerPCTargetInfo();
  //LLVMInitializeRISCVTargetInfo();
  //LLVMInitializeSparcTargetInfo();
  //LLVMInitializeSystemZTargetInfo();
  //LLVMInitializeWebAssemblyTargetInfo();
  LLVMInitializeX86TargetInfo();
  //LLVMInitializeXCoreTargetInfo();
#endif

  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  llvm::Triple TheTriple;
  llvm::SubtargetFeatures Features;

  //
  // compute the set of verts for each function
  //
  for (binary_index_t BIdx = 0; BIdx < decompilation.Binaries.size(); ++BIdx) {
    auto &binary = decompilation.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;
    auto &SectMap = binary.SectMap;

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

      boost::icl::interval<tcg_uintptr_t>::type intervl =
          boost::icl::interval<tcg_uintptr_t>::right_open(0, binary.Data.size());

      assert(SectMap.find(intervl) == SectMap.end());

      section_properties_t sectprop;
      sectprop.name = ".text";
      sectprop.contents = llvm::ArrayRef<uint8_t>((uint8_t *)&binary.Data[0], binary.Data.size());
      sectprop.w = false;
      sectprop.x = true;
      sectprop.initArray = false;
      sectprop.finiArray = false;
      SectMap.add({intervl, {sectprop}});
    } else {
      std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

      binary.ObjectFile = std::move(BinRef);

      assert(llvm::isa<ELFO>(binary.ObjectFile.get()));
      ELFO &O = *llvm::cast<ELFO>(binary.ObjectFile.get());

      TheTriple = O.makeTriple();
      Features = O.getFeatures();

      const ELFF &E = *O.getELFFile();

      //
      // build section map
      //
      llvm::Expected<Elf_Shdr_Range> sections = E.sections();
      if (!sections) {
        WithColor::error() << "error: could not get ELF sections for binary "
                           << binary.Path << '\n';
        return 1;
      }

      for (const Elf_Shdr &Sec : *sections) {
        if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
          continue;

        llvm::Expected<llvm::StringRef> name = E.getSectionName(&Sec);

        if (!name)
          continue;

        if ((Sec.sh_flags & llvm::ELF::SHF_TLS) &&
            *name == std::string(".tbss"))
          continue;

        if (!Sec.sh_size)
          continue;

        section_properties_t sectprop;
        sectprop.name = *name;

        if (Sec.sh_type == llvm::ELF::SHT_NOBITS) {
          sectprop.contents = llvm::ArrayRef<uint8_t>();
        } else {
          llvm::Expected<llvm::ArrayRef<uint8_t>> contents =
              E.getSectionContents(&Sec);
          assert(contents);
          sectprop.contents = *contents;
        }

        sectprop.w = !!(Sec.sh_flags & llvm::ELF::SHF_WRITE);
        sectprop.x = !!(Sec.sh_flags & llvm::ELF::SHF_EXECINSTR);

        sectprop.initArray = Sec.sh_type == llvm::ELF::SHT_INIT_ARRAY;
        sectprop.finiArray = Sec.sh_type == llvm::ELF::SHT_FINI_ARRAY;

        boost::icl::interval<tcg_uintptr_t>::type intervl =
            boost::icl::interval<tcg_uintptr_t>::right_open(
                Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

        {
          auto it = SectMap.find(intervl);
          if (it != SectMap.end()) {
            WithColor::error() << "the following sections intersect: "
                               << (*(*it).second.begin()).name << " and "
                               << sectprop.name << '\n';
            return 1;
          }
        }

        SectMap.add({intervl, {sectprop}});
      }
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
    auto &SectMap = binary.SectMap;
    basic_block_t bb = boost::vertex(BBIdx, ICFG);

    tcg_uintptr_t Addr = ICFG[bb].Addr;
    unsigned Size = ICFG[bb].Size;

    auto it = SectMap.find(Addr);
    if (it == SectMap.end()) {
      WithColor::warning() << llvm::formatv(
          "no section for given address {0:x}", Addr);
      return "ERROR";
    }

    const auto &SectProp = *(*it).second.begin();
    const uintptr_t SectBase = (*it).first.lower();

#if 0
    TCG->set_section(SectBase, SectProp.contents.data());
#endif

    //std::string res = (fmt("%08x [%u]\n\n") % ICFG[bb].Addr % ICFG[bb].Size).str();
    std::string res;

    tcg_uintptr_t End = Addr + Size;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    if (ICFG[bb].Term.Type != TERMINATOR::NONE)
      End += 4; /* delay slot */
#endif

    uint64_t InstLen = 0;
    for (uintptr_t A = Addr; A < End; A += InstLen) {
      llvm::MCInst Inst;

      std::string errmsg;
      bool Disassembled;
      {
        llvm::raw_string_ostream ErrorStrStream(errmsg);

        ptrdiff_t Offset = A - SectBase;
        Disassembled = DisAsm->getInstruction(
            Inst, InstLen, SectProp.contents.slice(Offset), A, ErrorStrStream);
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

  auto translate_basic_block = [&](binary_index_t BIdx,
                                   basic_block_index_t BBIdx) -> std::string {
    auto &binary = decompilation.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;
    auto &SectMap = binary.SectMap;
    basic_block_t bb = boost::vertex(BBIdx, ICFG);

    tcg_uintptr_t Addr = ICFG[bb].Addr;
    unsigned Size = ICFG[bb].Size;

    auto it = SectMap.find(Addr);
    if (it == SectMap.end()) {
      WithColor::warning() << llvm::formatv(
          "no section for given address {0:x}", Addr);
      return "ERROR";
    }

    const auto &SectProp = *(*it).second.begin();
    const uintptr_t SectBase = (*it).first.lower();

    tcg.set_elf(llvm::cast<ELFO>(binary.ObjectFile.get())->getELFFile());

    std::string res;

    unsigned count = 0;
    unsigned size = 0;
    do {
      unsigned len;
      jove::terminator_info_t T;

      std::tie(len, T) = tcg.translate(Addr + size, Addr + Size);
      ++count;

      dumped_ops.clear();
      is_dumping_ops = true;
      tcg.dump_operations();
      is_dumping_ops = false;

      res.append(dumped_ops);

      size += len;
    } while (size < Size);

    res.push_back('\n');
    res.append(std::to_string(count));
    res.push_back(' ');
    res.append("time");
    if (count > 1)
      res.push_back('s');
    res.push_back('\n');

    return res;
  };

  //
  // disassemble every block in the trace
  //
  for (const auto &pair : trace) {
    binary_index_t BIdx;
    basic_block_index_t BBIdx;

    std::tie(BIdx, BBIdx) = pair;

    if (std::find(opts::ExcludeBinaries.begin(),
                  opts::ExcludeBinaries.end(), BIdx) != opts::ExcludeBinaries.end())
      continue;

    llvm::outs() << '\n' << disassemble_basic_block(BIdx, BBIdx) << '\n';
    if (opts::tcg)
      llvm::outs() << '\n' << translate_basic_block(BIdx, BBIdx) << '\n';
  }

  return 1;
}

// TODO this whole function needs to be obliterated
int InitStateForBinaries(void) {

  return 0;
}

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

void _qemu_log(const char *cstr) {
  if (is_dumping_ops) {
    dumped_ops.append(cstr);
    return;
  }

  llvm::outs() << cstr;
}

}

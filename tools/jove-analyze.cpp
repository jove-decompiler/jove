#include <boost/icl/interval_set.hpp>
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
class BasicBlock;
namespace object {
class Binary;
}
}

#define JOVE_EXTRA_BB_PROPERTIES                                               \
  tcg_global_set_t IN, OUT;                                                    \
                                                                               \
  void Analyze(binary_index_t);                                                \
                                                                               \
  llvm::BasicBlock *B;

#define JOVE_EXTRA_FN_PROPERTIES                                               \
  binary_index_t BIdx;                                                         \
  function_index_t FIdx;                                                       \
  std::vector<basic_block_t> BasicBlocks;                                      \
  std::vector<basic_block_t> ExitBasicBlocks;                                  \
                                                                               \
  bool IsLeaf;                                                                 \
                                                                               \
  void Analyze(void);

#define JOVE_EXTRA_BIN_PROPERTIES                                              \
  std::unique_ptr<llvm::object::Binary> ObjectFile;                            \
  boost::icl::split_interval_map<uintptr_t, section_properties_set_t> SectMap;

#include "tcgcommon.hpp"

#include <tuple>
#include <memory>
#include <sstream>
#include <fstream>
#include <unordered_set>
#include <random>
#include <boost/filesystem.hpp>
#include <boost/graph/graphviz.hpp>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/ADT/Statistic.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/GlobalIFunc.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/InitializePasses.h>
#include <llvm/LinkAllPasses.h>
#include <llvm/Linker/Linker.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ELFObjectFile.h>
#include <thread>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/WithColor.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/LowerMemIntrinsics.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "jove/jove.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/format.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/graph/copy.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/filtered_graph.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/container_hash/extensions.hpp>

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

#include "analyze.hpp"

namespace jove {
static unsigned num_cpus(void);
}

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

static cl::list<std::string>
    PinnedGlobals("pinned-globals", cl::CommaSeparated,
                  cl::value_desc("glb_1,glb_2,...,glb_n"),
                  cl::desc("force specified TCG globals to always go through CPUState"),
                  cl::cat(JoveCategory));

} // namespace opts

namespace jove {
static int analyze(void);

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::AddExtraVersionPrinter([](llvm::raw_ostream &OS) -> void {
    OS << "jove version " JOVE_VERSION "\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "Jove Analyze\n");

  if (!fs::exists(opts::jv)) {
    llvm::errs() << "decompilation does not exist\n";
    return 1;
  }

  return jove::analyze();
}

namespace jove {

typedef boost::format fmt;

static int ProcessCommandLine(void);
static int ParseDecompilation(void);
static int ProcessDynamicTargets(void);
static int InitStateForBinaries(void);
static int CreateModule(void);
static int PrepareToTranslateCode(void);
static int AnalyzeBlocks(void);
static int AnalyzeFunctions(void);
static int WriteDecompilation(void);

int analyze(void) {
  return ParseDecompilation()
      || ProcessDynamicTargets()
      || InitStateForBinaries()
      || CreateModule()
      || PrepareToTranslateCode()
      || ProcessCommandLine() /* must do this after TCG is ready */
      || AnalyzeBlocks()
      || AnalyzeFunctions()
      || WriteDecompilation();
}

void _qemu_log(const char *cstr) {
  llvm::errs() << cstr;
}

bool isDFSan(void) {
  return false;
}

int ProcessCommandLine(void) {
  auto tcg_index_of_named_global = [&](const char *nm) -> int {
    for (int i = 0; i < TCG->_ctx.nb_globals; i++) {
      if (strcmp(TCG->_ctx.temps[i].name, nm) == 0)
        return i;
    }

    return -1;
  };

  for (const std::string &PinnedGlobalName : opts::PinnedGlobals) {
    int idx = tcg_index_of_named_global(PinnedGlobalName.c_str());
    if (idx < 0) {
      WithColor::warning() << llvm::formatv(
          "unknown global {0} (--pinned-globals); ignoring\n", idx);
      continue;
    }

    CmdlinePinnedEnvGlbs.set(idx);
  }

  return 0;
}

int ParseDecompilation(void) {
  std::ifstream ifs(
      fs::is_directory(opts::jv) ? (opts::jv + "/decompilation.jv") : opts::jv);

  boost::archive::text_iarchive ia(ifs);
  ia >> Decompilation;

  return 0;
}

int ProcessDynamicTargets(void) {
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &binary = Decompilation.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;

    for (basic_block_index_t BBIdx = 0; BBIdx < boost::num_vertices(ICFG);
         ++BBIdx) {
      basic_block_t bb = boost::vertex(BBIdx, ICFG);

      for (const auto &DynTarget : ICFG[bb].DynTargets) {
        if (DynTarget.first == BIdx)
          continue;

        function_t &callee = Decompilation.Binaries[DynTarget.first]
                                .Analysis.Functions[DynTarget.second];

        callee.IsABI = true;
      }
    }
  }

  //
  // dynamic ifunc resolver targets are ABIs
  //
  for (const binary_t &binary : Decompilation.Binaries) {
    for (const auto &pair : binary.Analysis.IFuncDynTargets) {
      for (const auto &IdxPair : pair.second) {
        binary_index_t BIdx;
        function_index_t FIdx;
        std::tie(BIdx, FIdx) = IdxPair;

        function_t &f =
            Decompilation.Binaries.at(BIdx).Analysis.Functions.at(FIdx);

        f.IsABI = true;
      }
    }
  }

#if 0
  //
  // resolved symbols are ABIs
  //
  for (const binary_t &binary : Decompilation.Binaries) {
    for (const auto &pair : binary.Analysis.SymDynTargets) {
      for (const auto &IdxPair : pair.second) {
        binary_index_t BIdx;
        function_index_t FIdx;
        std::tie(BIdx, FIdx) = IdxPair;

        function_t &f =
            Decompilation.Binaries.at(BIdx).Analysis.Functions.at(FIdx);

        f.IsABI = true;
      }
    }
  }
#endif

#if 0
  //
  // _start is *not* an ABI XXX
  //
  for (auto &binary : Decompilation.Binaries) {
    auto &A = binary.Analysis;
    if (binary.IsExecutable) {
      if (is_function_index_valid(A.EntryFunction))
        A.Functions[A.EntryFunction].IsABI = false;

      break;
    }
  }
#endif

  return 0;
}

#include "elf.hpp"

// XXX code duplication
int InitStateForBinaries(void) {
  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &binary = Decompilation.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;
    auto &SectMap = binary.SectMap;

    for (function_index_t FIdx = 0; FIdx < binary.Analysis.Functions.size(); ++FIdx) {
      function_t &f = binary.Analysis.Functions[FIdx];

      f.BIdx = BIdx;
      f.FIdx = FIdx;
    }

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
      if (!binary.IsVDSO)
        WithColor::error() << llvm::formatv(
            "failed to create binary from {0}\n", binary.Path);

      boost::icl::interval<uintptr_t>::type intervl =
          boost::icl::interval<uintptr_t>::right_open(0, binary.Data.size());

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

        boost::icl::interval<uintptr_t>::type intervl =
            boost::icl::interval<uintptr_t>::right_open(
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

  return 0;
}

int CreateModule(void) {
  Context.reset(new llvm::LLVMContext);

  const char *bootstrap_mod_name = isDFSan() ? "jove.dfsan" : "jove";

  std::string bootstrap_mod_path =
      (boost::dll::program_location().parent_path() /
       (std::string(bootstrap_mod_name) + ".bc"))
          .string();

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
      llvm::MemoryBuffer::getFile(bootstrap_mod_path);
  if (!BufferOr) {
    WithColor::error() << "failed to open bitcode " << bootstrap_mod_path
                       << ": " << BufferOr.getError().message() << '\n';
    return 1;
  }

  llvm::Expected<std::unique_ptr<llvm::Module>> moduleOr =
      llvm::parseBitcodeFile(BufferOr.get()->getMemBufferRef(), *Context);
  if (!moduleOr) {
    llvm::logAllUnhandledErrors(moduleOr.takeError(), llvm::errs(),
                                "could not parse helper bitcode: ");
    return 1;
  }

  Module = std::move(moduleOr.get());

  DL = Module->getDataLayout();

  return 0;
}

int PrepareToTranslateCode(void) {
  TCG.reset(new tiny_code_generator_t);

  return 0;
}

int AnalyzeBlocks(void) {
  WithColor::note() << "Analyzing basic blocks...\n";

  for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
    auto &binary = Decompilation.Binaries[BIdx];
    auto &ICFG = binary.Analysis.ICFG;

    icfg_t::vertex_iterator vi, vi_end;
    for (std::tie(vi, vi_end) = boost::vertices(ICFG); vi != vi_end; ++vi) {
      basic_block_t bb = *vi;

      ICFG[bb].Analyze(BIdx);
    }
  }

  return 0;
}

static void worker1(std::atomic<dynamic_target_t *> &Q_ptr,
                    dynamic_target_t *Q_end);
static void worker2(std::atomic<dynamic_target_t *> &Q_ptr,
                    dynamic_target_t *Q_end);

static int GuessParallelism();

int AnalyzeFunctions(void) {
  // let N be the count of all functions (in all binaries)
  unsigned N = std::accumulate(
      Decompilation.Binaries.begin(),
      Decompilation.Binaries.end(), 0,
      [&](unsigned res, const binary_t &binary) -> unsigned {
        return res + binary.Analysis.Functions.size();
      });

  {
    std::vector<dynamic_target_t> Q;
    Q.reserve(N);

    //
    // Build queue with all function pairs (b, f)
    //
    for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx)
      for (function_index_t FIdx = 0; FIdx < Decompilation.Binaries[BIdx].Analysis.Functions.size(); ++FIdx)
        Q.emplace_back(BIdx, FIdx);

    if (!Q.empty()) {
      //
      // Determine IsLeaf for every function
      //
      std::atomic<dynamic_target_t *> Q_ptr(Q.data());

      WithColor::note() << llvm::formatv("Analyzing {0} functions [1]...\n", Q.size());

      {
        std::vector<std::thread> workers;

        unsigned NumThreads = GuessParallelism();

        workers.reserve(NumThreads);
        for (unsigned i = 0; i < NumThreads; ++i)
          workers.push_back(std::thread(worker1,
                                        std::ref(Q_ptr),
                                        Q.data() + Q.size()));

        for (std::thread &t : workers)
          t.join();
      }
    }
  }

  {
    std::vector<dynamic_target_t> Q;
    Q.reserve(N);

    //
    // Build queue with functions having stale analyses in Q2.
    //
    for (binary_index_t BIdx = 0; BIdx < Decompilation.Binaries.size(); ++BIdx) {
      binary_t &binary = Decompilation.Binaries[BIdx];
      for (function_index_t FIdx = 0; FIdx < binary.Analysis.Functions.size(); ++FIdx) {
        function_t &f = binary.Analysis.Functions[FIdx];
        if (f.Analysis.Stale)
          Q.emplace_back(BIdx, FIdx);
      }
    }

    if (!Q.empty()) {
      //
      // Analyze every function
      //
      std::atomic<dynamic_target_t *> Q_ptr(Q.data());

      WithColor::note() << llvm::formatv("Analyzing {0} functions [2]...\n", Q.size());

      {
        std::vector<std::thread> workers;

        unsigned NumThreads = GuessParallelism();

        workers.reserve(NumThreads);
        for (unsigned i = 0; i < NumThreads; ++i)
          workers.push_back(std::thread(worker2,
                                        std::ref(Q_ptr),
                                        Q.data() + Q.size()));

        for (std::thread &t : workers)
          t.join();
      }
    }
  }

  return 0;
}

void worker1(std::atomic<dynamic_target_t *> &Q_ptr,
             dynamic_target_t *Q_end) {
  for (dynamic_target_t *p = Q_ptr++; p < Q_end; p = Q_ptr++) {
    dynamic_target_t IdxPair = *p;

    binary_t &binary = Decompilation.Binaries.at(IdxPair.first);
    auto &ICFG = binary.Analysis.ICFG;

    function_t &f = binary.Analysis.Functions.at(IdxPair.second);

    //
    // BasicBlocks (in DFS order)
    //
    std::map<basic_block_t, boost::default_color_type> color;
    dfs_visitor<interprocedural_control_flow_graph_t> vis(f.BasicBlocks);
    depth_first_visit(
        ICFG, boost::vertex(f.Entry, ICFG), vis,
        boost::associative_property_map<
            std::map<basic_block_t, boost::default_color_type>>(color));

    //
    // ExitBasicBlocks
    //
    std::copy_if(f.BasicBlocks.begin(),
                 f.BasicBlocks.end(),
                 std::back_inserter(f.ExitBasicBlocks),
                 [&](basic_block_t bb) -> bool {
                   return IsExitBlock(ICFG, bb);
                 });

    f.Returns = f.Returns || !f.ExitBasicBlocks.empty();

    f.IsLeaf = std::all_of(f.ExitBasicBlocks.begin(),
                           f.ExitBasicBlocks.end(),
                           [&](basic_block_t bb) -> bool {
                             auto T = ICFG[bb].Term.Type;
                             return T == TERMINATOR::RETURN
                                 || T == TERMINATOR::UNREACHABLE;
                           }) &&

               std::none_of(f.BasicBlocks.begin(),
                            f.BasicBlocks.end(),
                   [&](basic_block_t bb) -> bool {
                     auto T = ICFG[bb].Term.Type;
                     return (T == TERMINATOR::INDIRECT_JUMP &&
                             boost::out_degree(bb, ICFG) == 0)
                          || T == TERMINATOR::INDIRECT_CALL
                          || T == TERMINATOR::CALL;
                   });
  }
}

void worker2(std::atomic<dynamic_target_t *>& Q_ptr,
             dynamic_target_t *Q_end) {
  for (dynamic_target_t *p = Q_ptr++; p < Q_end; p = Q_ptr++) {
    dynamic_target_t IdxPair = *p;

    function_t &f = Decompilation.Binaries.at(IdxPair.first)
                       .Analysis.Functions.at(IdxPair.second);

    f.Analyze();
  }
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

unsigned num_cpus(void) {
  cpu_set_t cpu_mask;
  if (sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask) < 0) {
    WithColor::error() << "sched_getaffinity failed : " << strerror(errno)
                       << '\n';
    abort();
  }

  return CPU_COUNT(&cpu_mask);
}

int GuessParallelism() {
  switch (int processors = num_cpus()) {
  case 0:
  case 1:
    return 2;
  case 2:
    return 3;
  default:
    return processors + 2;
  }
}

static void IgnoreCtrlC(void) {
  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = SIG_IGN;

  if (sigaction(SIGINT, &sa, nullptr) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("{0}: sigaction failed ({1})\n",
                                        __func__, strerror(err));
  }
}

int WriteDecompilation(void) {
  IgnoreCtrlC();

  {
    std::ofstream ofs(fs::is_directory(opts::jv)
                          ? (opts::jv + "/decompilation.jv")
                          : opts::jv);

    boost::archive::text_oarchive oa(ofs);
    oa << Decompilation;
  }

  //
  // git commit
  //
  std::string msg("[jove-analyze]");

  // TODO check that there are no uncommitted changes
  if (fs::is_directory(opts::jv)) {
    pid_t pid = fork();
    if (!pid) { /* child */
      chdir(opts::jv.c_str());

      const char *argv[] = {"/usr/bin/git", "commit",    ".",
                            "-m",           msg.c_str(), nullptr};

      execve(argv[0], const_cast<char **>(argv), ::environ);
      abort();
    }

    await_process_completion(pid);
  }

  return 0;
}

} // namespace jove

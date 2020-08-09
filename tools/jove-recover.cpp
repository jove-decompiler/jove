#include "tcgcommon.hpp"

#include <tuple>
#include <numeric>
#include <memory>
#include <sstream>
#include <fstream>
#include <cinttypes>
#include <array>
#include <boost/filesystem.hpp>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
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
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <sys/uio.h>
#if !defined(__x86_64__) && defined(__i386__)
#include <asm/ldt.h>
#endif

#include "jove/jove.h"
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/format.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

static cl::list<std::string>
    DynTarget("dyn-target", cl::CommaSeparated,
              cl::value_desc("CallerBIdx,CallerBBIdx,CalleeBIdx,CalleeFIdx"),
              cl::desc("New target for indirect branch"),
              cl::cat(JoveCategory));

static cl::list<std::string>
    BasicBlock("basic-block", cl::CommaSeparated,
               cl::value_desc("IndBrBIdx,IndBrBBIdx,FileAddr"),
               cl::desc("New target for indirect branch"),
               cl::cat(JoveCategory));

static cl::list<std::string> Returns("returns", cl::CommaSeparated,
                                     cl::value_desc("CallBIdx,CallBBIdx"),
                                     cl::desc("A call has returned"),
                                     cl::cat(JoveCategory));

} // namespace opts

namespace jove {

static int recover(void);

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::ParseCommandLineOptions(argc, argv, "Jove Recover\n");

  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;

    sigaction(SIGINT, &sa, nullptr);
  }

  if (!fs::exists(opts::jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  if (opts::DynTarget.size() > 0 && opts::DynTarget.size() != 4) {
    WithColor::error() << "-dyn-target: invalid tuple\n";
    return 1;
  }

  if (opts::BasicBlock.size() > 0 && opts::BasicBlock.size() != 3) {
    WithColor::error() << "-basic-block: invalid tuple\n";
    return 1;
  }

  return jove::recover();
}

namespace jove {

typedef boost::format fmt;

static decompilation_t Decompilation;

static void InvalidateAllFunctionAnalyses(void) {
  for (binary_t &binary : Decompilation.Binaries)
    for (function_t &f : binary.Analysis.Functions)
      f.InvalidateAnalysis();
}

struct section_properties_t {
  llvm::StringRef name;
  llvm::ArrayRef<uint8_t> contents;

  bool w, x;

  bool operator==(const section_properties_t &sect) const {
    return name == sect.name;
  }

  bool operator<(const section_properties_t &sect) const {
    return name < sect.name;
  }
};
typedef std::set<section_properties_t> section_properties_set_t;

// we have a BB & Func map for each binary_t
struct binary_state_t {
  std::unordered_map<uintptr_t, function_index_t> FuncMap;
  boost::icl::split_interval_map<uintptr_t, basic_block_index_t> BBMap;
  boost::icl::split_interval_map<uintptr_t, section_properties_set_t> SectMap;
};

static std::vector<binary_state_t> BinStateVec;

typedef std::tuple<llvm::MCDisassembler &, const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &>
    disas_t;

static basic_block_index_t translate_basic_block(binary_index_t,
                                                 tiny_code_generator_t &,
                                                 disas_t &,
                                                 const target_ulong Addr);

#if defined(__x86_64__) || defined(__aarch64__) || defined(__mips64)
typedef typename obj::ELF64LEObjectFile ELFO;
typedef typename obj::ELF64LEFile ELFT;
#elif defined(__i386__) || defined(__mips__)
typedef typename obj::ELF32LEObjectFile ELFO;
typedef typename obj::ELF32LEFile ELFT;
#else
#error
#endif

static std::string DescribeFunction(binary_index_t, function_index_t);
static std::string DescribeBasicBlock(binary_index_t, basic_block_index_t);

static int await_process_completion(pid_t);

static std::error_code lockFile(int FD) {
  struct flock Lock;
  memset(&Lock, 0, sizeof(Lock));
  Lock.l_type = F_WRLCK;
  Lock.l_whence = SEEK_SET;
  Lock.l_start = 0;
  Lock.l_len = 0;
  if (::fcntl(FD, F_SETLKW, &Lock) != -1)
    return std::error_code();
  int Error = errno;
  return std::error_code(Error, std::generic_category());
}

static std::error_code unlockFile(int FD) {
  struct flock Lock;
  Lock.l_type = F_UNLCK;
  Lock.l_whence = SEEK_SET;
  Lock.l_start = 0;
  Lock.l_len = 0;
  if (::fcntl(FD, F_SETLK, &Lock) != -1)
    return std::error_code();
  return std::error_code(errno, std::generic_category());
}

int recover(void) {
  bool git = fs::is_directory(opts::jv);

  //
  // parse the existing decompilation file
  //
  {
    std::string path = fs::is_directory(opts::jv)
                           ? (opts::jv + "/decompilation.jv")
                           : opts::jv;

    int fd = ::open(path.c_str(), O_RDONLY);
    assert(!(fd < 0));

    lockFile(fd);

    {
      std::ifstream ifs(path);

      boost::archive::binary_iarchive ia(ifs);
      ia >> Decompilation;
    }

    unlockFile(fd);
    close(fd);
  }

  tiny_code_generator_t tcg;

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetDisassembler();

  llvm::Triple TheTriple;
  llvm::SubtargetFeatures Features;

  //
  // initialize state associated with every binary
  //
  BinStateVec.resize(Decompilation.Binaries.size());
  for (binary_index_t i = 0; i < Decompilation.Binaries.size(); ++i) {
    binary_t &binary = Decompilation.Binaries[i];
    binary_state_t &st = BinStateVec[i];

    //
    // build FuncMap
    //
    for (function_index_t f_idx = 0; f_idx < binary.Analysis.Functions.size();
         ++f_idx) {
      function_t &f = binary.Analysis.Functions[f_idx];
      assert(f.Entry != invalid_basic_block_index);
      basic_block_t EntryBB = boost::vertex(f.Entry, binary.Analysis.ICFG);
      st.FuncMap[binary.Analysis.ICFG[EntryBB].Addr] = f_idx;
    }

    //
    // build BBMap
    //
    for (basic_block_index_t bb_idx = 0;
         bb_idx < boost::num_vertices(binary.Analysis.ICFG); ++bb_idx) {
      basic_block_t bb = boost::vertex(bb_idx, binary.Analysis.ICFG);
      const auto &bbprop = binary.Analysis.ICFG[bb];

      boost::icl::interval<uintptr_t>::type intervl =
          boost::icl::interval<uintptr_t>::right_open(
              bbprop.Addr, bbprop.Addr + bbprop.Size);
      assert(st.BBMap.find(intervl) == st.BBMap.end());

      st.BBMap.add({intervl, 1 + bb_idx});
    }

    //
    // build section map
    //
    llvm::StringRef Buffer(reinterpret_cast<char *>(&binary.Data[0]),
                           binary.Data.size());
    llvm::StringRef Identifier(binary.Path);
    llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(MemBuffRef);
    if (!BinOrErr) {
      WithColor::error() << "failed to create binary from " << binary.Path
                         << '\n';
      return 1;
    }

    std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

    if (!llvm::isa<ELFO>(Bin.get())) {
      WithColor::error() << binary.Path << " is not ELF of expected type\n";
      return 1;
    }

    ELFO &O = *llvm::cast<ELFO>(Bin.get());

    TheTriple = O.makeTriple();
    Features = O.getFeatures();

    const ELFT &E = *O.getELFFile();

    typedef typename ELFT::Elf_Shdr Elf_Shdr;
    typedef typename ELFT::Elf_Shdr_Range Elf_Shdr_Range;

    llvm::Expected<Elf_Shdr_Range> sections = E.sections();
    if (!sections) {
      WithColor::error() << "could not get ELF sections for binary "
                         << binary.Path << '\n';
      return 1;
    }

    for (const Elf_Shdr &Sec : *sections) {
      if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
        continue;

      if (!Sec.sh_size)
        continue;

      section_properties_t sectprop;

      {
        llvm::Expected<llvm::StringRef> name = E.getSectionName(&Sec);

        if (!name) {
          std::string Buf;
          {
            llvm::raw_string_ostream OS(Buf);
            llvm::logAllUnhandledErrors(name.takeError(), OS, "");
          }

          WithColor::note()
              << llvm::formatv("could not get section name ({0})\n", Buf);
          continue;
        }

        sectprop.name = *name;
      }

      if ((Sec.sh_flags & llvm::ELF::SHF_TLS) &&
          sectprop.name == std::string(".tbss"))
        continue;

      if (Sec.sh_type == llvm::ELF::SHT_NOBITS) {
        sectprop.contents = llvm::ArrayRef<uint8_t>();
      } else {
        llvm::Expected<llvm::ArrayRef<uint8_t>> contents =
            E.getSectionContents(&Sec);

        if (!contents) {
          std::string Buf;
          {
            llvm::raw_string_ostream OS(Buf);
            llvm::logAllUnhandledErrors(contents.takeError(), OS, "");
          }

          WithColor::note()
              << llvm::formatv("could not get section {0} contents ({1})\n",
                               sectprop.name, Buf);
          continue;
        }

        sectprop.contents = *contents;
      }

      sectprop.w = !!(Sec.sh_flags & llvm::ELF::SHF_WRITE);
      sectprop.x = !!(Sec.sh_flags & llvm::ELF::SHF_EXECINSTR);

      boost::icl::interval<uintptr_t>::type intervl =
          boost::icl::interval<uintptr_t>::right_open(
              Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

      {
        auto it = st.SectMap.find(intervl);
        if (it != st.SectMap.end()) {
          WithColor::error() << "the following sections intersect: "
                             << (*(*it).second.begin()).name << " and "
                             << sectprop.name << '\n';
          return 1;
        }
      }

      st.SectMap.add({intervl, {sectprop}});
    }
  }

  //
  // initialize the LLVM objects necessary for disassembling instructions
  //
  std::string ArchName;
  std::string Error;

  const llvm::Target *TheTarget =
      llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget) {
    WithColor::error() << "failed to lookup target: " << Error << '\n';
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;

  std::unique_ptr<const llvm::MCRegisterInfo> MRI(
      TheTarget->createMCRegInfo(TripleName));
  if (!MRI) {
    WithColor::error() << "no register info for target\n";
    return 1;
  }

  llvm::MCTargetOptions Options;
  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
  if (!AsmInfo) {
    WithColor::error() << "no assembly info\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU,
                                       Features.getString()));
  if (!STI) {
    WithColor::error() << "no subtarget info\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCInstrInfo> MII(
      TheTarget->createMCInstrInfo());
  if (!MII) {
    WithColor::error() << "no instruction info\n";
    return 1;
  }

  llvm::MCObjectFileInfo MOFI;
  llvm::MCContext Ctx(AsmInfo.get(), MRI.get(), &MOFI);
  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI.InitMCObjectFileInfo(llvm::Triple(TripleName), false, Ctx);

  std::unique_ptr<llvm::MCDisassembler> DisAsm(
      TheTarget->createMCDisassembler(*STI, Ctx));
  if (!DisAsm) {
    WithColor::error() << "no disassembler for target\n";
    return 1;
  }

  int AsmPrinterVariant = 1 /* AsmInfo->getAssemblerDialect() */; // Intel
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    WithColor::error() << "no instruction printer\n";
    return 1;
  }

  disas_t dis(*DisAsm, std::cref(*STI), *IP);

  std::string msg;

  if (opts::DynTarget.size() > 0) {
    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } Caller;

    struct {
      binary_index_t BIdx;
      function_index_t FIdx;
    } Callee;

    Caller.BIdx = strtoul(opts::DynTarget[0].c_str(), nullptr, 10);
    Caller.BBIdx = strtoul(opts::DynTarget[1].c_str(), nullptr, 10);

    Callee.BIdx = strtoul(opts::DynTarget[2].c_str(), nullptr, 10);
    Callee.FIdx = strtoul(opts::DynTarget[3].c_str(), nullptr, 10);

    // Check that Callee is valid
    (void)Decompilation.Binaries.at(Callee.BIdx)
             .Analysis.Functions.at(Callee.FIdx);

    auto &ICFG = Decompilation.Binaries.at(Caller.BIdx).Analysis.ICFG;

    bool wasDynTargetsEmpty =
        ICFG[boost::vertex(Caller.BBIdx, ICFG)].DynTargets.empty();

    bool isNewTarget = ICFG[boost::vertex(Caller.BBIdx, ICFG)]
                           .DynTargets.insert({Callee.BIdx, Callee.FIdx})
                           .second;

    // TODO only invalidate the functions which contain...
    if (wasDynTargetsEmpty && isNewTarget)
      InvalidateAllFunctionAnalyses();

    msg = (fmt("[jove-recover] (call) %s -> %s") %
           DescribeBasicBlock(Caller.BIdx, Caller.BBIdx) %
           DescribeFunction(Callee.BIdx, Callee.FIdx))
              .str();
  } else if (opts::BasicBlock.size() > 0) {
    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;

      uint64_t Target;
    } IndBr;

    IndBr.BIdx = strtoul(opts::BasicBlock[0].c_str(), nullptr, 10);
    IndBr.BBIdx = strtoul(opts::BasicBlock[1].c_str(), nullptr, 10);

    IndBr.Target = strtoul(opts::BasicBlock[2].c_str(), nullptr, 10);

    auto &ICFG = Decompilation.Binaries.at(IndBr.BIdx).Analysis.ICFG;

    basic_block_t bb = boost::vertex(IndBr.BBIdx, ICFG);

    uintptr_t TermAddr = ICFG[bb].Term.Addr;

    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);
    basic_block_index_t target_bb_idx =
        translate_basic_block(IndBr.BIdx, tcg, dis, IndBr.Target);
    if (!is_basic_block_index_valid(target_bb_idx)) {
      WithColor::error() << llvm::formatv(
          "failed to recover control flow -> {0:x}\n", IndBr.Target);
      return 1;
    }

    basic_block_t target_bb = boost::vertex(target_bb_idx, ICFG);

    binary_state_t &st = BinStateVec.at(IndBr.BIdx);
    auto &BBMap = st.BBMap;
    {
      auto it = BBMap.find(TermAddr);
      assert(it != BBMap.end());

      basic_block_index_t bbidx = (*it).second - 1;
      bb = boost::vertex(bbidx, ICFG);
    }

    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

    bool isNewTarget = boost::add_edge(bb, target_bb, ICFG).second;

    // TODO invalidate only the functions who are affected...
    if (isNewTarget)
      InvalidateAllFunctionAnalyses();

    msg = (fmt("[jove-recover] (goto) %s -> %s") %
           DescribeBasicBlock(IndBr.BIdx, IndBr.BBIdx) %
           DescribeBasicBlock(IndBr.BIdx, target_bb_idx))
              .str();
  } else if (opts::Returns.size() > 0) {
    struct {
      binary_index_t BIdx;
      basic_block_index_t BBIdx;
    } Call;

    Call.BIdx = strtoul(opts::Returns[0].c_str(), nullptr, 10);
    Call.BBIdx = strtoul(opts::Returns[1].c_str(), nullptr, 10);

    auto &ICFG = Decompilation.Binaries.at(Call.BIdx).Analysis.ICFG;

    basic_block_t bb = boost::vertex(Call.BBIdx, ICFG);

    uintptr_t NextAddr = ICFG[bb].Addr + ICFG[bb].Size;

    uintptr_t TermAddr = ICFG[bb].Term.Addr;

    bool isCall =
      ICFG[bb].Term.Type == TERMINATOR::CALL;
    bool isIndirectCall =
      ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL;

    assert(isCall || isIndirectCall);
    assert(TermAddr);

    if (isCall)
      ICFG[bb].Term._call.Returns = true;
    if (isIndirectCall)
      ICFG[bb].Term._indirect_call.Returns = true;

    unsigned deg = boost::out_degree(bb, ICFG);
    if (deg != 0) {
      WithColor::warning() << llvm::formatv("unexpected out degree {0}\n", deg);
      return 1;
    }

#if 0
    {
      binary_state_t &st = BinStateVec[Call.BIdx];
      auto it = st.BBMap.find(NextAddr);
      assert(it == st.BBMap.end());
    }
#endif

    basic_block_index_t next_bb_idx =
        translate_basic_block(Call.BIdx, tcg, dis, NextAddr);

    binary_state_t &st = BinStateVec.at(Call.BIdx);
    auto &BBMap = st.BBMap;
    {
      auto it = BBMap.find(TermAddr);
      assert(it != BBMap.end());

      basic_block_index_t bbidx = (*it).second - 1;
      bb = boost::vertex(bbidx, ICFG);
    }

    if (ICFG[bb].Term.Type == TERMINATOR::CALL &&
        is_function_index_valid(ICFG[bb].Term._call.Target)) {
      function_t &f =
          Decompilation.Binaries.at(Call.BIdx).Analysis.Functions.at(
              ICFG[bb].Term._call.Target);
      f.Returns = true;
    }

    assert(is_basic_block_index_valid(next_bb_idx));
    basic_block_t next_bb = boost::vertex(next_bb_idx, ICFG);

    //assert(boost::out_degree(bb, ICFG) == 0);
    bool isNewTarget = boost::add_edge(bb, next_bb, ICFG).second;

    if (isNewTarget)
      InvalidateAllFunctionAnalyses();

    msg = (fmt("[jove-recover] (returned) %s") %
           DescribeBasicBlock(Call.BIdx, next_bb_idx))
              .str();
  } else {
    WithColor::error() << "no command provided\n";
    return 1;
  }

  assert(!msg.empty());
  llvm::outs() << msg << '\n';

  //
  // write decompilation
  //
  {
    std::string path = fs::is_directory(opts::jv)
                           ? (opts::jv + "/decompilation.jv")
                           : opts::jv;

    int fd = ::open(path.c_str(), O_RDONLY);
    assert(!(fd < 0));

    lockFile(fd);

    {
      std::ofstream ofs(path);

      boost::archive::binary_oarchive oa(ofs);
      oa << Decompilation;
    }

    unlockFile(fd);
    close(fd);
  }

  //
  // git commit
  //
  if (git) {
    pid_t pid = fork();
    if (!pid) { /* child */
      chdir(opts::jv.c_str());

      const char *argv[] = {"/usr/bin/git", "commit",    ".",
                            "-m",           msg.c_str(), nullptr};

      return execve(argv[0], const_cast<char **>(argv), ::environ);
    }

    if (int ret = await_process_completion(pid))
      return ret;
  }

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

static function_index_t translate_function(binary_index_t binary_idx,
                                           tiny_code_generator_t &tcg,
                                           disas_t &dis,
                                           target_ulong Addr) {
  binary_t &binary = Decompilation.Binaries.at(binary_idx);
  auto &FuncMap = BinStateVec.at(binary_idx).FuncMap;

  {
    auto it = FuncMap.find(Addr);
    if (it != FuncMap.end())
      return (*it).second;
  }

  function_index_t res = binary.Analysis.Functions.size();
  FuncMap[Addr] = res;
  binary.Analysis.Functions.resize(res + 1);
  binary.Analysis.Functions[res].Entry =
      translate_basic_block(binary_idx, tcg, dis, Addr);
  binary.Analysis.Functions[res].Analysis.Stale = true;
  binary.Analysis.Functions[res].IsABI = false;
  binary.Analysis.Functions[res].IsSignalHandler = false;

  return res;
}

static bool does_function_definitely_return(binary_index_t, function_index_t);

basic_block_index_t translate_basic_block(binary_index_t binary_idx,
                                          tiny_code_generator_t &tcg,
                                          disas_t &dis,
                                          const target_ulong Addr) {
  binary_t &binary = Decompilation.Binaries.at(binary_idx);
  auto &ICFG = binary.Analysis.ICFG;
  auto &BBMap = BinStateVec.at(binary_idx).BBMap;
  auto &SectMap = BinStateVec.at(binary_idx).SectMap;

  //
  // does this new basic block start in the middle of a previously-created
  // basic block?
  //
  {
    auto it = BBMap.find(Addr);
    if (it != BBMap.end()) {
      basic_block_index_t bbidx = (*it).second - 1;
      basic_block_t bb = boost::vertex(bbidx, ICFG);

      assert(bbidx < boost::num_vertices(ICFG));

      uintptr_t beg = ICFG[bb].Addr;

      if (Addr == beg) {
        assert(ICFG[bb].Addr == (*it).first.lower());
        return bbidx;
      }

      //
      // before splitting the basic block, let's check to make sure that the
      // new block doesn't start in the middle of an instruction. if that would
      // occur, then we will assume the control-flow is invalid
      //
      {
        llvm::MCDisassembler &DisAsm = std::get<0>(dis);
        const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
        llvm::MCInstPrinter &IP = std::get<2>(dis);

        auto sectit = SectMap.find(beg);
        assert(sectit != SectMap.end());
        const section_properties_t &SectProp = *(*sectit).second.begin();

        uint64_t InstLen = 0;
        for (target_ulong A = beg; A < beg + ICFG[bb].Size; A += InstLen) {
          llvm::MCInst Inst;

          std::string errmsg;
          bool Disassembled;
          {
            llvm::raw_string_ostream ErrorStrStream(errmsg);

            std::ptrdiff_t SectOffset = A - (*sectit).first.lower();
            Disassembled = DisAsm.getInstruction(
                Inst, InstLen, SectProp.contents.slice(SectOffset), A,
                ErrorStrStream);
          }

          if (!Disassembled)
            WithColor::error() << llvm::formatv(
                "failed to disassemble {0:x} {1}\n", A, errmsg);

          assert(Disassembled);

          if (A == Addr)
            goto on_insn_boundary;
        }

        WithColor::error() << llvm::formatv(
            "control flow to {0:x} in {1} doesn't lie on instruction boundary\n",
            Addr, binary.Path);

        return invalid_basic_block_index;

on_insn_boundary:
        //
        // proceed.
        //
        ;
      }

      std::vector<basic_block_t> out_verts;
      {
        icfg_t::out_edge_iterator e_it, e_it_end;
        for (std::tie(e_it, e_it_end) = boost::out_edges(bb, ICFG);
             e_it != e_it_end; ++e_it)
          out_verts.push_back(boost::target(*e_it, ICFG));
      }

      // if we get here, we know that beg != Addr
      assert(Addr > beg);

      ptrdiff_t off = Addr - beg;
      assert(off > 0);

      boost::icl::interval<uintptr_t>::type orig_intervl = (*it).first;

      basic_block_index_t newbbidx = boost::num_vertices(ICFG);
      basic_block_t newbb = boost::add_vertex(ICFG);
      {
        basic_block_properties_t &newbbprop = ICFG[newbb];
        newbbprop.Addr = beg;
        newbbprop.Size = off;
        newbbprop.Term.Type = TERMINATOR::NONE;
        newbbprop.Term.Addr = 0; /* XXX? */
        newbbprop.DynTargetsComplete = false;
        newbbprop.Term._call.Target = invalid_function_index;
        newbbprop.Term._call.Returns = false;
        newbbprop.Term._indirect_call.Returns = false;
        newbbprop.Term._return.Returns = false;
        newbbprop.InvalidateAnalysis();
      }

      ICFG[bb].InvalidateAnalysis();

      std::swap(ICFG[bb], ICFG[newbb]);
      ICFG[newbb].Addr = Addr;
      ICFG[newbb].Size -= off;

      assert(ICFG[newbb].Addr + ICFG[newbb].Size == orig_intervl.upper());

      boost::clear_out_edges(bb, ICFG);
      boost::add_edge(bb, newbb, ICFG);

      for (basic_block_t out_vert : out_verts) {
        boost::add_edge(newbb, out_vert, ICFG);
      }

      assert(ICFG[bb].Term.Type == TERMINATOR::NONE);
      assert(boost::out_degree(bb, ICFG) == 1);

      boost::icl::interval<uintptr_t>::type intervl1 =
          boost::icl::interval<uintptr_t>::right_open(
              ICFG[bb].Addr, ICFG[bb].Addr + ICFG[bb].Size);

      boost::icl::interval<uintptr_t>::type intervl2 =
          boost::icl::interval<uintptr_t>::right_open(
              ICFG[newbb].Addr, ICFG[newbb].Addr + ICFG[newbb].Size);

      assert(boost::icl::disjoint(intervl1, intervl2));

      unsigned n = BBMap.iterative_size();
      BBMap.erase((*it).first);
      assert(BBMap.iterative_size() == n - 1);

      assert(BBMap.find(intervl1) == BBMap.end());
      assert(BBMap.find(intervl2) == BBMap.end());

      BBMap.add({intervl1, 1 + bbidx});
      BBMap.add({intervl2, 1 + newbbidx});

      {
        auto _it = BBMap.find(intervl1);
        assert(_it != BBMap.end());
        assert((*_it).second == 1 + bbidx);
      }

      {
        auto _it = BBMap.find(intervl2);
        assert(_it != BBMap.end());
        assert((*_it).second == 1 + newbbidx);
      }

      return newbbidx;
    }
  }

  auto sectit = SectMap.find(Addr);
  if (sectit == SectMap.end()) {
    WithColor::error()
        << (fmt("warning: no section for address 0x%lx") % Addr).str() << '\n';
    return invalid_basic_block_index;
  }
  const section_properties_t &sectprop = *(*sectit).second.begin();
  if (!sectprop.x) {
    WithColor::note() << llvm::formatv("section is not executable @ {0:x}\n",
                                       Addr);
    return invalid_basic_block_index;
  }
  tcg.set_section((*sectit).first.lower(), sectprop.contents.data());

  unsigned Size = 0;
  jove::terminator_info_t T;
  do {
    unsigned size;
    std::tie(size, T) = tcg.translate(Addr + Size);

    Size += size;

    {
      boost::icl::interval<uintptr_t>::type intervl =
          boost::icl::interval<uintptr_t>::right_open(Addr, Addr + Size);
      auto it = BBMap.find(intervl);
      if (it != BBMap.end()) {
        const boost::icl::interval<uintptr_t>::type &_intervl = (*it).first;

        assert(intervl.lower() < _intervl.lower());

        //
        // solution here is to prematurely end the basic block with a NONE
        // terminator, and with a next_insn address of _intervl.lower()
        //
        Size = _intervl.lower() - intervl.lower();
        T.Type = TERMINATOR::NONE;
        T.Addr = 0; /* XXX? */
        T._none.NextPC = _intervl.lower();
        break;
      }
    }
  } while (T.Type == TERMINATOR::NONE);

  if (T.Type == TERMINATOR::UNKNOWN) {
    WithColor::error() << (fmt("error: unknown terminator @ %#lx") % Addr).str()
                       << '\n';

    llvm::MCDisassembler &DisAsm = std::get<0>(dis);
    const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
    llvm::MCInstPrinter &IP = std::get<2>(dis);

    uint64_t InstLen;
    for (target_ulong A = Addr; A < Addr + Size; A += InstLen) {
      std::ptrdiff_t Offset = A - (*sectit).first.lower();

      llvm::MCInst Inst;
      bool Disassembled =
          DisAsm.getInstruction(Inst, InstLen, sectprop.contents.slice(Offset),
                                A, llvm::nulls());

      if (!Disassembled) {
        WithColor::error() << (fmt("failed to disassemble %#lx") % Addr).str()
                           << '\n';
        break;
      }

      IP.printInst(&Inst, A, "", STI, llvm::errs());
      llvm::errs() << '\n';
    }

    tcg.dump_operations();
    fputc('\n', stdout);
    return invalid_basic_block_index;
  }

  auto is_invalid_terminator = [&](void) -> bool {
    if (T.Type == TERMINATOR::CALL) {
      if (SectMap.find(T._call.Target) == SectMap.end()) {
        WithColor::error()
            << (fmt("warning: call to bad address %#lx") % T._call.Target).str()
            << '\n';
        return true;
      }
    }

    return false;
  };

  if (is_invalid_terminator()) {
    WithColor::error() << "assuming unreachable code\n";
    T.Type = TERMINATOR::UNREACHABLE;
  }

  basic_block_index_t bbidx = boost::num_vertices(ICFG);
  basic_block_t bb = boost::add_vertex(ICFG);
  {
    basic_block_properties_t &bbprop = ICFG[bb];
    bbprop.Addr = Addr;
    bbprop.Size = Size;
    bbprop.Term.Type = T.Type;
    bbprop.Term.Addr = T.Addr;
    bbprop.DynTargetsComplete = false;
    bbprop.Term._call.Target = invalid_function_index;
    bbprop.Term._call.Returns = false;
    bbprop.Term._indirect_call.Returns = false;
    bbprop.Term._return.Returns = false;
    bbprop.InvalidateAnalysis();
    InvalidateAllFunctionAnalyses();

    boost::icl::interval<uintptr_t>::type intervl =
        boost::icl::interval<uintptr_t>::right_open(bbprop.Addr,
                                                    bbprop.Addr + bbprop.Size);
    assert(BBMap.find(intervl) == BBMap.end());
    BBMap.add({intervl, 1 + bbidx});
  }

  //
  // conduct analysis of last instruction (the terminator of the block) and
  // (recursively) descend into branch targets, translating basic blocks
  //
  auto control_flow = [&](uintptr_t Target) -> void {
    assert(Target);

    basic_block_index_t succidx =
        translate_basic_block(binary_idx, tcg, dis, Target);

    assert(succidx != invalid_basic_block_index);

    basic_block_t _bb;
    {
      auto it = T.Addr ? BBMap.find(T.Addr) : BBMap.find(Addr);
      assert(it != BBMap.end());

      basic_block_index_t _bbidx = (*it).second - 1;
      _bb = boost::vertex(_bbidx, ICFG);
      assert(T.Type == ICFG[_bb].Term.Type);
    }

    basic_block_t succ = boost::vertex(succidx, ICFG);
    bool isNewTarget = boost::add_edge(_bb, succ, ICFG).second;

    // TODO invalidate all the function analyses which contain this bb
    if (isNewTarget)
      InvalidateAllFunctionAnalyses();
  };

  switch (T.Type) {
  case TERMINATOR::UNCONDITIONAL_JUMP:
    control_flow(T._unconditional_jump.Target);
    break;

  case TERMINATOR::CONDITIONAL_JUMP:
    control_flow(T._conditional_jump.Target);
    control_flow(T._conditional_jump.NextPC);
    break;

  case TERMINATOR::CALL: {
    function_index_t FIdx =
        translate_function(binary_idx, tcg, dis, T._call.Target);

    basic_block_t _bb;
    {
      auto it = T.Addr ? BBMap.find(T.Addr) : BBMap.find(Addr);
      assert(it != BBMap.end());
      basic_block_index_t _bbidx = (*it).second - 1;
      _bb = boost::vertex(_bbidx, ICFG);
    }

    assert(ICFG[_bb].Term.Type == TERMINATOR::CALL);
    ICFG[_bb].Term._call.Target = FIdx;

    if (is_function_index_valid(FIdx) &&
        does_function_definitely_return(binary_idx, FIdx))
      control_flow(T._call.NextPC);

    break;
  }

  case TERMINATOR::INDIRECT_CALL:
    //control_flow(T._indirect_call.NextPC);
    break;

  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::RETURN:
  case TERMINATOR::UNREACHABLE:
    break;

  case TERMINATOR::NONE:
    control_flow(T._none.NextPC);
    break;

  default:
    abort();
  }

  return bbidx;
}

template <typename GraphTy>
struct dfs_visitor : public boost::default_dfs_visitor {
  typedef typename GraphTy::vertex_descriptor VertTy;

  std::vector<VertTy> &out;

  dfs_visitor(std::vector<VertTy> &out) : out(out) {}

  void discover_vertex(VertTy v, const GraphTy &) const { out.push_back(v); }
};

bool does_function_definitely_return(binary_index_t BIdx,
                                     function_index_t FIdx) {
  assert(is_binary_index_valid(BIdx));
  assert(is_function_index_valid(FIdx));

  binary_t &b = Decompilation.Binaries.at(BIdx);
  function_t &f = b.Analysis.Functions.at(FIdx);
  auto &ICFG = b.Analysis.ICFG;

  assert(is_basic_block_index_valid(f.Entry));

  std::vector<basic_block_t> BasicBlocks;
  std::vector<basic_block_t> ExitBasicBlocks;

  std::map<basic_block_t, boost::default_color_type> color;
  dfs_visitor<interprocedural_control_flow_graph_t> vis(BasicBlocks);
  boost::depth_first_visit(
      ICFG, boost::vertex(f.Entry, ICFG), vis,
      boost::associative_property_map<
          std::map<basic_block_t, boost::default_color_type>>(color));

  //
  // ExitBasicBlocks
  //
  std::copy_if(BasicBlocks.begin(),
               BasicBlocks.end(),
               std::back_inserter(ExitBasicBlocks),
               [&](basic_block_t bb) -> bool {
                 return ICFG[bb].Term.Type == TERMINATOR::RETURN ||
                        IsDefinitelyTailCall(ICFG, bb);
               });

  return !ExitBasicBlocks.empty();
}

template <class T>
static T unwrapOrError(llvm::Expected<T> EO) {
  if (EO)
    return *EO;

  std::string Buf;
  {
    llvm::raw_string_ostream OS(Buf);
    llvm::logAllUnhandledErrors(EO.takeError(), OS, "");
  }
  WithColor::error() << Buf << '\n';
  exit(1);
}

std::string DescribeFunction(binary_index_t BIdx,
                             function_index_t FIdx) {
  auto &binary = Decompilation.Binaries.at(BIdx);
  function_t &f = binary.Analysis.Functions.at(FIdx);

  auto &ICFG = binary.Analysis.ICFG;
  uintptr_t Addr = ICFG[boost::vertex(f.Entry, ICFG)].Addr;

  return (fmt("%s+%#lx") % fs::path(binary.Path).filename().string() % Addr).str();
}

std::string DescribeBasicBlock(binary_index_t BIdx,
                               basic_block_index_t BBIdx) {
  auto &binary = Decompilation.Binaries.at(BIdx);

  auto &ICFG = binary.Analysis.ICFG;
  uintptr_t Addr = ICFG[boost::vertex(BBIdx, ICFG)].Addr;

  return (fmt("%s+%#lx") % fs::path(binary.Path).filename().string() % Addr).str();
}

void _qemu_log(const char *cstr) { llvm::errs() << cstr; }

}

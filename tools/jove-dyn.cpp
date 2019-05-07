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
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> Prog(cl::Positional, cl::desc("prog"), cl::Required,
                                 cl::value_desc("filename"),
                                 cl::cat(JoveCategory));

static cl::list<std::string> Args("args", cl::CommaSeparated,
                                  cl::value_desc("arg_1,arg_2,...,arg_n"),
                                  cl::desc("Program arguments"),
                                  cl::cat(JoveCategory));

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

static cl::opt<bool>
    Verbose("verbose",
            cl::desc("Print extra information for debugging purposes"),
            cl::cat(JoveCategory));

static cl::alias VerboseAlias("v", cl::desc("Alias for -verbose."),
                              cl::aliasopt(Verbose), cl::cat(JoveCategory));
static cl::opt<bool>
    VeryVerbose("veryverbose",
                cl::desc("Print extra information for debugging purposes"),
                cl::cat(JoveCategory));

static cl::alias VeryVerboseAlias("vv", cl::desc("Alias for -veryverbose."),
                                  cl::aliasopt(VeryVerbose),
                                  cl::cat(JoveCategory));

static cl::opt<bool> Quiet("quiet", cl::desc("Suppress non-error messages"),
                           cl::cat(JoveCategory));

static cl::alias QuietAlias("q", cl::desc("Alias for -quiet."),
                            cl::aliasopt(Quiet), cl::cat(JoveCategory));
} // namespace opts

namespace jove {

static int ChildProc(void);
static int ParentProc(pid_t child);

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::ParseCommandLineOptions(argc, argv, "Jove Dynamic Analysis\n");

  if (!fs::exists(opts::Prog)) {
    WithColor::error() << "program does not exist\n";
    return 1;
  }

  if (!fs::exists(opts::jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  pid_t child = fork();
  if (!child)
    return jove::ChildProc();

  return jove::ParentProc(child);
}

namespace jove {

typedef boost::format fmt;

static decompilation_t decompilation;

static bool verify_arch(const obj::ObjectFile &);
static bool update_view_of_virtual_memory(int child);

static bool SeenExec = false;

struct vm_properties_t {
  uintptr_t beg;
  uintptr_t end;
  std::ptrdiff_t off;

  bool r, w, x; /* unix permissions */
  bool p;       /* private memory? (i.e. not shared) */

  std::string nm;

  bool operator==(const vm_properties_t &vm) const {
    return beg == vm.beg && end == vm.end;
  }

  bool operator<(const vm_properties_t &vm) const { return beg < vm.beg; }
};
typedef std::set<vm_properties_t> vm_properties_set_t;

static boost::icl::split_interval_map<uintptr_t, vm_properties_set_t> vmm;

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

// we have a BB & Func map for each binary_t
struct binary_state_t {
  std::unordered_map<uintptr_t, function_index_t> FuncMap;
  boost::icl::split_interval_map<uintptr_t, basic_block_index_t> BBMap;
  boost::icl::split_interval_map<uintptr_t, section_properties_set_t> SectMap;

  struct {
    uintptr_t LoadAddr, LoadAddrEnd;
  } dyn;
};

static std::vector<binary_state_t> BinStateVec;
static boost::dynamic_bitset<> BinFoundVec;
static std::unordered_map<std::string, binary_index_t> BinPathToIdxMap;

typedef std::set<binary_index_t> binary_index_set_t;
static boost::icl::split_interval_map<uintptr_t, binary_index_set_t>
    AddressSpace;

struct indirect_branch_t {
  binary_index_t binary_idx;
  basic_block_index_t bbidx;

  uintptr_t TermAddr;

  std::vector<uint8_t> InsnBytes;
  llvm::MCInst Inst;
};

static std::unordered_map<uintptr_t, indirect_branch_t> IndBrMap;

static uintptr_t va_of_rva(uintptr_t Addr, binary_index_t idx) {
  assert(idx < BinStateVec.size());
  assert(BinStateVec[idx].dyn.LoadAddr);

  return Addr + BinStateVec[idx].dyn.LoadAddr;
}

static uintptr_t rva_of_va(uintptr_t Addr, binary_index_t idx) {
  assert(idx < BinStateVec.size());
  assert(BinStateVec[idx].dyn.LoadAddr);
  assert(Addr >= BinStateVec[idx].dyn.LoadAddr);
  assert(Addr < BinStateVec[idx].dyn.LoadAddrEnd);

  return Addr - BinStateVec[idx].dyn.LoadAddr;
}

typedef std::tuple<llvm::MCDisassembler &, const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &>
    disas_t;

struct breakpoint_t {
  unsigned long word;
  void (*callback)(pid_t, tiny_code_generator_t &, disas_t &);
};
static std::unordered_map<uintptr_t, breakpoint_t> BrkMap;

static void search_address_space_for_binaries(pid_t, disas_t &);
static void place_breakpoint_at_indirect_branch(pid_t, uintptr_t Addr,
                                                indirect_branch_t &, disas_t &);
static void place_breakpoint(pid_t, uintptr_t Addr, breakpoint_t &, disas_t &);
static void on_breakpoint(pid_t, tiny_code_generator_t &, disas_t &);

#if !defined(__x86_64__) && defined(__i386__)
static uintptr_t segment_address_of_selector(pid_t, unsigned segsel);
#endif

static void _ptrace_get_gpr(pid_t, struct user_regs_struct &out);
static void _ptrace_set_gpr(pid_t, const struct user_regs_struct &in);

static unsigned long _ptrace_peekdata(pid_t, uintptr_t addr);
static void _ptrace_pokedata(pid_t, uintptr_t addr, unsigned long data);

static int await_process_completion(pid_t);

#if defined(__x86_64__) || defined(__aarch64__)
typedef typename obj::ELF64LEObjectFile ELFO;
typedef typename obj::ELF64LEFile ELFT;
#elif defined(__i386__)
typedef typename obj::ELF32LEObjectFile ELFO;
typedef typename obj::ELF32LEFile ELFT;
#endif

int ParentProc(pid_t child) {
  //
  // observe the (initial) signal-delivery-stop
  //
  if (opts::VeryVerbose)
    llvm::errs() << "parent: waiting for initial stop of child " << child
                 << "...\n";

  int status;
  do
    waitpid(child, &status, 0);
  while (!WIFSTOPPED(status));

  if (opts::VeryVerbose)
    llvm::errs() << "parent: initial stop observed\n";

  //
  // select ptrace options
  //
  int ptrace_options = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL |
                       PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                       PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;

  //
  // set those options
  //
  if (opts::VeryVerbose)
    llvm::errs() << "parent: setting ptrace options...\n";

  ptrace(PTRACE_SETOPTIONS, child, 0, ptrace_options);

  if (opts::VeryVerbose)
    llvm::errs() << "ptrace options set!\n";

  tiny_code_generator_t tcg;

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetDisassembler();

  bool git = fs::is_directory(opts::jv);

  //
  // parse the existing decompilation file
  //
  {
    std::ifstream ifs(git ? (opts::jv + "/decompilation.jv") : opts::jv);

    boost::archive::binary_iarchive ia(ifs);
    ia >> decompilation;
  }

  //
  // verify that the binaries did not change on-disk
  //
  for (binary_t &binary : decompilation.Binaries) {
    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> FileOrErr =
        llvm::MemoryBuffer::getFileOrSTDIN(binary.Path);

    if (std::error_code EC = FileOrErr.getError()) {
      WithColor::error() << "failed to open binary " << binary.Path
                         << " in given decompilation\n";
      return 1;
    }

    std::unique_ptr<llvm::MemoryBuffer> &Buffer = FileOrErr.get();
    if (binary.Data.size() != Buffer->getBufferSize() ||
        memcmp(&binary.Data[0], Buffer->getBufferStart(), binary.Data.size())) {
      WithColor::error() << "contents of binary " << binary.Path
                         << "have changed\n";
      return 1;
    }
  }

  llvm::Triple TheTriple;
  llvm::SubtargetFeatures Features;

  //
  // initialize state associated with every binary
  //
  BinStateVec.resize(decompilation.Binaries.size());
  for (binary_index_t i = 0; i < decompilation.Binaries.size(); ++i) {
    binary_t &binary = decompilation.Binaries[i];
    binary_state_t &st = BinStateVec[i];

    // add to path -> index map
    BinPathToIdxMap[binary.Path] = i;

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

      if (opts::Verbose)
        llvm::errs() << "BBMap entry ["
                     << (fmt("%#lx") % intervl.lower()).str()
                     << ", "
                     << (fmt("%#lx") % intervl.upper()).str()
                     << ")" << st.BBMap.iterative_size() << "\n";

      st.BBMap.add({intervl, 1 + bb_idx});

#if 0
      llvm::errs() << "after=" << st.BBMap.iterative_size() << '\n';
#endif
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

      llvm::Expected<llvm::ArrayRef<uint8_t>> contents =
          E.getSectionContents(&Sec);

      if (!contents)
        continue;

      llvm::Expected<llvm::StringRef> name = E.getSectionName(&Sec);

      if (!name)
        continue;

      boost::icl::interval<uintptr_t>::type intervl =
          boost::icl::interval<uintptr_t>::right_open(
              Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

      section_properties_t sectprop;
      sectprop.name = *name;
      sectprop.contents = *contents;

      section_properties_set_t sectprops = {sectprop};
      st.SectMap.add(std::make_pair(intervl, sectprops));

      if (opts::VeryVerbose)
        llvm::errs() << (fmt("%-20s [0x%lx, 0x%lx)")
                         % std::string(sectprop.name)
                         % intervl.lower()
                         % intervl.upper())
                            .str()
                     << '\n';
    }
  }

  BinFoundVec.resize(decompilation.Binaries.size());

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

  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName));
  if (!AsmInfo) {
    WithColor::error() << "no assembly info\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI) {
    WithColor::error() << "no subtarget info\n";
    return 1;
  }

  std::unique_ptr<const llvm::MCInstrInfo> MII(TheTarget->createMCInstrInfo());
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

  siginfo_t si;
  long sig = 0;

  for (;;) {
    if (likely(!(child < 0))) {
      if (unlikely(ptrace(SeenExec && !BinFoundVec.all() ? PTRACE_SYSCALL
                                                         : PTRACE_CONT,
                          child, nullptr, reinterpret_cast<void *>(sig)) < 0))
        WithColor::error() << "failed to resume tracee : " << strerror(errno)
                           << '\n';
    }

    //
    // reset restart signal
    //
    sig = 0;

    //
    // wait for a child process to stop or terminate
    //
    int status;
    child = waitpid(-1, &status, __WALL);

    if (unlikely(child < 0)) {
      llvm::errs() << "exiting... (" << strerror(errno) << ")\n";
      break;
    }

    if (likely(WIFSTOPPED(status))) {
      //
      // the following kinds of ptrace-stops exist:
      //
      //   (1) syscall-stops
      //   (2) PTRACE_EVENT stops
      //   (3) group-stops
      //   (4) signal-delivery-stops
      //
      // they all are reported by waitpid(2) with WIFSTOPPED(status) true.
      // They may be differentiated by examining the value status>>8, and if
      // there is ambiguity in that value, by querying PTRACE_GETSIGINFO.
      // (Note: the WSTOPSIG(status) macro can't be used to perform this
      // examination, because it returns the value (status>>8) & 0xff.)
      //
      const int stopsig = WSTOPSIG(status);
      if (stopsig == (SIGTRAP | 0x80)) {
        //
        // (1) Syscall-enter-stop and syscall-exit-stop are observed by the
        // tracer as waitpid(2) returning with WIFSTOPPED(status) true, and-
        // if the PTRACE_O_TRACESYSGOOD option was set by the tracer- then
        // WSTOPSIG(status) will give the value (SIGTRAP | 0x80).
        //
        struct user_regs_struct gpr;
        _ptrace_get_gpr(child, gpr);

        unsigned syscallno =
#if defined(__x86_64__)
            gpr.orig_rax
#elif defined(__i386__)
            gpr.orig_eax
#elif defined(__aarch64__)
            gpr.regs[8]
#endif
            ;

        bool does_mmap = false
#ifdef __NR_mmap
                         || syscallno == __NR_mmap
#endif
#ifdef __NR_mmap2
                         || syscallno == __NR_mmap2
#endif
            ;

        if (does_mmap)
          search_address_space_for_binaries(child, dis);
      } else if (stopsig == SIGTRAP) {
        const unsigned int event = (unsigned int)status >> 16;

        //
        // PTRACE_EVENT stops (2) are observed by the tracer as waitpid(2)
        // returning with WIFSTOPPED(status), and WSTOPSIG(status) returns
        // SIGTRAP.
        //
        if (unlikely(event)) {
          switch (event) {
          case PTRACE_EVENT_VFORK:
            if (opts::VeryVerbose)
              llvm::errs() << "ptrace event (PTRACE_EVENT_VFORK) [" << child
                           << "]\n";
            break;
          case PTRACE_EVENT_FORK:
            if (opts::VeryVerbose)
              llvm::errs() << "ptrace event (PTRACE_EVENT_FORK) [" << child
                           << "]\n";
            break;
          case PTRACE_EVENT_CLONE: {
            pid_t new_child;
            ptrace(PTRACE_GETEVENTMSG, child, nullptr, &new_child);

            if (opts::VeryVerbose)
              llvm::errs() << "ptrace event (PTRACE_EVENT_CLONE) -> "
                           << new_child << " [" << child << "]\n";
            break;
          }
          case PTRACE_EVENT_VFORK_DONE:
            if (opts::VeryVerbose)
              llvm::errs() << "ptrace event (PTRACE_EVENT_VFORK_DONE) ["
                           << child << "]\n";
            break;
          case PTRACE_EVENT_EXEC:
            if (opts::VeryVerbose)
              llvm::errs() << "ptrace event (PTRACE_EVENT_EXEC) [" << child
                           << "]\n";
            SeenExec = true;
            break;
          case PTRACE_EVENT_EXIT:
            if (opts::VeryVerbose)
              llvm::errs() << "ptrace event (PTRACE_EVENT_EXIT) [" << child
                           << "]\n";
            break;
          case PTRACE_EVENT_STOP:
            if (opts::VeryVerbose)
              llvm::errs() << "ptrace event (PTRACE_EVENT_STOP) [" << child
                           << "]\n";
            break;
          case PTRACE_EVENT_SECCOMP:
            if (opts::VeryVerbose)
              llvm::errs() << "ptrace event (PTRACE_EVENT_SECCOMP) [" << child
                           << "]\n";
            break;
          }
        } else {
          on_breakpoint(child, tcg, dis);
        }
      } else if (ptrace(PTRACE_GETSIGINFO, child, 0, &si) < 0) {
        //
        // (3) group-stop
        //

        if (opts::VeryVerbose)
          llvm::errs() << "ptrace group-stop [" << child << "]\n";

        // When restarting a tracee from a ptrace-stop other than
        // signal-delivery-stop, recommended practice is to always pass 0 in
        // sig.
      } else {
        //
        // (4) signal-delivery-stop
        //
        if (opts::VeryVerbose)
          llvm::errs() << "delivering signal number " << stopsig << " ["
                       << child << "]\n";

        // deliver it
        sig = stopsig;
      }
    } else {
      //
      // the child terminated
      //
      if (opts::VeryVerbose)
        llvm::errs() << "child " << child << " terminated\n";

      child = -1;
    }
  }

  //
  // write decompilation
  //
  {
    std::ofstream ofs(git ? (std::string(opts::jv) + "/decompilation.jv")
                          : opts::jv);

    boost::archive::binary_oarchive oa(ofs);
    oa << decompilation;
  }

  //
  // git commit
  //
  if (git) {
    pid_t pid = fork();
    if (!pid) { /* child */
      std::string msg(opts::Prog);
      for (const std::string &arg : opts::Args) {
        msg.push_back(' ');
        msg.push_back('\'');
        msg.append(arg);
        msg.push_back('\'');
      }

      chdir(opts::jv.c_str());

      std::vector<char *> arg_vec;
      arg_vec.push_back(const_cast<char *>("/usr/bin/git"));
      arg_vec.push_back(const_cast<char *>("commit"));
      arg_vec.push_back(const_cast<char *>("."));
      arg_vec.push_back(const_cast<char *>("-m"));
      arg_vec.push_back(const_cast<char *>(msg.c_str()));
      arg_vec.push_back(nullptr);

      return execve("/usr/bin/git", arg_vec.data(), ::environ);
    }

    if (int ret = await_process_completion(pid))
      return ret;
  }

  return 0;
}

int await_process_completion(pid_t pid) {
  int wstatus;
  do {
    if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) < 0) {
      if (errno != EINTR) {
        WithColor::error() << "waitpid failed : " << strerror(errno) << '\n';
        abort();
      }
    }
  } while (!WIFEXITED(wstatus));

  return WEXITSTATUS(wstatus);
}

static basic_block_index_t translate_basic_block(pid_t,
                                                 binary_index_t binary_idx,
                                                 tiny_code_generator_t &,
                                                 disas_t &,
                                                 const target_ulong Addr,
                                                 unsigned &brkpt_count);

static function_index_t translate_function(pid_t child,
                                           binary_index_t binary_idx,
                                           tiny_code_generator_t &tcg,
                                           disas_t &dis,
                                           target_ulong Addr,
                                           unsigned &brkpt_count) {
  binary_t &binary = decompilation.Binaries[binary_idx];
  auto &FuncMap = BinStateVec[binary_idx].FuncMap;

  {
    auto it = FuncMap.find(Addr);
    if (it != FuncMap.end())
      return (*it).second;
  }

  function_index_t res = binary.Analysis.Functions.size();
  FuncMap[Addr] = res;
  binary.Analysis.Functions.resize(res + 1);
  binary.Analysis.Functions[res].Entry =
      translate_basic_block(child, binary_idx, tcg, dis, Addr, brkpt_count);

  return res;
}

basic_block_index_t translate_basic_block(pid_t child,
                                          binary_index_t binary_idx,
                                          tiny_code_generator_t &tcg,
                                          disas_t &dis,
                                          const target_ulong Addr,
                                          unsigned &brkpt_count) {
  binary_t &binary = decompilation.Binaries[binary_idx];
  auto &BBMap = BinStateVec[binary_idx].BBMap;

  //
  // does this new basic block start in the middle of a previously-created
  // basic block?
  //
  {
    auto it = BBMap.find(Addr);
    if (it != BBMap.end()) {
      basic_block_index_t bbidx = (*it).second - 1;
      auto &ICFG = binary.Analysis.ICFG;
      basic_block_t bb = boost::vertex(bbidx, ICFG);

      assert(bbidx < boost::num_vertices(ICFG));

      uintptr_t beg = ICFG[bb].Addr;

      if (Addr == beg) {
        assert(ICFG[bb].Addr == (*it).first.lower());
        return bbidx;
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
      }

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

      llvm::outs() << "intervl1: [" << (fmt("%#lx") % intervl1.lower()).str()
                   << ", " << (fmt("%#lx") % intervl1.upper()).str() << ")\n";

      llvm::outs() << "intervl2: [" << (fmt("%#lx") % intervl2.lower()).str()
                   << ", " << (fmt("%#lx") % intervl2.upper()).str() << ")\n";

      llvm::outs() << "orig_intervl: ["
                   << (fmt("%#lx") % orig_intervl.lower()).str()
                   << ", "
                   << (fmt("%#lx") % orig_intervl.upper()).str()
                   << ")\n";

#if 0
      if ((*it).first.lower() == 0x1070 ||
          (*it).first.upper() == 0x109e) {
        llvm::outs()
          << "ISTHISIT?    ["
          << (fmt("%#lx") % (*it).first.lower()).str()
          << ", "
          << (fmt("%#lx") % (*it).first.upper()).str() << ")\n";
      }
#endif

      unsigned n = BBMap.iterative_size();
      BBMap.erase((*it).first);
      assert(BBMap.iterative_size() == n - 1);

      assert(BBMap.find(intervl1) == BBMap.end());
      assert(BBMap.find(intervl2) == BBMap.end());

      {
        auto _it = BBMap.find(intervl1);
        if (_it != BBMap.end()) {
          const auto &intervl = (*_it).first;
          WithColor::error() << "can't add interval1 to BBMap: ["
                             << (fmt("%#lx") % intervl1.lower()).str() << ", "
                             << (fmt("%#lx") % intervl1.upper()).str()
                             << "), BBMap already contains ["
                             << (fmt("%#lx") % intervl.lower()).str() << ", "
                             << (fmt("%#lx") % intervl.upper()).str() << ")\n";
          abort();
        }
      }

      {
        auto _it = BBMap.find(intervl2);
        if (_it != BBMap.end()) {
          const auto &intervl = (*_it).first;
          llvm::errs() << " Addr=" << (fmt("%#lx") % Addr).str() << '\n';

          WithColor::error() << "can't add interval2 to BBMap: ["
                             << (fmt("%#lx") % intervl2.lower()).str() << ", "
                             << (fmt("%#lx") % intervl2.upper()).str()
                             << "), BBMap already contains ["
                             << (fmt("%#lx") % intervl.lower()).str() << ", "
                             << (fmt("%#lx") % intervl.upper()).str() << ")\n";
          abort();
        }
      }

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

  auto &SectMap = BinStateVec[binary_idx].SectMap;
  auto sectit = SectMap.find(Addr);
  if (sectit == SectMap.end()) {
    WithColor::error()
        << (fmt("warning: no section for address 0x%lx") % Addr).str() << '\n';
    return invalid_basic_block_index;
  }
  const section_properties_t &sectprop = *(*sectit).second.begin();
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

        WithColor::error() << "can't translate further ["
                           << (fmt("%#lx") % intervl.lower()).str()
                           << ", "
                           << (fmt("%#lx") % intervl.upper()).str()
                           << "), BBMap already contains ["
                           << (fmt("%#lx") % _intervl.lower()).str()
                           << ", "
                           << (fmt("%#lx") % _intervl.upper()).str()
                           << ")\n";

        assert(intervl.lower() < _intervl.lower());

        //assert(intervl.upper() == _intervl.upper());

        if (intervl.upper() != _intervl.upper()) {
          WithColor::warning() << "we've translated into another basic block:"
                               << (fmt("%#lx") % intervl.lower()).str()
                               << ", "
                               << (fmt("%#lx") % intervl.upper()).str()
                               << "), BBMap already contains ["
                               << (fmt("%#lx") % _intervl.lower()).str()
                               << ", "
                               << (fmt("%#lx") % _intervl.upper()).str()
                               << ")\n";
        }

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
                                A, llvm::nulls(), llvm::nulls());

      if (!Disassembled) {
        WithColor::error() << (fmt("failed to disassemble %#lx") % Addr).str()
                           << '\n';
        break;
      }

      IP.printInst(&Inst, llvm::errs(), "", STI);
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

  basic_block_index_t bbidx = boost::num_vertices(binary.Analysis.ICFG);
  basic_block_t bb = boost::add_vertex(binary.Analysis.ICFG);
  {
    basic_block_properties_t &bbprop = binary.Analysis.ICFG[bb];
    bbprop.Addr = Addr;
    bbprop.Size = Size;
    bbprop.Term.Type = T.Type;
    bbprop.Term.Addr = T.Addr;

    boost::icl::interval<uintptr_t>::type intervl =
        boost::icl::interval<uintptr_t>::right_open(bbprop.Addr,
                                                    bbprop.Addr + bbprop.Size);
    assert(BBMap.find(intervl) == BBMap.end());
    BBMap.add({intervl, 1 + bbidx});

    //
    // if it's an indirect branch, we need to (1) add it to the indirect branch
    // map and (2) install a breakpoint at the correct program counter
    //
    if (bbprop.Term.Type == TERMINATOR::INDIRECT_CALL ||
        bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP) {
      uintptr_t termpc = va_of_rva(bbprop.Term.Addr, binary_idx);

      assert(IndBrMap.find(termpc) == IndBrMap.end());
      indirect_branch_t &indbr = IndBrMap[termpc];
      indbr.binary_idx = binary_idx;
      indbr.bbidx = bbidx;
      indbr.TermAddr = bbprop.Term.Addr;
      indbr.InsnBytes.resize(bbprop.Size - (bbprop.Term.Addr - bbprop.Addr));

      memcpy(&indbr.InsnBytes[0],
             &sectprop.contents[bbprop.Term.Addr - (*sectit).first.lower()],
             indbr.InsnBytes.size());

      //
      // now that we have the bytes for each indirect branch, disassemble them
      //
      llvm::MCInst &Inst = indbr.Inst;

      llvm::MCDisassembler &DisAsm = std::get<0>(dis);
      uint64_t InstLen;
      bool Disassembled = DisAsm.getInstruction(
        Inst, InstLen, indbr.InsnBytes, bbprop.Term.Addr, llvm::nulls(),
        llvm::nulls());
      assert(Disassembled);

      ++brkpt_count;
      place_breakpoint_at_indirect_branch(child, termpc, indbr, dis);
    }
  }

  //
  // conduct analysis of last instruction (the terminator of the block) and
  // (recursively) descend into branch targets, translating basic blocks
  //
  auto control_flow = [&](uintptr_t Target) -> void {
    assert(Target);

    basic_block_index_t succidx =
        translate_basic_block(child, binary_idx, tcg, dis, Target, brkpt_count);

    assert(succidx != invalid_basic_block_index);

    basic_block_t _bb;
    {
      auto it = T.Addr ? BBMap.find(T.Addr) : BBMap.find(Addr);
      assert(it != BBMap.end());

      auto &ICFG = binary.Analysis.ICFG;
      basic_block_index_t _bbidx = (*it).second - 1;
      _bb = boost::vertex(_bbidx, ICFG);
      assert(T.Type == ICFG[_bb].Term.Type);
    }

    basic_block_t succ = boost::vertex(succidx, binary.Analysis.ICFG);
    boost::add_edge(_bb, succ, binary.Analysis.ICFG);
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
    binary.Analysis.ICFG[bb].Term._call.Target = translate_function(
        child, binary_idx, tcg, dis, T._call.Target, brkpt_count);

    control_flow(T._call.NextPC);
    break;

  case TERMINATOR::INDIRECT_CALL:
    control_flow(T._indirect_call.NextPC);
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

static std::string StringOfMCInst(llvm::MCInst &, disas_t &);

void place_breakpoint_at_indirect_branch(pid_t child,
                                         uintptr_t Addr,
                                         indirect_branch_t &indbr,
                                         disas_t &dis) {
  llvm::MCInst &Inst = indbr.Inst;

  auto is_opcode_handled = [](unsigned opc) -> bool {
#if defined(__x86_64__)
    return opc == llvm::X86::JMP64r
        || opc == llvm::X86::JMP64m
        || opc == llvm::X86::CALL64m
        || opc == llvm::X86::CALL64r;
#elif defined(__i386__)
    return opc == llvm::X86::JMP32r
        || opc == llvm::X86::JMP32m
        || opc == llvm::X86::CALL32m
        || opc == llvm::X86::CALL32r;
#elif defined(__aarch64__)
    return opc == llvm::AArch64::BLR
        || opc == llvm::AArch64::BR;
#endif
  };

  if (!is_opcode_handled(Inst.getOpcode())) {
    binary_t &Binary = decompilation.Binaries[indbr.binary_idx];
    const auto &ICFG = Binary.Analysis.ICFG;
    throw std::runtime_error(
      (fmt("could not place breakpoint @ %#lx\n"
           "%s BB %#lx\n"
           "%s")
       % Addr
       % Binary.Path
       % ICFG[boost::vertex(indbr.bbidx, ICFG)].Addr
       % StringOfMCInst(Inst, dis)).str());
  }

  // read a word of the branch instruction
  unsigned long word = _ptrace_peekdata(child, Addr);

  // insert breakpoint
#if defined(__x86_64__) || defined(__i386__)
  reinterpret_cast<uint8_t *>(&word)[0] = 0xcc; /* int3 */
#elif defined(__aarch64__)
  reinterpret_cast<uint32_t *>(&word)[0] = 0xd4200000; /* brk */
#endif

  // write the word back
  _ptrace_pokedata(child, Addr, word);

  if (opts::VeryVerbose)
    llvm::errs() << (fmt("breakpoint placed @ %#lx") % Addr).str() << '\n';
}

void place_breakpoint(pid_t child,
                      uintptr_t Addr,
                      breakpoint_t &brk,
                      disas_t &dis) {
  // read a word of the instruction
  unsigned long word = _ptrace_peekdata(child, Addr);

  brk.word = word;

  // insert breakpoint
#if defined(__x86_64__) || defined(__i386__)
  reinterpret_cast<uint8_t *>(&word)[0] = 0xcc; /* int3 */
#elif defined(__aarch64__)
  reinterpret_cast<uint32_t *>(&word)[0] = 0xd4200000; /* brk */
#endif

  // write the word back
  _ptrace_pokedata(child, Addr, word);

  if (opts::VeryVerbose)
    llvm::errs() << (fmt("breakpoint placed @ %#lx") % Addr).str() << '\n';
}

static std::string description_of_program_counter(uintptr_t);

struct ScopedGPR {
  pid_t child;
  struct user_regs_struct gpr;

  ScopedGPR(pid_t child) : child(child) { _ptrace_get_gpr(child, gpr); }
  ~ScopedGPR() { _ptrace_set_gpr(child, gpr); }
};

void on_breakpoint(pid_t child, tiny_code_generator_t &tcg, disas_t &dis) {
  ScopedGPR _scoped_gpr(child);

  auto &gpr = _scoped_gpr.gpr;

  auto &pc =
#if defined(__x86_64__)
      gpr.rip
#elif defined(__i386__)
      gpr.eip
#elif defined(__aarch64__)
      gpr.pc
#endif
      ;

  //
  // rewind before the breakpoint instruction
  //
#if defined(__x86_64__) || defined(__i386__)
  pc -= 1; /* int3 */
#elif defined(__aarch64__)
  //pc -= 4; /* brk */
#endif

  //
  // lookup indirect branch info
  //
  const uintptr_t _pc = pc;

  {
    auto it = BrkMap.find(_pc);
    if (it != BrkMap.end()) {
      breakpoint_t &brk = (*it).second;
      brk.callback(child, tcg, dis);

      _ptrace_pokedata(child, _pc, brk.word);
      return;
    }
  }

  auto indirect_branch_of_address = [](uintptr_t addr) -> indirect_branch_t & {
    auto it = IndBrMap.find(addr);
    if (it == IndBrMap.end())
      throw std::runtime_error((fmt("unknown breakpoint @ %#lx") % addr).str());

    return (*it).second;
  };

  indirect_branch_t &IndBrInfo = indirect_branch_of_address(_pc);
  binary_t &binary = decompilation.Binaries[IndBrInfo.binary_idx];
  auto &BBMap = BinStateVec[IndBrInfo.binary_idx].BBMap;
  auto &ICFG = binary.Analysis.ICFG;

  //
  // update program counter so it is as it should be
  //
  pc += IndBrInfo.InsnBytes.size();

  //
  // shorthand-functions for reading the tracee's memory and registers
  //
  basic_block_index_t bbidx;
  {
    assert(IndBrInfo.TermAddr);
    auto it = BBMap.find(IndBrInfo.TermAddr);

    if (it == BBMap.end()) {
      WithColor::error() << "WTF? BBMap has no entry for "
                         << (fmt("%#lx") % IndBrInfo.TermAddr).str()
                         << " @ "
                         << fs::path(binary.Path).filename().string()
                         << '\n';
      llvm::errs() << "dumping BBMap (iterative_size=" << BBMap.iterative_size()
                   << ")\n";
      for (const auto &pair : BBMap) {
        llvm::errs()
          << "["
          << (fmt("%#lx") % pair.first.lower()).str()
          << ", "
          << (fmt("%#lx") % pair.first.upper()).str()
          << ")\n";
      }
      abort();
    }

    bbidx = (*it).second - 1;
  }

  basic_block_t bb = boost::vertex(bbidx, ICFG);

  assert(ICFG[bb].Term.Type != TERMINATOR::NONE);

  llvm::MCInst &Inst = IndBrInfo.Inst;

  auto RegValue = [&](unsigned llreg) -> long {
    switch (llreg) {
#if defined(__x86_64__)
    case llvm::X86::RAX:
      return gpr.rax;
    case llvm::X86::RBP:
      return gpr.rbp;
    case llvm::X86::RBX:
      return gpr.rbx;
    case llvm::X86::RCX:
      return gpr.rcx;
    case llvm::X86::RDI:
      return gpr.rdi;
    case llvm::X86::RDX:
      return gpr.rdx;
    case llvm::X86::RIP:
      return gpr.rip;
    case llvm::X86::RSI:
      return gpr.rsi;
    case llvm::X86::RSP:
      return gpr.rsp;

#define __REG_CASE(n, i, data)                                                 \
  case BOOST_PP_CAT(llvm::X86::R, i):                                          \
    return BOOST_PP_CAT(gpr.r, i);

BOOST_PP_REPEAT_FROM_TO(8, 16, __REG_CASE, void)

#undef __REG_CASE

#elif defined(__i386__)

    case llvm::X86::NoRegister:
      return 0L;

    case llvm::X86::EAX:
      return gpr.eax;
    case llvm::X86::EBP:
      return gpr.ebp;
    case llvm::X86::EBX:
      return gpr.ebx;
    case llvm::X86::ECX:
      return gpr.ecx;
    case llvm::X86::EDI:
      return gpr.edi;
    case llvm::X86::EDX:
      return gpr.edx;
    case llvm::X86::EIP:
      return gpr.eip;
    case llvm::X86::ESI:
      return gpr.esi;
    case llvm::X86::ESP:
      return gpr.esp;

    //
    // for segment registers, return the base address of the segment descriptor
    // which they reference (bits 15-3)
    //
    case llvm::X86::SS:
      return segment_address_of_selector(child, gpr.xss);
    case llvm::X86::CS:
      return segment_address_of_selector(child, gpr.xcs);
    case llvm::X86::DS:
      return segment_address_of_selector(child, gpr.xds);
    case llvm::X86::ES:
      return segment_address_of_selector(child, gpr.xes);
    case llvm::X86::FS:
      return segment_address_of_selector(child, gpr.xfs);
    case llvm::X86::GS:
      return segment_address_of_selector(child, gpr.xgs);

#elif defined(__aarch64__)

#define __REG_CASE(n, i, data)                                                 \
  case BOOST_PP_CAT(llvm::AArch64::X, i):                                      \
    return gpr.regs[i];

BOOST_PP_REPEAT(29, __REG_CASE, void)

#undef __REG_CASE

#endif

    default:
      throw std::runtime_error(
          (fmt("RegValue: unknown llreg %u @ %s : BB %#lx\n%s") % llreg %
           binary.Path % ICFG[bb].Addr % StringOfMCInst(Inst, dis))
              .str());
    }
  };

  auto LoadAddr = [&](uintptr_t addr) -> uintptr_t {
    return _ptrace_peekdata(child, addr);
  };

  auto GetTarget = [&](void) -> uintptr_t {
    switch (Inst.getOpcode()) {

#if defined(__x86_64__)

    case llvm::X86::JMP64m: /* jmp qword ptr [reg0 + imm3] */
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(3).isImm());
      return LoadAddr(RegValue(Inst.getOperand(0).getReg()) +
                      Inst.getOperand(3).getImm());

    case llvm::X86::JMP64r: /* jmp reg0 */
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

    case llvm::X86::CALL64m: /* call qword ptr [rip + 3071542] */
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(3).isImm());
      return LoadAddr(RegValue(Inst.getOperand(0).getReg()) +
                      Inst.getOperand(3).getImm());

    case llvm::X86::CALL64r: /* call rax */
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

#elif defined(__i386__)

    case llvm::X86::JMP32m: /* jmp dword ptr [ebx + 20] */
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(3).isImm());
      return LoadAddr(RegValue(Inst.getOperand(0).getReg()) +
                      Inst.getOperand(3).getImm());

    case llvm::X86::JMP32r: /* jmp eax */
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

    case llvm::X86::CALL32m:
      assert(Inst.getNumOperands() == 5);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(1).isImm());
      assert(Inst.getOperand(2).isReg());
      assert(Inst.getOperand(3).isImm());
      assert(Inst.getOperand(4).isReg());

      if (Inst.getOperand(4).getReg() == llvm::X86::NoRegister) {
        /* e.g. call dword ptr [esi + 4*edi - 280] */
        return LoadAddr(RegValue(Inst.getOperand(0).getReg()) +
                        Inst.getOperand(1).getImm() *
                            RegValue(Inst.getOperand(2).getReg()) +
                        Inst.getOperand(3).getImm());
      } else {
        /* e.g. call dword ptr gs:[16] */
        return LoadAddr(RegValue(Inst.getOperand(4).getReg()) +
                        Inst.getOperand(3).getImm());
      }

    case llvm::X86::CALL32r: /* call edx */
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

#elif defined(__aarch64__)

    case llvm::AArch64::BLR: /* blr x3 */
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

    case llvm::AArch64::BR: /* br x17 */
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());
#endif

    default:
      abort();
    }
  };

  uintptr_t target = GetTarget();

  //
  // if the instruction is a call, we need to emulate the semantics of
  // saving the return address on the stack for certain architectures
  //
  if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL) {
#if defined(__x86_64__)
    gpr.rsp -= sizeof(uintptr_t);
    _ptrace_pokedata(child, gpr.rsp, pc);
#elif defined(__i386__)
    gpr.esp -= sizeof(uintptr_t);
    _ptrace_pokedata(child, gpr.esp, pc);
#elif defined(__aarch64__)
    gpr.regs[30 /* lr */] = pc;
#endif
  }

  //
  // set program counter to be branch target
  //
  pc = target;

  if (opts::VeryVerbose)
    llvm::errs() << (fmt("target=%#lx") % target).str() << '\n';

  //
  // update the decompilation based on the target
  //
  auto it = AddressSpace.find(target);
  if (it == AddressSpace.end()) {
    llvm::errs() << "warning: unknown binary for "
                 << description_of_program_counter(target) << '\n';
    return;
  }

  binary_index_t binary_idx = *(*it).second.begin();

  bool isNewTarget = false;
  bool isLocal = IndBrInfo.binary_idx == binary_idx;

  const char *print_prefix = "(call) ";

  unsigned brkpt_count = 0;

  if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL) {
    function_index_t f_idx =
        translate_function(child, binary_idx, tcg, dis,
                           rva_of_va(target, binary_idx), brkpt_count);

#if 0
    if (rva_of_va(target, binary_idx) == 0x2050) {
      llvm::errs() << "target binary_idx=" << binary_idx << " f_idx=" << f_idx
                   << " ICFG[bb].Addr=" << (fmt("%#lx") % ICFG[bb].Addr).str()
                   << " DynTargets.size=" << ICFG[bb].DynTargets.size() << '\n';
      llvm::errs() << "[after] DynTargets.size=" << ICFG[bb].DynTargets.size()
                   << " isNewTarget=" << isNewTarget << '\n';

      isNewTarget = ICFG[bb].DynTargets.insert({binary_idx, f_idx}).second;
    }
#endif

    isNewTarget = ICFG[bb].DynTargets.insert({binary_idx, f_idx}).second;
  } else if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP) {
    if (isLocal) {
      basic_block_index_t target_bb_idx =
          translate_basic_block(child, binary_idx, tcg, dis,
                                rva_of_va(target, binary_idx), brkpt_count);
      basic_block_t target_bb = boost::vertex(target_bb_idx, ICFG);

      isNewTarget = boost::add_edge(bb, target_bb, ICFG).second;

      print_prefix = "(jump) ";
    } else { /* tail call */
      function_index_t f_idx =
          translate_function(child, binary_idx, tcg, dis,
                             rva_of_va(target, binary_idx), brkpt_count);

      isNewTarget = ICFG[bb].DynTargets.insert({binary_idx, f_idx}).second;
    }
  } else {
    abort();
  }

  if (brkpt_count > 0) {
    binary_t &binary = decompilation.Binaries[binary_idx];
    llvm::errs() << "placed " << brkpt_count << " breakpoints in "
                 << binary.Path << '\n';
  }

  if (!opts::Quiet)
    llvm::errs() << print_prefix
                 << description_of_program_counter(_pc) << " -> "
                 << description_of_program_counter(target) << '\n';
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

struct relocation_t {
  enum class TYPE {
    NONE,
    RELATIVE,
    IRELATIVE,
    ABSOLUTE,
    COPY,
    ADDRESSOF,
    TPOFF
  } Type;
};

static void harvest_ifunc_resolver_targets(pid_t child,
                                           tiny_code_generator_t &tcg,
                                           disas_t &dis) {
  for (binary_index_t BIdx = 0; BIdx < decompilation.Binaries.size(); ++BIdx) {
    auto &Binary = decompilation.Binaries[BIdx];

    //
    // parse the ELF
    //
    llvm::StringRef Buffer(reinterpret_cast<const char *>(&Binary.Data[0]),
                           Binary.Data.size());
    llvm::StringRef Identifier(Binary.Path);
    llvm::MemoryBufferRef MemBuffRef(Buffer, Identifier);

    llvm::Expected<std::unique_ptr<obj::Binary>> BinOrErr =
        obj::createBinary(MemBuffRef);
    if (!BinOrErr) {
      WithColor::error() << "failed to create binary from " << Binary.Path
                         << '\n';
      return;
    }

    std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

    assert(llvm::isa<ELFO>(Bin.get()));
    ELFO &O = *llvm::cast<ELFO>(Bin.get());
    const ELFT &E = *O.getELFFile();

    typedef typename ELFT::Elf_Phdr Elf_Phdr;
    typedef typename ELFT::Elf_Dyn Elf_Dyn;
    typedef typename ELFT::Elf_Dyn_Range Elf_Dyn_Range;
    typedef typename ELFT::Elf_Sym_Range Elf_Sym_Range;
    typedef typename ELFT::Elf_Shdr Elf_Shdr;
    typedef typename ELFT::Elf_Sym Elf_Sym;
    typedef typename ELFT::Elf_Rela Elf_Rela;

    auto process_elf_rela = [&](const Elf_Shdr &Sec,
                                const Elf_Rela &R) -> void {
      auto relocation_type_of_elf_rela_type =
          [](uint64_t elf_rela_ty) -> relocation_t::TYPE {
        switch (elf_rela_ty) {
#include "relocs.hpp"
        default:
          return relocation_t::TYPE::NONE;
        }
      };

      relocation_t::TYPE reloc_type =
          relocation_type_of_elf_rela_type(R.getType(E.isMips64EL()));
      if (reloc_type == relocation_t::TYPE::IRELATIVE) {
        uintptr_t Addr = va_of_rva(R.r_offset, BIdx);
        unsigned long resolved_addr = _ptrace_peekdata(child, Addr);

        auto it = AddressSpace.find(resolved_addr);
        if (it == AddressSpace.end()) {
          WithColor::warning()
              << "harvest_ifunc_resolver_targets: unknown binary for "
              << description_of_program_counter(resolved_addr) << '\n';
          return;
        }

        binary_index_t binary_idx = *(*it).second.begin();
        bool isLocal = binary_idx == BIdx;

        if (!isLocal) {
          WithColor::warning()
              << "nonlocal ifunc resolver target "
              << description_of_program_counter(resolved_addr) << '\n';
          return;
        }

        llvm::outs() << "ifunc resolver target: "
                     << (fmt("%#lx") % rva_of_va(resolved_addr, BIdx)).str()
                     << '\n';

        unsigned brkpt_count = 0;
        function_index_t resolved_fidx = translate_function(
            child, BIdx, tcg, dis, rva_of_va(resolved_addr, BIdx), brkpt_count);

        if (is_function_index_valid(resolved_fidx))
          Binary.Analysis.IFuncRelocDynTargets[R.r_offset].insert(
              resolved_fidx);
      }
    };

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      if (Sec.sh_type != llvm::ELF::SHT_RELA)
        continue;

      for (const Elf_Rela &Rela : unwrapOrError(E.relas(&Sec)))
        process_elf_rela(Sec, Rela);
    }
  }
}

void search_address_space_for_binaries(pid_t child, disas_t &dis) {
  if (!update_view_of_virtual_memory(child)) {
    WithColor::error() << "failed to read virtual memory maps of child "
                       << child << '\n';
    return;
  }

  for (auto &vm_prop_set : vmm) {
    const vm_properties_t &vm_prop = *vm_prop_set.second.begin();

    if (!vm_prop.x)
      continue;
    if (vm_prop.nm.empty())
      continue;
    if (!fs::exists(vm_prop.nm))
      continue;

    std::string Path = fs::canonical(vm_prop.nm).string();
    auto it = BinPathToIdxMap.find(Path);
    if (it != BinPathToIdxMap.end() && !BinFoundVec.test((*it).second)) {
      binary_index_t binary_idx = (*it).second;
      BinFoundVec.set(binary_idx);

      binary_state_t &st = BinStateVec[binary_idx];

      st.dyn.LoadAddr = vm_prop.beg - vm_prop.off;
      st.dyn.LoadAddrEnd = vm_prop.end;

      llvm::errs() << (fmt("found binary %s @ [%#lx, %#lx)")
                       % Path
                       % st.dyn.LoadAddr
                       % st.dyn.LoadAddrEnd).str()
                   << '\n';

      boost::icl::interval<uintptr_t>::type intervl =
          boost::icl::interval<uintptr_t>::right_open(vm_prop.beg, vm_prop.end);
      binary_index_set_t bin_idx_set = {binary_idx};
      AddressSpace.add(std::make_pair(intervl, bin_idx_set));

      binary_t &binary = decompilation.Binaries[binary_idx];

      //
      // if Prog has been loaded, set a breakpoint on the entry point of prog
      //
      bool IsProg = fs::equivalent(Path, opts::Prog);
      if (IsProg) {
        assert(is_function_index_valid(binary.Analysis.EntryFunction));

        basic_block_t entry_bb = boost::vertex(
            binary.Analysis.Functions[binary.Analysis.EntryFunction].Entry,
            binary.Analysis.ICFG);
        uintptr_t entry_rva = binary.Analysis.ICFG[entry_bb].Addr;
        uintptr_t Addr = va_of_rva(entry_rva, binary_idx);

        llvm::outs()
            << "found prog! entry point is "
            << (fmt("%#lx") % binary.Analysis.ICFG[entry_bb].Addr).str()
            << "\n";

        breakpoint_t &brk = BrkMap[Addr];
        brk.callback = harvest_ifunc_resolver_targets;

        place_breakpoint(child, Addr, brk, dis);
      }

      //
      // place breakpoints for indirect branches
      //
      llvm::MCDisassembler &DisAsm = std::get<0>(dis);

      unsigned cnt = 0;

      for (basic_block_index_t bbidx = 0;
           bbidx < boost::num_vertices(binary.Analysis.ICFG); ++bbidx) {
        basic_block_t bb = boost::vertex(bbidx, binary.Analysis.ICFG);

        basic_block_properties_t &bbprop = binary.Analysis.ICFG[bb];
        if (bbprop.Term.Type != TERMINATOR::INDIRECT_JUMP &&
            bbprop.Term.Type != TERMINATOR::INDIRECT_CALL)
          continue;

        uintptr_t Addr = va_of_rva(bbprop.Term.Addr, binary_idx);

        {
          auto it = IndBrMap.find(Addr);
          if (it != IndBrMap.end()) {
            indirect_branch_t &indbr = (*it).second;
            binary_t &indbr_binary = decompilation.Binaries[indbr.binary_idx];
            const auto &indbr_ICFG = indbr_binary.Analysis.ICFG;

            WithColor::error() << "WTF?\n"
              << "["
              << (fmt("%#lx") % binary.Analysis.ICFG[bb].Addr).str()
              << ", "
              << (fmt("%#lx") % (binary.Analysis.ICFG[bb].Addr +
                                 binary.Analysis.ICFG[bb].Size)).str()
              << ") @ "
              << fs::path(binary.Path).filename().string()
              << "but IndBr already exists...\n"
              << "["
              << (fmt("%#lx") % indbr_ICFG[boost::vertex(indbr.bbidx, indbr_ICFG)].Addr).str()
              << ", "
              << (fmt("%#lx") % (indbr_ICFG[boost::vertex(indbr.bbidx, indbr_ICFG)].Addr +
                                 indbr_ICFG[boost::vertex(indbr.bbidx, indbr_ICFG)].Size)).str()
              << ") @ "
              << fs::path(indbr_binary.Path).filename().string();
          }
        }

        assert(IndBrMap.find(Addr) == IndBrMap.end());
        indirect_branch_t &IndBrInfo = IndBrMap[Addr];
        IndBrInfo.binary_idx = binary_idx;
        IndBrInfo.bbidx = bbidx;
        IndBrInfo.TermAddr = bbprop.Term.Addr;
        IndBrInfo.InsnBytes.resize(bbprop.Size - (bbprop.Term.Addr - bbprop.Addr));

        auto sectit = st.SectMap.find(bbprop.Term.Addr);
        assert(sectit != st.SectMap.end());
        const section_properties_t &sectprop = *(*sectit).second.begin();

        memcpy(&IndBrInfo.InsnBytes[0],
               &sectprop.contents[bbprop.Term.Addr - (*sectit).first.lower()],
               IndBrInfo.InsnBytes.size());

        //
        // now that we have the bytes for each indirect branch, disassemble them
        //
        llvm::MCInst &Inst = IndBrInfo.Inst;

        uint64_t InstLen;
        bool Disassembled = DisAsm.getInstruction(
            Inst, InstLen, IndBrInfo.InsnBytes, bbprop.Term.Addr, llvm::nulls(),
            llvm::nulls());
        assert(Disassembled);

        place_breakpoint_at_indirect_branch(child, Addr, IndBrInfo, dis);
        ++cnt;
      }

      llvm::errs() << "placed " << cnt << " breakpoints in " << binary.Path
                   << '\n';
    }
  }
}

#if !defined(__x86_64__) && defined(__i386__)
constexpr unsigned GDT_ENTRY_TLS_ENTRIES = 3;

static void _ptrace_get_segment_descriptors(
    pid_t child, std::array<struct user_desc, GDT_ENTRY_TLS_ENTRIES> &out) {
  struct iovec iov = {.iov_base = out.data(),
                      .iov_len = sizeof(struct user_desc) * out.size()};

  unsigned long _request = PTRACE_GETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 0x200 /* NT_386_TLS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_GETREGSET failed : ") +
                             std::string(strerror(errno)));
}

uintptr_t segment_address_of_selector(pid_t child, unsigned segsel) {
  unsigned index = segsel >> 3;

  std::array<struct user_desc, GDT_ENTRY_TLS_ENTRIES> seg_descs;
  _ptrace_get_segment_descriptors(child, seg_descs);

  auto it = std::find_if(seg_descs.begin(), seg_descs.end(),
                         [&](const struct user_desc &desc) -> bool {
                           return desc.entry_number == index;
                         });

  if (it == seg_descs.end())
    throw std::runtime_error(std::string("segment_address_of_selector failed"));

  return (*it).base_addr;
}
#endif

void _ptrace_get_gpr(pid_t child, struct user_regs_struct &out) {
  struct iovec iov = {.iov_base = &out,
                      .iov_len = sizeof(struct user_regs_struct)};

  unsigned long _request = PTRACE_GETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_GETREGSET failed : ") +
                             std::string(strerror(errno)));
}

void _ptrace_set_gpr(pid_t child, const struct user_regs_struct &in) {
  struct iovec iov = {.iov_base = const_cast<struct user_regs_struct *>(&in),
                      .iov_len = sizeof(struct user_regs_struct)};

  unsigned long _request = PTRACE_SETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_SETREGSET failed : ") +
                             std::string(strerror(errno)));
}

unsigned long _ptrace_peekdata(pid_t child, uintptr_t addr) {
  unsigned long res;

  unsigned long _request = PTRACE_PEEKDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = reinterpret_cast<unsigned long>(&res);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_PEEKDATA failed : ") +
                             std::string(strerror(errno)));

  return res;
}

void _ptrace_pokedata(pid_t child, uintptr_t addr, unsigned long data) {
  unsigned long _request = PTRACE_POKEDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = data;

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_POKEDATA failed : ") +
                             std::string(strerror(errno)));
}

int ChildProc(void) {
  //
  // the request
  //
  ptrace(PTRACE_TRACEME);
  //
  // turns the calling thread into a tracee.  The thread continues to run
  // (doesn't enter ptrace-stop).  A common practice is to follow the
  // PTRACE_TRACEME with
  //
  raise(SIGSTOP);
  //
  // and allow the parent (which is our tracer now) to observe our
  // signal-delivery-stop.
  //

  std::vector<char *> arg_vec;
  arg_vec.resize(opts::Args.size());
  std::transform(opts::Args.begin(), opts::Args.end(), arg_vec.begin(),
                 [](const std::string &arg) -> char * {
                   return const_cast<char *>(arg.c_str());
                 });

  arg_vec.insert(arg_vec.begin(), const_cast<char *>(opts::Prog.c_str()));
  arg_vec.push_back(nullptr);

  std::vector<char *> env_vec;
  for (char **env = ::environ; *env; ++env)
    env_vec.push_back(*env);
  env_vec.push_back(const_cast<char *>("LD_BIND_NOW=1"));
  env_vec.push_back(nullptr);

  return execve(opts::Prog.c_str(), arg_vec.data(), env_vec.data());
}

bool verify_arch(const obj::ObjectFile &Obj) {
  const llvm::Triple::ArchType archty =
#if defined(__x86_64__)
      llvm::Triple::ArchType::x86_64
#elif defined(__i386__)
      llvm::Triple::ArchType::x86;
#elif defined(__aarch64__)
      llvm::Triple::ArchType::aarch64
#endif
      ;

  return Obj.getArch() == archty;
}

bool update_view_of_virtual_memory(int child) {
  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", child);

    fp = fopen(path, "r");
  }

  if (fp == NULL) {
    return false;
  }

  vmm.clear();

  while ((read = getline(&line, &len, fp)) != -1) {
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";
    fields = sscanf(line,
                    "%" PRIx64 "-%" PRIx64 " %c%c%c%c %" PRIx64 " %x:%x %d"
                    " %512s",
                    &min, &max, &flag_r, &flag_w, &flag_x, &flag_p, &offset,
                    &dev_maj, &dev_min, &inode, path);

    if ((fields < 10) || (fields > 11)) {
      continue;
    }

    boost::icl::interval<uintptr_t>::type intervl =
        boost::icl::interval<uintptr_t>::right_open(min, max);

    vm_properties_t vmprop;
    vmprop.beg = min;
    vmprop.end = max;
    vmprop.off = offset;
    vmprop.r = flag_r == 'r';
    vmprop.w = flag_w == 'w';
    vmprop.x = flag_x == 'x';
    vmprop.p = flag_p == 'p';
    vmprop.nm = path;

    //
    // create the mappings
    //
    vm_properties_set_t vmprops = {vmprop};
    vmm.add(make_pair(intervl, vmprops));
  }

  free(line);
  fclose(fp);

  return true;
}

std::string StringOfMCInst(llvm::MCInst &Inst, disas_t &dis) {
  const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
  llvm::MCInstPrinter &IP = std::get<2>(dis);

  std::string res;

  {
    llvm::raw_string_ostream ss(res);

    IP.printInst(&Inst, ss, "", STI);

    ss << '\n';
    ss << "[opcode: " << Inst.getOpcode() << ']';
    for (unsigned i = 0; i < Inst.getNumOperands(); ++i) {
      const llvm::MCOperand &opnd = Inst.getOperand(i);

      char buff[0x100];
      if (opnd.isReg())
        snprintf(buff, sizeof(buff), "<reg %u>", opnd.getReg());
      else if (opnd.isImm())
        snprintf(buff, sizeof(buff), "<imm %" PRId64 ">", opnd.getImm());
      else if (opnd.isFPImm())
        snprintf(buff, sizeof(buff), "<imm %lf>", opnd.getFPImm());
      else if (opnd.isExpr())
        snprintf(buff, sizeof(buff), "<expr>");
      else if (opnd.isInst())
        snprintf(buff, sizeof(buff), "<inst>");
      else
        snprintf(buff, sizeof(buff), "<unknown>");

      ss << (fmt(" %u:%s") % i % buff).str();
    }

    ss << '\n';
  }

  return res;
}

std::string description_of_program_counter(uintptr_t pc) {
  auto simple_desc = [=](void) -> std::string {
    return (fmt("%#lx") % pc).str();
  };

  auto vm_it = vmm.find(pc);
  if (vm_it == vmm.end()) {
    return simple_desc();
  } else {
    const vm_properties_set_t &vmprops = (*vm_it).second;
    const vm_properties_t &vmprop = *vmprops.begin();

    if (vmprop.nm.empty())
      return simple_desc();

    std::string str = fs::path(vmprop.nm).filename().string();
    uintptr_t off = pc - vmprop.beg + vmprop.off;
    return (fmt("%s+%#lx") % str % off).str();
  }
}

void _qemu_log(const char *cstr) { llvm::errs() << cstr; }

}

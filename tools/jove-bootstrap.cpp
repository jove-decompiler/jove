#if (defined(__x86_64__)  && defined(TARGET_X86_64))  || \
    (defined(__i386__)    && defined(TARGET_I386))    || \
    (defined(__aarch64__) && defined(TARGET_AARCH64)) || \
    (defined(__mips64)    && defined(TARGET_MIPS64))  || \
    (defined(__mips__)    && defined(TARGET_MIPS32))
#include "tool.h"
#include "elf.h"
#include "tcg.h"
#include "disas.h"
#include "explore.h"
#include "crypto.h"
#include "util.h"
#include "vdso.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>

#include <array>
#include <cinttypes>

#include <asm/auxvec.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <unistd.h>
#if !defined(__x86_64__) && defined(__i386__)
#include <asm/ldt.h>
#endif
#include <sys/ptrace.h>
#if defined(__mips__)
#include <asm/ptrace.h> /* for pt_regs */
#endif
#include <sys/mman.h>
//#include <linux/ptrace.h>

#include "jove_macros.h"

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#if defined(__mips64) || defined(__mips__)
#undef PC /* XXX */
#endif

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

//#define JOVE_HAVE_MEMFD

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

namespace {

struct binary_state_t {
  fnmap_t fnmap;
  bbmap_t bbmap;

  uintptr_t LoadAddr = std::numeric_limits<uintptr_t>::max();
  uintptr_t LoadOffset = std::numeric_limits<uintptr_t>::max();

  std::unique_ptr<llvm::object::Binary> ObjectFile;
  struct {
    DynRegionInfo DynamicTable;
    llvm::StringRef DynamicStringTable;
    const Elf_Shdr *SymbolVersionSection;
    std::vector<VersionMapEntry> VersionMap;
    llvm::Optional<DynRegionInfo> OptionalDynSymRegion;

    DynRegionInfo DynRelRegion;
    DynRegionInfo DynRelaRegion;
    DynRegionInfo DynRelrRegion;
    DynRegionInfo DynPLTRelRegion;
  } _elf;
};

}

struct proc_map_t {
  uintptr_t beg;
  uintptr_t end;
  std::ptrdiff_t off;

  bool r, w, x; /* unix permissions */
  bool p;       /* private memory? (i.e. not shared) */

  std::string nm;

  bool operator==(const proc_map_t &pm) const {
    return beg == pm.beg && end == pm.end;
  }

  bool operator<(const proc_map_t &pm) const {
    return beg < pm.beg;
  }
};

typedef std::set<struct proc_map_t> proc_map_set_t;

struct indirect_branch_t {
  unsigned long words[2];

  binary_index_t BIdx;

  uintptr_t TermAddr;

  std::vector<uint8_t> InsnBytes;
  llvm::MCInst Inst;

#if defined(__mips64) || defined(__mips__)
  llvm::MCInst DelaySlotInst;
#endif

  bool IsCall;
};

struct return_t {
  unsigned long words[2];

  binary_index_t BIdx;

  std::vector<uint8_t> InsnBytes;
  llvm::MCInst Inst;

#if defined(__mips64) || defined(__mips__)
  llvm::MCInst DelaySlotInst;
#endif

  uintptr_t TermAddr;
};

// one-shot breakpoint
struct breakpoint_t {
  unsigned long words[2];

  std::vector<uint8_t> InsnBytes;
  llvm::MCInst Inst;

#if defined(__mips64) || defined(__mips__)
  llvm::MCInst DelaySlotInst;
#endif

  std::function<void(pid_t, tiny_code_generator_t &, disas_t &)> callback;
};

struct child_syscall_state_t {
  unsigned no;
  long a1, a2, a3, a4, a5, a6;
  unsigned int dir : 1;

  unsigned long pc;

  child_syscall_state_t() : dir(0), pc(0) {}
};

struct BootstrapTool : public TransformerTool_Bin<binary_state_t> {
  struct Cmdline {
    cl::opt<std::string> Prog;
    cl::list<std::string> Args;
    cl::list<std::string> Envs;
    cl::opt<std::string> jv;
    cl::alias jvAlias;
    cl::opt<bool> VeryVerbose;
    cl::alias VeryVerboseAlias;
    cl::opt<bool> Quiet;
    cl::alias QuietAlias;
    cl::opt<std::string> HumanOutput;
    cl::opt<bool> RtldDbgBrk;
    cl::opt<bool> PrintPtraceEvents;
    cl::alias PrintPtraceEventsAlias;
    cl::opt<bool> Syscalls;
    cl::alias SyscallsAlias;
    cl::opt<bool> Signals;
    cl::opt<bool> PrintLinkMap;
    cl::alias ScanLinkMapAlias;
    cl::opt<unsigned> PID;
    cl::alias PIDAlias;
    cl::opt<bool> Fast;
    cl::alias FastAlias;
    cl::opt<bool> Longjmps;
    cl::opt<std::string> ShowMe;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)),

          Args("args", cl::CommaSeparated, cl::ConsumeAfter,
               cl::desc("<program arguments>..."), cl::cat(JoveCategory)),

          Envs("env", cl::CommaSeparated,
               cl::value_desc("KEY_1=VALUE_1,KEY_2=VALUE_2,...,KEY_n=VALUE_n"),
               cl::desc("Extra environment variables"), cl::cat(JoveCategory)),

          jv("jv", cl::desc("Jove jv"), cl::value_desc("filename"),
             cl::cat(JoveCategory)),

          jvAlias("d", cl::desc("Alias for -jv."), cl::aliasopt(jv),
                  cl::cat(JoveCategory)),

          VeryVerbose(
              "veryverbose",
              cl::desc("Print extra information for debugging purposes"),
              cl::cat(JoveCategory)),

          VeryVerboseAlias("vv", cl::desc("Alias for -veryverbose."),
                           cl::aliasopt(VeryVerbose), cl::cat(JoveCategory)),

          Quiet("quiet", cl::desc("Suppress non-error messages"),
                cl::cat(JoveCategory), cl::init(false)),

          QuietAlias("q", cl::desc("Alias for -quiet."), cl::aliasopt(Quiet),
                     cl::cat(JoveCategory)),

          HumanOutput("human-output",
                      cl::desc("Print messages to the given file path"),
                      cl::cat(JoveCategory)),

          RtldDbgBrk("rtld-dbg-brk", cl::desc("look for r_debug::r_brk"),
                     cl::cat(JoveCategory), cl::init(true)),

          PrintPtraceEvents("events",
                            cl::desc("Print PTRACE events when they occur"),
                            cl::cat(JoveCategory)),

          PrintPtraceEventsAlias("e", cl::desc("Alias for -events."),
                                 cl::aliasopt(PrintPtraceEvents),
                                 cl::cat(JoveCategory)),

          Syscalls("syscalls", cl::desc("Always trace system calls"),
                   cl::cat(JoveCategory)),

          SyscallsAlias("s", cl::desc("Alias for -syscalls."),
                        cl::aliasopt(Syscalls), cl::cat(JoveCategory)),

          Signals("signals", cl::desc("Print when delivering signals"),
                  cl::cat(JoveCategory)),

          PrintLinkMap("print-link-map", cl::desc("Always scan link map"),
                       cl::cat(JoveCategory)),

          ScanLinkMapAlias("l", cl::desc("Alias for -scan-link-map."),
                           cl::aliasopt(PrintLinkMap), cl::cat(JoveCategory)),

          PID("attach", cl::desc("attach to existing process PID"),
              cl::cat(JoveCategory)),

          PIDAlias("p", cl::desc("Alias for -attach."), cl::aliasopt(PID),
                   cl::cat(JoveCategory)),

          Fast("fast", cl::desc("\"Fast\" mode"), cl::cat(JoveCategory)),

          FastAlias("f", cl::desc("Alias for -fast."), cl::aliasopt(Fast),
                    cl::cat(JoveCategory)),

          Longjmps("longjmps", cl::desc("Print when longjmp happens"),
                   cl::cat(JoveCategory)),

          ShowMe("show",
                 cl::desc("Control whether to print when code is recovered"),
                 cl::value_desc("(n)ever|(a)lways|(s)ometimes"), cl::init("s"),
                 cl::cat(JoveCategory)) {}
  } opts;

  std::string jvfp;

  tiny_code_generator_t tcg;
  disas_t disas;

  explorer_t E;

  std::vector<struct proc_map_t> cached_proc_maps;

  boost::icl::split_interval_map<uintptr_t, proc_map_set_t> pmm;

  boost::icl::split_interval_map<uintptr_t, unsigned> AddressSpace;

  boost::dynamic_bitset<> BinFoundVec;
  std::unordered_map<std::string, binary_index_t> BinPathToIdxMap;

  unsigned TurboToggle = 0;

  pid_t _child = 0; /* XXX */

  std::unordered_map<uintptr_t, indirect_branch_t> IndBrMap;
  std::unordered_map<uintptr_t, return_t> RetMap;
  std::unordered_map<uintptr_t, breakpoint_t> BrkMap;

  struct {
    bool Found = false;
    uintptr_t Addr = 0;

    uintptr_t r_brk = 0;
  } _r_debug;

  std::unordered_map<pid_t, child_syscall_state_t> children_syscall_state;

  bool invalidateAnalyses = false;

#if defined(__mips64) || defined(__mips__)
  //
  // we need to find a code cave that can hold two instructions (8 bytes)
  //
  uintptr_t ExecutableRegionAddress = 0;
#endif

  bool ShowMeN = false;
  bool ShowMeA = false;
  bool ShowMeS = false;

public:
  BootstrapTool() : opts(JoveCategory), E(jv, disas, tcg) {}

  int Run(void);

  int ChildProc(int fd);
  int TracerLoop(pid_t child, tiny_code_generator_t &tcg);

  void add_binary(pid_t, tiny_code_generator_t &, const char *path);

  void on_new_basic_block(binary_t &, basic_block_t);

  void place_breakpoint_at_indirect_branch(pid_t, uintptr_t Addr,
                                           indirect_branch_t &);

  void place_breakpoint_at_return(pid_t child, uintptr_t Addr, return_t &Ret);

  void on_binary_loaded(pid_t, binary_index_t, const proc_map_t &);

  void on_dynamic_linker_loaded(pid_t, binary_index_t, const proc_map_t &);

  void place_breakpoint(pid_t, uintptr_t Addr, breakpoint_t &);
  void on_breakpoint(pid_t, tiny_code_generator_t &);
  void on_return(pid_t child, uintptr_t AddrOfRet, uintptr_t RetAddr,
                 tiny_code_generator_t &);

  void harvest_reloc_targets(pid_t, tiny_code_generator_t &);
  void rendezvous_with_dynamic_linker(pid_t);
  void scan_rtld_link_map(pid_t, tiny_code_generator_t &);

  void harvest_irelative_reloc_targets(pid_t child, tiny_code_generator_t &);
  void harvest_addressof_reloc_targets(pid_t child, tiny_code_generator_t &);
  void harvest_ctor_and_dtors(pid_t child, tiny_code_generator_t &tcg);

#if defined(__mips64) || defined(__mips__)
  void harvest_global_GOT_entries(pid_t child, tiny_code_generator_t &tcg);
#endif

  bool update_view_of_virtual_memory(pid_t);

  uintptr_t va_of_rva(uintptr_t Addr, binary_index_t BIdx);
  uintptr_t rva_of_va(uintptr_t Addr, binary_index_t BIdx);

  std::string description_of_program_counter(uintptr_t, bool Verbose = false);

  pid_t saved_child;
  std::atomic<bool> ToggleTurbo = false;
};

JOVE_REGISTER_TOOL("bootstrap", BootstrapTool);

typedef boost::format fmt;

static std::string ProcMapsForPid(pid_t);

static BootstrapTool *pTool;
static void SignalHandler(int no);

int BootstrapTool::Run(void) {
  pTool = this;

  for (char *dashdash_arg : dashdash_args)
    opts.Args.push_back(dashdash_arg);

  if (!opts.HumanOutput.empty())
    HumanOutToFile(opts.HumanOutput);

  if (opts.ShowMe.size() == 1) {
    ShowMeN = opts.ShowMe[0] == 'n';
    ShowMeA = opts.ShowMe[0] == 'a';
    ShowMeS = opts.ShowMe[0] == 's';

    WARN_ON(!ShowMeN && !ShowMeA && !ShowMeS);
  }

  if (!fs::exists(opts.Prog)) {
    HumanOut() << "program does not exist\n";
    return 1;
  }

#if 0
  //
  // OMG. this hack is awful. it is here because if a binary is dynamically
  // added to the jv, the std::vector will resize if necessary- and
  // if such an event occurs, pointers to the section data will be invalidated
  // because the binary_t::Data will be recopied. TODO
  //
  jv.Binaries.reserve(2 * jv.Binaries.size());
#endif

  for (binary_t &b : jv.Binaries)
    b.Analysis.ICFG.m_property.reset();

  //
  // verify that the binaries on-disk are those found in the jv.
  //
  for (binary_t &binary : jv.Binaries) {
    if (binary.IsExecutable)
      continue;

    if (binary.IsVDSO) {
      //
      // check that the VDSO hasn't changed
      //
      void *vdso;
      unsigned n;

      std::tie(vdso, n) = GetVDSO();

      if (vdso && n > 0) {
        if (binary.Data.size() != n ||
            memcmp(&binary.Data[0], vdso, binary.Data.size())) {
          HumanOut() << "[vdso] has changed\n";
          return 1;
        }
      }
    } else {
      llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> FileOrErr =
          llvm::MemoryBuffer::getFileOrSTDIN(binary.path_str());

      if (std::error_code EC = FileOrErr.getError()) {
        HumanOut() << llvm::formatv("failed to open binary {0}\n", binary.path_str());
        return 1;
      }

      std::unique_ptr<llvm::MemoryBuffer> &Buffer = FileOrErr.get();
      if (binary.Data.size() != Buffer->getBufferSize() ||
          memcmp(&binary.Data[0], Buffer->getBufferStart(), binary.Data.size())) {
        HumanOut() << llvm::formatv(
            "binary {0} has changed ; re-run jove-init?\n", binary.path_str());
        return 1;
      }
    }
  }

  llvm::Triple TheTriple;
  llvm::SubtargetFeatures Features;

  //
  // initialize state associated with every binary
  //
  for_each_binary(jv, [&](binary_t &binary) {
    binary_index_t BIdx = index_of_binary(binary, jv);

    // add to path -> index map
    if (binary.IsVDSO)
      BinPathToIdxMap["[vdso]"] = BIdx;
    else
      BinPathToIdxMap[binary.path_str()] = BIdx;

    binary_state_t &x = state.for_binary(binary);

    construct_fnmap(jv, binary, x.fnmap);
    construct_bbmap(jv, binary, x.bbmap);

    try {
      x.ObjectFile = CreateBinary(binary.data());
    } catch (const std::exception &) {
      if (!binary.IsVDSO)
        HumanOut() << llvm::formatv("failed to create binary for {0}\n",
                                    binary.path_str());
      return;
    }

    if (!llvm::isa<ELFO>(x.ObjectFile.get())) {
      HumanOut() << binary.path_str() << " is not ELF of expected type\n";
      return;
    }

    ELFO &O = *llvm::cast<ELFO>(x.ObjectFile.get());
    const ELFF &Elf = *O.getELFFile();

    loadDynamicTable(&Elf, &O, x._elf.DynamicTable);

    x._elf.OptionalDynSymRegion =
        loadDynamicSymbols(&Elf, &O,
                           x._elf.DynamicTable,
                           x._elf.DynamicStringTable,
                           x._elf.SymbolVersionSection,
                           x._elf.VersionMap);

    loadDynamicRelocations(&Elf, &O,
                           x._elf.DynamicTable,
                           x._elf.DynRelRegion,
                           x._elf.DynRelaRegion,
                           x._elf.DynRelrRegion,
                           x._elf.DynPLTRelRegion);

    TheTriple = O.makeTriple();
    Features = O.getFeatures();
  });

  BinFoundVec.resize(jv.Binaries.size());

#define INSTALL_SIG(sig)                                                       \
  do {                                                                         \
    struct sigaction sa;                                                       \
                                                                               \
    sigemptyset(&sa.sa_mask);                                                  \
    sa.sa_flags = SA_RESTART;                                                  \
    sa.sa_handler = SignalHandler;                                             \
                                                                               \
    if (::sigaction(sig, &sa, nullptr) < 0) {                                  \
      int err = errno;                                                         \
      HumanOut() << llvm::formatv("sigaction failed: {0}\n", strerror(err));   \
    }                                                                          \
  } while (0)

  INSTALL_SIG(SIGUSR1);
  INSTALL_SIG(SIGUSR2);
  INSTALL_SIG(SIGSEGV);
  INSTALL_SIG(SIGABRT);

  //
  // bootstrap has two modes of execution.
  //
  // (1) attach to existing process (--attach pid)
  // (2) create new process (PROG -- ARG_1 ARG_2 ... ARG_N)
  //
  if (pid_t child = opts.PID) {
    saved_child = child;

    //
    // mode 1: attach
    //
    if (::ptrace(PTRACE_ATTACH, child, 0UL, 0UL) < 0) {
      HumanOut() << llvm::formatv("PTRACE_ATTACH failed ({0})\n", strerror(errno));
      return 1;
    }

    //
    // since PTRACE_ATTACH succeeded, we know the tracee was sent a SIGSTOP.
    // wait on it.
    //
    if (IsVerbose())
      HumanOut() << "waiting for SIGSTOP...\n";

    {
      int status;
      do
        ::waitpid(-1, &status, __WALL);
      while (!WIFSTOPPED(status));
    }

    if (IsVerbose())
      HumanOut() << "waited on SIGSTOP.\n";

    {
      int ptrace_options = PTRACE_O_TRACESYSGOOD |
                        /* PTRACE_O_EXITKILL   | */
                           PTRACE_O_TRACEEXIT  |
                        /* PTRACE_O_TRACEEXEC  | */
                           PTRACE_O_TRACEFORK  |
                           PTRACE_O_TRACEVFORK |
                           PTRACE_O_TRACECLONE;

      if (::ptrace(PTRACE_SETOPTIONS, child, 0UL, ptrace_options) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("{0}: PTRACE_SETOPTIONS failed ({1})\n",
                                          __func__,
                                          strerror(err));
      }
    }

    return TracerLoop(child, tcg);
  } else {
    //
    // mode 2: create new process
    //
    int pipefd[2];
    if (::pipe(pipefd) < 0) { /* first, create a pipe */
      HumanOut() << "pipe(2) failed. bug?\n";
      return 1;
    }

    int rfd = pipefd[0];
    int wfd = pipefd[1];

    child = ::fork();
    if (!child) {
      {
        int rc = ::close(rfd);
        assert(!(rc < 0));
      }

      //
      // make pipe close-on-exec
      //
      {
        int rc = ::fcntl(wfd, F_SETFD, FD_CLOEXEC);
        assert(!(rc < 0));
      }

      return ChildProc(wfd);
    }

    saved_child = child;
    IgnoreCtrlC();

    {
      int rc = ::close(wfd);
      assert(!(rc < 0));
    }

    //
    // observe the (initial) signal-delivery-stop
    //
    if (IsVerbose())
      HumanOut() << "parent: waiting for initial stop of child " << child
                       << "...\n";

    {
      int status;
      do
        ::waitpid(child, &status, 0);
      while (!WIFSTOPPED(status));
    }

    if (IsVerbose())
      HumanOut() << "parent: initial stop observed\n";

    {
      //
      // trace exec for the following
      //
      int ptrace_options = PTRACE_O_TRACESYSGOOD |
                        /* PTRACE_O_EXITKILL   | */
                           PTRACE_O_TRACEEXIT  |
                           PTRACE_O_TRACEEXEC  | /* needs to be set here */
                           PTRACE_O_TRACEFORK  |
                           PTRACE_O_TRACEVFORK |
                           PTRACE_O_TRACECLONE;

      if (::ptrace(PTRACE_SETOPTIONS, child, 0UL, ptrace_options) < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("{0}: PTRACE_SETOPTIONS failed ({1})\n",
                                          __func__,
                                          strerror(err));
      }
    }

    //
    // allow the child to make progress (most importantly, execve)
    //
    if (::ptrace(PTRACE_CONT, child, 0UL, 0UL) < 0) {
      int err = errno;
      HumanOut() << llvm::formatv("failed to resume tracee! {0}", err);
      return 1;
    }

    //
    // "If a process attempts to read from an empty pipe, then read(2) will
    // block until data is available."
    //
    {
      ssize_t ret;
      do {
        uint8_t byte;
        ret = ::read(rfd, &byte, 1);
      } while (!(ret <= 0));

      /* if we got here, the other end of the pipe must have been closed,
       * most likely by close-on-exec */
      ::close(rfd);
    }

    return TracerLoop(-1, tcg);
  }
}

uintptr_t BootstrapTool::va_of_rva(uintptr_t Addr, binary_index_t BIdx) {
  binary_t &binary = jv.Binaries.at(BIdx);

  if (!BinFoundVec.test(BIdx))
    throw std::runtime_error(std::string(__func__) + ": given binary (" +
                             binary.path_str() + " is not loaded\n");

  if (!binary.IsPIC) {
    assert(binary.IsExecutable);
    return Addr;
  }

  return Addr + (state.for_binary(binary).LoadAddr - state.for_binary(binary).LoadOffset);
}

uintptr_t BootstrapTool::rva_of_va(uintptr_t Addr, binary_index_t BIdx) {
  binary_t &binary = jv.Binaries.at(BIdx);

  if (!BinFoundVec.test(BIdx))
    throw std::runtime_error(std::string(__func__) + ": given binary (" +
                             binary.path_str() + " is not loaded\n");

  if (!binary.IsPIC) {
    assert(binary.IsExecutable);
    return Addr;
  }

  return Addr - (state.for_binary(binary).LoadAddr - state.for_binary(binary).LoadOffset);
}

#if !defined(__x86_64__) && defined(__i386__)
static uintptr_t segment_address_of_selector(pid_t, unsigned segsel);
#endif

#if defined(__mips64) || defined(__mips__) || defined(__arm__)
typedef struct pt_regs cpu_state_t;
#else
typedef struct user_regs_struct cpu_state_t;
#endif

static void _ptrace_get_cpu_state(pid_t, cpu_state_t &out);
static void _ptrace_set_cpu_state(pid_t, const cpu_state_t &in);

static std::string _ptrace_read_string(pid_t, uintptr_t addr);

static unsigned long _ptrace_peekdata(pid_t, uintptr_t addr);
static void _ptrace_pokedata(pid_t, uintptr_t addr, unsigned long data);

static constexpr auto &pc_of_cpu_state(cpu_state_t &cpu_state) {
  return cpu_state.
#if defined(__x86_64__)
      rip
#elif defined(__i386__)
      eip
#elif defined(__aarch64__)
      pc
#elif defined(__arm__)
      uregs[15]
#elif defined(__mips64) || defined(__mips__)
      cp0_epc
#else
#error
#endif
      ;
}

int BootstrapTool::TracerLoop(pid_t child, tiny_code_generator_t &tcg) {
  siginfo_t si;
  long sig = 0;

  bool FirstTime = true;

  try {
    for (;;) {
      if (likely(!(child < 0))) {
        if (unlikely(::ptrace(opts.Syscalls || unlikely(!BinFoundVec.all())
                                ? PTRACE_SYSCALL
                                : PTRACE_CONT,
                            child, nullptr, reinterpret_cast<void *>(sig)) < 0))
          HumanOut() << "failed to resume tracee : " << strerror(errno)
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
      child = ::waitpid(-1, &status, __WALL);

      if (unlikely(child < 0)) {
        int err = errno;
        if (err == EINTR)
          continue;

        if (IsVerbose())
          HumanOut() << llvm::formatv("exiting... ({0})\n", strerror(err));
        break;
      }

      _child = child; /* XXX */

      if (likely(WIFSTOPPED(status))) {
        //
        // this is an opportunity to examine the state of the tracee
        //

        if (unlikely(FirstTime)) { /* is this the first ptrace-stop? */
          FirstTime = false;

          //
          // do *not* have ptrace option PTRACE_O_TRACEEXEC set
          //
          int ptrace_options = PTRACE_O_TRACESYSGOOD |
                            /* PTRACE_O_EXITKILL   | */
                               PTRACE_O_TRACEEXIT  |
                            /* PTRACE_O_TRACEEXEC  | */
                               PTRACE_O_TRACEFORK  |
                               PTRACE_O_TRACEVFORK |
                               PTRACE_O_TRACECLONE;

          if (::ptrace(PTRACE_SETOPTIONS, child, 0UL, ptrace_options) < 0) {
            int err = errno;
            HumanOut() << llvm::formatv("{0}: PTRACE_SETOPTIONS failed ({1})\n",
                                        __func__,
                                        strerror(err));
          }
        }

        if (unlikely(ToggleTurbo.load())) {
          ToggleTurbo.store(false);

          if (!TurboToggle) {
            HumanOut() << __ANSI_BOLD_GREEN "TURBO ON" __ANSI_NORMAL_COLOR "\n";

            for (const auto &Entry : RetMap) {
              uintptr_t Addr  = Entry.first;
              const auto &Ret = Entry.second;

              // write the word back
              try {
                _ptrace_pokedata(child, Addr, Ret.words[0]);
              } catch (...) {
                ;
              }
            }

            for (const auto &Entry : IndBrMap) {
              uintptr_t Addr  = Entry.first;
              const auto &Jmp = Entry.second;

              // write the word back
              try {
                _ptrace_pokedata(child, Addr, Jmp.words[0]);
              } catch (...) {
                ;
              }
            }

            for (const auto &Entry : BrkMap) {
              uintptr_t Addr = Entry.first;
              const auto &Brk = Entry.second;

              // write the word back
              try {
                _ptrace_pokedata(child, Addr, Brk.words[0]);
              } catch (...) {
                ;
              }
            }
          } else {
            HumanOut() << __ANSI_BOLD_RED "TURBO OFF" __ANSI_NORMAL_COLOR "\n";

            for (const auto &Entry : RetMap) {
              uintptr_t Addr  = Entry.first;
              const auto &Ret = Entry.second;

              // write the word back
              try {
                _ptrace_pokedata(child, Addr, Ret.words[1]);
              } catch (...) {
                ;
              }
            }

            for (const auto &Entry : IndBrMap) {
              uintptr_t Addr  = Entry.first;
              const auto &Jmp = Entry.second;

              // write the word back
              try {
                _ptrace_pokedata(child, Addr, Jmp.words[1]);
              } catch (...) {
                ;
              }
            }

            for (const auto &Entry : BrkMap) {
              uintptr_t Addr = Entry.first;
              const auto &Brk = Entry.second;

              // write the word back
              try {
                _ptrace_pokedata(child, Addr, Brk.words[1]);
              } catch (...) {
                ;
              }
            }
          }

          TurboToggle ^= 1;
        }

        rendezvous_with_dynamic_linker(child);

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
          child_syscall_state_t &syscall_state = children_syscall_state[child];

          cpu_state_t cpu_state;
          _ptrace_get_cpu_state(child, cpu_state);

          long pc = pc_of_cpu_state(cpu_state);
          long ra =
#if defined(__mips64) || defined(__mips__)
              cpu_state.regs[31]
#else
              0
#endif
              ;

          //
          // determine whether this syscall is entering or has exited
          //
#if defined(__arm__)
          unsigned dir = cpu_state.uregs[12]; /* unambiguous */
#else
          unsigned dir = syscall_state.dir;

          if (syscall_state.pc != pc)
            dir = 0; /* we must see the same pc twice */
#endif

          if (dir == 0 /* enter */) {
            //
            // syscall # and arguments
            //
#if defined(__x86_64__)
            long no = cpu_state.orig_rax;
            long a1 = cpu_state.rdi;
            long a2 = cpu_state.rsi;
            long a3 = cpu_state.rdx;
            long a4 = cpu_state.r10;
            long a5 = cpu_state.r8;
            long a6 = cpu_state.r9;
#elif defined(__i386__)
            long no = cpu_state.orig_eax;
            long a1 = cpu_state.ebx;
            long a2 = cpu_state.ecx;
            long a3 = cpu_state.edx;
            long a4 = cpu_state.esi;
            long a5 = cpu_state.edi;
            long a6 = cpu_state.ebp;
#elif defined(__aarch64__)
            long no = cpu_state.regs[8];
            long a1 = cpu_state.regs[0];
            long a2 = cpu_state.regs[1];
            long a3 = cpu_state.regs[2];
            long a4 = cpu_state.regs[3];
            long a5 = cpu_state.regs[4];
            long a6 = cpu_state.regs[5];
#elif defined(__mips64) || defined(__mips__)
            long no = cpu_state.regs[2];
            long a1 = cpu_state.regs[4];
            long a2 = cpu_state.regs[5];
            long a3 = cpu_state.regs[6];
            long a4 = cpu_state.regs[7];
            long a5;
            long a6;
            try {
              a5 = _ptrace_peekdata(child, cpu_state.regs[29 /* sp */] + 16);
              a6 = _ptrace_peekdata(child, cpu_state.regs[29 /* sp */] + 20);
            } catch (const std::exception &e) {
              HumanOut() << llvm::formatv(
                  "{0}: couldn't read arguments 5 and 6: {1}\n", __func__,
                  e.what());

              a5 = 0;
              a6 = 0;
            }
#else
#error
#endif

            syscall_state.no = no;
            syscall_state.a1 = a1;
            syscall_state.a2 = a2;
            syscall_state.a3 = a3;
            syscall_state.a4 = a4;
            syscall_state.a5 = a5;
            syscall_state.a6 = a6;

            auto on_syscall_enter = [&](void) -> void {
              switch (no) {
              case __NR_exit:
              case __NR_exit_group:
                if (IsVerbose())
                  HumanOut() << "Observed program exit.\n";
                harvest_reloc_targets(child, tcg);
                break;

              default:
                break;
              }
            };

            try {
              on_syscall_enter();
            } catch (const std::exception &e) {
              ;
            }
          } else { /* exit */
#if defined(__mips64) || defined(__mips__)
            long r7 = cpu_state.regs[7];
            long r2 = cpu_state.regs[2];
#endif

            long ret =
#if defined(__x86_64__)
                cpu_state.rax
#elif defined(__i386__)
                cpu_state.eax
#elif defined(__aarch64__)
                cpu_state.regs[0]
#elif defined(__arm__)
                cpu_state.uregs[0]
#elif defined(__mips64) || defined(__mips__)
                r7 && r2 > 0 ? -r2 : r2
#else
#error
#endif
                ;

            long no = syscall_state.no;

            long a1 = syscall_state.a1;
            long a2 = syscall_state.a2;
            long a3 = syscall_state.a3;
            long a4 = syscall_state.a4;
            long a5 = syscall_state.a5;
            long a6 = syscall_state.a6;

            auto on_syscall_exit = [&](void) -> void {
              if (unlikely(ret < 0 && ret > -4096))
                return; /* system call probably failed */

              switch (no) {
#ifdef __NR_rt_sigaction
              case __NR_rt_sigaction: {
                if (IsVerbose())
                  HumanOut() << llvm::formatv(
                      "rt_sigaction({0}, {1:x}, {2:x}, {3})\n", a1, a2, a3, a4);

                uintptr_t act = a2;
                if (act) {
                  constexpr unsigned handler_offset =
#if defined(__mips__)
                      4
#else
                      0
#endif
                      ;
                  uintptr_t handler = _ptrace_peekdata(child, act + handler_offset);

                  if (IsVerbose())
                    HumanOut() << llvm::formatv(
                        "on rt_sigaction(): handler={0:x}\n", handler);

                  if (handler && (void *)handler != SIG_IGN) {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
                    handler &= ~1UL;
#endif

                    update_view_of_virtual_memory(child);

                    auto it = AddressSpace.find(handler);
                    if (it != AddressSpace.end()) {
                      binary_index_t BIdx = -1+(*it).second;
                      binary_t &b = jv.Binaries[BIdx];

                      unsigned brkpt_count = 0;

                      basic_block_index_t entrybb_idx = E.explore_basic_block(
                          b, *state.for_binary(b).ObjectFile,
                          rva_of_va(handler, BIdx),
                          state.for_binary(b).fnmap,
                          state.for_binary(b).bbmap,
                          std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));

                      if (is_basic_block_index_valid(entrybb_idx)) {
                        function_index_t FIdx = E.explore_function(
                            b, *state.for_binary(b).ObjectFile,
                            rva_of_va(handler, BIdx),
                            state.for_binary(b).fnmap,
                            state.for_binary(b).bbmap,
                            std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));

                        if (is_function_index_valid(FIdx)) {
                          b.Analysis.Functions[FIdx].IsSignalHandler = true;
                          b.Analysis.Functions[FIdx].IsABI = true;
                        } else {
                          HumanOut() << llvm::formatv(
                              "on rt_sigaction(): failed to translate handler {0}\n",
                              description_of_program_counter(handler));
                        }
                      }
                    } else {
                      HumanOut() << llvm::formatv(
                          "on rt_sigaction(): handler {0} in unknown binary\n",
                          description_of_program_counter(handler, true));
                    }
                  }
                }

                break;
              }
#endif

              default:
                break;
              }
            };

            try {
              on_syscall_exit();
            } catch (const std::exception &e) {
              ;
            }
          }

          dir ^= 1;

          syscall_state.pc = pc;
          syscall_state.dir = dir;

          if (unlikely(opts.PrintLinkMap))
            scan_rtld_link_map(child, tcg);

          if (unlikely(!BinFoundVec.all()))
            update_view_of_virtual_memory(child);
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
              if (opts.PrintPtraceEvents)
                HumanOut() << "ptrace event (PTRACE_EVENT_VFORK) [" << child
                           << "]\n";
              break;
            case PTRACE_EVENT_FORK:
              if (opts.PrintPtraceEvents)
                HumanOut() << "ptrace event (PTRACE_EVENT_FORK) [" << child
                           << "]\n";
              break;
            case PTRACE_EVENT_CLONE: {
              pid_t new_child;
              ::ptrace(PTRACE_GETEVENTMSG, child, nullptr, &new_child);

              if (opts.PrintPtraceEvents)
                HumanOut() << "ptrace event (PTRACE_EVENT_CLONE) -> "
                           << new_child << " [" << child << "]\n";
              break;
            }
            case PTRACE_EVENT_VFORK_DONE:
              if (opts.PrintPtraceEvents)
                HumanOut() << "ptrace event (PTRACE_EVENT_VFORK_DONE) ["
                           << child << "]\n";
              break;
            case PTRACE_EVENT_EXEC:
              if (opts.PrintPtraceEvents)
                HumanOut() << "ptrace event (PTRACE_EVENT_EXEC) [" << child
                           << "]\n";
              break;
            case PTRACE_EVENT_EXIT:
              if (opts.PrintPtraceEvents)
                HumanOut() << "ptrace event (PTRACE_EVENT_EXIT) [" << child
                           << "]\n";

              if (child == saved_child) {
                if (IsVerbose())
                  HumanOut() << "Observed program exit.\n";
                harvest_reloc_targets(child, tcg);
              }
              break;
            case PTRACE_EVENT_STOP:
              if (opts.PrintPtraceEvents)
                HumanOut() << "ptrace event (PTRACE_EVENT_STOP) [" << child
                           << "]\n";
              break;
            case PTRACE_EVENT_SECCOMP:
              if (opts.PrintPtraceEvents)
                HumanOut() << "ptrace event (PTRACE_EVENT_SECCOMP) [" << child
                           << "]\n";
              break;
            }
          } else {
            try {
              on_breakpoint(child, tcg);
            } catch (const std::exception &e) {
              /* TODO rate-limit */
              HumanOut() << llvm::formatv(
                  "{0}: on_breakpoint failed: {1}\n", __func__, e.what());
            }
          }
        } else if (::ptrace(PTRACE_GETSIGINFO, child, 0UL, &si) < 0) {
          //
          // (3) group-stop
          //

          if (opts.PrintPtraceEvents)
            HumanOut() << "ptrace group-stop [" << child << "]\n";

          // When restarting a tracee from a ptrace-stop other than
          // signal-delivery-stop, recommended practice is to always pass 0 in
          // sig.
        } else {
          //
          // (4) signal-delivery-stop
          //

          // deliver it
          sig = stopsig;

#if defined(__mips64) || defined(__mips__)
          //
          // recognize the 'jr $zero' hack. This trickery is to avoid emulating
          // the delay slot instruction of a return instruction.
          //
          if (stopsig == SIGSEGV) {
            cpu_state_t cpu_state;
            _ptrace_get_cpu_state(child, cpu_state);

            if (cpu_state.cp0_epc == 0) {
              //
              // from here on out we are assuming a 'jr $ra' was replaced with
              // 'jr $zero', so we simply set the program counter to the return
              // address register.
              //
              uintptr_t RetAddr = cpu_state.regs[31 /* ra */];

              cpu_state.cp0_epc = RetAddr;
              _ptrace_set_cpu_state(child, cpu_state);

              sig = 0; /* suppress */

              on_return(child, 0 /* XXX */, RetAddr, tcg);
            }
          }
#endif

          if (sig && opts.Signals)
            HumanOut() << llvm::formatv("delivering signal {0} <{1}> [{2}]\n",
                                        sig, strsignal(sig), child);
        }
      } else {
        //
        // the child terminated
        //
        if (opts.VeryVerbose)
          HumanOut() << "child " << child << " terminated\n";

        child = -1;
      }
    }
  } catch (const std::exception &e) {
    std::string what(e.what());
    HumanOut() << llvm::formatv("exception! {0}\n", what);
  }

  IgnoreCtrlC(); /* user probably doesn't want to interrupt the following */

  {
    //
    // fix ambiguous indirect jumps. why do we do this here? because this
    // process involves removing edges from the graph, which can be messy.
    //
    unsigned NumChanged = 0;

    for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
      auto &b = jv.Binaries[BIdx];
      auto &ICFG = b.Analysis.ICFG;

      auto fix_ambiguous_indirect_jumps = [&](void) -> bool {
        icfg_t::vertex_iterator vi, vi_end;
        for (std::tie(vi, vi_end) = boost::vertices(ICFG); vi != vi_end; ++vi) {
          basic_block_t bb = *vi;

          if (ICFG[bb].Term.Type != TERMINATOR::INDIRECT_JUMP)
            continue;

          if (IsAmbiguousIndirectJump(ICFG, bb)) {
            //
            // we thought this was a goto, but now we know it's definitely a tail call.
            // translate all sucessors as functions, then store them into the dynamic
            // targets set for this bb. afterwards, delete the edges in the ICFG that
            // would originate from this basic block.
            //
            icfg_t::out_edge_iterator e_it, e_it_end;
            for (std::tie(e_it, e_it_end) = boost::out_edges(bb, ICFG);
                 e_it != e_it_end; ++e_it) {
              control_flow_t cf(*e_it);

              basic_block_t succ = boost::target(cf, ICFG);

              unsigned brkpt_count = 0;
              function_index_t FIdx = E.explore_function(
                  b, *state.for_binary(b).ObjectFile,
                  ICFG[succ].Addr,
                  state.for_binary(b).fnmap,
                  state.for_binary(b).bbmap,
                  std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));
              assert(is_function_index_valid(FIdx));
              ICFG[bb].insertDynTarget({BIdx, FIdx}, Alloc);

              (void)brkpt_count;
            }

            boost::clear_out_edges(bb, ICFG);
            return true;
          }
        }

        return false;
      };

      while (fix_ambiguous_indirect_jumps())
        ++NumChanged;
    }

    if (unlikely(NumChanged)) {
      jv.InvalidateFunctionAnalyses();

      HumanOut() << llvm::formatv(
          "fixed {0} ambiguous indirect jump{1}\n", NumChanged,
          NumChanged > 1 ? "s" : "");
    }
  }

  if (invalidateAnalyses)
    jv.InvalidateFunctionAnalyses(); /* FIXME */

  return 0;
}

void BootstrapTool::on_new_basic_block(binary_t &b, basic_block_t bb) {
  binary_index_t BIdx = index_of_binary(b, jv);
  auto &ICFG = b.Analysis.ICFG;
  const basic_block_properties_t &bbprop = ICFG[bb];

  //
  // if it's an indirect branch, we need to (1) add it to the indirect branch
  // map and (2) install a breakpoint at the correct program counter
  //
  if (bbprop.Term.Type == TERMINATOR::INDIRECT_CALL ||
      bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP) {
    uintptr_t termpc = va_of_rva(bbprop.Term.Addr, BIdx);

    assert(IndBrMap.find(termpc) == IndBrMap.end());

    indirect_branch_t &indbr = IndBrMap[termpc];
    indbr.IsCall = bbprop.Term.Type == TERMINATOR::INDIRECT_CALL;
    indbr.BIdx = BIdx;
    indbr.TermAddr = bbprop.Term.Addr;
    indbr.InsnBytes.resize(bbprop.Size - (bbprop.Term.Addr - bbprop.Addr));
#if defined(__mips64) || defined(__mips__)
    indbr.InsnBytes.resize(indbr.InsnBytes.size() + 4 /* delay slot */);
    assert(indbr.InsnBytes.size() == 2 * sizeof(uint32_t));
#endif

    assert(state.for_binary(b).ObjectFile.get());
    const ELFF &Elf = *llvm::cast<ELFO>(state.for_binary(b).ObjectFile.get())->getELFFile();

    llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(bbprop.Term.Addr);
    if (!ExpectedPtr)
      abort();

    memcpy(&indbr.InsnBytes[0], *ExpectedPtr, indbr.InsnBytes.size());

    //
    // now that we have the bytes for each indirect branch, disassemble them
    //
    llvm::MCInst &Inst = indbr.Inst;

    {
      uint64_t InstLen;
      bool Disassembled = disas.DisAsm->getInstruction(
          Inst, InstLen, indbr.InsnBytes, bbprop.Term.Addr, llvm::nulls());
      assert(Disassembled);
    }

#if defined(__mips64) || defined(__mips__)
    {
      uint64_t InstLen;
      bool Disassembled = disas.DisAsm->getInstruction(
          indbr.DelaySlotInst, InstLen,
          llvm::ArrayRef<uint8_t>(indbr.InsnBytes).slice(4),
          bbprop.Term.Addr + 4, llvm::nulls());
      assert(Disassembled);
    }
#endif

    try {
      place_breakpoint_at_indirect_branch(_child, termpc, indbr);
    } catch (const std::exception &e) {
      HumanOut() << llvm::formatv("failed to place breakpoint: {0}\n", e.what());
    }
  }

  //
  // if it's a return, we need to (1) add it to the return map and (2) install
  // a breakpoint at the correct pc
  //
  if (bbprop.Term.Type == TERMINATOR::RETURN) {
    uintptr_t termpc = va_of_rva(bbprop.Term.Addr, BIdx);

    assert(RetMap.find(termpc) == RetMap.end());

    return_t &RetInfo = RetMap[termpc];
    RetInfo.BIdx = BIdx;
    RetInfo.TermAddr = bbprop.Term.Addr;

    RetInfo.InsnBytes.resize(bbprop.Size - (bbprop.Term.Addr - bbprop.Addr));
#if defined(__mips64) || defined(__mips__)
    RetInfo.InsnBytes.resize(RetInfo.InsnBytes.size() + 4 /* delay slot */);
    assert(RetInfo.InsnBytes.size() == sizeof(uint64_t));
#endif

    assert(state.for_binary(b).ObjectFile.get());
    const ELFF &Elf = *llvm::cast<ELFO>(state.for_binary(b).ObjectFile.get())->getELFFile();

    llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(bbprop.Term.Addr);
    if (!ExpectedPtr)
      abort();

    memcpy(&RetInfo.InsnBytes[0], *ExpectedPtr, RetInfo.InsnBytes.size());

    {
      uint64_t InstLen;
      bool Disassembled =
          disas.DisAsm->getInstruction(RetInfo.Inst, InstLen, RetInfo.InsnBytes,
                                       bbprop.Term.Addr, llvm::nulls());
      assert(Disassembled);
    }

#if defined(__mips64) || defined(__mips__)
    //
    // disassemble delay slot
    //
    {
      uint64_t InstLen;
      bool Disassembled = disas.DisAsm->getInstruction(
          RetInfo.DelaySlotInst, InstLen,
          llvm::ArrayRef<uint8_t>(RetInfo.InsnBytes).slice(4),
          bbprop.Term.Addr + 4, llvm::nulls());
      assert(Disassembled);
    }
#endif

    try {
      place_breakpoint_at_return(_child, termpc, RetInfo);
    } catch (const std::exception &e) {
      HumanOut() << llvm::formatv("failed to place breakpoint at return: {0}\n", e.what());
    }
  }
}

static std::string StringOfMCInst(llvm::MCInst &, disas_t &);

#if defined(__mips64) || defined(__mips__)
unsigned reg_of_idx(unsigned idx) {
  switch (idx) {
    case 0:    return llvm::Mips::ZERO;
    case 1:    return llvm::Mips::AT;
    case 2:    return llvm::Mips::V0;
    case 3:    return llvm::Mips::V1;
    case 4:    return llvm::Mips::A0;
    case 5:    return llvm::Mips::A1;
    case 6:    return llvm::Mips::A2;
    case 7:    return llvm::Mips::A3;
    case 8:    return llvm::Mips::T0;
    case 9:    return llvm::Mips::T1;
    case 10:   return llvm::Mips::T2;
    case 11:   return llvm::Mips::T3;
    case 12:   return llvm::Mips::T4;
    case 13:   return llvm::Mips::T5;
    case 14:   return llvm::Mips::T6;
    case 15:   return llvm::Mips::T7;
    case 16:   return llvm::Mips::S0;
    case 17:   return llvm::Mips::S1;
    case 18:   return llvm::Mips::S2;
    case 19:   return llvm::Mips::S3;
    case 20:   return llvm::Mips::S4;
    case 21:   return llvm::Mips::S5;
    case 22:   return llvm::Mips::S6;
    case 23:   return llvm::Mips::S7;
    case 24:   return llvm::Mips::T8;
    case 25:   return llvm::Mips::T9;
    case 26:   return llvm::Mips::K0;
    case 27:   return llvm::Mips::K1;
    case 28:   return llvm::Mips::GP;
    case 29:   return llvm::Mips::SP;
    case 30:   return llvm::Mips::FP;
    case 31:   return llvm::Mips::RA;

    default:
      __builtin_trap();
      __builtin_unreachable();
  }
}
uint32_t code_cave_idx_of_reg(unsigned r) {
  switch (r) {
    case llvm::Mips::ZERO: return 0;
    case llvm::Mips::AT:   return 1;
    case llvm::Mips::V0:   return 2;
    case llvm::Mips::V1:   return 3;
    case llvm::Mips::A0:   return 4;
    case llvm::Mips::A1:   return 5;
    case llvm::Mips::A2:   return 6;
    case llvm::Mips::A3:   return 7;
    case llvm::Mips::T0:   return 8;
    case llvm::Mips::T1:   return 9;
    case llvm::Mips::T2:   return 10;
    case llvm::Mips::T3:   return 11;
    case llvm::Mips::T4:   return 12;
    case llvm::Mips::T5:   return 13;
    case llvm::Mips::T6:   return 14;
    case llvm::Mips::T7:   return 15;
    case llvm::Mips::S0:   return 16;
    case llvm::Mips::S1:   return 17;
    case llvm::Mips::S2:   return 18;
    case llvm::Mips::S3:   return 19;
    case llvm::Mips::S4:   return 20;
    case llvm::Mips::S5:   return 21;
    case llvm::Mips::S6:   return 22;
    case llvm::Mips::S7:   return 23;
    case llvm::Mips::T8:   return 24;
    case llvm::Mips::T9:   return 25;
    case llvm::Mips::K0:   return 26;
    case llvm::Mips::K1:   return 27;
    case llvm::Mips::GP:   return 28;
    case llvm::Mips::SP:   return 29;
    case llvm::Mips::FP:   return 30;
    case llvm::Mips::RA:   return 31;

    default:
      __builtin_trap();
      __builtin_unreachable();
  }
}
uint32_t encoding_of_jump_to_reg(unsigned r) {
  switch (r) {
    case llvm::Mips::ZERO: return 0x00000008;
    case llvm::Mips::AT:   return 0x00200008;
    case llvm::Mips::V0:   return 0x00400008;
    case llvm::Mips::V1:   return 0x00600008;
    case llvm::Mips::A0:   return 0x00800008;
    case llvm::Mips::A1:   return 0x00a00008;
    case llvm::Mips::A2:   return 0x00c00008;
    case llvm::Mips::A3:   return 0x00e00008;
    case llvm::Mips::T0:   return 0x01000008;
    case llvm::Mips::T1:   return 0x01200008;
    case llvm::Mips::T2:   return 0x01400008;
    case llvm::Mips::T3:   return 0x01600008;
    case llvm::Mips::T4:   return 0x01800008;
    case llvm::Mips::T5:   return 0x01a00008;
    case llvm::Mips::T6:   return 0x01c00008;
    case llvm::Mips::T7:   return 0x01e00008;
    case llvm::Mips::S0:   return 0x02000008;
    case llvm::Mips::S1:   return 0x02200008;
    case llvm::Mips::S2:   return 0x02400008;
    case llvm::Mips::S3:   return 0x02600008;
    case llvm::Mips::S4:   return 0x02800008;
    case llvm::Mips::S5:   return 0x02a00008;
    case llvm::Mips::S6:   return 0x02c00008;
    case llvm::Mips::S7:   return 0x02e00008;
    case llvm::Mips::T8:   return 0x03000008;
    case llvm::Mips::T9:   return 0x03200008;
    case llvm::Mips::K0:   return 0x03400008;
    case llvm::Mips::K1:   return 0x03600008;
    case llvm::Mips::GP:   return 0x03800008;
    case llvm::Mips::SP:   return 0x03a00008;
    case llvm::Mips::FP:   return 0x03c00008;
    case llvm::Mips::RA:   return 0x03e00008;

    default:
      __builtin_trap();
      __builtin_unreachable();
  }
}
#endif

static void arch_put_breakpoint(void *code);

void BootstrapTool::place_breakpoint_at_indirect_branch(pid_t child,
                                                        uintptr_t Addr,
                                                        indirect_branch_t &indbr) {
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
#elif defined(__mips64) || defined(__mips__)
    return opc == llvm::Mips::JALR
        || opc == llvm::Mips::JR;
#else
#error
#endif
  };

  if (!is_opcode_handled(Inst.getOpcode())) {
    binary_t &Binary = jv.Binaries[indbr.BIdx];
    const auto &ICFG = Binary.Analysis.ICFG;
    throw std::runtime_error(
      (fmt("could not place breakpoint @ %#lx\n"
           "%s BB %#lx\n"
           "%s")
       % Addr
       % Binary.path_str()
       % indbr.TermAddr
       % StringOfMCInst(Inst, disas)).str());
  }

  // read a word of the branch instruction
  unsigned long word = _ptrace_peekdata(child, Addr);

  indbr.words[0] = word;

  // insert breakpoint
  arch_put_breakpoint(&word);

  indbr.words[1] = word;

  // write the word back
  _ptrace_pokedata(child, Addr, word);

  if (opts.VeryVerbose)
    HumanOut() << (fmt("breakpoint placed @ %#lx") % Addr).str() << '\n';
}

void BootstrapTool::place_breakpoint(pid_t child, uintptr_t Addr,
                                     breakpoint_t &brk) {
  // read a word of the instruction
  unsigned long word = _ptrace_peekdata(child, Addr);

  brk.words[0] = word;

  arch_put_breakpoint(&word);

  brk.words[1] = word;

  // write the word back
  _ptrace_pokedata(child, Addr, word);

  if (opts.VeryVerbose)
    HumanOut() << (fmt("breakpoint placed @ %#lx") % Addr).str() << '\n';
}

void BootstrapTool::place_breakpoint_at_return(pid_t child, uintptr_t Addr,
                                               return_t &r) {
  // read a word of the instruction

  unsigned long word = _ptrace_peekdata(child, Addr);

  r.words[0] = word;

#if defined(__mips64) || defined(__mips__)
  //
  // by overwriting the return instruction with 'jr $zero' rather than the
  // conventional trap, we can get by without having to emulate the delay slot
  // instruction. hooray! the downside with this trick is that one piece of
  // information is lost: the program counter. for returns instructions, this
  // doesn't really matter.
  //
  ((uint32_t *)&word)[0] = encoding_of_jump_to_reg(llvm::Mips::ZERO);
#else
  arch_put_breakpoint(&word);
#endif

  r.words[1] = word;

  // write the word back
  _ptrace_pokedata(child, Addr, word);

  if (opts.VeryVerbose)
    HumanOut() << (fmt("breakpoint placed @ %#lx") % Addr).str() << '\n';
}

struct ScopedCPUState {
  pid_t child;
  cpu_state_t gpr;

  ScopedCPUState(pid_t child) : child(child) { _ptrace_get_cpu_state(child, gpr); }
  ~ScopedCPUState()                          { _ptrace_set_cpu_state(child, gpr); }
};

void BootstrapTool::on_breakpoint(pid_t child, tiny_code_generator_t &tcg) {
  ScopedCPUState  _scoped_cpu_state(child);

  auto &gpr = _scoped_cpu_state.gpr;
  auto &pc = pc_of_cpu_state(_scoped_cpu_state.gpr);

#if defined(__x86_64__) || defined(__i386__)
  //
  // rewind before the breakpoint instruction (why is this x86-specific?)
  //
  pc -= 1; /* int3 */
#endif

  //
  // lookup indirect branch info
  //
  const uintptr_t saved_pc = pc;

  //
  // define some helper functions for accessing the cpu state
  //
#if defined(__x86_64__)
  typedef unsigned long long RegValue_t;
#elif defined(__i386__)
  typedef long RegValue_t;
#elif defined(__aarch64__)
  typedef unsigned long long RegValue_t;
#elif defined(__mips64)
  typedef unsigned long RegValue_t;
#elif defined(__mips__)
  typedef unsigned long long RegValue_t;
#else
#error
#endif

#if defined(__i386__)
  struct {
    long ss;
    long cs;
    long ds;
    long es;
    long fs;
    long gs;
  } _hack; /* purely so we can take a reference to the segment fields */
#endif

  auto RegValue = [&](unsigned llreg) -> RegValue_t & {
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
      _hack.ss = segment_address_of_selector(child, gpr.xss);
      return _hack.ss;

    case llvm::X86::CS:
      _hack.cs = segment_address_of_selector(child, gpr.xcs);
      return _hack.cs;

    case llvm::X86::DS:
      _hack.ds = segment_address_of_selector(child, gpr.xds);
      return _hack.ds;

    case llvm::X86::ES:
      _hack.es = segment_address_of_selector(child, gpr.xes);
      return _hack.es;

    case llvm::X86::FS:
      _hack.fs = segment_address_of_selector(child, gpr.xfs);
      return _hack.fs;

    case llvm::X86::GS:
      _hack.gs = segment_address_of_selector(child, gpr.xgs);
      return _hack.gs;

#elif defined(__aarch64__)

#define __REG_CASE(n, i, data)                                                 \
  case BOOST_PP_CAT(llvm::AArch64::X, i):                                      \
    return gpr.regs[i];

BOOST_PP_REPEAT(29, __REG_CASE, void)

#undef __REG_CASE

#elif defined(__mips64) || defined(__mips__)

    case llvm::Mips::ZERO: assert(gpr.regs[0] == 0); return gpr.regs[0];
    case llvm::Mips::AT: return gpr.regs[1];
    case llvm::Mips::V0: return gpr.regs[2];
    case llvm::Mips::V1: return gpr.regs[3];
    case llvm::Mips::A0: return gpr.regs[4];
    case llvm::Mips::A1: return gpr.regs[5];
    case llvm::Mips::A2: return gpr.regs[6];
    case llvm::Mips::A3: return gpr.regs[7];
    case llvm::Mips::T0: return gpr.regs[8];
    case llvm::Mips::T1: return gpr.regs[9];
    case llvm::Mips::T2: return gpr.regs[10];
    case llvm::Mips::T3: return gpr.regs[11];
    case llvm::Mips::T4: return gpr.regs[12];
    case llvm::Mips::T5: return gpr.regs[13];
    case llvm::Mips::T6: return gpr.regs[14];
    case llvm::Mips::T7: return gpr.regs[15];
    case llvm::Mips::S0: return gpr.regs[16];
    case llvm::Mips::S1: return gpr.regs[17];
    case llvm::Mips::S2: return gpr.regs[18];
    case llvm::Mips::S3: return gpr.regs[19];
    case llvm::Mips::S4: return gpr.regs[20];
    case llvm::Mips::S5: return gpr.regs[21];
    case llvm::Mips::S6: return gpr.regs[22];
    case llvm::Mips::S7: return gpr.regs[23];
    case llvm::Mips::T8: return gpr.regs[24];
    case llvm::Mips::T9: return gpr.regs[25];


    case llvm::Mips::GP: return gpr.regs[28];
    case llvm::Mips::SP: return gpr.regs[29];
    case llvm::Mips::FP: return gpr.regs[30];
    case llvm::Mips::RA: return gpr.regs[31];

#else
#error
#endif

    default:
      throw std::runtime_error(
          (fmt("RegValue: unknown llreg %u\n") % llreg).str());
    }
  };

#if defined(__mips64) || defined(__mips__)
  auto emulate_delay_slot = [&](llvm::MCInst &I,
                                const std::vector<uint8_t> &InsnBytes,
                                unsigned reg) -> void {
    const unsigned opc = I.getOpcode();

    //
    // emulate delay slot instruction
    //
    switch (opc) {
    default: { /* fallback to code cave XXX */
      if (IsVerbose())
        HumanOut() << llvm::formatv("delayslot: {0} ({1})\n", I,
                                    StringOfMCInst(I, disas));

      assert(ExecutableRegionAddress);

      unsigned idx = code_cave_idx_of_reg(reg);
      uintptr_t jumpr_insn_addr = ExecutableRegionAddress +
                                  idx * (2 * sizeof(uint32_t));
      uintptr_t delay_slot_addr = jumpr_insn_addr  + sizeof(uint32_t);

      {
        uint32_t val = ((uint32_t *)InsnBytes.data())[1];
        _ptrace_pokedata(child, delay_slot_addr, val);
      }

      pc = jumpr_insn_addr;
      return;
    }

    case llvm::Mips::LW:
    case llvm::Mips::SW: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      auto &Reg = RegValue(I.getOperand(0).getReg());
      long Base = RegValue(I.getOperand(1).getReg());
      long Offs = I.getOperand(2).getImm();
      long Addr = Base + Offs;

      if (opc == llvm::Mips::LW)
        Reg = _ptrace_peekdata(child, Addr);
      else /* SW */
        _ptrace_pokedata(child, Addr, Reg);

      break;
    }

    case llvm::Mips::LB: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      auto &Reg = RegValue(I.getOperand(0).getReg());
      long Base = RegValue(I.getOperand(1).getReg());
      long Offs = I.getOperand(2).getImm();
      long Addr = Base + Offs;

      unsigned long word = _ptrace_peekdata(child, Addr);

      int8_t byte = *((int8_t *)&word);

      Reg = byte;
      break;
    }

    case llvm::Mips::LHu: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      long Base = RegValue(b);
      long Offs = I.getOperand(2).getImm();
      long Addr = Base + Offs;

      unsigned long word = _ptrace_peekdata(child, Addr);

      static_assert(sizeof(word) >= sizeof(uint16_t));

      RegValue(a) = static_cast<unsigned long>(((uint16_t *)&word)[0]);

      break;
    }

    case llvm::Mips::SH: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      int64_t Base = RegValue(b);
      int64_t Offs = I.getOperand(2).getImm();
      int64_t Addr = Base + Offs;

      unsigned long word = _ptrace_peekdata(child, Addr);
      ((uint16_t *)&word)[0] = RegValue(a);
      _ptrace_pokedata(child, Addr, word);

      break;
    }

    case llvm::Mips::OR: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      RegValue(a) = RegValue(b) | RegValue(c);
      break;
    }

    case llvm::Mips::ADDiu: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      unsigned long x = I.getOperand(2).getImm();

      RegValue(a) = static_cast<unsigned long>(RegValue(b)) + x;
      break;
    }

    case llvm::Mips::ADDu: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      RegValue(a) = static_cast<unsigned long>(RegValue(b)) +
                    static_cast<unsigned long>(RegValue(c));
      break;
    }

    case llvm::Mips::SUBu: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      RegValue(a) = static_cast<unsigned long>(RegValue(b)) -
                    static_cast<unsigned long>(RegValue(c));
      break;
    }

    case llvm::Mips::SLL: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      unsigned long x = I.getOperand(2).getImm();

      RegValue(a) = static_cast<unsigned long>(RegValue(b)) << x;
      break;
    }

    case llvm::Mips::SRL: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      unsigned long x = I.getOperand(2).getImm();

      RegValue(a) = static_cast<unsigned long>(RegValue(b)) >> x;
      break;
    }

    case llvm::Mips::MOVZ_I_I: {
      assert(I.getNumOperands() == 4);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());
      assert(I.getOperand(3).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();
      unsigned d = I.getOperand(3).getReg();

      WARN_ON(a != d);

      if (RegValue(c) == 0)
        RegValue(a) = RegValue(b);

      break;
    }

    case llvm::Mips::MFLO: {
      assert(I.getNumOperands() == 1);
      assert(I.getOperand(0).isReg());

      unsigned a = I.getOperand(0).getReg();

      RegValue(a) = gpr.lo;

      break;
    }

    case llvm::Mips::XOR: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      RegValue(a) = RegValue(b) ^ RegValue(c);

      break;
    }

    case llvm::Mips::LUi: {
      assert(I.getNumOperands() == 2);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isImm());

      unsigned a = I.getOperand(0).getReg();

      unsigned long x = I.getOperand(1).getImm();

      RegValue(a) = x << 16;

      break;
    }

    case llvm::Mips::AND: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      RegValue(a) = RegValue(b) & RegValue(c);

      break;
    }

    case llvm::Mips::MUL: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      int64_t x = RegValue(b);
      int64_t y = RegValue(c);
      int64_t z = x * y;

      RegValue(a) = ((uint32_t *)&z)[0];

      break;
    }

    case llvm::Mips::SLTu: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      unsigned long x = RegValue(b);
      unsigned long y = RegValue(c);

      RegValue(a) = x < y;
      break;
    }

    case llvm::Mips::SLTiu: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).isReg();
      unsigned b = I.getOperand(1).isReg();

      unsigned long x = I.getOperand(2).getImm();

      RegValue(a) = static_cast<unsigned long>(RegValue(b)) < x;
      break;
    }

    case llvm::Mips::SB: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      int64_t Base = RegValue(b);
      int64_t Offset = I.getOperand(2).getImm();
      int64_t Addr = Base + Offset;

      unsigned long word = _ptrace_peekdata(child, Addr);
      ((uint8_t *)&word)[0] = RegValue(a);
      _ptrace_pokedata(child, Addr, word);

      break;
    }

    case llvm::Mips::ORi: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      unsigned long x = I.getOperand(2).getImm();
      RegValue(a) = RegValue(b) | x;
      break;
    }

    case llvm::Mips::MOVN_I_I: {
      assert(I.getNumOperands() == 4);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());
      assert(I.getOperand(3).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();
      unsigned d = I.getOperand(3).getReg();

      WARN_ON(a != d);

      if (RegValue(c) != 0)
        RegValue(a) = RegValue(b);

      break;
    }

    case llvm::Mips::ANDi: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      unsigned long x = I.getOperand(2).getImm();

      RegValue(a) = RegValue(b) & x;

      break;
    }

    case llvm::Mips::NOP:
      break;
    }

    if (opts.VeryVerbose)
      HumanOut() << llvm::formatv("emudelayslot: {0} ({1})\n", I,
                                  StringOfMCInst(I, disas));

    uintptr_t target = RegValue(reg);

    target &= ~1UL;

    pc = target;
  };
#endif

  //
  // helper function to emulate a return instruction
  //
  auto emulate_return = [&](llvm::MCInst &Inst,
#if defined(__mips64) || defined(__mips__)
                            llvm::MCInst &DelaySlotInst,
#endif
                            const std::vector<uint8_t> &InsnBytes) -> void {
#if defined(__x86_64__)
    pc = _ptrace_peekdata(child, gpr.rsp);
    gpr.rsp += sizeof(uint64_t);
#elif defined(__i386__)
    pc = _ptrace_peekdata(child, gpr.esp);
    gpr.esp += sizeof(uint32_t);
#elif defined(__aarch64__)
    pc = gpr.regs[30] /* lr */;
#elif defined(__mips64) || defined(__mips__)
    assert(InsnBytes.size() == 2 * sizeof(uint32_t));

    if (!(Inst.getOpcode() == llvm::Mips::JR &&
          Inst.getNumOperands() == 1 &&
          Inst.getOperand(0).isReg() &&
          Inst.getOperand(0).getReg() == llvm::Mips::RA)) {
      HumanOut() << llvm::formatv(
          "emulate_return: expected jr $ra, instead {0} {1} @ {2}\n",
          Inst, StringOfMCInst(Inst, disas),
          description_of_program_counter(saved_pc, true));
    }

    emulate_delay_slot(DelaySlotInst, InsnBytes, llvm::Mips::RA);
#else
#error
#endif

#if defined(__x86_64__) || defined(__i386__)
    if (Inst.getNumOperands() > 0) {
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isImm());

      auto &sp =
#if defined(__x86_64__)
          gpr.rsp
#else
          gpr.esp
#endif
          ;

      sp += Inst.getOperand(0).getImm();
    }
#endif
  };

  //
  // is the dynamic linker doing something?
  //
  {
    if (unlikely(saved_pc == _r_debug.r_brk)) {
      if (IsVerbose()) {
        HumanOut() << llvm::formatv(
            "*_r_debug.r_brk [{0}]\n",
            description_of_program_counter(_r_debug.r_brk, true));
      }

      //
      // we assume that this is a 'ret' TODO verify this assumption
      //
      auto it = BrkMap.find(saved_pc);
      assert(it != BrkMap.end());
      breakpoint_t &brk = (*it).second;

      brk.callback(child, tcg, disas);

      try {
        emulate_return(brk.Inst,
#if defined(__mips64) || defined(__mips__)
                       brk.DelaySlotInst,
#endif
                       brk.InsnBytes);
      } catch (const std::exception &e) {
        HumanOut() << llvm::formatv("failed to emulate return: {0}\n", e.what());
      }
      return;
    }
  }

  //
  // is it a return?
  //
  {
    auto it = RetMap.find(saved_pc);
    if (it != RetMap.end()) {
      return_t &ret = (*it).second;

      try {
        emulate_return(ret.Inst,
#if defined(__mips64) || defined(__mips__)
                       ret.DelaySlotInst,
#endif
                       ret.InsnBytes);
      } catch (const std::exception &e) {
        HumanOut() << llvm::formatv("failed to emulate return: {0}\n", e.what());
      }

      try {
        on_return(child, saved_pc, pc, tcg);
      } catch (const std::exception &e) {
        HumanOut() << llvm::formatv("{0} failed: {1}\n", __func__, e.what());
      }
      return;
    }
  }

  //
  // is it a one-shot breakpoint?
  //
  {
    auto it = BrkMap.find(saved_pc);
    if (it != BrkMap.end()) {
      breakpoint_t &brk = (*it).second;
      brk.callback(child, tcg, disas);

      if (IsVerbose())
        HumanOut() << llvm::formatv("one-shot breakpoint hit @ {0}\n",
                                      description_of_program_counter(saved_pc));

      try {
        _ptrace_pokedata(child, saved_pc, brk.words[0]);
      } catch (const std::exception &e) {
        HumanOut() << "failed restoring breakpoint instruction bytes\n";
      }

      return;
    }
  }

  auto indirect_branch_of_address = [&](uintptr_t addr) -> indirect_branch_t & {
    auto it = IndBrMap.find(addr);
    if (it == IndBrMap.end()) {
      update_view_of_virtual_memory(child);

      throw std::runtime_error("unknown breakpoint @ " +
                               description_of_program_counter(addr, true));
    }

    return (*it).second;
  };

  //
  // it's an indirect branch.
  //
  indirect_branch_t &IndBrInfo = indirect_branch_of_address(saved_pc);
  binary_t &binary = jv.Binaries[IndBrInfo.BIdx];
  auto &bbmap = state.for_binary(binary).bbmap;
  auto &ICFG = binary.Analysis.ICFG;
  basic_block_t bb = basic_block_at_address(IndBrInfo.TermAddr, binary, bbmap);

  llvm::MCInst &Inst = IndBrInfo.Inst;

  //
  // push program counter past instruction (on x86_64 this is necessary to make
  // EIP-relative expressions correct)
  //
  pc += IndBrInfo.InsnBytes.size();

  //
  // shorthand-functions for reading the tracee's memory and registers
  //
  auto LoadAddr = [&](uintptr_t addr) -> uintptr_t {
    return _ptrace_peekdata(child, addr);
  };

  auto GetTarget = [&](void) -> uintptr_t {
    switch (Inst.getOpcode()) {

#if defined(__x86_64__)

    case llvm::X86::JMP64m: /* jmp qword ptr [reg0 + imm3] */
      assert(Inst.getNumOperands() == 5);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(1).isImm());
      assert(Inst.getOperand(2).isReg());
      assert(Inst.getOperand(3).isImm());
      assert(Inst.getOperand(4).isReg());

      if (Inst.getOperand(4).getReg() == llvm::X86::NoRegister) {
        unsigned x_r = Inst.getOperand(0).getReg();
        unsigned y_r = Inst.getOperand(2).getReg();

        long x = x_r == llvm::X86::NoRegister ? 0L : RegValue(x_r);
        long A = Inst.getOperand(1).getImm();
        long y = y_r == llvm::X86::NoRegister ? 0L : RegValue(y_r);
        long B = Inst.getOperand(3).getImm();

        return LoadAddr(x + A * y + B);
      } else {
        abort();
      }

    case llvm::X86::JMP64r: /* jmp reg0 */
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());

      return RegValue(Inst.getOperand(0).getReg());

    case llvm::X86::CALL64m: /* call qword ptr [rip + 3071542] */
      assert(Inst.getNumOperands() == 5);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(1).isImm());
      assert(Inst.getOperand(2).isReg());
      assert(Inst.getOperand(3).isImm());
      assert(Inst.getOperand(4).isReg());

      if (Inst.getOperand(4).getReg() == llvm::X86::NoRegister) {
        unsigned x_r = Inst.getOperand(0).getReg();
        unsigned y_r = Inst.getOperand(2).getReg();

        long x = x_r == llvm::X86::NoRegister ? 0L : RegValue(x_r);
        long A = Inst.getOperand(1).getImm();
        long y = y_r == llvm::X86::NoRegister ? 0L : RegValue(y_r);
        long B = Inst.getOperand(3).getImm();

        return LoadAddr(x + A * y + B);
      } else {
        abort();
      }

    case llvm::X86::CALL64r: /* call rax */
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());

      return RegValue(Inst.getOperand(0).getReg());

#elif defined(__i386__)

    case llvm::X86::JMP32m: /* jmp dword ptr [ebx + 20] */
      assert(Inst.getNumOperands() == 5);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(1).isImm());
      assert(Inst.getOperand(2).isReg());
      assert(Inst.getOperand(3).isImm());
      assert(Inst.getOperand(4).isReg());

      if (Inst.getOperand(4).getReg() == llvm::X86::NoRegister) {
        unsigned x_r = Inst.getOperand(0).getReg();
        unsigned y_r = Inst.getOperand(2).getReg();

        long x = x_r == llvm::X86::NoRegister ? 0L : RegValue(x_r);
        long A = Inst.getOperand(1).getImm();
        long y = y_r == llvm::X86::NoRegister ? 0L : RegValue(y_r);
        long B = Inst.getOperand(3).getImm();

        return LoadAddr(x + A * y + B);
      } else {
        /* e.g. jmp dword ptr gs:[16] */
        return LoadAddr(RegValue(Inst.getOperand(4).getReg()) +
                        Inst.getOperand(3).getImm());
      }

    case llvm::X86::JMP32r: { /* jmp eax */
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());
      unsigned r = Inst.getOperand(0).getReg();
      assert(r != llvm::X86::NoRegister);
      return RegValue(r);
    }

    case llvm::X86::CALL32m:
      assert(Inst.getNumOperands() == 5);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(1).isImm());
      assert(Inst.getOperand(2).isReg());
      assert(Inst.getOperand(3).isImm());
      assert(Inst.getOperand(4).isReg());

      if (Inst.getOperand(4).getReg() == llvm::X86::NoRegister) {
        /* e.g. call dword ptr [esi + 4*edi - 280] */

        unsigned x_r = Inst.getOperand(0).getReg();
        unsigned y_r = Inst.getOperand(2).getReg();

        long x = x_r == llvm::X86::NoRegister ? 0L : RegValue(x_r);
        long A = Inst.getOperand(1).getImm();
        long y = y_r == llvm::X86::NoRegister ? 0L : RegValue(y_r);
        long B = Inst.getOperand(3).getImm();

        return LoadAddr(x + A * y + B);
      } else {
        /* e.g. call dword ptr gs:[16] */
        return LoadAddr(RegValue(Inst.getOperand(4).getReg()) +
                        Inst.getOperand(3).getImm());
      }

    case llvm::X86::CALL32r: /* call edx */
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

#elif defined(__aarch64__)

    case llvm::AArch64::BLR: /* blr x3 */
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

    case llvm::AArch64::BR: /* br x17 */
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

#elif defined(__mips64) || defined(__mips__)

    case llvm::Mips::JALR: /* jalr $25 */
      assert(Inst.getNumOperands() == 2);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(0).getReg() == llvm::Mips::RA);
      assert(Inst.getOperand(1).isReg());
      return RegValue(Inst.getOperand(1).getReg());

    case llvm::Mips::JR: /* jr $25 */
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

#else
#error
#endif

    default:
      abort();
    }
  };

  //
  // determine the target address of the indirect control transfer
  //
  struct {
    uintptr_t Addr = 0UL;
    binary_index_t BIdx = invalid_binary_index;
    bool isNew = false;
  } Target;

  try {
    Target.Addr = GetTarget();
  } catch (const std::exception &e) {
    HumanOut() << llvm::formatv("failed to determine target address: {0}\n", e.what());
    throw;
  }

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  Target.Addr &= ~1UL;
#endif

  {
    auto it = AddressSpace.find(Target.Addr);
    if (it == AddressSpace.end()) {
      if (IsVerbose()) {
        update_view_of_virtual_memory(child);

        HumanOut() << llvm::formatv("{0} -> {1} (unknown binary)\n",
                                    description_of_program_counter(saved_pc, true),
                                    description_of_program_counter(Target.Addr, true));
      }
      return;
    }

    Target.BIdx = -1+(*it).second;
  }

  //
  // if the instruction is a call, we need to emulate whatever happens to the
  // return address
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
#elif defined(__mips64) || defined(__mips__)
    gpr.regs[31 /* ra */] = pc;
#else
#error
#endif
  }

  //
  // set program counter to be branch target
  //
#if !defined(__mips64) && !defined(__mips__)
  pc = Target.Addr;
#else /* delay slot madness */
  try {
    assert(ExecutableRegionAddress);

    assert(IndBrInfo.InsnBytes.size() == 2 * sizeof(uint32_t));

    unsigned reg = std::numeric_limits<unsigned>::max();
    if (Inst.getOpcode() == llvm::Mips::JR) {
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());

      reg = Inst.getOperand(0).getReg();
    } else if (Inst.getOpcode() == llvm::Mips::JALR) {
      assert(Inst.getNumOperands() == 2);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(0).getReg() == llvm::Mips::RA);
      assert(Inst.getOperand(1).isReg());

      reg = Inst.getOperand(1).getReg();
    } else {
      HumanOut() << llvm::formatv(
          "unknown indirect branch instruction {2} ({0}:{1})", __FILE__,
          __LINE__, Inst);
    }
    assert(reg != std::numeric_limits<unsigned>::max());

    emulate_delay_slot(IndBrInfo.DelaySlotInst,
                       IndBrInfo.InsnBytes,
                       reg);
  } catch (const std::exception &e) {
    HumanOut() << llvm::formatv("failed to emulate delay slot: {0}\n", e.what());
  }
#endif

  //
  // update the jv based on the target
  //

  binary_t &TargetBinary = jv.Binaries[Target.BIdx];

  struct {
    bool IsGoto = false;
  } ControlFlow;

  try {
    if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL) {
      function_index_t FIdx =
          E.explore_function(TargetBinary,
                             *state.for_binary(TargetBinary).ObjectFile,
                             rva_of_va(Target.Addr, Target.BIdx),
                             state.for_binary(TargetBinary).fnmap,
                             state.for_binary(TargetBinary).bbmap,
                             std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));

      assert(is_function_index_valid(FIdx));

      Target.isNew = ICFG[bb].insertDynTarget({Target.BIdx, FIdx}, Alloc);

      /* term bb may been split */
      bb = basic_block_at_address(IndBrInfo.TermAddr, binary, bbmap);
      assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL);

      if (Target.isNew &&
          boost::out_degree(bb, ICFG) == 0 &&
          does_function_return(TargetBinary.Analysis.Functions[FIdx], TargetBinary)) {
        //
        // this call instruction will return, so explore the return block
        //
        basic_block_index_t NextBBIdx =
            E.explore_basic_block(binary, *state.for_binary(binary).ObjectFile,
                                  IndBrInfo.TermAddr + IndBrInfo.InsnBytes.size(),
                                  state.for_binary(binary).fnmap,
                                  state.for_binary(binary).bbmap,
                                  std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));

        assert(is_basic_block_index_valid(NextBBIdx));

        /* term bb may been split */
        bb = basic_block_at_address(IndBrInfo.TermAddr, binary, bbmap);
        assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL);

        boost::add_edge(bb, boost::vertex(NextBBIdx, ICFG), ICFG);
      }
    } else {
      assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

      if (unlikely(ICFG[bb].Term._indirect_jump.IsLj)) {
        //
        // non-local goto (aka "long jump")
        //
        E.explore_basic_block(TargetBinary, *state.for_binary(TargetBinary).ObjectFile,
                              rva_of_va(Target.Addr, Target.BIdx),
                              state.for_binary(TargetBinary).fnmap,
                              state.for_binary(TargetBinary).bbmap,
                              std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));

        ControlFlow.IsGoto = true;
        Target.isNew = opts.Longjmps;
      } else {
        // on an indirect jump, we must determine one of two possibilities.
        //
        // (1) transfers control to a label (i.e. a goto or switch-case statement)
        //
        // or
        //
        // (2) transfers control to a function (i.e. calling a function pointer)
        //
        bool isTailCall =
            IsDefinitelyTailCall(ICFG, bb) ||
            IndBrInfo.BIdx != Target.BIdx ||
            (boost::out_degree(bb, ICFG) == 0 &&
             state.for_binary(TargetBinary).fnmap.count(rva_of_va(Target.Addr, Target.BIdx)));

        if (isTailCall) {
          function_index_t FIdx =
              E.explore_function(TargetBinary, *state.for_binary(TargetBinary).ObjectFile,
                                 rva_of_va(Target.Addr, Target.BIdx),
                                 state.for_binary(TargetBinary).fnmap,
                                 state.for_binary(TargetBinary).bbmap,
                                 std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));

          assert(is_function_index_valid(FIdx));

          /* term bb may been split */
          bb = basic_block_at_address(IndBrInfo.TermAddr, binary, bbmap);
          assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

          Target.isNew = ICFG[bb].insertDynTarget({Target.BIdx, FIdx}, Alloc);
        } else {
          basic_block_index_t TargetBBIdx =
              E.explore_basic_block(TargetBinary, *state.for_binary(TargetBinary).ObjectFile,
                                    rva_of_va(Target.Addr, Target.BIdx),
                                    state.for_binary(TargetBinary).fnmap,
                                    state.for_binary(TargetBinary).bbmap,
                                    std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));

          assert(is_basic_block_index_valid(TargetBBIdx));
          basic_block_t TargetBB = boost::vertex(TargetBBIdx, ICFG);

          /* term bb may been split */
          bb = basic_block_at_address(IndBrInfo.TermAddr, binary, bbmap);
          assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

          Target.isNew = boost::add_edge(bb, TargetBB, ICFG).second;
          if (Target.isNew)
            ICFG[bb].InvalidateAnalysis();

          ControlFlow.IsGoto = true;
        }
      }
    }

    if (unlikely(!opts.Quiet && !ShowMeN && (ShowMeA || (ShowMeS && Target.isNew))))
      HumanOut() << llvm::formatv("{3}({0}) {1} -> {2}" __ANSI_NORMAL_COLOR "\n",
                                  ControlFlow.IsGoto ? (ICFG[bb].Term._indirect_jump.IsLj ? "longjmp" : "goto") : "call",
                                  description_of_program_counter(saved_pc),
                                  description_of_program_counter(Target.Addr),
                                  ControlFlow.IsGoto ? (ICFG[bb].Term._indirect_jump.IsLj ? __ANSI_MAGENTA : __ANSI_GREEN) : __ANSI_CYAN);
  } catch (const std::exception &e) { /* _jove_g2h probably threw an exception */
    HumanOut() << llvm::formatv(
        "on_breakpoint failed: {0} [target: {1}+{2:x} ({3:x}) binary.LoadAddr: {4:x}]\n",
        e.what(), fs::path(TargetBinary.path_str()).filename().string(),
        rva_of_va(Target.Addr, Target.BIdx), Target.Addr,
        state.for_binary(TargetBinary).LoadAddr);

    HumanOut() << ProcMapsForPid(child);
  }
}

#include "relocs_common.hpp"

void BootstrapTool::harvest_irelative_reloc_targets(pid_t child,
                                                    tiny_code_generator_t &tcg) {
  auto processDynamicReloc = [&](binary_t &b, const Relocation &R) -> void {
    binary_index_t BIdx = index_of_binary(b, jv);

    if (!is_irelative_relocation(R))
      return;

    struct {
      uintptr_t Addr;

      binary_index_t BIdx;
      function_index_t FIdx;
    } Resolved;

    try {
      Resolved.Addr = _ptrace_peekdata(child, va_of_rva(R.Offset, BIdx));
    } catch (const std::exception &e) {
      if (IsVerbose())
        HumanOut()
            << llvm::formatv("{0}: exception: {1}\n",
                             "harvest_irelative_reloc_targets", e.what());
      return;
    }

    auto it = AddressSpace.find(Resolved.Addr);
    if (it == AddressSpace.end()) {
      if (IsVerbose())
        HumanOut()
            << llvm::formatv("{0}: unknown binary for {1}: R.Offset={2:x}\n",
                             "harvest_irelative_reloc_targets",
                             description_of_program_counter(Resolved.Addr, true),
                             R.Offset);
      return;
    }

    Resolved.BIdx = -1+(*it).second;

    if (IsVerbose())
      HumanOut() << llvm::formatv("IFunc dyn target: {0:x} [R.Offset={1:x}]\n",
                                  rva_of_va(Resolved.Addr, Resolved.BIdx),
                                  R.Offset);

    binary_t &ResolvedBinary = jv.Binaries[Resolved.BIdx];

    Resolved.FIdx = E.explore_function(
        ResolvedBinary, *state.for_binary(ResolvedBinary).ObjectFile,
        rva_of_va(Resolved.Addr, Resolved.BIdx),
        state.for_binary(ResolvedBinary).fnmap,
        state.for_binary(ResolvedBinary).bbmap,
        std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));

    if (is_function_index_valid(Resolved.FIdx)) {
      if (R.Addend)
        b.Analysis.addIFuncDynTarget(*R.Addend, {Resolved.BIdx, Resolved.FIdx});

      b.Analysis.addRelocDynTarget(R.Offset, {Resolved.BIdx, Resolved.FIdx});
    }
  };

  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    auto &b = jv.Binaries[BIdx];
    if (b.IsVDSO)
      continue;

    if (!BinFoundVec[BIdx])
      continue;

    std::unique_ptr<obj::Binary> &Bin = state.for_binary(b).ObjectFile;

    assert(Bin.get());
    assert(llvm::isa<ELFO>(Bin.get()));
    ELFO &O = *llvm::cast<ELFO>(Bin.get());
    const ELFF &Elf = *O.getELFFile();

    for_each_dynamic_relocation(Elf,
                                state.for_binary(b)._elf.DynRelRegion,
                                state.for_binary(b)._elf.DynRelaRegion,
                                state.for_binary(b)._elf.DynRelrRegion,
                                state.for_binary(b)._elf.DynPLTRelRegion,
                                [&](const Relocation &R) {
                                  processDynamicReloc(b, R);
                                });
  }
}

void BootstrapTool::harvest_addressof_reloc_targets(pid_t child,
                                                    tiny_code_generator_t &tcg) {
  auto processDynamicReloc = [&](binary_t &b, const Relocation &R) -> void {
    binary_index_t BIdx = index_of_binary(b, jv);

    if (!is_addressof_relocation(R))
      return;

    std::unique_ptr<obj::Binary> &Bin = state.for_binary(b).ObjectFile;

    assert(Bin.get());
    assert(llvm::isa<ELFO>(Bin.get()));
    ELFO &O = *llvm::cast<ELFO>(Bin.get());
    const ELFF &Elf = *O.getELFFile();

    auto dynamic_symbols = [&](void) -> Elf_Sym_Range {
      return state.for_binary(b)._elf.OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();
    };

    RelSymbol RelSym =
        getSymbolForReloc(O, dynamic_symbols(), state.for_binary(b)._elf.DynamicStringTable, R);

    if (const Elf_Sym *Sym = RelSym.Sym) {
      if (Sym->getType() != llvm::ELF::STT_FUNC)
        return;
      if (!Sym->isUndefined())
        return;

      struct {
        uintptr_t Addr;

        binary_index_t BIdx;
        function_index_t FIdx;
      } Resolved;

      try {
        Resolved.Addr = _ptrace_peekdata(child, va_of_rva(R.Offset, BIdx));
      } catch (const std::exception &e) {
        if (IsVerbose())
          HumanOut()
              << llvm::formatv("{0}: exception: {1}\n",
                               "harvest_addressof_reloc_targets", e.what());

        return;
      }

      auto it = AddressSpace.find(Resolved.Addr);
      if (it == AddressSpace.end()) {
        if (IsVerbose())
          HumanOut()
              << llvm::formatv("{0}: unknown binary for {1}\n",
                               "harvest_addressof_reloc_targets",
                               description_of_program_counter(Resolved.Addr, true));

        return;
      }

      Resolved.BIdx = -1+(*it).second;

      if (Resolved.BIdx == BIdx) /* _dl_fixup... */
        return;

      binary_t &ResolvedBinary = jv.Binaries[Resolved.BIdx];

      unsigned brkpt_count = 0;
      Resolved.FIdx = E.explore_function(
          ResolvedBinary, *state.for_binary(ResolvedBinary).ObjectFile,
          rva_of_va(Resolved.Addr, Resolved.BIdx),
          state.for_binary(ResolvedBinary).fnmap,
          state.for_binary(ResolvedBinary).bbmap,
          std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));

      if (is_function_index_valid(Resolved.FIdx)) {
        b.Analysis.addSymDynTarget(RelSym.Name, {Resolved.BIdx, Resolved.FIdx});
        b.Analysis.addRelocDynTarget(R.Offset, {Resolved.BIdx, Resolved.FIdx});
      }
    }
  };

  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    auto &b = jv.Binaries[BIdx];
    if (b.IsVDSO)
      continue;

    if (!BinFoundVec[BIdx])
      continue;

    if (!state.for_binary(b)._elf.OptionalDynSymRegion)
      continue;

    std::unique_ptr<obj::Binary> &Bin = state.for_binary(b).ObjectFile;

    assert(Bin.get());
    assert(llvm::isa<ELFO>(Bin.get()));
    ELFO &O = *llvm::cast<ELFO>(Bin.get());
    const ELFF &Elf = *O.getELFFile();

    for_each_dynamic_relocation(Elf,
                                state.for_binary(b)._elf.DynRelRegion,
                                state.for_binary(b)._elf.DynRelaRegion,
                                state.for_binary(b)._elf.DynRelrRegion,
                                state.for_binary(b)._elf.DynPLTRelRegion,
                                [&](const Relocation &R) {
                                  processDynamicReloc(b, R);
                                });
  }
}

void BootstrapTool::harvest_ctor_and_dtors(pid_t child,
                                           tiny_code_generator_t &tcg) {
  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    auto &Binary = jv.Binaries[BIdx];
    if (Binary.IsVDSO)
      continue;

    if (!BinFoundVec[BIdx])
      continue;

    unsigned brkpt_count = 0;

    std::unique_ptr<obj::Binary> &ObjectFile = state.for_binary(Binary).ObjectFile;

    assert(ObjectFile.get());
    assert(llvm::isa<ELFO>(ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(ObjectFile.get());
    const ELFF &Elf = *O.getELFFile();

    llvm::Expected<Elf_Shdr_Range> ExpectedSections = Elf.sections();

    if (ExpectedSections) {
      for (const Elf_Shdr &Sec : *ExpectedSections) {
        if (!(Sec.sh_flags & llvm::ELF::SHF_ALLOC))
          continue;

        bool ctor = false, dtor = false;

        switch (Sec.sh_type) {
        case llvm::ELF::SHT_INIT_ARRAY:
          ctor = true;
          break;

        case llvm::ELF::SHT_FINI_ARRAY:
          dtor = true;
          break;

        default:
          continue;
        }

        assert(ctor ^ dtor);

        assert(Sec.sh_size % sizeof(uintptr_t) == 0);
        unsigned N = Sec.sh_size / sizeof(uintptr_t);

        for (unsigned j = 0; j < N; ++j) {
          try {
            uintptr_t rva = Sec.sh_addr + j * sizeof(uintptr_t);

            uintptr_t Proc = _ptrace_peekdata(child, va_of_rva(rva, BIdx));

            auto it = AddressSpace.find(Proc);
            if (it != AddressSpace.end() &&
                -1+(*it).second == BIdx) {
              function_index_t FIdx = E.explore_function(
                  Binary, *state.for_binary(Binary).ObjectFile,
                  rva_of_va(Proc, BIdx),
                  state.for_binary(Binary).fnmap,
                  state.for_binary(Binary).bbmap,
                  std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));

              if (is_function_index_valid(FIdx))
                Binary.Analysis.Functions[FIdx].IsABI = true; /* it is an ABI */
            }
          } catch (const std::exception &e) {
            if (IsVerbose())
              HumanOut()
                  << llvm::formatv("failed examining ctor: {0}\n", e.what());
          }
        }
      }
    }

    if (brkpt_count > 0) {
      HumanOut() << llvm::formatv("placed {0} breakpoint{1} in {2}\n",
                                  brkpt_count,
                                  brkpt_count > 1 ? "s" : "",
                                  Binary.path_str());
    }
  }
}

#if defined(__mips64) || defined(__mips__)
void BootstrapTool::harvest_global_GOT_entries(pid_t child,
                                               tiny_code_generator_t &tcg) {
  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    auto &b = jv.Binaries[BIdx];
    if (b.IsVDSO)
      continue;

    if (!BinFoundVec[BIdx])
      continue;

    if (!state.for_binary(b)._elf.OptionalDynSymRegion)
      continue;

    unsigned brkpt_count = 0;

    std::unique_ptr<obj::Binary> &ObjectFile = state.for_binary(b).ObjectFile;

    assert(ObjectFile.get());
    assert(llvm::isa<ELFO>(ObjectFile.get()));
    ELFO &O = *llvm::cast<ELFO>(ObjectFile.get());
    const ELFF &Elf = *O.getELFFile();

    auto dynamic_table = [&](void) -> Elf_Dyn_Range {
      return state.for_binary(b)._elf.DynamicTable.getAsArrayRef<Elf_Dyn>();
    };

    auto dynamic_symbols = [&](void) -> Elf_Sym_Range {
      return state.for_binary(b)._elf.OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();
    };

    MipsGOTParser Parser(Elf, b.path_str());

    if (llvm::Error Err = Parser.findGOT(dynamic_table(),
                                         dynamic_symbols())) {
      HumanOut() << llvm::formatv("Parser.findGOT failed: {0}\n", Err);
      continue;
    }

    for (const MipsGOTParser::Entry &Ent : Parser.getGlobalEntries()) {
      const uint64_t Addr = Parser.getGotAddress(&Ent);

      const Elf_Sym *Sym = Parser.getGotSym(&Ent);
      assert(Sym);

      bool is_undefined =
          Sym->isUndefined() || Sym->st_shndx == llvm::ELF::SHN_UNDEF;
      if (!is_undefined)
        continue;
      if (Sym->getType() != llvm::ELF::STT_FUNC)
        continue;

      llvm::Expected<llvm::StringRef> ExpectedSymName = Sym->getName(state.for_binary(b)._elf.DynamicStringTable);
      if (!ExpectedSymName)
        continue;

      llvm::StringRef SymName = *ExpectedSymName;

      ip_string tmp(Alloc);
      ip_dynamic_target_set &SymDynTargets =
          (*b.Analysis.SymDynTargets
                .insert(std::make_pair(to_ips(tmp, SymName.str()),
                                       ip_dynamic_target_set(Alloc))).first).second;
      if (!SymDynTargets.empty())
        continue;

      if (IsVerbose())
        HumanOut() << llvm::formatv("{0}: GlobalEntry: {1}\n", __func__, SymName);

      struct {
        uintptr_t Addr;

        binary_index_t BIdx;
        function_index_t FIdx;
      } Resolved;

      try {
        Resolved.Addr = _ptrace_peekdata(child, va_of_rva(Addr, BIdx));
      } catch (const std::exception &e) {
        if (IsVerbose())
          HumanOut() << llvm::formatv("{0}: exception: {1}\n", __func__, e.what());

        continue;
      }

#if defined(__mips64) || defined(__mips__)
      Resolved.Addr &= ~1UL;
#endif

      auto it = AddressSpace.find(Resolved.Addr);
      if (it == AddressSpace.end()) {
        if (IsVerbose())
          HumanOut()
              << llvm::formatv("{0}: unknown binary for {1}\n", __func__,
                               description_of_program_counter(Resolved.Addr, true));

        continue;
      }

      Resolved.BIdx = -1+(*it).second;
      binary_t &ResolvedBinary = jv.Binaries.at(Resolved.BIdx);

      unsigned brkpt_count = 0;
      basic_block_index_t resolved_bbidx = E.explore_basic_block(
          ResolvedBinary, *state.for_binary(ResolvedBinary).ObjectFile,
          rva_of_va(Resolved.Addr, Resolved.BIdx),
          state.for_binary(ResolvedBinary).fnmap,
          state.for_binary(ResolvedBinary).bbmap,
          std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));

      if (!is_basic_block_index_valid(resolved_bbidx))
        continue;

      Resolved.FIdx = E.explore_function(
          ResolvedBinary, *state.for_binary(ResolvedBinary).ObjectFile,
          rva_of_va(Resolved.Addr, Resolved.BIdx),
          state.for_binary(ResolvedBinary).fnmap,
          state.for_binary(ResolvedBinary).bbmap,
          std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));
      if (is_function_index_valid(Resolved.FIdx)) {
        SymDynTargets.insert({Resolved.BIdx, Resolved.FIdx});
      }
    }
  }
}

#endif

void BootstrapTool::harvest_reloc_targets(pid_t child,
                                          tiny_code_generator_t &tcg) {
  harvest_irelative_reloc_targets(child, tcg);
  harvest_addressof_reloc_targets(child, tcg);
  harvest_ctor_and_dtors(child, tcg);

#if defined(__mips64) || defined(__mips__)
  harvest_global_GOT_entries(child, tcg);
#endif
}

static bool load_proc_maps(pid_t child, std::vector<struct proc_map_t> &out);

bool BootstrapTool::update_view_of_virtual_memory(pid_t child) {
  if (!load_proc_maps(child, cached_proc_maps))
    return false;

  pmm.clear();
  AddressSpace.clear();
  for_each_binary(jv, [&](binary_t &b) {
    state.for_binary(b).LoadAddr = state.for_binary(b).LoadOffset = std::numeric_limits<uintptr_t>::max(); /* reset */
  });

  for (const auto &proc_map : cached_proc_maps) {
    boost::icl::interval<uintptr_t>::type intervl =
        boost::icl::interval<uintptr_t>::right_open(proc_map.beg,
                                                    proc_map.end);

    if (WARN_ON(pmm.find(intervl) != pmm.end()))
        ;
    else
      pmm.add({intervl, {proc_map}});

    auto it = BinPathToIdxMap.find(proc_map.nm);
    if (it == BinPathToIdxMap.end()) {
      if (IsVerbose())
        HumanOut() << llvm::formatv("{0}: what is this? \"{1}\"\n",
                                    __func__, proc_map.nm);
      continue;
    }

    {
      binary_index_t BIdx = (*it).second;

      if (WARN_ON(AddressSpace.find(intervl) != AddressSpace.end()))
        ;
      else
        AddressSpace.add({intervl, 1+BIdx});

      auto &b = jv.Binaries[BIdx];

      uintptr_t SavedLoadAddr = state.for_binary(b).LoadAddr;
      state.for_binary(b).LoadAddr = std::min(state.for_binary(b).LoadAddr, proc_map.beg);
      bool Changed = state.for_binary(b).LoadAddr != SavedLoadAddr;

      if (Changed) {
        state.for_binary(b).LoadOffset = proc_map.off;

        if (IsVerbose())
          HumanOut() << llvm::formatv("LoadAddr for {0} is {1:x} (was {2:x})\n",
                                      b.path_str(), state.for_binary(b).LoadAddr, SavedLoadAddr);
      }

      if (!proc_map.x)
        continue;

      if (!BinFoundVec.test(BIdx)) {
        BinFoundVec.set(BIdx);

        on_binary_loaded(child, BIdx, proc_map);
      }
    }
  }

  return true;
}

void BootstrapTool::on_binary_loaded(pid_t child,
                                     binary_index_t BIdx,
                                     const proc_map_t &proc_map) {
  binary_t &binary = jv.Binaries[BIdx];

  auto &ObjectFile = state.for_binary(binary).ObjectFile;

  if (IsVerbose())
    HumanOut() << (fmt("found binary %s @ [%#lx, %#lx)")
                   % proc_map.nm
                   % proc_map.beg
                   % proc_map.end).str()
               << '\n';

  //
  // if Prog has been loaded, set a breakpoint on the entry point of prog
  //
  if (binary.IsExecutable &&
      is_function_index_valid(binary.Analysis.EntryFunction)) {
    basic_block_t entry_bb = boost::vertex(
        binary.Analysis.Functions[binary.Analysis.EntryFunction].Entry,
        binary.Analysis.ICFG);
    uintptr_t entry_rva = binary.Analysis.ICFG[entry_bb].Addr;
    uintptr_t Addr = va_of_rva(entry_rva, BIdx);

    breakpoint_t &brk = BrkMap[Addr];
    brk.callback = std::bind(&BootstrapTool::harvest_reloc_targets, this, std::placeholders::_1, std::placeholders::_2);

    try {
      place_breakpoint(child, Addr, brk);
    } catch (const std::exception &e) {
      HumanOut() << llvm::formatv("failed to place breakpoint: {0}\n", e.what());
    }
  }

  //
  // if it's the dynamic linker, we need to set a breakpoint on the address of a
  // function internal to the run-time linker, that will always be called when
  // the linker begins to map in a library or unmap it, and again when the
  // mapping change is complete.
  //
  if (binary.IsDynamicLinker)
    on_dynamic_linker_loaded(child, BIdx, proc_map);

#if defined(__mips64) || defined(__mips__)
  if (binary.IsVDSO) {
    WARN_ON(ExecutableRegionAddress);

    constexpr unsigned num_trampolines = 32;

    //
    // find a code cave that can hold 2*num_trampolines instructions
    //
    ExecutableRegionAddress = proc_map.end - num_trampolines * (2 * sizeof(uint32_t));

    //
    // "initialize" code cave
    //
    for (unsigned i = 0; i < 32; ++i) {
      uint32_t insn = encoding_of_jump_to_reg(reg_of_idx(i));

      _ptrace_pokedata(child, ExecutableRegionAddress + i * (2 * sizeof(uint32_t)), insn);
    }

    if (IsVerbose())
        HumanOut()
            << llvm::formatv("ExecutableRegionAddress = 0x{0:x}\n",
                             ExecutableRegionAddress);
  }
#endif

  //
  // place breakpoints for indirect branches
  //
  for (basic_block_index_t bbidx = 0;
       bbidx < boost::num_vertices(binary.Analysis.ICFG); ++bbidx) {
    basic_block_t bb = boost::vertex(bbidx, binary.Analysis.ICFG);

    basic_block_properties_t &bbprop = binary.Analysis.ICFG[bb];
    if (bbprop.Term.Type != TERMINATOR::INDIRECT_JUMP &&
        bbprop.Term.Type != TERMINATOR::INDIRECT_CALL)
      continue;

    uintptr_t Addr = va_of_rva(bbprop.Term.Addr, BIdx);

    assert(IndBrMap.find(Addr) == IndBrMap.end());

    indirect_branch_t &IndBrInfo = IndBrMap[Addr];
    IndBrInfo.IsCall = bbprop.Term.Type == TERMINATOR::INDIRECT_CALL;
    IndBrInfo.BIdx = BIdx;
    IndBrInfo.TermAddr = bbprop.Term.Addr;
    IndBrInfo.InsnBytes.resize(bbprop.Size - (bbprop.Term.Addr - bbprop.Addr));
#if defined(__mips64) || defined(__mips__)
    IndBrInfo.InsnBytes.resize(IndBrInfo.InsnBytes.size() + 4 /* delay slot */);
    assert(IndBrInfo.InsnBytes.size() == 2 * sizeof(uint32_t));
#endif

    assert(ObjectFile.get());
    const ELFF &Elf = *llvm::cast<ELFO>(ObjectFile.get())->getELFFile();

    llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(bbprop.Term.Addr);
    if (!ExpectedPtr)
      abort();

    memcpy(&IndBrInfo.InsnBytes[0], *ExpectedPtr, IndBrInfo.InsnBytes.size());

    //
    // now that we have the bytes for each indirect branch, disassemble them
    //
    llvm::MCInst &Inst = IndBrInfo.Inst;

    {
      uint64_t InstLen;
      bool Disassembled = disas.DisAsm->getInstruction(
          Inst, InstLen, IndBrInfo.InsnBytes, bbprop.Term.Addr, llvm::nulls());
      assert(Disassembled);
    }

#if defined(__mips64) || defined(__mips__)
    {
      uint64_t InstLen;
      bool Disassembled = disas.DisAsm->getInstruction(
          IndBrInfo.DelaySlotInst, InstLen,
          llvm::ArrayRef<uint8_t>(IndBrInfo.InsnBytes).slice(4),
          bbprop.Term.Addr + 4, llvm::errs());
      assert(Disassembled);
    }
#endif

    try {
      if (opts.Fast && bbprop.hasDynTarget()) {
        ;
      } else {
        place_breakpoint_at_indirect_branch(child, Addr, IndBrInfo);
      }
    } catch (const std::exception &e) {
      HumanOut() << llvm::formatv(
          "failed to place breakpoint at indirect branch: {0}\n", e.what());
    }
  }

  //
  // place breakpoints for returns
  //
  for (basic_block_index_t bbidx = 0;
       bbidx < boost::num_vertices(binary.Analysis.ICFG); ++bbidx) {
    basic_block_t bb = boost::vertex(bbidx, binary.Analysis.ICFG);

    basic_block_properties_t &bbprop = binary.Analysis.ICFG[bb];
    if (bbprop.Term.Type != TERMINATOR::RETURN)
      continue;

    uintptr_t Addr = va_of_rva(bbprop.Term.Addr, BIdx);

    assert(RetMap.find(Addr) == RetMap.end());

    auto &RetInfo = RetMap[Addr];
    RetInfo.BIdx = BIdx;
    RetInfo.TermAddr = bbprop.Term.Addr;

    RetInfo.InsnBytes.resize(bbprop.Size - (bbprop.Term.Addr - bbprop.Addr));
#if defined(__mips64) || defined(__mips__)
    RetInfo.InsnBytes.resize(RetInfo.InsnBytes.size() + 4 /* delay slot */);
    assert(RetInfo.InsnBytes.size() == 2 * sizeof(uint32_t));
#endif

    assert(ObjectFile.get());
    const ELFF &Elf = *llvm::cast<ELFO>(ObjectFile.get())->getELFFile();

    llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(bbprop.Term.Addr);
    if (!ExpectedPtr)
      abort();

    memcpy(&RetInfo.InsnBytes[0], *ExpectedPtr, RetInfo.InsnBytes.size());

    {
      uint64_t InstLen;
      bool Disassembled =
          disas.DisAsm->getInstruction(RetInfo.Inst, InstLen, RetInfo.InsnBytes,
                                       bbprop.Term.Addr, llvm::nulls());
      assert(Disassembled);
      assert(InstLen <= RetInfo.InsnBytes.size());
    }

#if defined(__mips64) || defined(__mips__)
    {
      uint64_t InstLen;
      bool Disassembled = disas.DisAsm->getInstruction(
          RetInfo.DelaySlotInst, InstLen,
          llvm::ArrayRef<uint8_t>(RetInfo.InsnBytes).slice(4),
          bbprop.Term.Addr + 4, llvm::nulls());
      assert(Disassembled);
    }
#endif

    try {
      if (opts.Fast) {
        ;
      } else {
        place_breakpoint_at_return(child, Addr, RetInfo);
      }
    } catch (const std::exception &e) {
      HumanOut() << llvm::formatv(
          "failed to place breakpoint at return: {0}\n", e.what());
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

void _ptrace_get_cpu_state(pid_t child, cpu_state_t &out) {
#if defined(__mips64) || defined(__mips__)
  unsigned long _request = PTRACE_GETREGS;
  unsigned long _pid = child;
  unsigned long _addr = 0;
  unsigned long _data = reinterpret_cast<unsigned long>(&out.regs[0]);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_GETREGS failed : ") +
                             std::string(strerror(errno)));
#else
  struct iovec iov = {.iov_base = &out,
                      .iov_len = sizeof(cpu_state_t)};

  unsigned long _request = PTRACE_GETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_GETREGSET failed : ") +
                             std::string(strerror(errno)));
#endif
}

void _ptrace_set_cpu_state(pid_t child, const cpu_state_t &in) {
#if defined(__mips64) || defined(__mips__)
  unsigned long _request = PTRACE_SETREGS;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&in.regs[0]);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_SETREGS failed : ") +
                             std::string(strerror(errno)));
#else
  struct iovec iov = {.iov_base = const_cast<cpu_state_t *>(&in),
                      .iov_len = sizeof(cpu_state_t)};

  unsigned long _request = PTRACE_SETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_SETREGSET failed : ") +
                             std::string(strerror(errno)));
#endif
}

unsigned long _ptrace_peekdata(pid_t child, uintptr_t addr) {
  unsigned long res;

  unsigned long _request = PTRACE_PEEKDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = reinterpret_cast<unsigned long>(&res);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error((fmt("PTRACE_PEEKDATA(%d, %p) failed : %s") %
                              child % addr % strerror(errno)).str());

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

int BootstrapTool::ChildProc(int pipefd) {
  std::vector<const char *> arg_vec;
  arg_vec.push_back(opts.Prog.c_str());

  for (const std::string &Arg : opts.Args)
    arg_vec.push_back(Arg.c_str());

  arg_vec.push_back(nullptr);

  std::vector<const char *> env_vec;
  for (char **env = ::environ; *env; ++env)
    env_vec.push_back(*env);
  env_vec.push_back("LD_BIND_NOW=1");

#if defined(__x86_64__)
  // <3 glibc
  env_vec.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
                    "-AVX,"
                    "-AVX2,"
                    "-AVX_Usable,"
                    "-AVX2_Usable,"
                    "-AVX512F_Usable,"
                    "-SSE4_1,"
                    "-SSE4_2,"
                    "-SSSE3,"
                    "-Fast_Unaligned_Load,"
                    "-ERMS,"
                    "-AVX_Fast_Unaligned_Load");
#elif defined(__i386__)
  // <3 glibc
  env_vec.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
                    "-SSE4_1,"
                    "-SSE4_2,"
                    "-SSSE3,"
                    "-Fast_Rep_String,"
                    "-Fast_Unaligned_Load,"
                    "-SSE2");
#endif

  for (const std::string &Env : opts.Envs)
    env_vec.push_back(Env.c_str());

  if (fs::exists("/firmadyne/libnvram.so"))
    env_vec.push_back("LD_PRELOAD=/firmadyne/libnvram.so");

  env_vec.push_back(nullptr);

  //
  // the request
  //
  ::ptrace(PTRACE_TRACEME);
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

#ifdef JOVE_HAVE_MEMFD
  std::string name = "jove/bootstrap" + jv.Binaries.at(0).path_str();
  int fd = ::memfd_create(name.c_str(), MFD_CLOEXEC);
  if (fd < 0) {
    ::close(pipefd);
    abort();
  }
  if (robust_write(fd,
                   &jv.Binaries.at(0).Data[0],
                   jv.Binaries.at(0).Data.size()) < 0) {
    ::close(pipefd);
    ::close(fd);
    abort();
  }
  std::string exe_path = "/proc/self/fd/" + std::to_string(fd);
#else
  std::string exe_path = arg_vec[0];
#endif

  ::execve(exe_path.c_str(),
           const_cast<char **>(&arg_vec[0]),
           const_cast<char **>(&env_vec[0]));

  /* if we got here, execve failed */
  int err = errno;
  HumanOut() << llvm::formatv("failed to execve (reason: {0})",
                              strerror(err));

  ::close(pipefd);
#ifdef JOVE_HAVE_MEMFD
  ::close(fd);
#endif
  return 1;
}

bool load_proc_maps(pid_t child, std::vector<struct proc_map_t> &out) {
  std::string path = "/proc/" + std::to_string(child) + "/maps";
  std::string maps = read_file_into_string(path.c_str());

  if (maps.empty())
    return false;

  out.clear();

  unsigned n = maps.size();
  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = (char *)memchr(line, '\n', left);
    }

    assert(eol);

    unsigned left = eol - line;

#if 0
    *eol = '\0';
    llvm::errs() << line << '\n';
#endif

    struct proc_map_t &proc_map = out.emplace_back();

    char *const dash = (char *)memchr(line, '-', left);
    assert(dash);

    char *const space = (char *)memchr(line, ' ', left);
    assert(space);

    *dash = '\0';
    proc_map.beg = strtoul(line, nullptr, 0x10);

    *space = '\0';
    proc_map.end = strtoul(dash + 1, nullptr, 0x10);

    proc_map.r = space[1] == 'r';
    proc_map.w = space[2] == 'w';
    proc_map.x = space[3] == 'x';
    proc_map.p = space[4] == 'p';

    char *const space2 = space + 5;
    assert(*space2 == ' ');

    char *const space3 = (char *)memchr(space2 + 1, ' ', eol - (space2 + 1));
    assert(space3);

    *space3 = '\0';
    proc_map.off = strtoul(space2 + 1, nullptr, 0x10);

    char *const space4 = (char *)memchr(space3 + 1, ' ', eol - (space3 + 1));
    assert(space4);

    char *const space5 = (char *)memchr(space4 + 1, ' ', eol - (space4 + 1));
    assert(space5);

    std::string &nm = proc_map.nm;

    *eol = '\0';
    nm = space5;

    boost::trim_left(nm);

#ifdef JOVE_HAVE_MEMFD
    //
    // XXX memfd cover-up
    //
    if (boost::algorithm::starts_with(nm, "/memfd:jove/bootstrap")) {
      nm = nm.substr(sizeof("/memfd:jove/bootstrap") - 1); /* chop it off */

      if (boost::algorithm::ends_with(nm, " (deleted)"))
        nm = nm.substr(0, nm.size() - sizeof(" (deleted)") + 1); /* chop it off */
    }
#endif

#if 0
    llvm::errs() << llvm::formatv(
        "[{0:x}, {1:x}) {2} {3} {4} {5} {6:x} \"{7}\"\n", proc_map.beg,
        proc_map.end, proc_map.r, proc_map.w, proc_map.x, proc_map.p,
        proc_map.off, nm);
#endif
  }

  return true;
}

struct link_map {
  /* These first few members are part of the protocol with the debugger.
     This is the same format used in SVR4.  */

  unsigned long l_addr; /* Difference between the address in the ELF file and
                           the addresses in memory.  */
  char *l_name;         /* Absolute file name object was found in.  */
  unsigned long *l_ld;  /* Dynamic section of the shared object.  */
  struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
};

struct r_debug {
  int r_version; /* Version number for this protocol.  */

  struct link_map *r_map; /* Head of the chain of loaded objects.  */

  /* This is the address of a function internal to the run-time linker,
     that will always be called when the linker begins to map in a
     library or unmap it, and again when the mapping change is complete.
     The debugger can set a breakpoint at this address if it wants to
     notice shared object mapping changes.  */
  unsigned long r_brk;
  enum {
    /* This state value describes the mapping change taking place when
       the `r_brk' address is called.  */
    RT_CONSISTENT, /* Mapping change is complete.  */
    RT_ADD,        /* Beginning to add a new object.  */
    RT_DELETE      /* Beginning to remove an object mapping.  */
  } r_state;

  unsigned long r_ldbase; /* Base address the linker is loaded at.  */
};

static ssize_t _ptrace_memcpy(pid_t, void *dest, const void *src, size_t n);

void BootstrapTool::scan_rtld_link_map(pid_t child, tiny_code_generator_t &tcg) {
  if (!_r_debug.Addr)
    return;

  struct r_debug r_dbg;
  memset(&r_dbg, 0, sizeof(r_dbg));

  try {
    ssize_t ret = _ptrace_memcpy(child,
                                 &r_dbg,
                                 (void *)_r_debug.Addr,
                                 sizeof(struct r_debug));

    if (ret != sizeof(struct r_debug)) {
      HumanOut() << __func__ << ": couldn't read r_debug structure\n";
      return;
    }
  } catch (const std::exception &e) {
    if (IsVerbose())
      HumanOut() << llvm::formatv("{0}: couldn't read r_debug structure ({1})\n", __func__, e.what());

    return;
  }

  if (opts.PrintLinkMap)
      HumanOut() << llvm::formatv("[r_debug] r_version = {0}\n"
                                  "          r_map     = {1}\n"
                                  "          r_brk     = {2}\n"
                                  "          r_state   = {3}\n"
                                  "          r_ldbase  = {4}\n",
                                  (void *)r_dbg.r_version,
                                  (void *)r_dbg.r_map,
                                  (void *)r_dbg.r_brk,
                                  (void *)r_dbg.r_state,
                                  (void *)r_dbg.r_ldbase);

  if (IsVerbose()) {
    WARN_ON(r_dbg.r_state != r_debug::RT_CONSISTENT &&
            r_dbg.r_state != r_debug::RT_ADD &&
            r_dbg.r_state != r_debug::RT_DELETE);
  }

  if (!r_dbg.r_map)
    return;

  bool newbin = false;

  struct link_map *lmp = r_dbg.r_map;
  do {
    struct link_map lm;

    try {
      ssize_t ret = _ptrace_memcpy(child, &lm, lmp, sizeof(struct link_map));

      if (ret != sizeof(struct link_map)) {
        HumanOut() << __func__
                   << ": couldn't read link_map structure\n";
        return;
      }
    } catch (const std::exception &e) {
      HumanOut() << llvm::formatv("failed to read link_map: {0}\n", e.what());
      return;
    }

    std::string s;
    try {
      s = _ptrace_read_string(child, reinterpret_cast<uintptr_t>(lm.l_name));
    } catch (const std::exception &e) {
      ;
    }

    if (opts.PrintLinkMap)
      HumanOut() << llvm::formatv("[link_map] l_addr = {0}\n"
                                  "           l_name =\"{1}\"\n"
                                  "           l_prev = {2}\n"
                                  "           l_next = {3}\n"
                                  "           l_ld   = {4}\n",
                                  (void *)lm.l_addr,
                                  s,
                                  (void *)lm.l_prev,
                                  (void *)lm.l_next,
                                  (void *)lm.l_ld);

    if (!s.empty() && s.front() == '/' && fs::exists(s)) {
      fs::path path = s;

      //
      // the following may throw an exception if the current working directory
      // has been deleted
      //
      try { path = fs::canonical(s); } catch (...) {}

      auto it = BinPathToIdxMap.find(path.c_str());
      if (it == BinPathToIdxMap.end()) {
        HumanOut() << llvm::formatv("adding \"{0}\" to jv\n",
                                    path.c_str());
        add_binary(child, tcg, path.c_str());

        newbin = true;
      }
    }

    lmp = lm.l_next;
  } while (lmp && lmp != r_dbg.r_map);

  if (newbin)
    update_view_of_virtual_memory(child);
}

void BootstrapTool::add_binary(pid_t child, tiny_code_generator_t &tcg,
                               const char *path) {
  std::string jvfp = temporary_dir() + path + ".jv";
  fs::create_directories(fs::path(jvfp).parent_path());

  binary_index_t BIdx = jv.Add(path, E);
  state.update();

  binary_t &binary = jv.Binaries[BIdx];
  binary.IsDynamicallyLoaded = true;

  BinFoundVec.resize(BinFoundVec.size() + 1, false);
  BinPathToIdxMap[binary.path_str()] = BIdx;

  //
  // initialize state associated with every binary FIXME
  //
  assert(!binary.IsVDSO);
  BinPathToIdxMap[binary.path_str()] = BIdx;

  construct_fnmap(jv, binary, state.for_binary(binary).fnmap);
  construct_bbmap(jv, binary, state.for_binary(binary).bbmap);

  try {
    state.for_binary(binary).ObjectFile = CreateBinary(binary.data());
  } catch (const std::exception &) {
    HumanOut() << llvm::formatv(
        "{0}: failed to create binary from {1}\n", __func__, binary.path_str());
    return;
  }

  assert(llvm::isa<ELFO>(state.for_binary(binary).ObjectFile.get()));

  ELFO &O = *llvm::cast<ELFO>(state.for_binary(binary).ObjectFile.get());
  const ELFF &Elf = *O.getELFFile();

  loadDynamicTable(&Elf, &O, state.for_binary(binary)._elf.DynamicTable);

  state.for_binary(binary)._elf.OptionalDynSymRegion =
      loadDynamicSymbols(&Elf, &O,
                         state.for_binary(binary)._elf.DynamicTable,
                         state.for_binary(binary)._elf.DynamicStringTable,
                         state.for_binary(binary)._elf.SymbolVersionSection,
                         state.for_binary(binary)._elf.VersionMap);

  loadDynamicRelocations(&Elf, &O,
                         state.for_binary(binary)._elf.DynamicTable,
                         state.for_binary(binary)._elf.DynRelRegion,
                         state.for_binary(binary)._elf.DynRelaRegion,
                         state.for_binary(binary)._elf.DynRelrRegion,
                         state.for_binary(binary)._elf.DynPLTRelRegion);
}

void BootstrapTool::on_dynamic_linker_loaded(pid_t child,
                                             binary_index_t BIdx,
                                             const proc_map_t &proc_map) {
  binary_t &b = jv.Binaries[BIdx];

  if (state.for_binary(b)._elf.OptionalDynSymRegion) {
    auto DynSyms = state.for_binary(b)._elf.OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();

    for (const Elf_Sym &Sym : DynSyms) {
      if (Sym.isUndefined())
        continue;

      llvm::Expected<llvm::StringRef> ExpectedSymName = Sym.getName(state.for_binary(b)._elf.DynamicStringTable);
      if (!ExpectedSymName)
        continue;

      llvm::StringRef SymName = *ExpectedSymName;
      if (SymName == "_r_debug" ||
          SymName == "_dl_debug_addr") {
        WARN_ON(Sym.getType() != llvm::ELF::STT_OBJECT);

        _r_debug.Addr = va_of_rva(Sym.st_value, BIdx);
        _r_debug.Found = true;

        rendezvous_with_dynamic_linker(child);
        goto Found;
      }
    }
  }

  //
  // if we get here, we didn't find _r_debug
  //
  HumanOut() << llvm::formatv("{0}: could not find _r_debug\n",
                              __func__);

Found:
  ;
}

void BootstrapTool::rendezvous_with_dynamic_linker(pid_t child) {
  if (!_r_debug.Found)
    return;

  //
  // _r_debug is the "Rendezvous structure used by the run-time dynamic linker
  // to communicate details of shared object loading to the debugger."
  //
  if (!_r_debug.r_brk) {
    struct r_debug r_dbg;

    ssize_t ret;
    try {
      ret = _ptrace_memcpy(child, &r_dbg, (void *)_r_debug.Addr, sizeof(struct r_debug));
    } catch (const std::exception &e) {
      if (IsVerbose())
        HumanOut() << llvm::formatv("failed to read r_debug structure: {0}\n",
                                    e.what());
      return;
    }

    if (ret != sizeof(struct r_debug)) {
      if (ret < 0) {
        int err = errno;
        HumanOut() << llvm::formatv("couldn't read r_debug structure ({0})\n",
                                    strerror(err));
      } else {
        HumanOut() << llvm::formatv("couldn't read r_debug structure [{0}]\n",
                                    ret);
      }
      return;
    }

    if (unlikely(IsVerbose()) && unlikely(r_dbg.r_brk))
      HumanOut() << llvm::formatv("r_brk={0:x}\n", r_dbg.r_brk);

    _r_debug.r_brk = r_dbg.r_brk;
  }

  if (_r_debug.r_brk) {
    if (unlikely(BrkMap.find(_r_debug.r_brk) == BrkMap.end()) && opts.RtldDbgBrk) {
      try {
        breakpoint_t brk;
        brk.callback = std::bind(&BootstrapTool::scan_rtld_link_map, this, std::placeholders::_1, std::placeholders::_2);
        brk.InsnBytes.resize(2 * sizeof(uint32_t));
        _ptrace_memcpy(child, &brk.InsnBytes[0], (void *)_r_debug.r_brk, brk.InsnBytes.size());

        {
          uint64_t InstLen = 0;
          bool Disassembled = disas.DisAsm->getInstruction(
              brk.Inst,
              InstLen,
              brk.InsnBytes,
              0 /* XXX should not matter */,
              llvm::nulls());

          if (unlikely(!Disassembled))
            throw std::runtime_error("could not disassemble instruction at "
                                     "address pointed to by _r_debug.r_brk");

        }
#if defined(__mips64) || defined(__mips__)
        //
        // disassemble delay slot
        //
        {
          uint64_t InstLen = 0;
          bool Disassembled =
              disas.DisAsm->getInstruction(brk.DelaySlotInst,
                                           InstLen,
                                           llvm::ArrayRef<uint8_t>(brk.InsnBytes).slice(4),
                                           4 /* should not matter */,
                                           llvm::nulls());
        }
#endif

        place_breakpoint(child, _r_debug.r_brk, brk);

        BrkMap.insert({_r_debug.r_brk, brk});
      } catch (const std::exception &e) {
        if (IsVerbose())
          HumanOut() << llvm::formatv(
              "{0}: couldn't place breakpoint at r_brk [{1:x}] ({2})\n",
              __func__,
              _r_debug.r_brk,
              e.what());
      }
    }
  }
}

void BootstrapTool::on_return(pid_t child,
                              uintptr_t AddrOfRet,
                              uintptr_t RetAddr,
                              tiny_code_generator_t &tcg) {
  if (unlikely(!opts.Quiet && !ShowMeN && ShowMeA))
    HumanOut() << llvm::formatv(__ANSI_YELLOW "(ret) {0} <-- {1}" __ANSI_NORMAL_COLOR "\n",
                                  description_of_program_counter(RetAddr),
                                  description_of_program_counter(AddrOfRet));
  //
  // examine AddrOfRet
  //
  if (AddrOfRet)
  {
    uintptr_t pc = AddrOfRet;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    pc &= ~1UL;
#endif

    binary_index_t BIdx = invalid_binary_index;
    {
      auto it = AddressSpace.find(pc);
      if (it == AddressSpace.end()) {
        update_view_of_virtual_memory(child);
        it = AddressSpace.find(pc);
      }

      if (it == AddressSpace.end()) {
        HumanOut()
            << llvm::formatv("{0}: (1) unknown binary for {1}\n", __func__,
                             description_of_program_counter(pc, true));

        if (IsVerbose())
          HumanOut() << ProcMapsForPid(child);
      } else {
        BIdx = -1+(*it).second;

        binary_t &binary = jv.Binaries.at(BIdx);
        auto &bbmap = state.for_binary(binary).bbmap;
        auto &ICFG = binary.Analysis.ICFG;

        uintptr_t rva = rva_of_va(pc, BIdx);

        auto it = bbmap.find(rva);
        assert(it != bbmap.end());
        basic_block_index_t bbidx = (*it).second - 1;
        basic_block_t bb = boost::vertex(bbidx, ICFG);

        assert(ICFG[bb].Term.Type == TERMINATOR::RETURN);
        ICFG[bb].Term._return.Returns = true;
      }
    }
  }

  //
  // examine RetAddr; we know this is the start of a block
  //
  if (RetAddr)
  {
    uintptr_t pc = RetAddr;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    pc &= ~1UL;
#endif

    binary_index_t BIdx = invalid_binary_index;
    {
      auto it = AddressSpace.find(pc);
      if (it == AddressSpace.end()) {
        update_view_of_virtual_memory(child);
        it = AddressSpace.find(pc);
      }

      if (it == AddressSpace.end()) {
        HumanOut()
            << llvm::formatv("{0}: (2) unknown binary for {1}\n", __func__,
                             description_of_program_counter(pc, true));
        if (IsVerbose())
          HumanOut() << ProcMapsForPid(child);
      } else {
        BIdx = -1+(*it).second;

        try {
        binary_t &binary = jv.Binaries.at(BIdx);
        auto &bbmap = state.for_binary(binary).bbmap;
        auto &ICFG = binary.Analysis.ICFG;

        if (!state.for_binary(binary).ObjectFile.get()) {
          if (!binary.IsVDSO)
            HumanOut()
                << llvm::formatv("{0}: (3) unknown RetAddr {1}\n", __func__,
                                 description_of_program_counter(pc, true));
          return;
        }

        uintptr_t rva = rva_of_va(pc, BIdx);

        unsigned brkpt_count = 0;
        basic_block_index_t next_bb_idx =
            E.explore_basic_block(binary, *state.for_binary(binary).ObjectFile,
                                  rva,
                                  state.for_binary(binary).fnmap,
                                  state.for_binary(binary).bbmap,
                                  std::bind(&BootstrapTool::on_new_basic_block, this, std::placeholders::_1, std::placeholders::_2));
        if (is_basic_block_index_valid(next_bb_idx)) {
          basic_block_t bb;

          {
            constexpr unsigned delay_slot =
#if defined(__mips64) || defined(__mips__)
                4
#else
                0
#endif
                ;

            auto it = bbmap.find(rva - delay_slot - 1);
            if (it == bbmap.end()) {
              //
              // we have no preceeding call
              //
              if (IsVerbose())
                HumanOut() << llvm::formatv(
                    "{0}: could not find preceeding call @ {1:x}\n", __func__,
                    rva);
              return;
            }

            basic_block_index_t bbidx = (*it).second - 1;
            bb = boost::vertex(bbidx, ICFG);
          }

          bool isCall = ICFG[bb].Term.Type == TERMINATOR::CALL;
          bool isIndirectCall = ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL;

          if (!isCall && !isIndirectCall) { /* this can occur on i386 because of
                                               hack in tcg.hpp */
            if (IsVerbose())
              HumanOut() << llvm::formatv("on_return: unexpected terminator {0}\n",
                                          description_of_terminator(ICFG[bb].Term.Type));
            return;
          }

          assert(isCall || isIndirectCall);
          assert(boost::out_degree(bb, ICFG) == 0 ||
                 boost::out_degree(bb, ICFG) == 1);

          if (isCall) {
            ICFG[bb].Term._call.Returns = true;
            if (is_function_index_valid(ICFG[bb].Term._call.Target))
              binary.Analysis.Functions.at(ICFG[bb].Term._call.Target).Returns =
                  true;
          }

          if (isIndirectCall)
            ICFG[bb].Term._indirect_call.Returns = true;

          basic_block_t next_bb = boost::vertex(next_bb_idx, ICFG);
          if (boost::add_edge(bb, next_bb, ICFG).second)
            invalidateAnalyses = true;
        }

        if (brkpt_count > 0)
          HumanOut() << llvm::formatv("placed {0} breakpoint{1} in {2}\n",
                                      brkpt_count,
                                      brkpt_count > 1 ? "s" : "",
                                      binary.path_str());
        } catch (const std::exception &e) {
          std::string s = fs::path(jv.Binaries[BIdx].path_str()).filename().string();
          HumanOut()
              << llvm::formatv("{0} failed: {1} [RetAddr: {2}+{3:x} ({4:x})]\n",
                               __func__, e.what(), s, rva_of_va(pc, BIdx), pc);
        }
      }
    }
  }
}

std::string _ptrace_read_string(pid_t child, uintptr_t Addr) {
  std::string res;

  for (;;) {
    auto word = _ptrace_peekdata(child, Addr);

    for (unsigned i = 0; i < sizeof(word); ++i) {
      char ch = reinterpret_cast<char *>(&word)[i];
      if (ch == '\0')
        return res;
      res.push_back(ch);
    }

    Addr += sizeof(word);
  }

  return res;
}

std::string StringOfMCInst(llvm::MCInst &Inst, disas_t &disas) {
  std::string res;

  {
    llvm::raw_string_ostream ss(res);

    disas.IP->printInst(&Inst, 0x0 /* XXX */, "", *disas.STI, ss);

#if 0
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
#endif
  }

  return res;
}

std::string BootstrapTool::description_of_program_counter(uintptr_t pc, bool Verbose) {
#if 0 /* defined(__mips64) || defined(__mips__) */
  if (ExecutableRegionAddress &&
      pc >= ExecutableRegionAddress &&
      pc < ExecutableRegionAddress + 8) {
    uintptr_t off = pc - ExecutableRegionAddress;
    return (fmt("[exeregion]+%#lx") % off).str();
  }
#endif
  std::string simple_desc = (fmt("%#lx") % pc).str();

  auto pm_it = pmm.find(pc);
  if (pm_it == pmm.end()) {
    return simple_desc;
  } else {
    std::string extra =
        Verbose || opts.VeryVerbose ? (" (" + simple_desc + ")") : "";

    const proc_map_set_t &pms = (*pm_it).second;
    assert(pms.size() == 1);

    const proc_map_t &pm = *pms.begin();

    if (pm.nm.empty())
      return (fmt("%#lx+%#lx%s") % pm.beg % (pc - pm.beg) % extra).str();

    auto b_it = BinPathToIdxMap.find(pm.nm);
    if (b_it == BinPathToIdxMap.end())
      return (fmt("%s+%#lx%s") % pm.nm % (pc - (pm.beg - pm.off)) % extra).str();

    binary_index_t BIdx = (*b_it).second;
    if (!BinFoundVec.test(BIdx))
      HumanOut()
          << __func__
          << ": inconsistency with (BinFoundVec, pmm) (BUG)\n";

    auto as_it = AddressSpace.find(pc);
    if (as_it == AddressSpace.end() || -1+(*as_it).second != BIdx)
      HumanOut()
          << __func__
          << ": inconsistency with (BinFoundVec, pmm, AddressSpace) (BUG)\n";

    uintptr_t rva = rva_of_va(pc, BIdx);
    std::string str = fs::path(pm.nm).filename().string();

    return (fmt("%s+%#lx%s") % str % rva % extra).str();
  }
}

ssize_t _ptrace_memcpy(pid_t child, void *dest, const void *src, size_t n) {
  std::vector<uint8_t> buff;
  buff.reserve(n);

  uintptr_t Addr = reinterpret_cast<uintptr_t>(src);

  for (;;) {
    auto word = _ptrace_peekdata(child, Addr);

    for (unsigned i = 0; i < sizeof(word); ++i) {
      buff.push_back(reinterpret_cast<uint8_t *>(&word)[i]);
      if (buff.size() == n) {
        memcpy(dest, &buff[0], n); /* we're done */
        return n;
      }
    }

    Addr += sizeof(word);
  }

  __builtin_trap();
  __builtin_unreachable();
}

void arch_put_breakpoint(void *code) {
#if defined(__x86_64__) || defined(__i386__)
  reinterpret_cast<uint8_t *>(code)[0] = 0xcc; /* int3 */
#elif defined(__aarch64__)
  reinterpret_cast<uint32_t *>(code)[0] = 0xd4200000; /* brk */
#elif defined(__mips64) || defined(__mips__)
  reinterpret_cast<uint32_t *>(code)[0] = 0x00ff000d; /* break 0xff */
#else
#error
#endif
}

std::string ProcMapsForPid(pid_t pid) {
  std::string path = "/proc/" + std::to_string(pid) + "/maps";
  return read_file_into_string(path.c_str());
}

void SignalHandler(int no) {
  assert(pTool);
  BootstrapTool &tool = *pTool;

  switch (no) {
  case SIGABRT:
  case SIGSEGV: {
    tool.HumanOut() << "***JOVE*** bootstrap crashed! detaching from tracee...\n";

    //
    // detach from tracee
    //
    if (::ptrace(PTRACE_DETACH, tool.saved_child, 0UL, 0UL) < 0) {
      int err = errno;
      tool.HumanOut() << llvm::formatv(
          "failed to detach from tracee [{0}]: {1}\n",
          tool.saved_child,
          strerror(err));
      exit(1);
    }

    tool.HumanOut() << llvm::formatv(
        "***JOVE*** bootstrap crashed! attach a debugger [{0}]...", getpid());

    for (;;) {
      sleep(1);

      tool.HumanOut() << ".";
    }

    __builtin_unreachable();
  }

  case SIGUSR1:
    tool.ToggleTurbo.store(true);
    break;

  //
  // SIGUSR2: write jv and exit
  //
  case SIGUSR2: {
    tool.HumanOut() << "writing jv and exiting...\n";

    //
    // write jv
    //
    SerializeJVToFile(tool.jv, "/tmp/serialized.jv");

    exit(0);
  }

  default:
    abort();
  }

  if (tool.saved_child) {
    //
    // instigate a ptrace-stop
    //
    if (::kill(tool.saved_child, SIGSTOP /* SIGWINCH */) < 0) {
      int err = errno;
      tool.HumanOut() << llvm::formatv("kill of {0} failed: {1}\n",
                                       tool.saved_child, strerror(err));
    }
  }
}

}

#else

//
// target architecture != host architecture
//
#include "tool.h"

namespace jove {

struct BootstrapTool : public Tool {
  int Run(void) {
    HumanOut() << "bootstrap: host architecture != target\n";
    return 1;
  }
};

JOVE_REGISTER_TOOL("bootstrap", BootstrapTool);

}

#endif

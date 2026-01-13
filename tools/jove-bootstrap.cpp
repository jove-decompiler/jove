#if (defined(__x86_64__)  && defined(TARGET_X86_64))  || \
    (defined(__i386__)    && defined(TARGET_I386))    || \
    (defined(__aarch64__) && defined(TARGET_AARCH64)) || \
    (defined(__mips64)    && defined(TARGET_MIPS64))  || \
    (defined(__mips__)    && defined(TARGET_MIPS32))
#include "tool.h"
#include "B.h"
#include "tcg.h"
#include "disas.h"
#include "explore.h"
#include "crypto.h"
#include "util.h"
#include "vdso.h"
#include "symbolizer.h"
#include "serialize.h"
#include "warn.h"
#include "ansi.h"
#include "ptrace.h"
#include "robust.h"
#include "fork.h"
#include "pidfd.h"
#include "autoreap.h"
#include "emulate.h"
#include "fallthru.h"
#include "wine.h"
#include "jove/assert.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>
#include <boost/lockfree/queue.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/anonymous_shared_memory.hpp>
#include <boost/range/adaptor/reversed.hpp>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/ScopedPrinter.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/WithColor.h>

#include <bit>
#include <array>
#include <cinttypes>
#include <mutex>
#include <condition_variable>

#include <asm/auxvec.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

static const char *syscall_names[] = {
#define ___SYSCALL(nr, nm) [nr] = #nm,
#include "syscalls.inc.h"
};

//#define JOVE_HAVE_MEMFD

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

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

  bool operator<(const proc_map_t &pm) const { return beg < pm.beg; }
};

using indirect_branch_t = trapped_t;
using return_t          = trapped_t;
using breakpoint_t      = trapped_t;

struct child_syscall_state_t {
  unsigned no;
  unsigned long a1, a2, a3, a4, a5, a6;
  unsigned int dir : 1;

  unsigned long pc;

  child_syscall_state_t() : dir(0), pc(0) {}
};

struct binary_state_t {
  bool Skip = false;

  uintptr_t LoadAddr = std::numeric_limits<uintptr_t>::max();
  uintptr_t LoadOffset = std::numeric_limits<uintptr_t>::max();

  bool Loaded(void) const {
    return LoadAddr != std::numeric_limits<uintptr_t>::max() &&
           LoadOffset != std::numeric_limits<uintptr_t>::max();
  }

  B::unique_ptr Bin;
  struct {
    elf::DynRegionInfo DynamicTable;
    llvm::StringRef DynamicStringTable;
    const Elf_Shdr *SymbolVersionSection;
    std::vector<elf::VersionMapEntry> VersionMap;
    std::optional<elf::DynRegionInfo> OptionalDynSymRegion;

    elf::DynRegionInfo DynRelRegion;
    elf::DynRegionInfo DynRelaRegion;
    elf::DynRegionInfo DynRelrRegion;
    elf::DynRegionInfo DynPLTRelRegion;
  } _elf;

  binary_state_t(const auto &b) {
    Bin = B::Create(b.data());

    B::_elf(Bin.get(), [&](ELFO &Obj) {
    elf::loadDynamicTable(Obj, _elf.DynamicTable);

    _elf.OptionalDynSymRegion =
        loadDynamicSymbols(Obj,
                           _elf.DynamicTable,
                           _elf.DynamicStringTable,
                           _elf.SymbolVersionSection,
                           _elf.VersionMap);

    loadDynamicRelocations(Obj,
                           _elf.DynamicTable,
                           _elf.DynRelRegion,
                           _elf.DynRelaRegion,
                           _elf.DynRelrRegion,
                           _elf.DynPLTRelRegion);
    });
  }
};

struct notrap_exception {
  uintptr_t pc;
};

struct BootstrapTool
    : public StatefulJVTool<ToolKind::Standard, binary_state_t, void, void> {
  struct Cmdline {
    cl::opt<std::string> Prog;
    cl::list<std::string> Args;
    cl::list<std::string> Envs;
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
    cl::alias PrintLinkMapAlias;
    cl::opt<unsigned> PID;
    cl::alias PIDAlias;
    cl::opt<bool> Fast;
    cl::alias FastAlias;
    cl::opt<bool> Longjmps;
    cl::opt<std::string> ShowMe;
    cl::opt<bool> Symbolize;
    cl::opt<bool> Addr2Line;
    cl::opt<std::string> Group;
    cl::alias GroupAlias;
    cl::opt<std::string> User;
    cl::alias UserAlias;
    cl::list<std::string> SkipBins;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)),

          Args("args", cl::CommaSeparated, cl::ConsumeAfter,
               cl::desc("<program arguments>..."), cl::cat(JoveCategory)),

          Envs("env", cl::CommaSeparated,
               cl::value_desc("KEY_1=VALUE_1,KEY_2=VALUE_2,...,KEY_n=VALUE_n"),
               cl::desc("Extra environment variables"), cl::cat(JoveCategory)),

          Quiet("quiet", cl::desc("Suppress non-error messages"),
                cl::cat(JoveCategory), cl::init(false)),

          QuietAlias("q", cl::desc("Alias for -quiet."), cl::aliasopt(Quiet),
                     cl::cat(JoveCategory)),

          HumanOutput("human-output",
                      cl::desc("Print messages to the given file path"),
                      cl::cat(JoveCategory)),

          RtldDbgBrk("rtld-dbg-brk", cl::desc("look for r_debug::r_brk"),
                     cl::cat(JoveCategory)),

          PrintPtraceEvents("events",
                            cl::desc("Print PTRACE events when they occur"),
                            cl::cat(JoveCategory)),

          PrintPtraceEventsAlias("e", cl::desc("Alias for -events."),
                                 cl::aliasopt(PrintPtraceEvents),
                                 cl::cat(JoveCategory)),

          Addr2Line("addr2line", cl::desc("Run addr2line to symbolize"),
                   cl::cat(JoveCategory)),

          Syscalls("syscalls", cl::desc("Always trace system calls"),
                   cl::cat(JoveCategory)),

          SyscallsAlias("s", cl::desc("Alias for -syscalls."),
                        cl::aliasopt(Syscalls), cl::cat(JoveCategory)),

          Signals("signals", cl::desc("Print when delivering signals"),
                  cl::cat(JoveCategory)),

          PrintLinkMap("print-link-map", cl::desc("Always scan link map"),
                       cl::cat(JoveCategory)),

          PrintLinkMapAlias("l", cl::desc("Alias for -print-link-map."),
                            cl::aliasopt(PrintLinkMap), cl::cat(JoveCategory)),

          PID("attach", cl::desc("attach to existing process PID"),
              cl::cat(JoveCategory), cl::init(0)),

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
                 cl::cat(JoveCategory)),

          Symbolize("symbolize", cl::desc("Whether to run addr2line"),
                    cl::init(true), cl::cat(JoveCategory)),

          Group("group", cl::desc("Run as given group"), cl::cat(JoveCategory)),

          GroupAlias("g", cl::desc("Alias for --group"), cl::aliasopt(Group),
                     cl::cat(JoveCategory)),

          User("user", cl::desc("Run as given user"), cl::cat(JoveCategory)),

          UserAlias("u", cl::desc("Alias for --user"), cl::aliasopt(User),
                    cl::cat(JoveCategory)),

          SkipBins("skip-binaries", cl::CommaSeparated, cl::value_desc("name"),
                   cl::cat(JoveCategory)) {}
  } opts;

  template <typename Key, typename Value>
  using unordered_map = boost::unordered::unordered_flat_map<Key, Value>;

  template <typename T>
  using unordered_set = boost::unordered::unordered_flat_set<T>;

  bool RightArch = true;
  const bool IsCOFF;
  bool ForkFirstTime = true;
  unordered_set<pid_t> forked;
  unordered_set<pid_t> exited;

  std::unique_ptr<ptrace_emulator_t<IsToolMT, IsToolMinSize>> emulator;

  std::unique_ptr<tiny_code_generator_t> tcg;
  std::unique_ptr<disas_t> disas;
  std::unique_ptr<symbolizer_t> symbolizer;
  std::unique_ptr<explorer_t<IsToolMT, IsToolMinSize>> E;

  std::vector<struct proc_map_t> cached_proc_maps;

  typedef boost::container::flat_map<addr_intvl, unsigned, addr_intvl_cmp>
      pmm_t;

  pmm_t pmm;

  unordered_set<binary_index_t> Loaded;
  bool AllLoaded(void) const { return Loaded.size() == jv.Binaries.size(); }

  address_space_t AddressSpace;

  struct {
    std::string path_to_debug_log;
  } _coff;

  unsigned TurboToggle = 0;

  static constexpr int ptrace_options =
      PTRACE_O_TRACESYSGOOD
    | PTRACE_O_EXITKILL
    | PTRACE_O_TRACEEXIT
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
  ;

  pid_t _child = 0; /* XXX */

  std::set<pid_t> children;

  unordered_map<uintptr_t, trapped_t> trapmap;

  struct {
    bool Found = false;

    void *ptr = nullptr;
    uintptr_t brk = 0;

    void Reset(void) {
      Found = false;

      ptr = nullptr;
      brk = 0;
    }
  } _r_debug;

  unordered_map<pid_t, child_syscall_state_t> children_syscall_state;

  bool ShowMeN = false;
  bool ShowMeA = false;
  bool ShowMeS = false;

  void on_new_binary(binary_t &b) {
    const binary_index_t BIdx = index_of_binary(b, jv);

    assert(is_binary_index_valid(BIdx));

    b.IsDynamicallyLoaded = true;

    if (IsVerbose())
      HumanOut() << llvm::formatv("added {0}\n", b.Name.c_str());
  }

  void Reset(void) noexcept {
    RightArch = true;

    trapmap.clear();
    Loaded.clear();
    cached_proc_maps.clear();
    pmm.clear();
    AddressSpace.clear();
    children_syscall_state.clear();

    _r_debug.Reset();

    emulator->ExecutableRegionAddress = 0x0;
    TurboToggle = 0;
  }

public:
  BootstrapTool()
      : opts(JoveCategory),
        IsCOFF(B::is_coff(state.for_binary(jv.Binaries.at(0)).Bin.get())) {}

  int Run(void) override;

  int TracerLoop(pid_t child);

  // breakpoints aren't placed until on_binary_loaded()

  template <bool ValidatePath>
  binary_index_t BinaryFromPath(pid_t, const char *path);
  binary_index_t BinaryFromData(pid_t, std::string_view data,
                                const char *name = nullptr);

  void on_new_basic_block(binary_t &, bbprop_t &, basic_block_index_t);
  void on_new_function(binary_t &, function_t &);

  void place_breakpoint_at_indirect_branch(pid_t, uintptr_t Addr,
                                           indirect_branch_t &);

  void place_breakpoint_at_return(pid_t child, uintptr_t Addr, return_t &Ret);

  void on_binary_loaded(pid_t, binary_index_t, const proc_map_t &);

  void on_dynamic_linker_loaded(pid_t, binary_index_t, const proc_map_t &);

  trapped_t &place_breakpoints_in_block(binary_t &, bbprop_t &, basic_block_index_t);
  void place_breakpoint(pid_t, uintptr_t Addr, breakpoint_t &);
  void on_breakpoint(pid_t, ptrace::tracee_state_t &);
  void on_return(pid_t child,
                 binary_index_t RetBIdx,
                 uintptr_t AddrOfRet,
                 uintptr_t RetAddr);

  void rendezvous_with_dynamic_linker(pid_t);
  void scan_rtld_link_map(pid_t);

  bool UpdateVM(pid_t);
  void ScanAddressSpace(pid_t child, bool VMUpdate = true);

  uintptr_t pc_of_offset(uintptr_t off, binary_index_t BIdx);
  uintptr_t pc_of_va(uintptr_t Addr, binary_index_t BIdx);
  uintptr_t va_of_pc(uintptr_t Addr, binary_index_t BIdx);

  binary_index_t binary_at_program_counter(pid_t, uintptr_t valid_pc);
  block_t
  block_at_program_counter(pid_t, uintptr_t valid_pc);
  std::pair<binary_index_t, function_index_t>
  function_at_program_counter(pid_t, uintptr_t valid_pc);

  std::pair<binary_index_t, basic_block_index_t>
  existing_block_at_program_counter(pid_t child, uintptr_t pc);

  std::string description_of_program_counter(uintptr_t, bool Verbose = false, bool Symbolize = true);
  std::string StringOfMCInst(llvm::MCInst &);

  pid_t saved_child = -1;
  std::atomic<bool> ToggleTurbo = false;

  static_assert(sizeof(binary_index_t) + sizeof(basic_block_index_t) == 8);

  bool DidAttach(void) {
    return opts.PID != 0;
  }

  void DropPrivileges(void);
};

JOVE_REGISTER_TOOL("bootstrap", BootstrapTool);

typedef boost::format fmt;

static inline void print_command(const char **argv) {
  for (const char **argp = argv; *argp; ++argp) {
    llvm::errs() << *argp;

    if (*(argp + 1))
      llvm::errs() << ' ';
  }

  llvm::errs() << '\n';
}

static std::string ProcMapsForPid(pid_t);

static BootstrapTool *pTool;
static void SignalHandler(int no);

int BootstrapTool::Run(void) {
  pTool = this;

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
  if (ShouldSleepOnCrash()) {
    INSTALL_SIG(SIGSEGV);
    INSTALL_SIG(SIGABRT);
  }

  AutomaticallyReap();

  if (IsCOFF)
    _coff.path_to_debug_log = temporary_dir() + "/stderr";

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

    return TracerLoop(child);
  }

  //
  // mode 2: create new process
  //
  const pid_t child = saved_child = ({
    std::string path_to_exe;
    try {
      path_to_exe = fs::canonical(opts.Prog).string();
    } catch (...) {
      WithColor::error() << llvm::formatv(
          "failed to canonicalize given path (\"{0}\")\n", opts.Prog);
      return 1;
    }

    if (!fs::exists(path_to_exe)) {
      WithColor::error() << llvm::formatv(
          "no executable at given path (\"{0}\")\n", path_to_exe);
      return 1;
    }

    if (!fs::equivalent(path_to_exe, jv.Binaries.at(0).path_str())) {
      WithColor::error() << llvm::formatv("unexpected executable \"{0}\"\n",
                                          jv.Binaries.at(0).Name.c_str());
      return 1;
    }

#ifdef JOVE_HAVE_MEMFD
    scoped_fd memfd;
    if (!IsCOFF) {
      std::string name = "jove/bootstrap" + jv.Binaries.at(0).path_str();
      memfd = ::memfd_create(name.c_str(), 0);
      assert(memfd);

      const unsigned N = jv.Binaries.at(0).Data.size();
      if (robust::write(memfd.get(), &jv.Binaries.at(0).Data[0], N) == N)
        path_to_exe = "/proc/self/fd/" + std::to_string(memfd.get());
    }
#endif

    if (IsVerbose())
      HumanOut() << llvm::formatv("parent: running {0}\n", path_to_exe);

    struct {
      std::string path_to_wine;
      std::string path_to_exe;
    } _coff;

    if (IsCOFF) {
      _coff.path_to_wine = locator().wine(IsTarget32);
      _coff.path_to_exe = path_to_exe;
    }

    if (::chmod(temporary_dir().c_str(), 0777) < 0)
      throw std::runtime_error(
          "failed to change permissions of temporary directory: " +
          std::string(strerror(errno)));

    RunExecutable(
        IsCOFF ? locator().wine(IsTarget32) : path_to_exe,
        [&](auto Arg) {
          if (IsCOFF) {
            Arg(std::move(_coff.path_to_wine));
            Arg(std::move(_coff.path_to_exe));
          } else {
            Arg(std::move(opts.Prog));
          }
          for (auto &x : opts.Args)
            Arg(std::move(x));
        },
        [&](auto Env) {
          for (char **env = ::environ; *env; ++env)
            Env(*env);
          SetupEnvironForRun(Env);
          for (auto &y : opts.Envs)
            Env(std::move(y));

          if (fs::exists("/firmadyne/libnvram.so"))
            Env("LD_PRELOAD=/firmadyne/libnvram.so");

#if 0
          std::string wine_stderr_path = temporary_dir() + "/wine.stderr";
          if (IsVerbose())
            WithColor::note()
                << llvm::formatv("WINEDEBUGLOG={0}\n", wine_stderr_path);

          // FIXME look for preexisting WINEDEBUG?
          Env("WINEDEBUG=+module,+loaddll,+err,+process,+seh");
          Env("WINEDEBUGLOG=" + wine_stderr_path);
#endif
        },
        "", "",
        [&](const char **argv, const char **envp) {
          if (IsVerbose())
            print_command(argv);

          //
          // the request
          //
          ::ptrace(PTRACE_TRACEME);
          //
          // turns the calling thread into a tracee.  the thread continues to
          // run (doesn't enter ptrace-stop).  a common practice is to follow
          // the PTRACE_TRACEME with raise(SIGSTOP), but if we did that here
          // the parent would wait forever for the exec to (never) happen.
          //
          // we'll rely on the SIGTRAP being sent following a successful execve.
          //

          DropPrivileges();
        });
  });

  //
  // observe the (initial) stop
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

  //
  // initialize objects required for exploration.
  //
  disas = std::make_unique<disas_t>();
  tcg = std::make_unique<tiny_code_generator_t>();
  if (opts.Symbolize) {
  symbolizer = std::make_unique<symbolizer_t>(locator(), opts.Addr2Line);
  }
  E = std::make_unique<explorer_t<IsToolMT, IsToolMinSize>>(
      jv_file, jv, *disas, *tcg, GetVerbosityLevel());
  emulator =
      std::make_unique<ptrace_emulator_t<IsToolMT, IsToolMinSize>>(jv, *disas);
  emulator->SetVerbosityLevel(GetVerbosityLevel());
  E->set_newbb_proc(std::bind(&BootstrapTool::on_new_basic_block, this,
                              std::placeholders::_1,
                              std::placeholders::_2,
                              std::placeholders::_3));
  E->set_newfn_proc(std::bind(&BootstrapTool::on_new_function, this,
                              std::placeholders::_1,
                              std::placeholders::_2));

  //
  // look around, what do we see?
  //
  _child = child;
  ScanAddressSpace(child);

  if (IsVerbose()) {
    //
    // we should be at the entry point of the dynamic linker
    //
    ptrace::tracee_state_t tracee_state;
    ptrace::get(child, tracee_state);

    if (IsVerbose())
      HumanOut() << llvm::formatv(
          "first ptrace-stop @ {0}\n",
          description_of_program_counter(
              ptrace::pc_of_tracee_state(tracee_state), true));

    auto BBPair = block_at_program_counter(
        child, ptrace::pc_of_tracee_state(tracee_state));

    if (unlikely(!is_basic_block_index_valid(BBPair.second)))
      HumanOut() << llvm::formatv(
          "failed to translate block at first ptrace-stop @ {0}\n",
          description_of_program_counter(
              ptrace::pc_of_tracee_state(tracee_state), true));
  }

  //
  // establish options
  //
  if (::ptrace(PTRACE_SETOPTIONS, child, 0UL, ptrace_options) < 0) {
    int err = errno;
    HumanOut() << llvm::formatv("{0}: PTRACE_SETOPTIONS failed ({1})\n",
                                __func__, strerror(err));
  }

  return TracerLoop(child);
}

uintptr_t BootstrapTool::pc_of_offset(uintptr_t off, binary_index_t BIdx) {
  binary_t &binary = jv.Binaries.at(BIdx);
  auto &x = state.for_binary(binary);

  if (!x.Loaded())
    throw std::runtime_error(std::string(__func__) + ": given binary (" +
                             binary.Name.c_str() + " is not loaded\n");

  return off + (x.LoadAddr - x.LoadOffset);
}

uintptr_t BootstrapTool::pc_of_va(uintptr_t Addr, binary_index_t BIdx) {
  binary_t &binary = jv.Binaries.at(BIdx);
  auto &x = state.for_binary(binary);

  if (!x.Loaded())
    throw std::runtime_error(std::string(__func__) + ": given binary (" +
                             binary.Name.c_str() + " is not loaded\n");

  if (!binary.IsPIC) {
    //assert(binary.IsExecutable);
    return Addr;
  }

  uint64_t off = B::offset_of_va(x.Bin.get(), Addr);
  return off + (x.LoadAddr - x.LoadOffset);
}

uintptr_t BootstrapTool::va_of_pc(uintptr_t pc, binary_index_t BIdx) {
  binary_t &binary = jv.Binaries.at(BIdx);
  auto &x = state.for_binary(binary);

  if (!x.Loaded())
    throw std::runtime_error(std::string(__func__) + ": given binary (" +
                             binary.Name.c_str() + " is not loaded\n");

  if (!binary.IsPIC) {
    //assert(binary.IsExecutable);
    return pc;
  }

  uint64_t off = pc - (x.LoadAddr - x.LoadOffset);
  return B::va_of_offset(x.Bin.get(), off);
}

int BootstrapTool::TracerLoop(pid_t child) {
  siginfo_t si;
  long sig = 0;

  {
    for (;;) {
      if (likely(!(child < 0))) {
        if (unlikely(::ptrace((RightArch && opts.Syscalls) ? PTRACE_SYSCALL : PTRACE_CONT,
                              child, nullptr,
                              reinterpret_cast<void *>(sig)) < 0))
          HumanOut() << llvm::formatv("failed to resume tracee {0}: {1}\n",
                                      child, strerror(errno));
      }

      //
      // reset restart signal
      //
      sig = 0;

      //
      // wait for a child process to stop or terminate
      //
      int status;
      child = saved_child = _jove_sys_wait4(-1, &status, __WALL, NULL);
      if (unlikely(child < 0)) {
        const int err = -child;
        assert(err != EINTR);

        if (IsVerbose())
          HumanOut() << llvm::formatv("exiting... ({0})\n", strerror(err));

        break;
      }

      children.insert(child);
      _child = child; /* XXX */

      if (likely(WIFSTOPPED(status))) {
        //
        // this is an opportunity to examine the state of the tracee
        //
        if (unlikely(forked.contains(child))) {
          const pid_t new_child = child;

          forked.erase(new_child);

          if (IsVeryVerbose())
            llvm::errs() << llvm::formatv("waited on forked child. [{0}]\n", child);

          //
          // upon a fork(), we detach, fork(), and then reattach.
          //
          if (::ptrace(PTRACE_DETACH, new_child, 0UL, reinterpret_cast<void *>(SIGSTOP)) < 0) {
            int err = errno;
            die("PTRACE_DETACH on fork(): " + std::string(strerror(err)));
          } else {
            if (IsVeryVerbose())
              llvm::errs() << llvm::formatv("detached [{0}]\n", new_child);
          }

          scoped_fd our_pfd(pidfd_open(::getpid(), 0));
          if (jove::fork()) {
            child = -1;
          } else {
            if (::prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
              int err = errno;
              if (IsVerbose())
                WithColor::warning()
                    << llvm::formatv("prctl failed: {0}\n", strerror(err));
            }

            if (our_pfd) {
              const int poll_ret = ({
                struct pollfd pfd = {.fd = our_pfd.get(), .events = POLLIN};
                sys::retry_eintr(::poll, &pfd, 1, 0);
              });

              aassert(poll_ret >= 0);

              our_pfd.close();
              if (poll_ret != 0) {
                //
                // parent is already gone.
                //
                for (;;)
                  _exit(0);
                __builtin_unreachable();
              }
            }

            if (::ptrace(PTRACE_ATTACH, new_child, 0UL, 0UL) < 0) {
              int err = errno;
              die("PTRACE_ATTACH on fork() " + std::string(strerror(err)));
            } else {
              if (IsVeryVerbose())
                llvm::errs() << llvm::formatv("attached [{0}]\n", new_child);

              //
              // the tracee will not necessarily have stopped by the completion of this call.
              //
              {
                int status;
                do
                  ::waitpid(-1, &status, __WALL);
                while (!WIFSTOPPED(status));
              }

              //
              // establish options
              //
              static_assert(ptrace_options & PTRACE_O_TRACEEXEC, "needs to be set here");

              if (::ptrace(PTRACE_SETOPTIONS, new_child, 0UL, ptrace_options) < 0) {
                int err = errno;
                HumanOut() << llvm::formatv("{0}: PTRACE_SETOPTIONS failed ({1})\n",
                                                  __func__,
                                                  strerror(err));
              }
            }
          }

          continue;
        }

#if 0
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
#endif

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
        if (likely(RightArch) && stopsig == (SIGTRAP | 0x80)) {
          //
          // (1) Syscall-enter-stop and syscall-exit-stop are observed by the
          // tracer as waitpid(2) returning with WIFSTOPPED(status) true, and-
          // if the PTRACE_O_TRACESYSGOOD option was set by the tracer- then
          // WSTOPSIG(status) will give the value (SIGTRAP | 0x80).
          //
          child_syscall_state_t &syscall_state = children_syscall_state[child];

          ptrace::tracee_state_t tracee_state;
          ptrace::get(child, tracee_state);

          long pc = ptrace::pc_of_tracee_state(tracee_state);
          long ra =
#if defined(__mips64) || defined(__mips__)
              tracee_state.regs[31]
#else
              0
#endif
              ;

          //
          // determine whether this syscall is entering or has exited
          //
#if defined(__arm__)
          unsigned dir = tracee_state.uregs[12]; /* unambiguous */
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
            const auto no = tracee_state.orig_rax;
            const auto a1 = tracee_state.rdi;
            const auto a2 = tracee_state.rsi;
            const auto a3 = tracee_state.rdx;
            const auto a4 = tracee_state.r10;
            const auto a5 = tracee_state.r8;
            const auto a6 = tracee_state.r9;
#elif defined(__i386__)
            const auto no = tracee_state.orig_eax;
            const auto a1 = tracee_state.ebx;
            const auto a2 = tracee_state.ecx;
            const auto a3 = tracee_state.edx;
            const auto a4 = tracee_state.esi;
            const auto a5 = tracee_state.edi;
            const auto a6 = tracee_state.ebp;
#elif defined(__aarch64__)
            const auto no = tracee_state.regs[8];
            const auto a1 = tracee_state.regs[0];
            const auto a2 = tracee_state.regs[1];
            const auto a3 = tracee_state.regs[2];
            const auto a4 = tracee_state.regs[3];
            const auto a5 = tracee_state.regs[4];
            const auto a6 = tracee_state.regs[5];
#elif defined(__mips64) || defined(__mips__)
            const auto no = tracee_state.regs[2];
            const auto a1 = tracee_state.regs[4];
            const auto a2 = tracee_state.regs[5];
            const auto a3 = tracee_state.regs[6];
            const auto a4 = tracee_state.regs[7];
            const auto a5 = ptrace::peekdata(child, tracee_state.regs[29 /* sp */] + 16);
            const auto a6 = ptrace::peekdata(child, tracee_state.regs[29 /* sp */] + 20);
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
            long r7 = tracee_state.regs[7];
            long r2 = tracee_state.regs[2];
#endif

            long ret =
#if defined(__x86_64__)
                tracee_state.rax
#elif defined(__i386__)
                tracee_state.eax
#elif defined(__aarch64__)
                tracee_state.regs[0]
#elif defined(__arm__)
                tracee_state.uregs[0]
#elif defined(__mips64) || defined(__mips__)
                r7 && r2 > 0 ? -r2 : r2
#else
#error
#endif
                ;

            const auto no = syscall_state.no;
            const auto a1 = syscall_state.a1;
            const auto a2 = syscall_state.a2;
            const auto a3 = syscall_state.a3;
            const auto a4 = syscall_state.a4;
            const auto a5 = syscall_state.a5;
            const auto a6 = syscall_state.a6;

            auto on_syscall_exit = [&](void) -> void {
              if (unlikely(ret < 0 && ret > -4096))
                return; /* system call probably failed */

              HumanOut() << syscall_names[no] << '\n';

              switch (no) {
#ifdef __NR_rt_sigaction
              case __NR_rt_sigaction: {
                if (IsVeryVerbose())
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
                  uintptr_t handler = ptrace::peekdata(child, act + handler_offset);

                  if (IsVeryVerbose() && handler)
                    HumanOut() << llvm::formatv(
                        "on rt_sigaction(): handler={0:x}\n", handler);

                  if (handler && (void *)handler != SIG_IGN) {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
                    handler &= ~1UL;
#endif

                    binary_index_t BIdx;
                    function_index_t FIdx;
                    std::tie(BIdx, FIdx) = function_at_program_counter(child, handler);
                    if (likely(is_function_index_valid(FIdx))) {
                      function_t &f = jv.Binaries.at(BIdx).Analysis.Functions.at(FIdx);
                      f.IsSignalHandler = true;
                      f.IsABI = true;
                    } else {
                      HumanOut() << llvm::formatv(
                          "on rt_sigaction(): failed to translate handler {0}\n",
                          description_of_program_counter(handler), true);
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
            scan_rtld_link_map(child);

          if (unlikely(!AllLoaded()))
            ScanAddressSpace(child);
        } else if (stopsig == SIGTRAP) {
          const unsigned int event = (unsigned int)status >> 16;

          //
          // PTRACE_EVENT stops (2) are observed by the tracer as waitpid(2)
          // returning with WIFSTOPPED(status), and WSTOPSIG(status) returns
          // SIGTRAP.
          //
          if (unlikely(event)) {
            switch (event) {
            default:
              if (opts.PrintPtraceEvents)
                HumanOut() << llvm::formatv("unknown ptrace event {0}\n",
                                            event);
              break;

            case PTRACE_EVENT_VFORK:
            case PTRACE_EVENT_FORK: {
              unsigned long new_child;
              if (::ptrace(PTRACE_GETEVENTMSG, child, 0UL, &new_child) < 0) {
                HumanOut() << llvm::formatv("what the fuck? [{0}]\n", child);
                die("PTRACE_GETEVENTMSG on fork()/vfork()");
              }

              if (opts.PrintPtraceEvents)
                HumanOut() << llvm::formatv(
                    "<PTRACE_EVENT_{0}FORK> {1} => {2}\n",
                    event == PTRACE_EVENT_VFORK ? "V" : "", child, new_child);

#if 1
              sig = SIGSTOP;
              forked.insert(new_child);
#endif
              break;
            }
            case PTRACE_EVENT_CLONE: {
              unsigned long new_child;
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
            case PTRACE_EVENT_EXEC: {
              unsigned long new_pid;
              if (::ptrace(PTRACE_GETEVENTMSG, child, 0UL, &new_pid) < 0) {
                int err = errno;
                WithColor::warning() << llvm::formatv(
                    "PTRACE_GETEVENTMSG failed: {0} (PTRACE_EVENT_EXEC)\n",
                    strerror(err));

                new_pid = child;
              }

              std::string exe_path;
              exe_path.resize(2 * PATH_MAX);

              {
                ssize_t len = ({
                  char buff[PATH_MAX];
                  snprintf(buff, sizeof(buff), "/proc/%lu/exe", new_pid);

                  ::readlink(buff, &exe_path[0], exe_path.size() - 1);
                });

                aassert(len != exe_path.size());
#if 0
                if (len < 0) {
                  len = 0;

                  int err = errno;
                  WithColor::warning() << llvm::formatv(
                      "readlink() of {0} failed: {1} (PTRACE_EVENT_EXEC)\n",
                      buff, strerror(err));
                }
#endif
                exe_path.resize(len);
              }

              std::vector<std::string> args;

              {
                std::string argv;
                {
                  char buff[PATH_MAX];
                  snprintf(buff, sizeof(buff), "/proc/%lu/cmdline", new_pid);
                  argv = read_file_into_string(buff);
                }

                const char *p = argv.data();
                const char *end = p + argv.size();

                while (p < end) {
                  const char *q =
                      static_cast<const char *>(memchr(p, '\0', end - p));

                  if (!q) {
                    break; // malformed, but be defensive
                  }

                  if (q > p) { // skip empty final NUL
                    args.emplace_back(p, q);
                  }

                  p = q + 1;
                }

              }

              if (opts.PrintPtraceEvents)
                HumanOut() << llvm::formatv(
                    "<PTRACE_EVENT_EXEC> \"{0}\" [{1}]\n", exe_path, new_pid);
              else if (IsVerbose())
                HumanOut() << llvm::formatv(
                    "tracee {0} exec'd!{1}\n", new_pid,
                    IsVeryVerbose() ? (" (" + exe_path + ")") : "");

              //
              // the address space has been reset, so we need
              // to clear our breakpoint tables and anything else that is
              // dependent on the tracee's state.
              //
              this->Reset(); /* right arch is assumed */

              //
              // check that the executable architecture matches our target.
              //
              // even if one provides a 64-bit windows program for WINE to run,
              // it still may exec a 32-bit windows program (i.e. the preloader)
              // as part of the startup sequence.
              //
              if (!exe_path.empty()) {
                std::vector<uint8_t> BinBytes;
                B::unique_ptr Bin;

                //
                // XXX memfd cover-up
                //
                const bool Ex =
                    ignore_exception([&] {
                      if (boost::algorithm::starts_with(exe_path, "/memfd:jove/bootstrap"))
                        Bin = B::Create(jv.Binaries.at(0).data());
                      else
                        Bin = B::CreateFromFile(exe_path.c_str(), BinBytes);
                    });

                if (Ex || (!B::is_elf(Bin.get()) && !B::is_coff(Bin.get()))) {
                  RightArch = false;

                  //if (IsVeryVerbose())
                    WithColor::note() << llvm::formatv("!RightArch [{0}]\n", child);
                }
              }

              auto DetachFromChild = [&](void) -> void {
                if (::ptrace(PTRACE_DETACH, child, nullptr, nullptr) < 0) {
                  int err = errno;
                  die("PTRACE_DETACH on exec of wineserver: " + std::string(strerror(err)));
                }

                ::kill(child, SIGCONT);

                child = -1;
              };

              bool ShouldDetach = false;

              if (fs::equivalent(locator().wine_server(IsTarget32), exe_path))
                ShouldDetach = true;
              if (fs::equivalent(locator().wine_preloader(IsTarget32), exe_path)) {
                aassert(args.size() >= 3);

                if (!fs::equivalent(args.at(2), jv.Binaries.at(0).path_str())) {
                  ShouldDetach = true;

#if 0
                HumanOut() << "preloader!\n";
                for (const auto &arg : args)
                  HumanOut() << "arg=" << arg << '\n';
#endif
                }
              }

              if (ShouldDetach) {
                DetachFromChild();
              } else {
                ScanAddressSpace(child, true);
              }

              break;
            }

            case PTRACE_EVENT_EXIT:
              if (opts.PrintPtraceEvents)
                HumanOut() << "ptrace event (PTRACE_EVENT_EXIT) [" << child
                           << "]\n";

              if (child == saved_child) {
                if (IsVerbose())
                  HumanOut() << "Child has exited.\n";
              }

              exited.insert(child);
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
            ptrace::tracee_state_t tracee_state;
            ptrace::scoped_tracee_state_t scoped_tracee_state(child,
                                                              tracee_state);
            try {
              on_breakpoint(child, tracee_state);
            } catch (const notrap_exception &) {
              if (::ptrace(PTRACE_GETSIGINFO, child, 0UL, &si) < 0) {
                HumanOut() << "getsiginfo failed!\n";
              }
#if 0
              {
                HumanOut() << "si.si_signo=" << si.si_signo << '\n';
                HumanOut() << "si.si_code=" << si.si_code << '\n';
              }
#endif

              if (si.si_code <= 0) {
                //
                // SIGTRAP was generated by a user-space action
                //
                ;
              } else if (si.si_code == 128) {
#if 1
                ScanAddressSpace(child);
#endif
                auto &pc = ptrace::pc_of_tracee_state(tracee_state);

                uintptr_t SavedPC = pc;

#if defined(__x86_64__) || defined(__i386__)
                //
                // rewind before the breakpoint instruction (why is this x86-specific?)
                //
                SavedPC -= 1; /* int3 */
#endif

                binary_index_t BIdx;
                basic_block_index_t BBIdx;
                std::tie(BIdx, BBIdx) =
                    existing_block_at_program_counter(child, SavedPC);

                if (unlikely(!is_basic_block_index_valid(BBIdx))) {
                  HumanOut() << llvm::formatv(
                      "wtf @ {0}\n",
                      description_of_program_counter(SavedPC, true));
                }

                binary_t &b = jv.Binaries.at(BIdx);
                auto &ICFG = b.Analysis.ICFG;
                fallthru<void>(
                    jv, BIdx, BBIdx,
                    [&](bbprop_t &bbprop, basic_block_index_t BBIdx_) {
                      if (IsTerminatorIndirect(bbprop.Term.Type))
                        place_breakpoints_in_block(
                            b, ICFG[ICFG.vertex<false>(BBIdx_)], BBIdx_);
                    });

                try {
                  on_breakpoint(child, tracee_state);
                } catch (const notrap_exception &) {
                  die("wtf");
                }
              }
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

          if (stopsig == SIGSEGV) {
            ptrace::tracee_state_t tracee_state;
            ptrace::get(child, tracee_state);
#if defined(__mips64) || defined(__mips__)
          //
          // recognize the 'jr $zero' hack. This trickery is to avoid emulating
          // the delay slot instruction of a return instruction.
          //

            if (tracee_state.cp0_epc == 0) {
              //
              // from here on out we are assuming a 'jr $ra' was replaced with
              // 'jr $zero', so we simply set the program counter to the return
              // address register.
              //
              uintptr_t RetAddr = tracee_state.regs[31 /* ra */];

              tracee_state.cp0_epc = RetAddr;
              ptrace::set(child, tracee_state);

              sig = 0; /* suppress */

              on_return(child, invalid_binary_index, 0 /* XXX */, RetAddr);
            }
#else
            if (IsVerbose()) {
              HumanOut() << llvm::formatv(
                  "sigsegv @ {0}\n",
                  description_of_program_counter(
                      ptrace::pc_of_tracee_state(tracee_state), true));
            }
#endif
          }

          if (sig && opts.Signals)
            HumanOut() << llvm::formatv("delivering signal {0} <{1}> [{2}]\n",
                                        sig, strsignal(sig), child);
        }
      } else {
        int the_status = -1;
        if (WIFEXITED(status)) {
          the_status = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
          the_status = 128 + WTERMSIG(status);
        } else {
          die("?");
        }

        //
        // the child terminated
        //
        if (IsVerbose())
          HumanOut() << llvm::formatv("child {0} terminated ({1})\n", child,
                                      the_status);

        child = -1;
      }
    }
  }

  IgnoreCtrlC(); /* user probably doesn't want to interrupt the following */

  {
    //
    // fix ambiguous indirect jumps. why do we do this here? because this
    // process involves removing edges from the graph, which can be messy.
    //
    std::atomic<unsigned> NumChanged = 0;

    for_each_binary(maybe_par_unseq, jv, [&](binary_t &b) {
      auto &ICFG = b.Analysis.ICFG;

      for (;;) {
        taddr_t TermAddr = 0;

        {
          auto s_lck = b.BBMap.shared_access();

          auto vi_pair = ICFG.vertices();
          for (auto vi = vi_pair.first; vi != vi_pair.second; ++vi) {
            bb_t bb = *vi;

            if (ICFG[bb].Term.Type != TERMINATOR::INDIRECT_JUMP)
              continue;

            if (IsAmbiguousIndirectJump(ICFG, bb)) {
              TermAddr = ICFG[bb].Term.Addr;
              break;
            }
          }
        }

        if (!TermAddr)
          break;

        if (b.FixAmbiguousIndirectJump(TermAddr, *E,
                                       state.for_binary(b).Bin.get(), jv))
          ++NumChanged;
      }
    });

    if (IsVerbose())
      if (unsigned c = NumChanged.load())
        HumanOut() << llvm::formatv("fixed {0} ambiguous indirect jump{1}\n", c,
                                    c > 1 ? "s" : "");
  }

  return 0;
}

void BootstrapTool::on_new_basic_block(binary_t &b,
                                       bbprop_t &bbprop,
                                       basic_block_index_t BBIdx) {
  if (!IsTerminatorIndirect(bbprop.Term.Type))
    return;

  place_breakpoints_in_block(b, bbprop, BBIdx);
}

void BootstrapTool::on_new_function(binary_t &b, function_t &f) {
  //state.update();
}

trapped_t &
BootstrapTool::place_breakpoints_in_block(binary_t &b, bbprop_t &bbprop,
                                          basic_block_index_t BBIdx) {
  auto &x = state.for_binary(b);
  auto &ICFG = b.Analysis.ICFG;

#if 0
  if (x.Skip)
    return;
#endif

  const binary_index_t BIdx = index_of_binary(b, jv);

  assert(x.Loaded());

  const auto TermType = bbprop.Term.Type;
  aassert(IsTerminatorIndirect(TermType));

  const uintptr_t termpc = pc_of_va(bbprop.Term.Addr, BIdx);
#if 0
  if (trapmap.contains(termpc))
    return;
#endif
  aassert(!trapmap.contains(termpc));

  assert(disas);

  auto trapmap_pair =
      trapmap.emplace(termpc, trapped_t(*emulator, BBIdx, BIdx, saved_child, reinterpret_cast<void *>(termpc), x.Bin.get()));
  aassert(trapmap_pair.second);
  trapped_t &trapped = (*trapmap_pair.first).second;

  if (TermType == TERMINATOR::RETURN)
    place_breakpoint_at_return(_child, termpc, trapped);
  else
    place_breakpoint_at_indirect_branch(_child, termpc, trapped);

  return trapped;
}

static void arch_put_breakpoint(void *code);

void BootstrapTool::place_breakpoint_at_indirect_branch(pid_t child,
                                                        uintptr_t Addr,
                                                        indirect_branch_t &indbr) {
  if (IsVeryVerbose())
    llvm::errs() << llvm::formatv("indjmp @ {0:x}\n", Addr);

  unsigned long word = ptrace::peekdata(child, Addr);
  arch_put_breakpoint(&word);
  ptrace::pokedata(child, Addr, word);
}

void BootstrapTool::place_breakpoint(pid_t child, uintptr_t Addr,
                                     breakpoint_t &brk) {
  if (IsVeryVerbose())
    llvm::errs() << llvm::formatv("break @ {0:x}\n", Addr);

  unsigned long word = ptrace::peekdata(child, Addr);
  arch_put_breakpoint(&word);
  ptrace::pokedata(child, Addr, word);
}

void BootstrapTool::place_breakpoint_at_return(pid_t child, uintptr_t Addr,
                                               return_t &r) {
  if (IsVeryVerbose())
    llvm::errs() << llvm::formatv("return @ {0:x}\n", Addr);

  unsigned long word = ptrace::peekdata(child, Addr);

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

  ptrace::pokedata(child, Addr, word);
}

void BootstrapTool::on_breakpoint(pid_t child, ptrace::tracee_state_t &tracee_state) {
  uintptr_t SavedPC = ~0UL;
  trapped_t *ptrapped  = nullptr;

  const uintptr_t TargetAddr = ({
    auto &pc = ptrace::pc_of_tracee_state(tracee_state);

    SavedPC = pc;

#if defined(__x86_64__) || defined(__i386__)
    //
    // rewind before the breakpoint instruction (why is this x86-specific?)
    //
    SavedPC -= 1; /* int3 */
#endif

    {
      binary_index_t       BIdx;
      basic_block_index_t BBIdx;

      auto it = trapmap.find(SavedPC);
      if (unlikely(it == trapmap.end()))
        throw notrap_exception(SavedPC);

      {
        trapped_t &trapped = (*it).second;

        BIdx = trapped.BIdx;
        BBIdx = trapped.BBIdx;
      }

      binary_t &b = jv.Binaries.at(BIdx);
      auto &ICFG = b.Analysis.ICFG;
      auto &x = state.for_binary(b);

#if 0
      if (B::is_coff(x.Bin.get())) {
      trapmap.erase(SavedPC);

      fallthru<void>(jv, BIdx, BBIdx,
                     [&](bbprop_t &bbprop, basic_block_index_t BBIdx_) {
        ptrapped = &place_breakpoints_in_block(b, bbprop, BBIdx_);
      });
      } else {
#endif
      ptrapped = &(*it).second;
#if 0
      }
#endif

      assert(ptrapped);
    }

    trapped_t &trapped = *ptrapped;

#if defined(__mips64) || defined(__mips__)
    if (IsVeryVerbose())
      HumanOut() << llvm::formatv("trapped @ {0} <{1:x}>\n",
                                  description_of_program_counter(SavedPC),
                                  trapped.DelaySlotInsn);
#endif


    const uintptr_t ExecutableRegionAddress = emulator->ExecutableRegionAddress;
    pc = SavedPC;
    const uintptr_t NewPC = trapped.single_step_proc(tracee_state, trapped, child
                                                   , ExecutableRegionAddress
                                                     );

#if !defined(__mips64) && !defined(__mips__)

#if 0
#if defined(__i386__)
    if (!(pc >= ExecutableRegionAddress && pc < ExecutableRegionAddress + emulator->N))
#endif
#endif
    pc = NewPC;
#endif

    NewPC;
  });

  assert(ptrapped);
  trapped_t &trapped = *ptrapped;

#if 0
#ifndef NDEBUG
  if (IsVerbose())
    HumanOut() << StringOfMCInst(trapped.Inst) << '\n';
#endif
#endif

  const binary_index_t BIdx       = trapped.BIdx;
  const basic_block_index_t BBIdx = trapped.BBIdx;

  const auto TermType = static_cast<TERMINATOR>(trapped.TT);
  const auto TermAddr = trapped.TermAddr;
  const bool IsCall   = static_cast<bool>(trapped.IC);
  const bool IsLj     = static_cast<bool>(trapped.LJ);
  const unsigned OutDeg = trapped.OD;
  const unsigned HasDynTarget = trapped.DT;

  struct {
    bool isNew = false;
    binary_index_t BIdx = invalid_binary_index;
  } Target;

  Target.BIdx = binary_at_program_counter(child, TargetAddr);

  struct {
    bool IsGoto = false;
  } ControlFlow;

  auto print_thing = [&](void) -> void {
    if (unlikely(!opts.Quiet && !ShowMeN && (ShowMeA || (ShowMeS && Target.isNew))))
      HumanOut() << llvm::formatv("{3}[{4}] ({0}) {1} -> {2}" __ANSI_NORMAL_COLOR "\n",
                                  ControlFlow.IsGoto ? (IsLj ? "longjmp" : "goto") : "call",
                                  description_of_program_counter(SavedPC),
                                  description_of_program_counter(TargetAddr),
                                  ControlFlow.IsGoto ? (IsLj ? __ANSI_MAGENTA : __ANSI_GREEN) : __ANSI_CYAN,
                                  child).str();
  };

  if (unlikely(!is_binary_index_valid(Target.BIdx))) {
    print_thing();
    return;
  }

  assert(is_binary_index_valid(Target.BIdx));

  auto &TargetBinary = jv.Binaries.at(Target.BIdx);
  auto &TargetICFG = TargetBinary.Analysis.ICFG;

  auto &x = state.for_binary(TargetBinary);
  assert(x.Loaded()); /* XXX this is important */

  binary_t &binary = jv.Binaries.at(BIdx);

  try {
    if (TermType == TERMINATOR::RETURN) {
      const uintptr_t AddrOfRet = SavedPC;
      const uintptr_t RetAddr = TargetAddr;

      on_return(child, BIdx, AddrOfRet, RetAddr);
    } else if (TermType == TERMINATOR::INDIRECT_CALL) {
      function_index_t FIdx = E->explore_function(
          TargetBinary, x.Bin.get(), va_of_pc(TargetAddr, Target.BIdx));

      assert(is_function_index_valid(FIdx));

      Target.isNew = fallthru<bool>(
          jv, BIdx, BBIdx, [&](bbprop_t &bbprop, basic_block_index_t) -> bool {
            assert(bbprop.Term.Type == TERMINATOR::INDIRECT_CALL);

            return bbprop.insertDynTarget(BIdx, {Target.BIdx, FIdx}, jv);
          });

      trapmap.at(SavedPC).DT = 1;
    } else {
      assert(TermType == TERMINATOR::INDIRECT_JUMP);

      if (unlikely(IsLj)) {
        //
        // non-local goto (aka "long jump")
        //
        const basic_block_index_t BBIdx = E->explore_basic_block(
            TargetBinary, x.Bin.get(), va_of_pc(TargetAddr, Target.BIdx));

        assert(is_basic_block_index_valid(BBIdx));

        ControlFlow.IsGoto = true;
        Target.isNew = opts.Longjmps;

        TargetICFG[basic_block_of_index(BBIdx, TargetICFG)].InvalidateAnalysis(
            jv, TargetBinary);
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
            HasDynTarget /* IsDefinitelyTailCall(TargetICFG, bb) */ ||
            BIdx != Target.BIdx ||
            (OutDeg == 0 &&
             exists_function_at_address(TargetBinary, va_of_pc(TargetAddr, Target.BIdx)));

        if (isTailCall) {
          function_index_t FIdx = E->explore_function(
              TargetBinary, x.Bin.get(), va_of_pc(TargetAddr, Target.BIdx));

          assert(is_function_index_valid(FIdx));

          Target.isNew = fallthru<bool>(
              jv, BIdx, BBIdx,
              [&](bbprop_t &bbprop, basic_block_index_t) -> bool {
                assert(bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP);

                return bbprop.insertDynTarget(BIdx, {Target.BIdx, FIdx}, jv);
              });

          trapmap.at(SavedPC).DT = 1;
        } else {
          const basic_block_index_t TargetBBIdx = E->explore_basic_block(
              TargetBinary, x.Bin.get(), va_of_pc(TargetAddr, Target.BIdx));

          assert(is_basic_block_index_valid(TargetBBIdx));
          bb_t TargetBB = basic_block_of_index(TargetBBIdx, TargetICFG);

          Target.isNew = fallthru<bool>(
              jv, BIdx, BBIdx,
              [&](bbprop_t &bbprop, basic_block_index_t TheBBIdx) -> bool {
                assert(bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP);

                bool res = TargetICFG
                               .add_edge<false>(
                                   binary.Analysis.ICFG.vertex<false>(TheBBIdx),
                                   TargetBB)
                               .second;

                if (res)
                  bbprop.InvalidateAnalysis(jv, binary);

                return res;
              });

          ControlFlow.IsGoto = true;
        }
      }
    }

    print_thing();
  } catch (const invalid_control_flow_exception &invalid_cf) {
    const std::string what = "invalid control-flow to " +
                             taddr2str(invalid_cf.pc, false) + " in \"" +
                             invalid_cf.name_of_binary + "\"";

    HumanOut() << llvm::formatv(
        "on_breakpoint failed: {0} [target: {1}+{2:x} ({3:x}) binary.LoadAddr: {4:x}]\n",
        what, fs::path(TargetBinary.Name.c_str()).filename().string(),
        va_of_pc(TargetAddr, Target.BIdx), TargetAddr,
        x.LoadAddr);

    if (IsVerbose())
      HumanOut() << ProcMapsForPid(child);
  }
}

static bool load_proc_maps(pid_t child, std::vector<struct proc_map_t> &out);

bool BootstrapTool::UpdateVM(pid_t child) {
  if (unlikely(!load_proc_maps(child, cached_proc_maps)))
    return false;

  pmm.clear();

  for (unsigned i = 0; i < cached_proc_maps.size(); ++i) {
    const proc_map_t &pm = cached_proc_maps[i];

    intvl_map_add(pmm, right_open_addr_intvl(pm.beg, pm.end), i);
  }

  return true;
}

std::pair<int, int> extract_fd_and_off(std::string_view s) {
  auto first = s.find(':');
  auto second = s.find(':', first + 1);
  auto end = s.find(']', second + 1);

  aassert(first != std::string::npos);
  aassert(second != std::string::npos);
  aassert(end != std::string::npos);

  int a = std::stoi(std::string(s.substr(first + 1, second - first - 1)));
  int b = std::stoi(std::string(s.substr(second + 1, end - second - 1)));

  return {a, b};
}

void BootstrapTool::ScanAddressSpace(pid_t child, bool VMUpdate) {
  if (unlikely(!RightArch))
    return;

  if (VMUpdate) {
    if (!UpdateVM(child))
      WithColor::warning() << "failed to update view of /proc/<PID>/maps\n";
  }

  //
  // forget what we think we know
  //
  AddressSpace.clear();
  for_each_binary(jv, [&](binary_t &b) {
    state.for_binary(b).LoadAddr =
    state.for_binary(b).LoadOffset =
        std::numeric_limits<uintptr_t>::max(); /* reset */
  });

  for (const proc_map_t &pm : cached_proc_maps) {
#if 0 /* XXX? */
    if (!pm.x)
      continue;
#endif

    const std::string &nm = pm.nm;
    if (nm.empty())
      continue;

    auto ItsTheBinary = [&](binary_index_t BIdx, uintptr_t off) -> void {
      if (!is_binary_index_valid(BIdx))
        return;

      binary_t &b = jv.Binaries.at(BIdx);

      intvl_map_add(AddressSpace, right_open_addr_intvl(pm.beg, pm.end), BIdx);

      auto &x = state.for_binary(b);

      bool NewlyLoaded = Loaded.insert(BIdx).second;
      if (updateVariable(x.LoadAddr, std::min(x.LoadAddr, pm.beg)))
        x.LoadOffset = off;

      if (NewlyLoaded) {
        assert(x.Loaded());
        on_binary_loaded(child, BIdx, pm);
      }
    };

    if (nm.front() == '/') {
      ItsTheBinary(BinaryFromPath<false>(child, nm.c_str()), pm.off);
    } else if (nm.front() == '[') {
      if (boost::algorithm::starts_with(nm , "[anon:")) {
        std::string the_path;
        the_path.resize(2 * PATH_MAX);

        //
        // WINE will sometimes open and read the contents of a section into
        // memory. to get around this, we preserve the file and offset of
        // one of these such mappings via PR_SET_VMA_ANON_NAME.
        //
        int the_off;
        ssize_t len = ({
          int the_fd;
          std::tie(the_fd, the_off) = extract_fd_and_off(nm);

          char buff[1024];
          snprintf(buff, sizeof(buff), "/proc/%d/fd/%d", (int)child, the_fd);
          ::readlink(buff, &the_path[0], the_path.size());
        });

        aassert(len != the_path.size() && len != -1);
        the_path.resize(len);

        ItsTheBinary(BinaryFromPath<false>(child, the_path.c_str()), the_off);
      } else {
        //
        // [vdso], [vsyscall], ...
        //
        binary_index_set BIdxSet;
        if (jv.LookupByName(nm.c_str(), BIdxSet)) {
          assert(!BIdxSet.empty());
#if 0
          if (BIdxSet.size() > 1 && IsVerbose())
            HumanOut() << llvm::formatv("ScanAddressSpace: \"{0}\" maps to more "
                                        "than one distinct binary!\n", nm);
#endif
          ItsTheBinary(*BIdxSet.begin(), pm.off);
        } else {
          if (IsVeryVerbose())
            HumanOut() << llvm::formatv("dont recognize {0}\n", nm);
        }
      }
    } else {
      HumanOut() << llvm::formatv("WTF? {0}\n", nm);
    }
  }
}

void BootstrapTool::on_binary_loaded(pid_t child,
                                     binary_index_t BIdx,
                                     const proc_map_t &pm) {
  binary_t &binary = jv.Binaries.at(BIdx);
  auto &ICFG = binary.Analysis.ICFG;
  auto &x = state.for_binary(binary);

#if 1
  for (const std::string &name : opts.SkipBins) {
    if (binary.Name.find(name) != ip_string::npos) {
      if (IsVerbose())
        WithColor::warning()
            << llvm::formatv("skipping {0}\n", binary.Name.c_str());

      x.Skip = true;
      return;
    }
  }
#else
  x.Skip = true;
  return;
#endif

  auto &Bin = x.Bin;

  if (IsVerbose())
    HumanOut() << (fmt("found binary %s @ [%#lx, %#lx)")
                   % pm.nm
                   % pm.beg
                   % pm.end).str()
               << '\n';

  //
  // if it's the dynamic linker, we need to set a breakpoint on the address of a
  // function internal to the run-time linker, that will always be called when
  // the linker begins to map in a library or unmap it, and again when the
  // mapping change is complete.
  //
  if (binary.IsDynamicLinker)
    on_dynamic_linker_loaded(child, BIdx, pm);

  if (binary.IsVDSO) {
    aassert(!emulator->ExecutableRegionAddress);

    aassert(pm.end - pm.beg >= emulator->N);
    const uintptr_t ExecutableRegionAddress = pm.end - emulator->N;
    emulator->ExecutableRegionAddress = ExecutableRegionAddress;

#if defined(__x86_64__) || defined(__i386__)
    const std::byte ret_insns[] = {
      static_cast<std::byte>(0xc3),
      static_cast<std::byte>(0xc2), static_cast<std::byte>(0x00), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0xc2), static_cast<std::byte>(0x04), static_cast<std::byte>(0x00),
      static_cast<std::byte>(0xc2), static_cast<std::byte>(0x08), static_cast<std::byte>(0x00)
    };

    ptrace::memcpy_to(child, reinterpret_cast<void *>(ExecutableRegionAddress),
                      &ret_insns[0], sizeof(ret_insns));
#elif defined(__mips64) || defined(__mips__)
    //
    // "initialize" code cave
    //
    for (unsigned i = 0; i < 32; ++i) {
      uint32_t insns[2] = {
        encoding_of_jump_to_reg(reg_of_idx(i)),
        0x00
      };

      const uintptr_t jumpr_insn_addr =
          emulator->ExecutableRegionAddress + i * (2 * sizeof(ptrace::word));
      const uintptr_t delay_slot_addr = jumpr_insn_addr + 4;

      uintptr_t addr = emulator->ExecutableRegionAddress + i * (2 * sizeof(ptrace::word));
      if constexpr (sizeof(ptrace::word) == 8) {
        ptrace::word the_poke;
        __builtin_memcpy_inline(&the_poke, &insns[0], sizeof(the_poke));
        ptrace::pokedata(child, jumpr_insn_addr, the_poke);
      } else if constexpr (sizeof(ptrace::word) == 4) {
        ptrace::word the_poke1;
        __builtin_memcpy_inline(&the_poke1, &insns[0], sizeof(the_poke1));
        ptrace::pokedata(child, jumpr_insn_addr, the_poke1);

        ptrace::word the_poke2;
        __builtin_memcpy_inline(&the_poke2, &insns[1], sizeof(the_poke2));
        ptrace::pokedata(child, delay_slot_addr, the_poke2);
      } else {
        __compiletime_unreachable();
      }
    }
#endif

    if (IsVerbose())
      HumanOut() << llvm::formatv("ExecutableRegionAddress = {0:x}\n",
                                  emulator->ExecutableRegionAddress);
  }

  for_each_basic_block_in_binary_if(
      binary,
      [&](bb_t bb) -> bool {
        const auto TermType = binary.Analysis.ICFG[bb].Term.Type;
        return IsTerminatorIndirect(TermType);
      },
      [&](bb_t bb) {
        fallthru<void>(jv, BIdx, index_of_basic_block(ICFG, bb),
                       [&](bbprop_t &bbprop, basic_block_index_t BBIdx) {
          place_breakpoints_in_block(binary, bbprop, BBIdx);
        });
      });
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

    proc_map_t &proc_map = out.emplace_back();

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

void BootstrapTool::scan_rtld_link_map(pid_t child) {
  void *const rdbg_ptr = _r_debug.ptr;
  if (!rdbg_ptr)
    return;

  struct r_debug rdbg;
  std::vector<std::byte> rdbg_bytes;

  if (catch_exception([&] {
        ptrace::memcpy_from(child,
                            rdbg_bytes,
                            rdbg_ptr,
                            sizeof(rdbg));
      }))
    return;

  aassert(rdbg_bytes.size() == sizeof(rdbg));
  __builtin_memcpy_inline(&rdbg, rdbg_bytes.data(), sizeof(rdbg));

  if (opts.PrintLinkMap)
      HumanOut() << llvm::formatv("[r_debug] r_version = {0}\n"
                                  "          r_map     = {1}\n"
                                  "          r_brk     = {2}\n"
                                  "          r_state   = {3}\n"
                                  "          r_ldbase  = {4}\n",
                                  (void *)rdbg.r_version,
                                  (void *)rdbg.r_map,
                                  (void *)rdbg.r_brk,
                                  (void *)rdbg.r_state,
                                  (void *)rdbg.r_ldbase);

  if (IsVerbose()) {
    WARN_ON(rdbg.r_state != r_debug::RT_CONSISTENT &&
            rdbg.r_state != r_debug::RT_ADD &&
            rdbg.r_state != r_debug::RT_DELETE);
  }

  if (!rdbg.r_map)
    return;

  const unsigned SavedNumBinaries = jv.NumBinaries();

  struct link_map *lmp = rdbg.r_map;
  do {
    struct link_map lm;
    std::vector<std::byte> lm_bytes;

    if (catch_exception([&] {
          ptrace::memcpy_from(child,
                              lm_bytes,
                              lmp,
                              sizeof(lm));
        }))
      return;

    aassert(lm_bytes.size() == sizeof(lm));
    __builtin_memcpy_inline(&lm, lm_bytes.data(), sizeof(lm));

    std::string s;
    try {
      s = ptrace::read_c_str(child, reinterpret_cast<uintptr_t>(lm.l_name));
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
      ignore_exception([&]() { BinaryFromPath<true>(child, s.c_str()); });
    }

    lmp = lm.l_next;
  } while (lmp && lmp != rdbg.r_map);

  if (jv.NumBinaries() > SavedNumBinaries)
    ScanAddressSpace(child);
}

template <bool ValidatePath>
binary_index_t BootstrapTool::BinaryFromPath(pid_t child, const char *path) {
  struct EmptyBasicBlockProcSetter {
    BootstrapTool &tool;
    on_newbb_proc_t<IsToolMT, IsToolMinSize> sav_proc;

    EmptyBasicBlockProcSetter(BootstrapTool &tool)
        : tool(tool), sav_proc(tool.E->get_newbb_proc()) {
      tool.E->set_newbb_proc(nop_on_newbb_proc<IsToolMT, IsToolMinSize>);
    }

    ~EmptyBasicBlockProcSetter() { tool.E->set_newbb_proc(sav_proc); }
  } __EmptyBasicBlockProcSetter(*this); /* on_binary_loaded will place brkpts */

  if (IsVeryVerbose())
    llvm::errs() << llvm::formatv("BinaryFromPath: \"{0}\"\n", path);

  using namespace std::placeholders;

  return jv.AddFromPath<ValidatePath>(*E, jv_file, path,
      std::bind(&BootstrapTool::on_new_binary, this, _1)).first;
}

binary_index_t BootstrapTool::BinaryFromData(pid_t child, std::string_view sv,
                                             const char *name) {
  struct EmptyBasicBlockProcSetter {
    BootstrapTool &tool;
    on_newbb_proc_t<IsToolMT, IsToolMinSize> sav_proc;

    EmptyBasicBlockProcSetter(BootstrapTool &tool)
        : tool(tool), sav_proc(tool.E->get_newbb_proc()) {
      tool.E->set_newbb_proc(nop_on_newbb_proc<IsToolMT, IsToolMinSize>);
    }

    ~EmptyBasicBlockProcSetter() { tool.E->set_newbb_proc(sav_proc); }
  } __EmptyBasicBlockProcSetter(*this); /* on_binary_loaded will place brkpts */

  if (IsVeryVerbose())
    llvm::errs() << llvm::formatv("BinaryFromData: \"{0}\"\n", name);

  using namespace std::placeholders;

  return jv.AddFromData(*E, jv_file, sv, name,
                        std::bind(&BootstrapTool::on_new_binary, this, _1)).first;
}

void BootstrapTool::on_dynamic_linker_loaded(pid_t child,
                                             binary_index_t BIdx,
                                             const proc_map_t &proc_map) {
  binary_t &b = jv.Binaries.at(BIdx);

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
        const uintptr_t off = Sym.st_value;
        const uintptr_t pc = pc_of_offset(off, BIdx);

        _r_debug.Found = true;
        _r_debug.ptr = (void *)pc;

        if (IsVerbose())
          HumanOut() << llvm::formatv("_r_debug @ {0} <{1}+{2}>\n",
                                      taddr2str(pc),
                                      b.Name.c_str(),
                                      taddr2str(off));

        WARN_ON(Sym.getType() != llvm::ELF::STT_OBJECT);
        rendezvous_with_dynamic_linker(child);
        return;
      }
    }
  }

  HumanOut() << llvm::formatv("{0}: could not find _r_debug\n", __PRETTY_FUNCTION__);
}

void BootstrapTool::rendezvous_with_dynamic_linker(pid_t child) {
  if (!opts.RtldDbgBrk)
    return;

  if (!_r_debug.Found)
    return;

  //
  // _r_debug is the "Rendezvous structure used by the run-time dynamic linker
  // to communicate details of shared object loading to the debugger."
  //
  if (!_r_debug.brk) {
    struct r_debug rdbg;
    std::vector<std::byte> rdbg_bytes;

    void *const rdbg_ptr = _r_debug.ptr;
    if (catch_exception([&] {
          ptrace::memcpy_from(child,
                              rdbg_bytes,
                              rdbg_ptr,
                              sizeof(rdbg));
        }))
      return;

    aassert(rdbg_bytes.size() == sizeof(rdbg));
    __builtin_memcpy_inline(&rdbg, rdbg_bytes.data(), sizeof(rdbg));

    const uintptr_t pc = rdbg.r_brk;
    if (!is_block_valid(block_at_program_counter(child, pc)))
      return;

    aassert(updateVariable(_r_debug.brk, pc));

    if (IsVerbose())
      HumanOut() << llvm::formatv("r_brk is now {0:x}\n", pc);
  }
}

void BootstrapTool::on_return(pid_t child,
                              binary_index_t RetBIdx,
                              uintptr_t AddrOfRet,
                              uintptr_t RetAddr) {
  if (unlikely(!opts.Quiet && !ShowMeN && ShowMeA))
    HumanOut() << llvm::formatv(__ANSI_YELLOW "[{2}] (ret) {0} <-- {1}" __ANSI_NORMAL_COLOR "\n",
                                description_of_program_counter(RetAddr),
                                description_of_program_counter(AddrOfRet),
                                child).str();

  //
  // examine AddrOfRet
  //
  if (AddrOfRet)
  {
    uintptr_t pc = AddrOfRet;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    pc &= ~1UL;
#endif

    binary_t &b = jv.Binaries.at(RetBIdx);

    auto s_lck = b.BBMap.shared_access();

    binary_index_t BIdx;
    basic_block_index_t BBIdx;
    std::tie(BIdx, BBIdx) = existing_block_at_program_counter(child, pc);
    if (unlikely(!is_basic_block_index_valid(BBIdx))) {
      if (IsVerbose())
        HumanOut() << llvm::formatv("on_return: unknown AddrOfRet @ {0}",
                                    description_of_program_counter(pc, true));
      return;
    }

    assert(BIdx == RetBIdx);

    auto &ICFG = b.Analysis.ICFG;
    bb_t bb = basic_block_of_index(BBIdx, ICFG);

    if (unlikely(ICFG[bb].Term.Type != TERMINATOR::RETURN))
      die("on_return: block @ " + description_of_program_counter(pc, true) +
          " does not return!");

    ICFG[bb].Term._return.Returns = true; /* witnessed */
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

    binary_index_t BIdx;
    basic_block_index_t BBIdx;
    std::tie(BIdx, BBIdx) = block_at_program_counter(child, pc);

    if (unlikely(!is_basic_block_index_valid(BBIdx)))
      die("on_return: returned to unknown @ " +
          description_of_program_counter(pc, true));

    binary_t &b = jv.Binaries.at(BIdx);

    auto s_lck = b.BBMap.shared_access();

    //
    // what came before?
    //
    uintptr_t before_pc = pc - 1 - IsMIPSTarget*4;

    binary_index_t Before_BIdx;
    basic_block_index_t Before_BBIdx;
    std::tie(Before_BIdx, Before_BBIdx) =
        existing_block_at_program_counter(child, before_pc);

    if (unlikely(!is_basic_block_index_valid(Before_BBIdx))) {
      if (IsVeryVerbose())
        HumanOut() << llvm::formatv("on_return: unknown block before @ {0}\n",
                                    description_of_program_counter(pc, true));
      return;
    }

    if (unlikely(BIdx != Before_BIdx)) {
      if (IsVeryVerbose())
        HumanOut() << llvm::formatv(
            "on_return: unexpected crossing of boundary @ {0}",
            description_of_program_counter(before_pc, true));
      return;
    }

    auto &ICFG = b.Analysis.ICFG;
    bb_t before_bb = basic_block_of_index(Before_BBIdx, ICFG);

    auto &before_Term = ICFG[before_bb].Term;

    bool isCall = before_Term.Type == TERMINATOR::CALL;
    bool isIndirectCall = before_Term.Type == TERMINATOR::INDIRECT_CALL;

    if (!isCall && !isIndirectCall) {
      if (IsVeryVerbose())
        HumanOut() << llvm::formatv("on_return: unexpected term {0} @ {1}\n",
                                    description_of_terminator(before_Term.Type),
                                    description_of_program_counter(before_pc, true));
      return;
    }

    assert(ICFG.out_degree(before_bb) <= 1);

    if (isCall && is_function_index_valid(before_Term._call.Target))
      b.Analysis.Functions.at(before_Term._call.Target).Returns = true;

    // connect
    if (ICFG.add_edge(before_bb, basic_block_of_index(BBIdx, ICFG)).second)
      ICFG[before_bb].InvalidateAnalysis(jv, b);
  }
}

std::string BootstrapTool::StringOfMCInst(llvm::MCInst &Inst) {
  std::string res;

  {
    llvm::raw_string_ostream ss(res);

    disas->IP->printInst(&Inst, 0x0 /* XXX */, "", *disas->STI, ss);

    ss << " <" << Inst.getOpcode() << '>';
    for (unsigned i = 0; i < Inst.getNumOperands(); ++i) {
      const llvm::MCOperand &opnd = Inst.getOperand(i);

      char buff[0x100];
      if (opnd.isReg())
        snprintf(buff, sizeof(buff), "<reg %u>", opnd.getReg());
      else if (opnd.isImm())
        snprintf(buff, sizeof(buff), "<imm %" PRId64 ">", opnd.getImm());
#if 0
      else if (opnd.isFPImm())
        snprintf(buff, sizeof(buff), "<imm %lf>", opnd.getFPImm());
#endif
      else if (opnd.isExpr())
        snprintf(buff, sizeof(buff), "<expr>");
      else if (opnd.isInst())
        snprintf(buff, sizeof(buff), "<inst>");
      else
        snprintf(buff, sizeof(buff), "<unknown>");

      ss << (fmt(" %u:%s") % i % buff).str();
    }
  }

  return res;
}

binary_index_t BootstrapTool::binary_at_program_counter(pid_t child,
                                                        uintptr_t pc) {
  {
    auto it = intvl_map_find(AddressSpace, pc);
    if (likely(it != AddressSpace.end()))
      return (*it).second;
  }

  //
  // sanity check
  //
  auto pm_it = intvl_map_find(pmm, pc);
  if (pm_it == pmm.end()) {
    UpdateVM(child);

    pm_it = intvl_map_find(pmm, pc);
    if (pm_it == pmm.end()) {
      if (IsVerbose())
      HumanOut() << llvm::formatv(
          "binary_at_program_counter: unknown code @ {0}\n",
          description_of_program_counter(pc, true));
      return invalid_binary_index;
    }
  }

  assert(pm_it != pmm.end());

  // WARN_ON(!pm.x);

#if 0
  const proc_map_t &pm = cached_proc_maps.at((*pm_it).second);

  binary_index_t BIdx = invalid_binary_index;

  const std::string &nm = pm.nm;
  if (nm.empty()) {
    if (IsVerbose())
      HumanOut() << llvm::formatv(
          "binary_at_program_counter: anonymous memory @ {0}\n",
          description_of_program_counter(pc, true));

    // no way to determine what this is
    return invalid_binary_index;
  } else if (nm.front() != '/') {
    //
    // [vdso], [vsyscall], ...
    //
    if (nm.front() != '[')
      die("unrecognized mapping \"" + nm + "\"");

    if (boost::algorithm::starts_with(nm , "[anon:")) {
      // COFF HACK

      int the_fd, the_off;
      std::tie(the_fd, the_off) = extract_fd_and_off(nm);

      // readlink fd
      // /proc/<child>/fd/<fd>
      char buff[PATH_MAX];
      char the_path[2 * PATH_MAX];

      snprintf(buff, sizeof(buff), "/proc/%d/fd/%d", (int)child, the_fd);
      buff[strlen(buff) - 1] = '\0';

      ssize_t len = ::readlink(buff, &the_path[0], sizeof(the_path));
      if (len == -1) {
        HumanOut() << "readlink failed: " << strerror(errno) << '\n';
      }
      aassert(len != sizeof(the_path) && len != -1);

      HumanOut() << "we got a path: " << the_path << '\n';

      BIdx = BinaryFromPath<false>(child, the_path);
    } else {
      const bool IsVDSO = nm == "[vdso]";
      std::string_view sv;
      std::vector<std::byte> buff_bytes;
      if (IsVDSO) {
        sv = get_vdso();
      } else {
        try {
          ptrace::memcpy_from(child, buff_bytes, (const void *)pm.beg, pm.end - pm.beg);
        } catch (const std::exception &e) {
          if (IsVerbose())
            HumanOut() << llvm::formatv("failed to read {0} in tracee\n", nm);
          return invalid_binary_index;
        }

        sv = std::string_view(reinterpret_cast<const char *>(buff_bytes.data()),
                              buff_bytes.size());
      }

      BIdx = BinaryFromData(child, sv, nm.c_str());

      if (is_binary_index_valid(BIdx) && IsVDSO)
        jv.Binaries.at(BIdx).IsVDSO = true;
    }
  } else {
    BIdx = BinaryFromPath<false>(child, nm.c_str());
  }

  if (!is_binary_index_valid(BIdx)) {
    if (IsVerbose()) {
      HumanOut() << llvm::formatv("failed to add {0} for {1} \n", nm, taddr2str(pc));
      if (IsVeryVerbose())
        HumanOut() << ProcMapsForPid(child);
    }

    return invalid_binary_index;
  }

  assert(is_binary_index_valid(BIdx));
#endif

  //
  // rescan address space (NOTE: we may just want to add the binary of interest)
  //
  ScanAddressSpace(child, false);

  {
    auto it = intvl_map_find(AddressSpace, pc);
    if (it == AddressSpace.end()) {
      if (IsVeryVerbose()) {
        const proc_map_t &pm = cached_proc_maps.at((*pm_it).second);
        die("added " + pm.nm + " but AddressSpace unchanged");
      }

      return invalid_binary_index;
    }

    return (*it).second;
  }
}

std::pair<binary_index_t, function_index_t>
BootstrapTool::function_at_program_counter(pid_t child, uintptr_t pc) {
  binary_index_t BIdx = binary_at_program_counter(child, pc);
  if (!is_binary_index_valid(BIdx))
    return std::make_pair(invalid_binary_index, invalid_function_index);

  binary_t &binary = jv.Binaries.at(BIdx);
  auto &x = state.for_binary(binary);

  assert(x.Loaded());

  basic_block_index_t BBIdx =
      E->explore_basic_block(binary, x.Bin.get(), va_of_pc(pc, BIdx));
  if (!is_basic_block_index_valid(BBIdx))
    return std::make_pair(BIdx, invalid_function_index);

  function_index_t FIdx =
      E->explore_function(binary, x.Bin.get(), va_of_pc(pc, BIdx));

  return std::make_pair(BIdx, FIdx);
}

block_t
BootstrapTool::block_at_program_counter(pid_t child, uintptr_t pc) {
  binary_index_t BIdx = binary_at_program_counter(child, pc);
  if (!is_binary_index_valid(BIdx))
    return std::make_pair(invalid_binary_index, invalid_basic_block_index);

  binary_t &binary = jv.Binaries.at(BIdx);
  auto &x = state.for_binary(binary);

  assert(x.Loaded());

  basic_block_index_t BBIdx =
      E->explore_basic_block(binary, x.Bin.get(), va_of_pc(pc, BIdx));

  return std::make_pair(BIdx, BBIdx);
}

// bbmap needs to be locked.
std::pair<binary_index_t, basic_block_index_t>
BootstrapTool::existing_block_at_program_counter(pid_t child, uintptr_t pc) {
  binary_index_t BIdx = binary_at_program_counter(child, pc);
  if (!is_binary_index_valid(BIdx))
    return std::make_pair(invalid_binary_index, invalid_basic_block_index);

  binary_t &b = jv.Binaries.at(BIdx);
  uintptr_t rva = va_of_pc(pc, BIdx);

  basic_block_index_t BBIdx = ({
    bbmap_t *const pbbmap = b.BBMap.map.get();
    assert(pbbmap);
    bbmap_t &bbmap = *pbbmap;
    auto it = bbmap_find(bbmap, rva);
    if (it == bbmap.end())
      return std::make_pair(BIdx, invalid_basic_block_index);

    (*it).second;
  });

  return std::make_pair(BIdx, BBIdx);
}

std::string BootstrapTool::description_of_program_counter(uintptr_t pc, bool Verbose, bool Symbolize) {
#if 0 /* defined(__mips64) || defined(__mips__) */
  if (ExecutableRegionAddress &&
      pc >= ExecutableRegionAddress &&
      pc < ExecutableRegionAddress + 8) {
    uintptr_t off = pc - ExecutableRegionAddress;
    return (fmt("[exeregion]+%#lx") % off).str();
  }
#endif

  if (!pc)
    return taddr2str(0x0, true);

  const std::string simple_desc = (fmt("%#lx") % pc).str();

#if 0
  return simple_desc;
#endif

  auto pm_it = intvl_map_find(pmm, pc);
  if (pm_it == pmm.end() && _child) {
    UpdateVM(_child);
    pm_it = intvl_map_find(pmm, pc);
  }

  if (pm_it == pmm.end()) {
    return simple_desc;
  } else {
    std::string extra = Verbose ? (" (" + simple_desc + ")") : "";

    const proc_map_t &pm = cached_proc_maps.at((*pm_it).second);

    std::string nm = pm.nm;
    uintptr_t the_off = pm.off;

    if (nm.empty())
      return (fmt("%#lx+%#lx%s") % pm.beg % (pc - pm.beg) % extra).str();

    if (boost::algorithm::starts_with(nm, "[anon:")) {
      nm.resize(2 * PATH_MAX);

      ssize_t len = ({
        int the_fd;
        std::tie(the_fd, the_off) = extract_fd_and_off(nm);

        char buff[1024];
        snprintf(buff, sizeof(buff), "/proc/%d/fd/%d", (int)_child, the_fd);
        ::readlink(buff, &nm[0], nm.size());
      });

      aassert(len != nm.size() && len != -1);
      nm.resize(len);
    }

    if (Symbolize) {
      auto it = intvl_map_find(AddressSpace, pc);
      if (it != AddressSpace.end()) {
        binary_index_t BIdx = (*it).second;
        binary_t &b = jv.Binaries.at(BIdx);
        auto &x = state.for_binary(b);

        if (x.Loaded()) {
          //
          // pc is in binary that's been "loaded"
          //
          ptrdiff_t off = pc - (pm.beg - the_off);

          uintptr_t Addr;
          try {
            Addr = B::va_of_offset(x.Bin.get(), off);

            symbolizer_t *const psymbolizer = symbolizer.get();
            if (psymbolizer) {
              std::string line = psymbolizer->addr2line(b, Addr);
              if (!line.empty())
                return line;
            }

            std::string str = fs::path(nm).filename().string();

            return (fmt("%s:%#lx%s") % str % Addr % extra).str();
          } catch (...) {}
        }
      }
    }

    return (fmt("%s+%#lx%s") % nm % (pc - (pm.beg - the_off)) % extra).str();
  }
}

void BootstrapTool::DropPrivileges(void) {
  if (!opts.Group.empty()) {
    unsigned gid = atoi(opts.Group.c_str());

    if (::setgid(gid) < 0) {
      int err = errno;
      HumanOut() << llvm::formatv("setgid failed: {0}", strerror(err));
    }
  }

  if (!opts.User.empty()) {
    unsigned uid = atoi(opts.User.c_str());

    if (::setuid(uid) < 0) {
      int err = errno;
      HumanOut() << llvm::formatv("setuid failed: {0}", strerror(err));
    }
  }
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
    for (pid_t child : boost::adaptors::reverse(tool.children)) {
//    for (unsigned i = 0; i < 10; ++i)
        if (::tgkill(child, child, SIGSTOP) < 0)
          continue;

      tool.HumanOut() << llvm::formatv("waiting on {0}...\n", child);

      int status;
      do
        ::waitpid(-1, &status, __WALL);
      while (!WIFSTOPPED(status));

      tool.HumanOut() << llvm::formatv("waited on {0}.\n", child);

      if (::ptrace(PTRACE_DETACH, child, 0UL, reinterpret_cast<void *>(SIGSTOP)) < 0) {
        int err = errno;
        tool.HumanOut() << llvm::formatv(
            "failed to detach from tracee [{0}]: {1}\n", child,
            strerror(err));
      } else {
        tool.HumanOut() << "PTRACE_DETACH succeeded\n";
      }
    }

    for (;;) sleep(1);

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
    SerializeJVToFile(tool.jv, tool.jv_file, "/tmp/serialized.jv", true /* text */);

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

namespace cl = llvm::cl;

namespace jove {

struct BootstrapTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> Prog;
    cl::list<std::string> Args;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Prog(cl::Positional, cl::desc("prog"), cl::Required,
               cl::value_desc("filename"), cl::cat(JoveCategory)),

          Args("args", cl::CommaSeparated, cl::ConsumeAfter,
               cl::desc("<program arguments>..."), cl::cat(JoveCategory)) {}
  } opts;

  BootstrapTool() : opts(JoveCategory) {}

  int Run(void) override {
    HumanOut() << "bootstrap: invalid host arch for target\n";
    return 1;
  }
};

JOVE_REGISTER_TOOL("bootstrap", BootstrapTool);

}

#endif

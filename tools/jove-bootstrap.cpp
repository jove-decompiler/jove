#if (defined(__x86_64__)  && defined(TARGET_X86_64))  || \
    (defined(__x86_64__)  && defined(TARGET_I386))  || \
    (defined(__i386__)    && defined(TARGET_I386))    || \
    (defined(__aarch64__) && defined(TARGET_AARCH64)) || \
    (defined(__mips64)    && defined(TARGET_MIPS64))  || \
    (defined(__mips64)    && defined(TARGET_MIPS32))  || \
    (defined(__mips__)    && defined(TARGET_MIPS32))
#include "bootstrap.h"
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
#include "brkpt.h"
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
#include <optional>

#include <linux/fs.h>
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

#ifdef JOVE_BOOTSTRAP_EAGER_INVALIDATION
#define eager_invalidate_block(__the_bbprop, __the_binary)                     \
  do {                                                                         \
    bbprop_t &___the_bbprop = __the_bbprop;                                    \
    binary_t &___the_binary = __the_binary;                                    \
                                                                               \
    this->invalidate_block(___the_bbprop, ___the_binary);                      \
  } while (false)
#else
#define eager_invalidate_block(...) do {} while (false)
#endif

namespace fs = boost::filesystem;
namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

#if defined(__x86_64__)
#define SYSCALLS_INC_H "arch/x86_64/syscalls.inc.h"
#define COMPAT_SYSCALLS_INC_H "arch/i386/syscalls.inc.h"
#elif defined(__i386__)
#define SYSCALLS_INC_H "arch/i386/syscalls.inc.h"
#elif defined(__aarch64__)
#define SYSCALLS_INC_H "arch/aarch64/syscalls.inc.h"
#elif defined(__mips64)
#define SYSCALLS_INC_H "arch/mips64/syscalls.inc.h"
#define COMPAT_SYSCALLS_INC_H "arch/mips32/syscalls.inc.h"
#elif defined(__mips__)
#define SYSCALLS_INC_H "arch/mips32/syscalls.inc.h"
#else
#error
#endif

namespace NR {
#define ___SYSCALL(nr, nm) static constexpr unsigned nm = nr;
#include SYSCALLS_INC_H
}
static const char *the_syscall_names[] = {
#define ___SYSCALL(nr, nm) [nr] = #nm,
#include SYSCALLS_INC_H
};
#undef SYSCALLS_INC_H

#ifdef COMPAT_SYSCALLS_INC_H
namespace compat {
namespace NR {
#define ___SYSCALL(nr, nm) static constexpr unsigned nm = nr;
#include COMPAT_SYSCALLS_INC_H
}
}
static const char *the_compat_syscall_names[] = {
#define ___SYSCALL(nr, nm) [nr] = #nm,
#include COMPAT_SYSCALLS_INC_H
};
#endif

struct notrap_exception {
  taddr_t pc;
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

BootstrapTool::~BootstrapTool() {}

scoped_fd &BootstrapTool::maps_for_child(void) {
  auto &fdmap = children.maps_fdmap;

  auto it = fdmap.find(_child);
  if (it == fdmap.end()) {
    std::string path_to_mem = "/proc/" + std::to_string(_child) + "/maps";
    int fd = sys::retry_eintr(::open, path_to_mem.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0)
      throw std::runtime_error("failed to open " + path_to_mem + ": " +
                               strerror(errno));

    return (*fdmap.emplace(_child, fd).first).second;
  }
  return (*it).second;
}

scoped_fd &BootstrapTool::mem_for_child(void) {
  auto &fdmap = children.mem_fdmap;

  auto it = fdmap.find(_child);
  if (it == fdmap.end()) {
    std::string path_to_mem = "/proc/" + std::to_string(_child) + "/mem";
    int fd = sys::retry_eintr(::open, path_to_mem.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0)
      throw std::runtime_error("failed to open " + path_to_mem + ": " +
                               strerror(errno));

    return (*fdmap.emplace(_child, fd).first).second;
  }
  return (*it).second;
}

template <bool Throw>
ssize_t BootstrapTool::peek(const taddr_t src,
                            uint8_t *const dst,
                            const size_t len) {
  auto peek_using_proc_mem = [&](void) -> bool {
    scoped_fd &fd = mem_for_child();
    if (unlikely(!fd))
      return false;

    size_t n = 0;
    while (n != len) {
      size_t left = len - n;
      ssize_t ret =
          sys::retry_eintr(::pread64, fd.get<false>(), &dst[n], left, src + n);

      if (likely(ret > 0)) {
        n += static_cast<size_t>(ret);
        continue;
      }

      if (ret == 0)
        return false;

      aassert(ret < 0);
      const int err = errno;

      if (err == EINTR)
        continue;

      if (err == EIO)
        return false;
    }

    return n == len;
  };

  auto peek_using_process_vm = [&](void) -> bool {
    return ptrace::vm_read<Throw>(_child, src, dst, len) == len;
  };

  auto peek_using_peekdata = [&](void) -> bool {
    return ptrace::vm_peek<Throw>(_child, src, dst, len) == len;
  };

  if (likely(peek_using_proc_mem()) ||
      peek_using_process_vm() ||
      peek_using_peekdata())
    return len;

  if constexpr (Throw)
    throw ptrace::tracer_exception(EIO, src);

  abort();
}

template <bool Throw>
ssize_t BootstrapTool::poke(const taddr_t dst,
                            const uint8_t *src,
                            const size_t len) {
  auto poke_using_proc_mem = [&](void) -> bool {
    scoped_fd &fd = mem_for_child();
    if (unlikely(!fd))
      return false;

    size_t n = 0;
    while (n != len) {
      size_t left  = len - n;
      ssize_t ret =
          sys::retry_eintr(::pwrite64, fd.get<false>(), &src[n], left, dst + n);

      if (likely(ret > 0)) {
        n += static_cast<size_t>(ret);
        continue;
      }

      if (ret == 0) {
        abort(); /* should never happen */
      }

      aassert(ret < 0);
      const int err = errno;

      if (err == EINTR)
        continue;

      if constexpr (Throw) {
        throw ptrace::tracer_exception(err, dst);
      }

      return -err;
    }

    return n == len;
  };

  auto poke_using_process_vm = [&](void) -> bool {
    return ptrace::vm_write<Throw>(_child, dst, src, len) == len;
  };

  auto poke_using_pokedata = [&](void) -> bool {
    return ptrace::vm_poke<Throw>(_child, dst, src, len) == len;
  };

  if (likely(poke_using_proc_mem()) ||
      poke_using_process_vm() ||
      poke_using_pokedata())
    return len;

  if constexpr (Throw)
    throw ptrace::tracer_exception(EIO, dst);

  abort();
}

int BootstrapTool::Run(void) {
  long ret = -1L;
  pTool = this;

  for_each_binary(maybe_par_unseq, jv, [&](binary_t &b) {
    for (const std::string &name : opts.SkipBins) {
      if (b.Name.find(name) != ip_string::npos) {
        if (IsVerbose())
          WithColor::warning()
              << llvm::formatv("skipping {0}\n", b.Name.c_str());

        state.for_binary(b).Skip = true;
        return;
      }
    }
  });

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

  aassert(SetAutomaticReaping(true));

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
    ret = _jove_sys_ptrace(PTRACE_ATTACH, child, 0UL, 0UL);
    if (unlikely(ret < 0)) {
      msg(llvm::formatv("PTRACE_ATTACH failed ({0})\n", strerror(-ret)).str());
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
      int tmp_options = PTRACE_O_TRACESYSGOOD |
                     /* PTRACE_O_EXITKILL   | */
                        PTRACE_O_TRACEEXIT  |
                     /* PTRACE_O_TRACEEXEC  | */
                        PTRACE_O_TRACEFORK  |
                        PTRACE_O_TRACEVFORK |
                        PTRACE_O_TRACECLONE;

      ret = _jove_sys_ptrace(PTRACE_SETOPTIONS, child, 0UL, tmp_options);
      if (unlikely(ret < 0)) {
        msg(llvm::formatv("{0}: PTRACE_SETOPTIONS failed ({1})\n", __func__,
                          strerror(-ret)).str());
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
      msg(llvm::formatv("parent: running {0}\n", path_to_exe).str());

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
          _jove_sys_ptrace(PTRACE_TRACEME, 0UL, 0UL, 0UL);
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
  tcg = std::make_unique<tcg_t<>>();
  if (opts.Symbolize) {
  symbolizer = std::make_unique<symbolizer_t>(jv, locator(), opts.Addr2Line);
  }
  E = std::make_unique<explorer_t<IsToolMT, IsToolMinSize>>(
      jv_file, jv, *disas, std::max<unsigned>(GetVerbosityLevel(), 1u));
  emulator = std::make_unique<ptrace_emulator_t>(*this, *disas);
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
  Engaged = true;

  llvm::errs() << ProcMapsForPid(_child);

  if (!has_ProcMapQuery)
    ScanAddressSpace(child);

  if (has_ProcMapQuery || IsVerbose()) {
    //
    // we should be at the entry point of the dynamic linker
    //
    ptrace::target_tracee_state_t tracee_state;
    tracee_state.get(child);

    const auto pc = tracee_state.program_counter();

    auto BBPair = block_at_program_counter(child, pc);

    if (unlikely(!is_basic_block_index_valid(BBPair.second)))
      msg(llvm::formatv(
              "failed to translate block at first ptrace-stop @ {0}\n",
              description_of_program_counter(pc, true)).str());

    if (IsVerbose())
      msg(llvm::formatv("first ptrace-stop @ {0}\n",
                        description_of_program_counter(pc, true)).str());
  }

  //
  // establish options
  //
  ret = _jove_sys_ptrace(PTRACE_SETOPTIONS, child, 0UL, ptrace_options);
  if (unlikely(ret < 0)) {
    msg(llvm::formatv("{0}: PTRACE_SETOPTIONS failed ({1})\n", __func__,
                      strerror(-ret)).str());
  }

  //
  // go
  //
  aassert(_jove_sys_ptrace(opts.Syscalls ? PTRACE_SYSCALL : PTRACE_CONT, child,
                           0UL, 0UL) == 0);

  return TracerLoop(child);
}

void BootstrapTool::Reset(void) {
  Engaged = true;

  {
  auto e_lck = safe_trapmap.exclusive_access();
  safe_trapmap.m.clear();
  }
  Loaded.clear();
  cached_proc_maps.clear();
  pmm.clear();
  {
    auto e_lck = SafeAddressSpace.exclusive_access();
    SafeAddressSpace.m.clear();
  }
#if 0
  children.set.clear();
#endif
  children.mem_fdmap.clear();
  children.is_target_map.clear();
  children_syscall_state_map.clear();

  _r_debug.Reset();

  emulator->ExecutableRegionAddress = 0x0;

#if defined(TARGET_I386)
  emulator->fs_base = ~0ul;
  emulator->fs_base = ~0ul;
#endif
}

taddr_t BootstrapTool::pc_of_offset(taddr_t off, const binary_index_t BIdx) {
  const auto &x = state.for_binary_of_index(BIdx);
  aassert(x.HasLoadAddr());

  // TODO? we can use the cached proc maps to get this faster
  return pc_of_va(B::cached::va_of_offset(x.cb, off), BIdx);
}

taddr_t BootstrapTool::pc_of_va(taddr_t addr, const binary_index_t BIdx) {
  const auto &x = state.for_binary_of_index(BIdx);
  aassert(x.HasLoadAddr());

  return x.LoadAddr + (addr - x.bounds.first);
}

taddr_t BootstrapTool::va_of_pc(taddr_t pc, const binary_index_t BIdx) {
  auto &x = state.for_binary_of_index(BIdx);
  aassert(x.HasLoadAddr());

  return (pc - x.LoadAddr) + x.bounds.first;
}

int BootstrapTool::TracerLoop(pid_t child) {
  siginfo_t si;
  long sig = 0;
  const unsigned long syscall_or_cont =
      opts.Syscalls ? PTRACE_SYSCALL : PTRACE_CONT;
  const unsigned SavedGeneration = jv.generation.load(boost::memory_order_relaxed);
  const unsigned SavedNumBinaries = jv.NumBinaries();

#ifndef JOVE_BOOTSTRAP_EAGER_INVALIDATION
  BOOST_SCOPE_DEFER [&] {
    bool Changed = false;

    Changed = Changed || (SavedNumBinaries != jv.NumBinaries());
    Changed = Changed || (jv.generation.load(boost::memory_order_relaxed) != SavedGeneration);

    if (Changed)
      jv.InvalidateAllFunctionAnalyses();
  };
#endif

  {
    for (;; (void)({
           if (!(child < 0)) {

             if (sig) {
//             aassert(child == si.si_pid);

#if 0
               const bool suppress =
                   (sig == SIGCHLD && (ignore_sigchld.erase(child) > 0)) ||
                   (sig == SIGSTOP && (ignore_sigstop.erase(child) > 0));
#else
               const bool suppress = false;
#endif
               if (suppress) {
                 if (IsVeryVerbose())
                   msg(llvm::formatv("suppressing signal {0} to {1}!", sig,
                                     child).str());

                 sig = 0;
               } else {
                 if (opts.Signals)
                   msg(llvm::formatv("delivering signal {0} <{1}> to {2}", sig,
                                     strsignal(sig), child).str());
               }
             }

             long ret = _jove_sys_ptrace(syscall_or_cont, child, 0UL, sig);
             if (unlikely(ret < 0))
               msg(llvm::formatv("failed to resume tracee {0}: {1}\n", child,
                                 strerror(-ret)).str());
           }

           0;
         })) {

      //
      // wait for a child process to stop or terminate
      //
      int status;
      _child = child = _jove_sys_wait4(-1, &status, __WALL, NULL);
      if (unlikely(child < 0)) {
        const int err = -child;
        assert(err != EINTR);

        if (IsVerbose())
          msg(llvm::formatv("exiting... ({0})\n", strerror(err)).str());

        break;
      }

#if 0
      children.set.insert(child);
#endif

      if (likely(WIFSTOPPED(status))) {
        //
        // this is an opportunity to examine the state of the tracee
        //
        sig = 0;

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
        if (likely(stopsig == SIGTRAP)) {
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
                msg(llvm::formatv("unknown ptrace event {0}\n", event).str());
              break;

            case PTRACE_EVENT_VFORK:
            case PTRACE_EVENT_FORK: {
              unsigned long new_child;
              if (_jove_sys_ptrace(PTRACE_GETEVENTMSG, child, 0UL,
                                   reinterpret_cast<uintptr_t>(&new_child)) < 0) {
                die("PTRACE_GETEVENTMSG on fork()/vfork()");
              }

              if (opts.PrintPtraceEvents)
                msg(llvm::formatv("<PTRACE_EVENT_{0}FORK> {1} => {2}\n",
                                  event == PTRACE_EVENT_VFORK ? "V" : "", child,
                                  new_child).str());

//            sig = SIGSTOP;
              forked.insert(new_child);
              break;
            }
            case PTRACE_EVENT_CLONE: {
              unsigned long new_child;
              _jove_sys_ptrace(PTRACE_GETEVENTMSG, child, 0UL,
                               reinterpret_cast<uintptr_t>(&new_child));

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
              long ret =
                  _jove_sys_ptrace(PTRACE_GETEVENTMSG, child, 0UL,
                                   reinterpret_cast<uintptr_t>(&new_pid));
              if (unlikely(ret < 0)) {
                WithColor::warning() << llvm::formatv(
                    "PTRACE_GETEVENTMSG failed: {0} (PTRACE_EVENT_EXEC)\n",
                    strerror(-ret));

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
                msg(llvm::formatv("<PTRACE_EVENT_EXEC> \"{0}\" [{1}]\n", exe_path, new_pid).str());
              else if (IsVerbose())
                msg(llvm::formatv("tracee {0} exec'd {1}\n", new_pid, exe_path).str());

              //
              // the address space has been reset, so we need
              // to clear our breakpoint tables and anything else that is
              // dependent on the tracee's state.
              //
              this->Reset(); /* right arch is assumed */

              auto DetachFromChild = [&](void) -> void {
                if (IsVerbose())
                  msg(llvm::formatv("detaching from {0}!\n", child).str());

                if (_jove_sys_ptrace(PTRACE_DETACH, child, 0UL, 0UL) < 0) {
                  int err = errno;
                  die("PTRACE_DETACH on exec of wineserver: " + std::string(strerror(err)));
                }

                ::kill(child, SIGCONT);

#if 0
                child = -1;
#endif
              };

              bool ShouldDetach = false;

              if (!is_child_target(child))
                Engaged = false;

              if (fs::equivalent(locator().wine_server(IsTarget32), exe_path)) {
                ShouldDetach = true;
              } else if (fs::equivalent(locator().wine_preloader(IsTarget32), exe_path)) {
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
                Engaged = false;
                DetachFromChild();
              } else if (Engaged) {
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
            aassert(is_child_target(child));
            if (unlikely(!handle_breakpoint())) {
              if (opts.PrintPtraceEvents)
                HumanOut() << "mysterious ptrace event\n";
            }
          }
        } else if (stopsig == (SIGTRAP | 0x80)) {
          //
          // (1) Syscall-enter-stop and syscall-exit-stop are observed by the
          // tracer as waitpid(2) returning with WIFSTOPPED(status) true, and-
          // if the PTRACE_O_TRACESYSGOOD option was set by the tracer- then
          // WSTOPSIG(status) will give the value (SIGTRAP | 0x80).
          //
          if constexpr (std::is_void_v<ptrace::compat_tracee_state_t>) {
            aassert(is_child_target(child));
            on_syscall_enter_or_exit<false>(child);
          } else {
            if (is_child_compat(child))
              on_syscall_enter_or_exit<true>(child);
            else
              on_syscall_enter_or_exit<false>(child);
          }
        } else if (_jove_sys_ptrace(PTRACE_GETSIGINFO, child, 0UL,
                                    reinterpret_cast<uintptr_t>(&si)) < 0) {
          //
          // (3) group-stop
          //

          if (opts.PrintPtraceEvents)
            msg(llvm::formatv("ptrace group-stop [{0}]", child).str());

          // When restarting a tracee from a ptrace-stop other than
          // signal-delivery-stop, recommended practice is to always pass 0 in
          // sig.
        } else {
          //
          // (4) signal-delivery-stop
          //

          // deliver it
          sig = stopsig;

          if (stopsig == SIGILL) { /* maybe us */
            if (handle_breakpoint())
              sig = 0; /* was us */
          } else if (stopsig == SIGSEGV) {
            if (ptrace::is_target_compat)
              aassert(is_child_compat(child));
            else
              aassert(!is_child_compat(child));

            ptrace::tracee_state_t tracee_state;
            tracee_state.get(child);
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
              taddr_t RetAddr = tracee_state.regs[31 /* ra */];

              tracee_state.cp0_epc = RetAddr;
              tracee_state.set(child);

              sig = 0; /* suppress */

              on_return(child, invalid_binary_index, 0 /* XXX */, RetAddr);
            }
#else
            if (IsVerbose()) {
              msg(llvm::formatv("sigsegv @ {0}",
                                description_of_program_counter(
                                    tracee_state.program_counter(), true)).str());
            }
#endif
          } else if (stopsig == SIGSTOP) {
            if (unlikely(forked.erase(child))) {
              sig = 0; /* suppress */

              const pid_t new_child = child;

              if (IsVeryVerbose())
                msg(llvm::formatv("waited on forked child. [{0}]", child).str());

              //
              // upon a fork(), we detach, fork(), and then reattach.
              //
              if (_jove_sys_ptrace(PTRACE_DETACH, new_child, 0UL, SIGSTOP) < 0) {
                int err = errno;
                die("PTRACE_DETACH on fork(): " + std::string(strerror(err)));
              } else {
                if (IsVeryVerbose())
                  msg(llvm::formatv("detached [{0}]", new_child).str());
              }

              scoped_fd our_pfd(pidfd_open(::getpid(), 0));

              if (jove::fork()) {
                if (IsVeryVerbose())
                  msg("forked!");

#if 0
                ignore_sigchld.insert(/* new_child */ saved_child);
#endif
                child = -1;
                continue;
              } else {
                if (IsVeryVerbose())
                  msg("hi!");

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

                int err = _jove_sys_ptrace(PTRACE_ATTACH, new_child, 0UL, 0UL);
                if (err < 0) {
                  die("PTRACE_ATTACH on fork() " + std::string(strerror(-err)));
                } else {
                  if (IsVeryVerbose())
                    msg(llvm::formatv("attached [{0}], suppressing next SIGSTOP", new_child).str());
#if 0
                  ignore_sigstop.insert(new_child);
#endif

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

                  long ret = _jove_sys_ptrace(PTRACE_SETOPTIONS, new_child, 0UL, ptrace_options);
                  if (unlikely(ret < 0)) {
                    die(llvm::formatv("{0}: PTRACE_SETOPTIONS failed ({1})",
                                      __func__, strerror(-ret)).str());
                  }
                }
              }
            }
          }
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
          msg(llvm::formatv("child {0} terminated ({1})", child, the_status).str());

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

        bb_t bb;
        {
          auto s_lck = b.BBMap.shared_access();

          auto vi_pair = ICFG.vertices();
          for (auto vi = vi_pair.first; vi != vi_pair.second; ++vi) {
            bb = *vi;

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

        if (E->fix_ambiguous_indirect_jump(b, state.for_binary(b).cb, TermAddr)) {
          eager_invalidate_block(ICFG[bb], b);
          ++NumChanged;
        }
      }
    });

    if (IsVerbose())
      if (unsigned c = NumChanged.load())
        msg(llvm::formatv("fixed {0} ambiguous indirect jump{1}", c,
                          c > 1 ? "s" : "").str());
  }

  return 0;
}

bool BootstrapTool::is_child_target(pid_t child) {
  auto it = children.is_target_map.find(child);
  if (it == children.is_target_map.end()) {
    std::string exe_path;
    exe_path.resize(2 * PATH_MAX);

    //
    // check that the executable architecture matches our target.
    //
    // even if one provides a 64-bit windows program for WINE to run,
    // it still may exec a 32-bit windows program (i.e. the preloader)
    // as part of the startup sequence.
    //
    {
      ssize_t len = ({
        char buff[PATH_MAX];
        snprintf(buff, sizeof(buff), "/proc/%u/exe",
                 static_cast<unsigned>(child));

        ::readlink(buff, &exe_path[0], exe_path.size() - 1);
      });

      aassert(len != exe_path.size());
      exe_path.resize(len);
    }

    bool is_target = true;

    std::vector<std::byte> BinBytes;
    B::unique_ptr Bin;
    const bool Ex = ignore_exception([&] {
      if (boost::algorithm::starts_with(exe_path, "/memfd:jove/bootstrap"))
        Bin = B::Create(jv.Binaries.at(0).data());
      else
        Bin = B::CreateFromFile(exe_path.c_str(), BinBytes);
    });

    if (Ex || (!B::is_elf(Bin.get()) && !B::is_coff(Bin.get())))
      is_target = false;

    children.is_target_map.emplace(child, is_target);

    return is_target;
  }

  return (*it).second; /* already computed */
}

bool BootstrapTool::is_child_compat(pid_t child) {
  const bool is_target = is_child_target(child);

  return (ptrace::is_target_compat && is_target) ||
    (!ptrace::is_target_compat && !is_target);
}

template <bool Compat>
enum PTraceStop BootstrapTool::on_syscall_enter_or_exit(pid_t child) {
  PTraceStop Res = PTraceStop::Unknown;

  using the_tracee_state_t =
      std::conditional_t<Compat,
                         ptrace::compat_tracee_state_t,
                         ptrace::tracee_state_t>;
  static constexpr bool is64 = the_tracee_state_t::is64;
  using word_t = std::conditional_t<is64, uint64_t, uint32_t>;

  child_syscall_state_t &syscall_state = children_syscall_state_map[child];

  the_tracee_state_t tracee_state;
  tracee_state.get(child);

  word_t pc = tracee_state.program_counter();
  word_t &syscall_pc = [&]() -> word_t & {
    if constexpr (is64)
      return syscall_state._64.pc;
    else
      return syscall_state._32.pc;
  }();

  //
  // determine whether this syscall is entering or has exited
  //
  unsigned dir = syscall_state.dir;

  if (syscall_pc != pc)
    dir = 0; /* we must see the same pc twice */

  if (dir == 0 /* enter */) {
    Res = PTraceStop::SyscallEnter;

    //
    // syscall # and arguments
    //
    const unsigned no = tracee_state.syscall_number();
    const word_t a0 = tracee_state.syscall_argument(0);
    const word_t a1 = tracee_state.syscall_argument(1);
    const word_t a2 = tracee_state.syscall_argument(2);
    const word_t a3 = tracee_state.syscall_argument(3);
    const word_t a4 = tracee_state.syscall_argument(4);
    const word_t a5 = tracee_state.syscall_argument(5);

    syscall_state.no = no;
    if (is64) {
      syscall_state._64.args[0] = a0;
      syscall_state._64.args[1] = a1;
      syscall_state._64.args[2] = a2;
      syscall_state._64.args[3] = a3;
      syscall_state._64.args[4] = a4;
      syscall_state._64.args[5] = a5;
    } else {
      syscall_state._32.args[0] = a0;
      syscall_state._32.args[1] = a1;
      syscall_state._32.args[2] = a2;
      syscall_state._32.args[3] = a3;
      syscall_state._32.args[4] = a4;
      syscall_state._32.args[5] = a5;
    }

    auto on_syscall_enter = [&](void) -> void {
      switch (no) {
      case __NR_exit:
      case __NR_exit_group:
        if (IsVerbose())
          msg("Observed program exit.");
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
    Res = PTraceStop::SyscallExit;

    const word_t ret = tracee_state.syscall_return();

    const unsigned no = syscall_state.no;
    word_t a0, a1, a2, a3, a4, a5;
    if constexpr (sizeof(word_t) == 8) {
      a0 = syscall_state._64.args[0];
      a1 = syscall_state._64.args[1];
      a2 = syscall_state._64.args[2];
      a3 = syscall_state._64.args[3];
      a4 = syscall_state._64.args[4];
      a5 = syscall_state._64.args[5];
    } else {
      a0 = syscall_state._32.args[0];
      a1 = syscall_state._32.args[1];
      a2 = syscall_state._32.args[2];
      a3 = syscall_state._32.args[3];
      a4 = syscall_state._32.args[4];
      a5 = syscall_state._32.args[5];
    }

    auto on_syscall_exit = [&](void) -> void {
      if (unlikely(ret < 0 && ret > -4096))
        return; /* system call probably failed */

      const char **syscall_names = nullptr;
      unsigned num_syscall_names = 0;

#ifdef COMPAT_SYSCALLS_INC_H
      if (Compat) {
        syscall_names = the_compat_syscall_names;
        num_syscall_names = ARRAY_SIZE(the_compat_syscall_names);
      } else {
        syscall_names = the_syscall_names;
        num_syscall_names = ARRAY_SIZE(the_syscall_names);
      }
#else
      static_assert(std::is_void_v<ptrace::compat_tracee_state_t>);

      aassert(!Compat);
      syscall_names = the_syscall_names;
      num_syscall_names = ARRAY_SIZE(the_syscall_names);
#endif

      if (IsVeryVerbose())
        HumanOut() << (no < num_syscall_names
                           ? std::string(syscall_names[no])
                           : ("unknown syscall " + std::to_string(no)))
                   << '\n';

#define VERY_UNIQUE_BASE 0xffffffULL
#define VERY_UNIQUE_NUM() (VERY_UNIQUE_BASE + __COUNTER__)

      static constexpr unsigned NR_set_thread_area =
#if defined(__x86_64__)
          Compat ? compat::NR::set_thread_area : VERY_UNIQUE_NUM()
#elif defined(__i386__)
          NR::set_thread_area
#else
          VERY_UNIQUE_NUM()
#endif
          ;

      static constexpr unsigned NR_modify_ldt =
#if defined(__x86_64__)
          Compat ? compat::NR::modify_ldt : VERY_UNIQUE_NUM()
#elif defined(__i386__)
          NR::modify_ldt
#else
          VERY_UNIQUE_NUM()
#endif
          ;

      static constexpr unsigned NR_arch_prctl =
#if defined(__x86_64__)
          Compat ? compat::NR::arch_prctl : VERY_UNIQUE_NUM()
#elif defined(__i386__)
          NR::arch_prctl
#else
          VERY_UNIQUE_NUM()
#endif
          ;

      static constexpr unsigned NR_clone =
#if defined(__x86_64__)
          Compat ? compat::NR::clone : VERY_UNIQUE_NUM()
#elif defined(__i386__)
          NR::clone
#else
          VERY_UNIQUE_NUM()
#endif
          ;

      static constexpr unsigned NR_clone3 =
#if defined(__x86_64__)
          Compat ? compat::NR::clone3 : VERY_UNIQUE_NUM()
#elif defined(__i386__)
          NR::clone3
#else
          VERY_UNIQUE_NUM()
#endif
          ;

      switch (no & 0xfffffful) {
#ifdef __NR_rt_sigaction
#if 0
      case __NR_rt_sigaction: {
        if (IsVeryVerbose())
          HumanOut() << llvm::formatv(
              "rt_sigaction({0}, {1:x}, {2:x}, {3})\n", a0, a1, a2, a3);

        taddr_t act = a2;
        if (act) {
          constexpr unsigned handler_offset =
#if defined(__mips__)
              4
#else
              0
#endif
            ;
          taddr_t handler = ptrace::peekdata(child, act + handler_offset);

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
#endif

#if defined(TARGET_I386)
      case NR_set_thread_area:
      case NR_modify_ldt:
      case NR_arch_prctl:
      case NR_clone:
      case NR_clone3:
        emulator->ss_base = ~0u;
        emulator->cs_base = ~0u;
        emulator->ds_base = ~0u;
        emulator->es_base = ~0u;
        emulator->fs_base = ~0u;
        emulator->gs_base = ~0u;
        break;
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

  syscall_pc = pc;
  syscall_state.dir = dir;

#if 0
  if (unlikely(opts.PrintLinkMap) && ((Compat && ptrace::is_target_compat) ||
                                      (!Compat && !ptrace::is_target_compat)))
    scan_rtld_link_map(child);

  if (unlikely(!AllLoaded()))
    ScanAddressSpace(child);
#endif

  return Res;
}

bool BootstrapTool::handle_breakpoint(void) {
  ptrace::target_tracee_state_t tracee_state;
  ptrace::scoped_tracee_state_t<ptrace::target_tracee_state_t>
      scoped_tracee_state(_child, tracee_state);

  if (!on_breakpoint(_child, tracee_state))
    return true;

  //
  // if we get here, it means trapmap doesn't contain an entry for the current
  // program counter.
  //
  const auto pc = tracee_state.program_counter();
  if (!has_ProcMapQuery)
    ScanAddressSpace(_child);
  else
    (void)binary_at_program_counter(_child, pc);

  const taddr_t SavedPC = pc - IsX86Target;

  binary_index_t BIdx;
  basic_block_index_t BBIdx;
  std::tie(BIdx, BBIdx) = existing_block_at_program_counter(_child, SavedPC);

  if (unlikely(!is_basic_block_index_valid(BBIdx))) {
    WithColor::error() << llvm::formatv(
        "wtf @ {0}\n",
        description_of_program_counter(SavedPC, true));
    return false;
  }

  binary_t &b = jv.Binaries.at(BIdx);
  auto &ICFG = b.Analysis.ICFG;
  fallthru<void>(
      b, BBIdx,
      [&](bbprop_t &bbprop, basic_block_index_t TheBBIdx) {
        if (IsTerminatorIndirect(bbprop.Term.Type))
          place_breakpoint_in_block(b, ICFG[ICFG.vertex<false>(TheBBIdx)], TheBBIdx);
      });

  /* TODO use return value of place_breakpoint_in_block */
  if (on_breakpoint(_child, tracee_state)) {
    vvmsg("!on_breakpoint()");
    return false; /* failure */
  }

  return true;
}

void BootstrapTool::on_new_basic_block(binary_t &b,
                                       bbprop_t &bbprop,
                                       basic_block_index_t BBIdx) { /* called with bb's lock held */
  if (!IsTerminatorIndirect(bbprop.Term.Type))
    return; /* N/A */

  place_breakpoint_in_block(b, bbprop, BBIdx);
}

void BootstrapTool::on_new_function(binary_t &b, function_t &f) {}

std::pair<trapped_t &, bool>
BootstrapTool::place_breakpoint_in_block(binary_t &b,
                                         bbprop_t &bbprop,
                                         basic_block_index_t BBIdx) {
  auto &x = state.for_binary(b);
  auto &ICFG = b.Analysis.ICFG;

  assert(!x.Skip);

  const binary_index_t BIdx = index_of_binary(b, jv);

  assert(x.HasLoadAddr());

  const auto TermType = bbprop.Term.Type;
  assert(IsTerminatorIndirect(TermType));

  const taddr_t TermAddr = bbprop.Term.Addr;
  const taddr_t termpc = pc_of_va(TermAddr, BIdx);

#if 0
  {
    auto it = trapmap.find(termpc);
    if (it != trapmap.end())
      return {(*it).second, false};
  }
#endif

  const bool IC = IsTerminatorCall(TermType);
  const bool Lj = bbprop.Lj;
  const bool NonZeroOutDegree = ICFG.template out_degree<false>(basic_block_of_index(BBIdx, b)) != 0;
  const bool HasDynTarget = bbprop.hasDynTarget();

  trapped_t *const ptrapped = ({
    auto e_lck = safe_trapmap.exclusive_access();
    auto trapped_pair = safe_trapmap.m.emplace(
        termpc, trapped_t(*emulator, BIdx, termpc, TermAddr, x.Bin().get()));
    aassert(trapped_pair.second);

    &(*trapped_pair.first).second;
  });

  assert(ptrapped);
  trapped_t &trapped = *ptrapped;

  trapped.BBIdx = BBIdx;

  trapped.BIdx = BIdx;
  trapped.TT = static_cast<unsigned>(TermType);
  trapped.IC = static_cast<unsigned>(IC);
  trapped.LJ = static_cast<unsigned>(Lj);
  trapped.OD = static_cast<unsigned>(NonZeroOutDegree);
  trapped.DT = static_cast<unsigned>(HasDynTarget);

#if 0
  if (TermType == TERMINATOR::RETURN)
    place_breakpoint_at_return(_child, termpc, trapped);
  else
    place_breakpoint_at_indirect_branch(_child, termpc, trapped);
#else
  /* FIXME (mips32/mips64, since we do differently for returns) */
  scoped_fd &mem_fd = mem_for_child();
  robust::pwrite(mem_fd.get(), TargetBrkpt, TargetBrkptLen, termpc);
#endif

  return {trapped, true};
}

static void arch_put_breakpoint(void *code);

void BootstrapTool::place_breakpoint_at_indirect_branch(pid_t child,
                                                        taddr_t pc,
                                                        indirect_branch_t &indbr) {
#if 0
  if (IsVeryVerbose())
    llvm::errs() << llvm::formatv("indjmp @ {0}\n",
                                  description_of_program_counter(pc));
#endif

  auto wrote = this->poke(pc, TargetBrkpt, TargetBrkptLen);
  aassert(wrote == TargetBrkptLen);
}

void BootstrapTool::place_breakpoint_at_return(pid_t child, taddr_t pc,
                                               return_t &r) {
#if 0
  if (IsVeryVerbose())
    llvm::errs() << llvm::formatv("return @ {0}\n", description_of_program_counter(pc));
#endif

  const uint8_t *src = nullptr;
  unsigned N = 0;

#if defined(__mips64) || defined(__mips__)
  //
  // by overwriting the return instruction with 'jr $zero' rather than the
  // conventional trap, we can get by without having to emulate the delay slot
  // instruction. hooray! the downside with this trick is that one piece of
  // information is lost: the program counter. for returns instructions, this
  // doesn't really matter.
  //
  const uint32_t insn = encoding_of_jump_to_reg(llvm::Mips::ZERO);

  src = reinterpret_cast<const uint8_t *>(&insn);
  N = sizeof(insn);
#else
  src = TargetBrkpt;
  N = TargetBrkptLen;
#endif

  auto wrote = this->poke(pc, src, N);
  aassert(wrote == N);
}

bool BootstrapTool::on_breakpoint(pid_t child,
                                  ptrace::target_tracee_state_t &tracee_state) {
  auto &pc = tracee_state.program_counter();
  const taddr_t SavedPC = pc - IsX86Target;

  trapped_t *const ptrapped = ({
    auto s_lck = safe_trapmap.shared_access();
    auto it = safe_trapmap.m.find(SavedPC);
    if (unlikely(it == safe_trapmap.m.end()))
      return true;

    &(*it).second;
  });

  assert(ptrapped);
  trapped_t &trapped = *ptrapped;

  const taddr_t TargetAddr = ({
    pc = SavedPC;
    const auto NewPC = trapped.single_step_proc(tracee_state, trapped, *emulator);

#if !(defined(TARGET_MIPS64) || defined(TARGET_MIPS32))
    pc = NewPC;
#endif

    NewPC;
  });

#ifndef NDEBUG
#if 0
  if (IsVeryVerbose())
    HumanOut() << StringOfMCInst(trapped.Inst) << '\n';
#endif
#endif

  const binary_index_t BIdx       = trapped.BIdx;
  binary_t &b = jv.Binaries.at(BIdx);
  auto &ICFG = b.Analysis.ICFG;

  const basic_block_index_t BBIdx = trapped.BBIdx;

  const auto TermType = static_cast<TERMINATOR>(trapped.TT);
  const auto TermAddr = trapped.TermAddr;
  const bool IsCall   = static_cast<bool>(trapped.IC);
  const bool IsLj     = static_cast<bool>(trapped.LJ);
  const unsigned OutDeg = trapped.OD;
  const unsigned HasDynTarget = trapped.DT;

  //////////////////////////////////////////////////////////////////////////////
  /// TONOTBE(trapped)
  ///

  struct {
    bool isNew = false;
    binary_index_t BIdx = invalid_binary_index;
  } Target;

  BOOST_SCOPE_DEFER [&] {
    if (Target.isNew)
      jv.generation.fetch_add(1, boost::memory_order_relaxed);
  };

  Target.BIdx = binary_at_program_counter(child, TargetAddr);

  struct {
    bool IsGoto = false;
  } ControlFlow;

  auto do_print_thing = [&](const char *extra = "") -> void {
    HumanOut() << llvm::formatv("{5}{3}[{4}] ({0}) {1} -> {2}" __ANSI_NORMAL_COLOR "\n",
                                ControlFlow.IsGoto ? (IsLj ? "longjmp" : "goto") : "call",
                                description_of_program_counter(SavedPC),
                                description_of_program_counter(TargetAddr),
                                ControlFlow.IsGoto ? (IsLj ? __ANSI_MAGENTA : __ANSI_GREEN) : __ANSI_CYAN,
                                child,
                                extra).str();
  };

  auto print_thing = [&](void) -> void {
    if (unlikely(!opts.Quiet && !ShowMeN && (ShowMeA || (ShowMeS && Target.isNew))))
      do_print_thing();
  };

  if (unlikely(!is_binary_index_valid(Target.BIdx))) {
    auto pm_it = intvl_map_find(pmm, TargetAddr);
    if (unlikely(pm_it == pmm.end())) {
      if (has_ProcMapQuery)
        UpdateVM(child);
      else
        ScanAddressSpace(child);
      Target.BIdx = binary_at_program_counter(child, TargetAddr);
      pm_it = intvl_map_find(pmm, TargetAddr);
    }

    const proc_map_t &pm = cached_proc_maps.at((*pm_it).second);
    if (!is_binary_index_valid(Target.BIdx)) {
      if (pm.nm.empty()) {
        //
        // anonymous memory. should we save it?
        //
      } else {
        if (IsVeryVerbose())
          do_print_thing("unknown branch target");
      }
      return false;
    }
  }

  auto &TargetBinary = jv.Binaries.at(Target.BIdx);
  auto &TargetICFG = TargetBinary.Analysis.ICFG;

  auto &x = state.for_binary(TargetBinary);
  assert(x.Loaded()); /* XXX this is important */

  binary_t &binary = jv.Binaries.at(BIdx);

  try {
    if (TermType == TERMINATOR::RETURN) {
      const taddr_t AddrOfRet = SavedPC;
      const taddr_t RetAddr = TargetAddr;

      on_return(child, BIdx, AddrOfRet, RetAddr);
    } else if (TermType == TERMINATOR::INDIRECT_CALL) {
      function_index_t FIdx = E->explore_function(
          TargetBinary, x.cb, va_of_pc(TargetAddr, Target.BIdx));

      assert(is_function_index_valid(FIdx));

      /* FIXME is new? */
      eager_invalidate_block(
          TargetICFG[basic_block_of_index(TargetBinary.Analysis.Functions.at(FIdx).Entry, TargetICFG)],
          TargetBinary);

      Target.isNew = fallthru<bool>(
          binary, BBIdx, [&](bbprop_t &bbprop, basic_block_index_t) -> bool {
            assert(bbprop.Term.Type == TERMINATOR::INDIRECT_CALL);

            bool res = bbprop.insertDynTarget(BIdx, {Target.BIdx, FIdx}, jv);
            if (res)
              eager_invalidate_block(bbprop, jv.Binaries.at(BIdx));

            return res;
          });

      {
        auto s_lck = safe_trapmap.shared_access();
        safe_trapmap.m.at(SavedPC).DT = 1;
      }
    } else {
      assert(TermType == TERMINATOR::INDIRECT_JUMP);

      if (unlikely(IsLj)) {
        //
        // non-local goto (aka "long jump")
        //
        const basic_block_index_t BBIdx = E->explore_basic_block(
            TargetBinary, x.cb, va_of_pc(TargetAddr, Target.BIdx));

        assert(is_basic_block_index_valid(BBIdx));

        ControlFlow.IsGoto = true;
        Target.isNew = opts.Longjmps;

        eager_invalidate_block(
            TargetICFG[basic_block_of_index(BBIdx, TargetICFG)], TargetBinary);
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
              TargetBinary, x.cb, va_of_pc(TargetAddr, Target.BIdx));

          assert(is_function_index_valid(FIdx));

          /* FIXME is new? */
          eager_invalidate_block(
              TargetICFG[basic_block_of_index(
                  TargetBinary.Analysis.Functions.at(FIdx).Entry, TargetICFG)],
              TargetBinary);

          Target.isNew = fallthru<bool>(
              binary, BBIdx,
              [&](bbprop_t &bbprop, basic_block_index_t) -> bool {
                assert(bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP);

                bool res = bbprop.insertDynTarget(BIdx, {Target.BIdx, FIdx}, jv);
                if (res)
                  eager_invalidate_block(bbprop, jv.Binaries.at(BIdx));

                return res;
              });

          {
            auto s_lck = safe_trapmap.shared_access();
            safe_trapmap.m.at(SavedPC).DT = 1;
          }
        } else {
          const basic_block_index_t TargetBBIdx = E->explore_basic_block(
              TargetBinary, x.cb, va_of_pc(TargetAddr, Target.BIdx));

          assert(is_basic_block_index_valid(TargetBBIdx));
          bb_t TargetBB = basic_block_of_index(TargetBBIdx, TargetICFG);

          Target.isNew = fallthru<bool>(
              binary, BBIdx,
              [&](bbprop_t &bbprop, basic_block_index_t TheBBIdx) -> bool {
                assert(bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP);

                bool res = TargetICFG
                               .add_edge<false>(
                                   binary.Analysis.ICFG.vertex<false>(TheBBIdx),
                                   TargetBB)
                               .second;

                if (res)
                  eager_invalidate_block(bbprop, binary);

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

  return false;
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

taddr_t BootstrapTool::compute_load_address(binary_t &b,
                                            binary_state_t &x,
                                            const taddr_t vma_start,
                                            const taddr_t off) {
  //
  // assuming that there exists a bijection between sections and vma's...
  //
  auto &svec = x.cb.second.svec;
  const auto &omap = x.cb.second.omap;
  auto it = intvl_map_find(x.cb.second.omap, off);
  aassert(it != omap.end());
  auto &section = svec[(*it).second];

  // assuming that there exists a bijection between sections and vma's...
  const auto bounds = x.bounds;
  const taddr_t LoadAddr = vma_start - (section.addr() - bounds.first);
  return LoadAddr;
}

void BootstrapTool::ScanAddressSpace(pid_t child, bool VMUpdate) {
  assert(!has_ProcMapQuery);

  if (unlikely(!Engaged))
    return;

  if (VMUpdate) {
    if (!UpdateVM(child))
      WithColor::warning() << "failed to update view of /proc/<PID>/maps\n";
  }

  //
  // forget what we think we know
  //
  {
    auto e_lck = SafeAddressSpace.exclusive_access();
    SafeAddressSpace.m.clear();
  }
  for_each_binary(jv, [&](binary_t &b) { state.for_binary(b).Reset(); });

  if (has_ProcMapQuery) {
    for (const proc_map_t &pm : cached_proc_maps) {
      if (!pm.x)
        continue;
      if (pm.nm.empty())
        continue;

      binary_at_program_counter(child, pm.beg);
    }
  } else {
  for (const proc_map_t &pm : cached_proc_maps) {
#if 0 /* XXX? */
    if (!pm.x)
      continue;
#endif

    const std::string &nm = pm.nm;
    if (nm.empty())
      continue;

    auto ItsTheBinary = [&](binary_index_t BIdx,
                            const taddr_t vma_start,
                            const taddr_t off) -> void {
      if (!is_binary_index_valid(BIdx))
        return;

      binary_t &b = jv.Binaries.at(BIdx);

      {
        auto e_lck = SafeAddressSpace.exclusive_access();
        intvl_map_add(SafeAddressSpace.m, right_open_addr_intvl(pm.beg, pm.end), BIdx);
      }

      auto &x = state.for_binary(b);

      x.LoadAddr = compute_load_address(b, x, vma_start, off);
      if (!x.Loaded()) {
        x.NumSectionsLoaded.store(x.cb.second.svec.size(), std::memory_order_relaxed); /* FIXME */
        on_binary_loaded(child, b);
      }
    };

    if (nm.front() == '/') {
      ItsTheBinary(BinaryFromPath<false>(child, nm.c_str()), pm.beg, pm.off);
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

        ItsTheBinary(BinaryFromPath<false>(child, the_path.c_str()), pm.beg, the_off);
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
          ItsTheBinary(*BIdxSet.begin(), pm.beg, pm.off);
        } else {
          if (IsVeryVerbose())
            msg(llvm::formatv("dont recognize {0}", nm).str());
        }
      }
    } else {
      msg(llvm::formatv("WTF? {0}", nm).str());
    }
  }
  }
}

void BootstrapTool::on_binary_loaded(pid_t child, binary_t &binary) {
  auto &ICFG = binary.Analysis.ICFG;
  auto &x = state.for_binary(binary);
  const binary_index_t BIdx = index_of_binary(binary, jv);

  assert(x.Loaded());
  assert(this->Loaded.insert(BIdx).second);

  //
  // if it's the dynamic linker, we need to set a breakpoint on the address of a
  // function internal to the run-time linker, that will always be called when
  // the linker begins to map in a library or unmap it, and again when the
  // mapping change is complete.
  //
  if (binary.IsDynamicLinker)
    on_dynamic_linker_loaded(child, BIdx);

  if (binary.IsVDSO) {
#if 0
    aassert(!emulator->ExecutableRegionAddress);

    aassert(pm.end - pm.beg >= emulator->N);
    const taddr_t ExecutableRegionAddress = pm.end - emulator->N;
    emulator->ExecutableRegionAddress = ExecutableRegionAddress;

#if defined(__x86_64__) || defined(__i386__)
    const uint8_t ret_insns[] = {
      0xc3,
      0xc2, 0x00, 0x00,
      0xc2, 0x04, 0x00,
      0xc2, 0x08, 0x00
    };

//  ptrace::memcpy_to(child, ExecutableRegionAddress,
//                    &ret_insns[0], sizeof(ret_insns));
#elif defined(__mips64) || defined(__mips__)
    //
    // "initialize" code cave
    //
    for (unsigned i = 0; i < 32; ++i) {
      uint32_t insns[2] = {
        encoding_of_jump_to_reg(reg_of_idx(i)),
        0x00
      };

      const taddr_t jumpr_insn_addr =
          emulator->ExecutableRegionAddress + i * (2 * sizeof(ptrace::word));
      const taddr_t delay_slot_addr = jumpr_insn_addr + 4;

      taddr_t addr = emulator->ExecutableRegionAddress + i * (2 * sizeof(ptrace::word));
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
      msg(llvm::formatv("ExecutableRegionAddress = {0:x}",
                        emulator->ExecutableRegionAddress).str());
#endif
  }
}

binary_index_t BootstrapTool::found_binary(const taddr_t vma_start,
                                           const taddr_t vma_end,
                                           const taddr_t off,
                                           const binary_index_t BIdx) {
  assert(has_ProcMapQuery);
  assert(is_binary_index_valid(BIdx));

  binary_t &b = jv.Binaries.at(BIdx);
  auto &x = state.for_binary(b);

  if (unlikely(x.Skip))
    return invalid_binary_index;

  //
  // NOTE: the dynamic linker may be in the middle of loading the binary into
  // memory. thus we may not see every section immediately. this is more
  // nontrivial than it actually looks- if we want to get _all the sections_.
  //
  // for the purposes of bootstrap's essential functioning, we'll only examine
  // the loaded sections which are actually executed. TODO
  //
  x.LoadAddr = compute_load_address(b, x, vma_start, off);

  //
  // it may be only half-loaded. nevertheless, we want to be eager about placing
  // breakpoints. there may already be other mappings that have been created.
  //
  struct JustLoadedSectionMap_t : public ip_base_rw_accessible_spin<IsToolMT> {
    boost::container::flat_map<addr_intvl, unsigned, addr_intvl_cmp> m;
  } JustLoadedSectionMap;

  std::atomic<unsigned> &NumSectionsLoaded = x.NumSectionsLoaded;
  NumSectionsLoaded.store(0, std::memory_order_relaxed);

  auto &svec = x.cb.second.svec;
  std::for_each(maybe_par_unseq, svec.begin(), svec.end(),
              [&](auto &section) {
                if (section.extra.Loaded) {
                  NumSectionsLoaded.fetch_add(1, std::memory_order_relaxed);
                  return;
                }

                const taddr_t pc = pc_of_va(section.addr(), BIdx);

                char name[PATH_MAX];
                name[0] = '\0';

                struct procmap_query q;
                q.size = sizeof(q);
                q.query_flags = PROCMAP_QUERY_VMA_READABLE;
                q.query_addr = pc;
                (void)q.vma_start;
                (void)q.vma_end;
                (void)q.vma_flags;
                (void)q.vma_page_size;
                (void)q.vma_offset;
                (void)q.inode;
                (void)q.dev_major;
                (void)q.dev_minor;
                q.vma_name_size = sizeof(name);   /* in/out */
                q.vma_name_addr = reinterpret_cast<uintptr_t>(&name[0]);
                q.build_id_size = 0;   /* in/out */
                q.build_id_addr = 0;

                scoped_fd &fd = maps_for_child();
                int ret = ProcMapQuery::get(fd.get(), q);
                if (likely(ret == 0)) {
                  if (IsVerbose())
                    HumanOut() << (fmt(/*just*/ "found section %s mapping [%#lx, %#lx) for %s\n")
                                   % section.Name.str()
                                   % q.vma_start
                                   % q.vma_end
                                   % name).str();

                  {
                    auto e_lck = SafeAddressSpace.exclusive_access();
                    intvl_map_add<false>(
                        SafeAddressSpace.m,
                        right_open_addr_intvl(q.vma_start, q.vma_end), BIdx);
                  }

                  const unsigned idx = &section - svec.data();
                  {
                    auto e_lck = JustLoadedSectionMap.exclusive_access();
                    intvl_map_add<true>(
                        JustLoadedSectionMap.m,
                        right_open_addr_intvl(q.vma_start, q.vma_end), idx);
                  }

                  NumSectionsLoaded.fetch_add(1, std::memory_order_relaxed);
                  on_section_loaded(_child, b, section);
                } else {
                  vvmsg(std::string("ProcMapQuery::get() failed: ") + strerror(-ret));
                }
              });

#ifndef NDEBUG
  {
    auto s_lck = SafeAddressSpace.shared_access();

    assert(intvl_map_find(SafeAddressSpace.m, vma_start) != SafeAddressSpace.m.end());
    assert(intvl_map_find(SafeAddressSpace.m, vma_end-1) != SafeAddressSpace.m.end());
  }
#endif

  scoped_fd &mem_fd = mem_for_child();

#if 0
  scoped_iouring iouring;
#endif

  auto &ICFG = b.Analysis.ICFG;
  for_each_basic_block_in_binary(maybe_par_unseq, b, [&](bb_t bb) -> void {
    bbprop_t &bbprop = b.Analysis.ICFG[bb];

    //
    // NOTE: we are assuming that the program counter of the start of the block
    // resides in the same section as the program counter of its terminator.
    //
    const taddr_t Addr0 = bbprop.Addr();
    const taddr_t pc = pc_of_va(Addr0, BIdx);
    {
      auto s_lck = JustLoadedSectionMap.shared_access(); /* unnecessary? (constconst) */
      auto it = intvl_map_find(JustLoadedSectionMap.m, pc);
      if (it == JustLoadedSectionMap.m.end())
        return;
    }


    TERMINATOR TermType;
    bool IC;
    bool Lj;
    bool NonZeroOutDegree;
    bool HasDynTarget;

    basic_block_index_t BBIdx = index_of_basic_block(b, bb);
    const std::optional<taddr_t> MaybeTermAddr =
        fallthru<std::optional<taddr_t>>(
            b, BBIdx,
            [&](bbprop_t &bbprop,
                basic_block_index_t TheBBIdx) -> std::optional<taddr_t> {
              const auto TheTermType = bbprop.Term.Type;
              if (!IsTerminatorIndirect(TheTermType))
                return {};

              BBIdx = TheBBIdx;
              TermType = TheTermType;
              IC = IsTerminatorCall(TheTermType);
              Lj = bbprop.Lj;
              NonZeroOutDegree = ICFG.template out_degree<false>(basic_block_of_index(TheBBIdx, b)) != 0;
              HasDynTarget = bbprop.hasDynTarget();

              return bbprop.Term.Addr;
            });

    if (!MaybeTermAddr)
      return;
    const taddr_t TermAddr = *MaybeTermAddr;

    assert(TermAddr);
    assert(TermAddr >= Addr0);
    const unsigned diff = TermAddr - Addr0;
    const taddr_t termpc = pc + diff;

    // NOTE: it's not the end of the world if BBIdx refers to a split block. we
    // could get a fresh index, but it could be split anyways, in the future.
    trapped_t *const ptrapped = ({
      auto e_lck = safe_trapmap.exclusive_access();
      auto trapped_pair = safe_trapmap.m.try_emplace(
          termpc, trapped_t(*emulator, BIdx, termpc, TermAddr, x.cb.first.get()));
      if (!trapped_pair.second)
        return;
      &(*trapped_pair.first).second;
    });

    assert(ptrapped);
    trapped_t &trapped = *ptrapped;

    trapped.BBIdx = BBIdx;

    trapped.BIdx = BIdx;
    trapped.TT = static_cast<unsigned>(TermType);
    trapped.IC = static_cast<unsigned>(IC);
    trapped.LJ = static_cast<unsigned>(Lj);
    trapped.OD = static_cast<unsigned>(NonZeroOutDegree);
    trapped.DT = static_cast<unsigned>(HasDynTarget);

#if 0
    iouring.prep_pwrite(mem_fd.get(), termpc, TargetBrkpt, TargetBrkptLen);
#else
    /* FIXME (mips32/mips64, since we do differently for returns) */
    robust::pwrite(mem_fd.get(), TargetBrkpt, TargetBrkptLen, termpc);
#endif
  });

  if (x.Loaded())
    on_binary_loaded(_child, b);

  return BIdx;
}

void BootstrapTool::on_section_loaded(pid_t child,
                                      binary_t &b,
                                      auto &section) {
  section.extra.Loaded = true;
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

  taddr_t l_addr; /* Difference between the address in the ELF file and
                           the addresses in memory.  */
  taddr_t l_name;         /* Absolute file name object was found in.  */
  taddr_t l_ld;  /* Dynamic section of the shared object.  */
  taddr_t l_next, l_prev; /* Chain of loaded objects.  */
};

struct r_debug {
  int r_version; /* Version number for this protocol.  */

  taddr_t r_map; /* Head of the chain of loaded objects.  */

  /* This is the address of a function internal to the run-time linker,
     that will always be called when the linker begins to map in a
     library or unmap it, and again when the mapping change is complete.
     The debugger can set a breakpoint at this address if it wants to
     notice shared object mapping changes.  */
  taddr_t r_brk;
  enum {
    /* This state value describes the mapping change taking place when
       the `r_brk' address is called.  */
    RT_CONSISTENT, /* Mapping change is complete.  */
    RT_ADD,        /* Beginning to add a new object.  */
    RT_DELETE      /* Beginning to remove an object mapping.  */
  } r_state;

  taddr_t r_ldbase; /* Base address the linker is loaded at.  */
};

void BootstrapTool::scan_rtld_link_map(pid_t child) {
  const taddr_t rdbg_ptr = _r_debug.ptr;
  if (!rdbg_ptr)
    return;

  struct r_debug rdbg;

  if (catch_exception([&] { peek(rdbg_ptr, (uint8_t *)(&rdbg), sizeof(rdbg)); }))
    return;

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

  taddr_t lmp = rdbg.r_map;
  do {
    struct link_map lm;

    if (catch_exception([&] { peek(lmp, (uint8_t *)&lm, sizeof(lm)); }))
      return;

    std::string s;
    try {
      s = ptrace::read_c_str(child, lm.l_name);
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

  vvmsg(llvm::formatv("BinaryFromPath: \"{0}\"", path).str());

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

  vvmsg(llvm::formatv("BinaryFromData: \"{0}\"", name).str());

  using namespace std::placeholders;

  return jv.AddFromData(*E, jv_file, sv, name,
                        std::bind(&BootstrapTool::on_new_binary, this, _1)).first;
}

void BootstrapTool::on_dynamic_linker_loaded(pid_t child,
                                             const binary_index_t BIdx) {
  if (!opts.RtldDbgBrk)
    return;

  binary_t &b = jv.Binaries.at(BIdx);

  if (state.for_binary(b)._elf.OptionalDynSymRegion) {
    auto DynSyms = state.for_binary(b)._elf.OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();

    for (const Elf_Sym &Sym : DynSyms) {
      if (Sym.isUndefined())
        continue;

      llvm::Expected<llvm::StringRef> ExpectedSymName =
          Sym.getName(state.for_binary(b)._elf.DynamicStringTable);
      if (!ExpectedSymName)
        continue;

      llvm::StringRef SymName = *ExpectedSymName;
      if (SymName == "_r_debug" ||
          SymName == "_dl_debug_addr") {
        const taddr_t va = Sym.st_value; /* FIXME? va vs. off */
        const taddr_t pc = pc_of_va(va, BIdx);

        _r_debug.Found = true;
        _r_debug.ptr = pc;

        if (IsVerbose())
          msg(llvm::formatv("_r_debug @ {0} ({1}:{2})",
                            taddr2str(pc),
                            b.Name.c_str(),
                            taddr2str(va)).str());

        WARN_ON(Sym.getType() != llvm::ELF::STT_OBJECT);
        rendezvous_with_dynamic_linker(child);
        return;
      }
    }
  }

  msg(llvm::formatv("{0}: could not find _r_debug", __PRETTY_FUNCTION__).str());
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

    if (catch_exception([&] { peek(_r_debug.ptr, (uint8_t *)&rdbg, sizeof(rdbg)); }))
      return;

    const taddr_t pc = rdbg.r_brk;
    if (!is_block_valid(block_at_program_counter(child, pc)))
      return;

    aassert(updateVariable(_r_debug.brk, pc));

    if (IsVerbose())
      msg(llvm::formatv("r_brk is now {0:x}", pc).str());
  }
}

void BootstrapTool::on_return(pid_t child,
                              binary_index_t RetBIdx,
                              taddr_t AddrOfRet,
                              taddr_t RetAddr) {
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
    taddr_t pc = AddrOfRet;

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
    taddr_t pc = RetAddr;

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
    taddr_t before_pc = pc - 1 - IsMIPSTarget*4;

    binary_index_t Before_BIdx;
    basic_block_index_t Before_BBIdx;
    std::tie(Before_BIdx, Before_BBIdx) =
        existing_block_at_program_counter(child, before_pc);

    if (unlikely(!is_basic_block_index_valid(Before_BBIdx))) {
      if (IsVeryVerbose())
        msg(llvm::formatv("on_return: unknown block before @ {0}",
                          description_of_program_counter(pc, true)).str());
      return;
    }

    if (unlikely(BIdx != Before_BIdx)) {
      if (IsVeryVerbose())
        msg(llvm::formatv("on_return: unexpected crossing of boundary @ {0}",
                          description_of_program_counter(before_pc, true)).str());
      return;
    }

    auto &ICFG = b.Analysis.ICFG;
    bb_t before_bb = basic_block_of_index(Before_BBIdx, ICFG);

    auto &before_Term = ICFG[before_bb].Term;

    bool isCall = before_Term.Type == TERMINATOR::CALL;
    bool isIndirectCall = before_Term.Type == TERMINATOR::INDIRECT_CALL;

    if (!isCall && !isIndirectCall) {
      if (IsVerbose())
        msg(llvm::formatv("on_return: unexpected term {0} @ {1}",
                          description_of_terminator(before_Term.Type),
                          description_of_program_counter(before_pc, true)).str());
      return;
    }

    assert(ICFG.out_degree(before_bb) <= 1);

    if (isCall && is_function_index_valid(before_Term._call.Target))
      b.Analysis.Functions.at(before_Term._call.Target).Returns = true;

    // connect
    if (ICFG.add_edge(before_bb, basic_block_of_index(BBIdx, ICFG)).second)
      eager_invalidate_block(ICFG[before_bb], b);
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
                                                        taddr_t pc) {
  {
    auto s_lck = SafeAddressSpace.shared_access();

    auto it = intvl_map_find(SafeAddressSpace.m, pc);
    if (likely(it != SafeAddressSpace.m.end()))
      return (*it).second;
  }

  if (has_ProcMapQuery) {
    scoped_fd &fd = maps_for_child();

    char name[PATH_MAX];
    name[0] = '\0';

    struct procmap_query q;
    q.size = sizeof(q);
    q.query_flags = PROCMAP_QUERY_VMA_READABLE;
    q.query_addr = pc;
    (void)q.vma_start;
    (void)q.vma_end;
    (void)q.vma_flags;
    (void)q.vma_page_size;
    (void)q.vma_offset;
    (void)q.inode;
    (void)q.dev_major;
    (void)q.dev_minor;
    q.vma_name_addr = reinterpret_cast<uintptr_t>(&name[0]);
    q.vma_name_size = sizeof(name);   /* in/out */
    q.build_id_size = 0;   /* in/out */
    q.build_id_addr = uintptr_t(0);

    int ret = ProcMapQuery::get(fd.get(), q);
    if (likely(ret == 0)) {
      if (q.vma_name_size) {
        const taddr_t the_start = q.vma_start;
        const taddr_t the_end = q.vma_end;
        const taddr_t the_off = (pc - q.vma_start) + q.vma_offset;
        auto the_binary = [&](binary_index_t BIdx) -> binary_index_t {
          if (!is_binary_index_valid(BIdx))
            return invalid_binary_index;

          if (state.for_binary(jv.Binaries.at(BIdx)).Loaded())
            return BIdx;

          return this->found_binary(the_start, the_end, the_off, BIdx);
        };

        const char front_ch = name[0];
        switch (front_ch) {
        case '/':
          break;
        case '[': {
          if (boost::algorithm::starts_with(name, "[anon:")) {
            //
            // WINE will sometimes open and read the contents of a section into
            // memory. we preserve the file and offset of such a mapping
            // via prctl(PR_SET_VMA_ANON_NAME, ...)
            //
            int the_off;
            ssize_t len = ({
              int the_fd;
              std::tie(the_fd, the_off) = extract_fd_and_off(name);

              char buff[1024];
              snprintf(buff, sizeof(buff), "/proc/%u/fd/%u",
                       static_cast<unsigned>(child),
                       static_cast<unsigned>(the_fd));
              ::readlink(buff, &name[0], sizeof(name));
            });

            q.vma_offset = the_off;
            break;
          }

          binary_index_set BIdxSet;
          if (jv.LookupByName(name, BIdxSet)) {
            assert(!BIdxSet.empty());
            return the_binary(*BIdxSet.begin());
          }

          vvmsg("unrecognized vma: " + std::string(name));
          return invalid_binary_index;
        }

        default:
          vvmsg("unknown vma: " + std::string(name));
          return invalid_binary_index;
        }

        return the_binary(BinaryFromPath<false>(child, name));
      } else {
        // anonymous. period. TODO?
//      vvmsg("anon");
        return invalid_binary_index;
      }
    } else {
      vvmsg(std::string("ProcMapQuery::get() failed: ") + strerror(-ret));
      return invalid_binary_index;
    }

    __compiletime_unreachable();
  }

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

  const proc_map_t &pm = cached_proc_maps.at((*pm_it).second);
  if (pm.nm.empty() || (pm.nm.front() == '[' && pm.nm != "[vdso]"))
    return invalid_binary_index;

  // WARN_ON(!pm.x);
#if 0
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
      std::vector<uint8_t> buff_bytes;
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
    const binary_index_t BIdx = ({
      auto s_lck = SafeAddressSpace.shared_access();
      auto it = intvl_map_find(SafeAddressSpace.m, pc);
      unlikely(it == SafeAddressSpace.m.end()) ? invalid_binary_index : (*it).second;
    });

    if (is_binary_index_valid(BIdx))
        return BIdx;

    if (IsVeryVerbose()) {
      const proc_map_t &pm = cached_proc_maps.at((*pm_it).second);
      die("added " + pm.nm + " but AddressSpace unchanged");
    }

    return invalid_binary_index;
  }
}

std::pair<binary_index_t, function_index_t>
BootstrapTool::function_at_program_counter(pid_t child, taddr_t pc) {
  binary_index_t BIdx = binary_at_program_counter(child, pc);
  if (!is_binary_index_valid(BIdx))
    return std::make_pair(invalid_binary_index, invalid_function_index);

  binary_t &binary = jv.Binaries.at(BIdx);
  auto &x = state.for_binary(binary);

  basic_block_index_t BBIdx =
      E->explore_basic_block(binary, x.cb, va_of_pc(pc, BIdx));
  if (!is_basic_block_index_valid(BBIdx))
    return std::make_pair(BIdx, invalid_function_index);

  function_index_t FIdx =
      E->explore_function(binary, x.cb, va_of_pc(pc, BIdx));

  /* FIXME is new? */
  eager_invalidate_block(binary.Analysis.ICFG[basic_block_of_index(binary.Analysis.Functions.at(FIdx).Entry, binary)], binary);

  return std::make_pair(BIdx, FIdx);
}

block_t
BootstrapTool::block_at_program_counter(pid_t child, taddr_t pc) {
  binary_index_t BIdx = binary_at_program_counter(child, pc);
  if (!is_binary_index_valid(BIdx))
    return std::make_pair(invalid_binary_index, invalid_basic_block_index);

  binary_t &binary = jv.Binaries.at(BIdx);
  auto &x = state.for_binary(binary);

  basic_block_index_t BBIdx =
      E->explore_basic_block(binary, x.cb, va_of_pc(pc, BIdx));

  return std::make_pair(BIdx, BBIdx);
}

// bbmap needs to be locked.
std::pair<binary_index_t, basic_block_index_t>
BootstrapTool::existing_block_at_program_counter(pid_t child, taddr_t pc) {
  binary_index_t BIdx = binary_at_program_counter(child, pc);
  if (!is_binary_index_valid(BIdx))
    return std::make_pair(invalid_binary_index, invalid_basic_block_index);

  binary_t &b = jv.Binaries.at(BIdx);
  taddr_t rva = va_of_pc(pc, BIdx);

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

std::string BootstrapTool::description_of_program_counter(taddr_t pc,
                                                          bool Verbose,
                                                          bool Symbolize) {
#if 0 /* defined(__mips64) || defined(__mips__) */
  if (ExecutableRegionAddress &&
      pc >= ExecutableRegionAddress &&
      pc < ExecutableRegionAddress + 8) {
    taddr_t off = pc - ExecutableRegionAddress;
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
    taddr_t the_off = pm.off;

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
      const binary_index_t BIdx = ({
        auto s_lck = SafeAddressSpace.shared_access();
        auto it = intvl_map_find(SafeAddressSpace.m, pc);
        it == SafeAddressSpace.m.end() ? invalid_binary_index : (*it).second;
      });

      if (is_binary_index_valid(BIdx)) {
        binary_t &b = jv.Binaries.at(BIdx);
        auto &x = state.for_binary(b);

        assert(x.Loaded());
        {
          //
          // pc is in binary that's been "loaded"
          //
          ptrdiff_t off = pc - (pm.beg - the_off);

          taddr_t Addr;
          try {
            Addr = B::cached::va_of_offset(x.cb, off);

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
      msg(llvm::formatv("setgid failed: {0}", strerror(err)).str());
    }
  }

  if (!opts.User.empty()) {
    unsigned uid = atoi(opts.User.c_str());

    if (::setuid(uid) < 0) {
      int err = errno;
      msg(llvm::formatv("setuid failed: {0}", strerror(err)).str());
    }
  }
}

#ifdef JOVE_BOOTSTRAP_EAGER_INVALIDATION
void BootstrapTool::invalidate_block(bbprop_t &bbprop,
                                     binary_t &binary) {
  bbprop.InvalidateAnalyses(this->jv, binary);
}
#endif

void BootstrapTool::msg(const std::string &s) {
  llvm::errs() << llvm::formatv("[{0}] {1}\n", _jove_sys_gettid(), s).str();
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
#if 0
    for (pid_t child : boost::adaptors::reverse(tool.children.set)) {
//    for (unsigned i = 0; i < 10; ++i)
        if (::tgkill(child, child, SIGSTOP) < 0)
          continue;

      tool.HumanOut() << llvm::formatv("waiting on {0}...\n", child);

      int status;
      do
        ::waitpid(-1, &status, __WALL);
      while (!WIFSTOPPED(status));

      tool.HumanOut() << llvm::formatv("waited on {0}.\n", child);

      if (_jove_sys_ptrace(PTRACE_DETACH, child, 0UL, SIGSTOP) < 0) {
        int err = errno;
        tool.HumanOut() << llvm::formatv(
            "failed to detach from tracee [{0}]: {1}\n", child,
            strerror(err));
      } else {
        tool.HumanOut() << "PTRACE_DETACH succeeded\n";
      }
    }
#endif

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

template ssize_t BootstrapTool::poke<true>(const taddr_t, const uint8_t *, const size_t);
template ssize_t BootstrapTool::poke<false>(const taddr_t, const uint8_t *, const size_t);

template ssize_t BootstrapTool::peek<true>(const taddr_t, uint8_t *const, const size_t);
template ssize_t BootstrapTool::peek<false>(const taddr_t, uint8_t *const, const size_t);

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

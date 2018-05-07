#include "tcgcommon.hpp"

#include <memory>
#include <sstream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
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
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Support/FileSystem.h>
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "jove/jove.h"
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>

namespace fs = boost::filesystem;
namespace po = boost::program_options;
namespace obj = llvm::object;

namespace jove {

static int ChildProc(int argc, char **argv);
static int ParentProc(pid_t child,
                      const char *decompilation_path,
                      const char *binary_path);
}

int main(int argc, char **argv) {
  llvm::StringRef ToolName = argv[0];
  llvm::sys::PrintStackTraceOnErrorSignal(ToolName);
  llvm::PrettyStackTraceProgram X(argc, argv);
  llvm::llvm_shutdown_obj Y;

  if (argc < 4 ||
      !fs::exists(argv[1]) ||
      !fs::exists(argv[2]) ||
      !fs::exists(argv[3])) {
    fprintf(stderr,
            "usage: %s <DECOMPILATION.jv> <ELF> <PROG> [<ARG1> <ARG2> ...]\n",
            argv[0]);
    return 1;
  }

  pid_t child = fork();
  if (!child)
    return jove::ChildProc(argc - 2, argv + 2);

  return jove::ParentProc(child, argv[1], argv[2]);
}

namespace jove {

static bool update_view_of_virtual_memory(int child);

static void verify_arch(const obj::ObjectFile &);
static void print_obj_info(const obj::ObjectFile &);

struct vm_properties_t {
  std::uintptr_t beg;
  std::uintptr_t end;
  std::ptrdiff_t off;

  bool r, w, x; /* unix permissions */
  bool p;       /* private memory? (i.e. not shared) */

  std::string nm;

  bool operator==(const vm_properties_t &vm) const {
    return beg == vm.beg && end == vm.end;
  }

  bool operator<(const vm_properties_t &vm) const { return beg < vm.beg; }
};

typedef std::set<vm_properties_t> vm_prop_set_t;

static boost::icl::interval_set<uintptr_t> allvms;
static boost::icl::split_interval_map<uintptr_t, vm_prop_set_t> vmm;

template <size_t N>
static const char *string_of_program_point(char (&out)[N], uintptr_t pc) {
  auto it = vmm.find(pc);
  if (it == vmm.end() || (*(*it).second.begin()).nm.empty()) {
    snprintf(out, sizeof(out), "0x%08lx", static_cast<unsigned long>(pc));
  } else {
    const vm_properties_t &vmprop = *(*it).second.begin();

    long module_offset = pc - vmprop.beg + vmprop.off;
    snprintf(out, sizeof(out), "%s+%#lx", vmprop.nm.c_str(), module_offset);
  }
  return out;
}

static const char *name_of_signal_number(int);
static const char *name_of_syscall_number(int);

int ParentProc(pid_t child,
               const char *decompilation_path,
               const char *binary_path) {
  //
  // parse the existing decompilation file
  //
  decompilation_t decompilation;
  {
    std::ifstream ifs(decompilation_path);

    boost::archive::text_iarchive ia(ifs);
    ia >> decompilation;
  }

  //
  // find the given binary in the decompilation
  //
  auto it =
      decompilation.Binaries.find(fs::canonical(binary_path).string().c_str());
  if (it == decompilation.Binaries.end()) {
    fprintf(stderr, "binary %s not found in %s", binary_path,
            decompilation_path);
    return 1;
  }

  binary_t& binary = (*it).second;

  {
    //
    // let's be sure that the binary hasn't changed a bit
    //
    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BinFileOrErr =
        llvm::MemoryBuffer::getFileOrSTDIN(binary_path);

    if (std::error_code EC = BinFileOrErr.getError()) {
      fprintf(stderr, "failed to open binary %s\n", binary_path);
      return 1;
    }

    std::unique_ptr<llvm::MemoryBuffer> &BinFileBuffer = BinFileOrErr.get();
    if (binary.Data.size() != BinFileBuffer->getBufferSize() ||
        memcmp(&binary.Data[0],
               BinFileBuffer->getBufferStart(),
               binary.Data.size()) != 0) {
      fprintf(stderr, "contents of binary %s have changed\n", binary_path);
      return 1;
    }
  }

  tiny_code_generator_t tcg;

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();

  llvm::Expected<obj::OwningBinary<obj::Binary>> BinaryOrErr =
      obj::createBinary(binary_path);

  if (!BinaryOrErr ||
      !llvm::isa<obj::ObjectFile>(BinaryOrErr.get().getBinary())) {
    fprintf(stderr, "failed to open %s\n", binary_path);
    return 1;
  }

  obj::ObjectFile &O =
      *llvm::cast<obj::ObjectFile>(BinaryOrErr.get().getBinary());

  verify_arch(O);
  print_obj_info(O);

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

  int AsmPrinterVariant = AsmInfo->getAssemblerDialect();
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    fprintf(stderr, "no instruction printer\n");
    return 1;
  }

  //
  // observe the (initial) signal-delivery-stop
  //
  fprintf(stderr, "parent: waiting for initial stop of child %d...\n", child);
  int status;
  do
    waitpid(child, &status, 0);
  while (!WIFSTOPPED(status));
  fprintf(stderr, "parent: initial stop observed\n");

  //
  // select ptrace options
  //
  int ptrace_options = 0;

  // When delivering system call traps, set bit 7 in the signal number (i.e.,
  // deliver SIGTRAP|0x80). This makes it easy for the tracer to distinguish
  // normal traps from those caused by a system call. Note:
  // PTRACE_O_TRACESYSGOOD may not work on all architectures.
  ptrace_options |= PTRACE_O_TRACESYSGOOD;

  // Send a SIGKILL signal to the tracee if the tracer exits. This option is
  // useful for ptrace jailers that want to ensure that tracees can never escape
  // the tracer's control.
  ptrace_options |= PTRACE_O_EXITKILL;

  // Stop the tracee at the next clone(2) and automatically start tracing the
  // newly cloned process, which will start with a SIGSTOP, or PTRACE_EVENT_STOP
  // if PTRACE_SEIZE was used.
  //
  // The PID of the new process can be retrieved with PTRACE_GETEVENTMSG. This
  // option may not catch clone(2) calls in all cases.  If the tracee calls
  // clone(2) with the CLONE_VFORK flag, PTRACE_EVENT_VFORK will be delivered
  // instead if PTRACE_O_TRACEVFORK is set; otherwise if the tracee calls
  // clone(2) with the exit signal set to SIGCHLD, PTRACE_EVENT_FORK will be
  // delivered if PTRACE_O_TRACEFORK is set.
  ptrace_options |= PTRACE_O_TRACECLONE;

  // Stop the tracee at the next execve(2).
  ptrace_options |= PTRACE_O_TRACEEXEC;

  // Stop the tracee at the next fork(2) and automatically start tracing the
  // newly forked process, which will start with a SIGSTOP, or PTRACE_EVENT_STOP
  // if PTRACE_SEIZE was used.
  ptrace_options |= PTRACE_O_TRACEFORK;

  // Stop the tracee at the next vfork(2) and automatically start tracing the
  // newly vforked process, which will start with a SIGSTOP, or
  // PTRACE_EVENT_STOP if PTRACE_SEIZE was used.
  //
  // The PID of the new process can be retrieved with PTRACE_GETEVENTMSG.
  ptrace_options |= PTRACE_O_TRACEVFORK;

  //
  // set those options
  //
  fprintf(stderr, "parent: setting ptrace options...\n");
  ptrace(PTRACE_SETOPTIONS, child, 0, ptrace_options);
  fprintf(stderr, "ptrace options set!\n");

  siginfo_t si;
  long sig = 0;

  for (;;) {
    if (likely(!(child < 0))) {
      if (unlikely(ptrace(PTRACE_SYSCALL, child, nullptr,
                          reinterpret_cast<void *>(sig)) < 0))
        fprintf(stderr, "failed to PTRACE_SYSCALL : %s [%d]\n", strerror(errno),
                child);
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
      fprintf(stderr, "waitpid failed : %s\n", strerror(errno));
      return 0;
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
      if (likely(stopsig == (SIGTRAP | 0x80))) {
        //
        // (1) Syscall-enter-stop and syscall-exit-stop are observed by the
        // tracer as waitpid(2) returning with WIFSTOPPED(status) true, and-
        // if the PTRACE_O_TRACESYSGOOD option was set by the tracer- then
        // WSTOPSIG(status) will give the value (SIGTRAP | 0x80).
        //
#if 0
        long no = ptrace(PTRACE_PEEKUSER, child,
#if defined(TARGET_X86_64)
                         __builtin_offsetof(struct user, regs.orig_rax),
#elif defined(TARGET_AARCH64)
                         __builtin_offsetof(struct user, regs.r15),
#else
#error "unknown architecture"
#endif
                         nullptr);

        const char *nm = name_of_syscall_number(no);
        if (nm)
          fprintf(stderr, "syscall %s\n", nm);
        else
          fprintf(stderr, "syscall %ld\n", no);

        if (!update_view_of_virtual_memory(child)) {
          fprintf(stderr, "failed to read virtual memory maps of child %d\n",
                  child);
          return 1;
        }

        std::uintptr_t Base = 0;

        for (auto &vm_prop_set : vmm) {
          const vm_properties_t &vm_prop = *vm_prop_set.second.begin();
          if (vm_prop.off)
            continue;

          if (vm_prop.nm.empty())
            continue;

          if (fs::equivalent(vm_prop.nm, argv[1])) {
            Base = vm_prop.beg;
            break;
          }
        }

        if (Base)
          fprintf(stderr, "%s @ %" PRIx64 "\n", argv[1], Base);
#endif

        //
        // is this a system call enter or exit stop?
        //
      } else if (stopsig == SIGTRAP) {
        const unsigned int event = (unsigned int)status >> 16;
        //
        // PTRACE_EVENT stops (2) are observed by the tracer as waitpid(2)
        // returning with WIFSTOPPED(status), and WSTOPSIG(status) returns
        // SIGTRAP.
        //
        switch (event) {
        case PTRACE_EVENT_VFORK:
          fprintf(stderr, "ptrace event (PTRACE_EVENT_VFORK) [%d]\n", child);
          break;
        case PTRACE_EVENT_FORK:
          fprintf(stderr, "ptrace event (PTRACE_EVENT_FORK) [%d]\n", child);
          break;
        case PTRACE_EVENT_CLONE: {
          pid_t new_child;
          ptrace(PTRACE_GETEVENTMSG, child, nullptr, &new_child);

          fprintf(stderr, "ptrace event (PTRACE_EVENT_CLONE) -> %d [%d]\n",
                  new_child, child);
          break;
        }
        case PTRACE_EVENT_VFORK_DONE:
          fprintf(stderr, "ptrace event (PTRACE_EVENT_VFORK_DONE) [%d]\n", child);
          break;
        case PTRACE_EVENT_EXEC:
          fprintf(stderr, "ptrace event (PTRACE_EVENT_EXEC) [%d]\n", child);
          break;
        case PTRACE_EVENT_EXIT:
          fprintf(stderr, "ptrace event (PTRACE_EVENT_EXIT) [%d]\n", child);
          break;
        case PTRACE_EVENT_STOP:
          fprintf(stderr, "ptrace event (PTRACE_EVENT_STOP) [%d]\n", child);
          break;
        case PTRACE_EVENT_SECCOMP:
          fprintf(stderr, "ptrace event (PTRACE_EVENT_SECCOMP) [%d]\n", child);
          break;
        default:
          if (ptrace(PTRACE_GETSIGINFO, child, 0l, &si) == -1) {
            fprintf(stderr,
                    "PTRACE_GETSIGINFO failed (unknown ptrace event %u) : %s [%d]\n",
                    event, strerror(errno), child);
          } else {
            if (si.si_code == TRAP_BRKPT) {
#if defined(TARGET_X86_64)
              constexpr unsigned forward_offset = 4;
#elif defined(TARGET_AARCH64)
              constexpr unsigned forward_offset = 4;
#else
#error "unknown architecture"
#endif
              uintptr_t pc = reinterpret_cast<uintptr_t>(si.si_addr);

              //
              // jump past the breakpoint
              //
              ptrace(PTRACE_POKEUSER, child,
#ifdef TARGET_X86_64
                     __builtin_offsetof(struct user, regs.rip),
#elif defined(TARGET_AARCH64)
                     __builtin_offsetof(struct user, regs.r15),
#else
#error "unknown architecture"
#endif
                     pc + forward_offset);

              //
              // detach from tracing this thread
              //
              if (ptrace(PTRACE_DETACH, child, nullptr, nullptr) == -1) {
                fprintf(stderr, "failed to detach from %d : %s\n", child,
                        strerror(errno));
              } else {
                fprintf(stderr, "detached from %d\n", child);

                child = -1;
              }
            } else {
              fprintf(stderr, "unknown ptrace event %u @ %p [%d]\n", event,
                      si.si_addr, child);
            }
          }
          break;
        }
      } else if (ptrace(PTRACE_GETSIGINFO, child, 0, &si) < 0) {
        //
        // (3) group-stop
        //

        fprintf(stderr, "ptrace group-stop [%d]\n", child);

        // When restarting a tracee from a ptrace-stop other than
        // signal-delivery-stop, recommended practice is to always pass 0 in
        // sig.
      } else {
        //
        // (4) signal-delivery-stop
        //

        switch (stopsig) {
        case SIGSEGV: {
          update_view_of_virtual_memory(child);

          long pc = ptrace(PTRACE_PEEKUSER, child,
#if defined(TARGET_X86_64)
                           __builtin_offsetof(struct user, regs.rip),
#elif defined(TARGET_AARCH64)
                           __builtin_offsetof(struct user, regs.r15),
#else
#error "unknown architecture"
#endif
                           nullptr);

          char buff[0x100];
          fprintf(stderr, "tracee SIGSEGV @ %s : *(%p)\n",
                  string_of_program_point(buff, pc), si.si_addr);
        }

        default:
          const char *signm = name_of_signal_number(stopsig);
          if (signm)
            fprintf(stderr, "delivering signal %s [%d]\n", signm, child);
          else
            fprintf(stderr, "delivering signal number %d [%d]\n", stopsig,
                    child);

          // deliver it
          sig = stopsig;
          break;
        }
      }
    } else {
      //
      // the child terminated
      //
      fprintf(stderr, "child %d terminated\n", child);
      child = -1;
    }
  }

  return 0;
}

int ChildProc(int argc, char **argv) {
  //
  // child
  //

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

  //
  // we have to do this little dance because of C++ const-ness
  //
  unsigned N = argc - 1;

  std::vector<std::vector<char>> execve_arg_datas;
  execve_arg_datas.resize(N);

  for (int i = 0; i < N; ++i) {
    unsigned M = strlen(argv[i + 1]);

    std::vector<char>& execve_arg_data = execve_arg_datas[i];
    execve_arg_data.resize(M + 1);
    strncpy(&execve_arg_data[0], argv[i + 1], execve_arg_data.size());
  }

  std::vector<char *> execve_args;
  execve_args.resize(N);
  for (unsigned i = 0; i < N; ++i)
    execve_args[i] = execve_arg_datas[i].data();
  execve_args.push_back(nullptr);

  return execve(argv[1], execve_args.data(), ::environ);
}

void verify_arch(const obj::ObjectFile &Obj) {
#if defined(TARGET_X86_64)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::x86_64;
#elif defined(TARGET_AARCH64)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::aarch64;
#else
#error "unknown architecture"
#endif

  if (Obj.getArch() != archty) {
    fprintf(stderr, "error: architecture mismatch\n");
    exit(1);
  }
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

  allvms.clear();
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

    auto intervl =
        boost::icl::discrete_interval<uintptr_t>::right_open(min, max);

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
    allvms.insert(intervl);

    vm_prop_set_t vmprops = {vmprop};
    vmm.add(make_pair(intervl, vmprops));
  }

  free(line);
  fclose(fp);

  return true;
}

void print_obj_info(const obj::ObjectFile &Obj) {
  printf("File: %s\n"
         "Format: %s\n"
         "Arch: %s\n"
         "AddressSize: %ubit\n",
         Obj.getFileName().str().c_str(), Obj.getFileFormatName().str().c_str(),
         llvm::Triple::getArchTypeName(Obj.getArch()).str().c_str(),
         8 * Obj.getBytesInAddress());
}

const char *name_of_signal_number(int num) {
  switch (num) {
#define _CHECK_SIGNAL(NM)                                                      \
  case NM:                                                                     \
    return #NM;

#ifdef SIGHUP
  _CHECK_SIGNAL(SIGHUP)
#endif
#ifdef SIGINT
  _CHECK_SIGNAL(SIGINT)
#endif
#ifdef SIGQUIT
  _CHECK_SIGNAL(SIGQUIT)
#endif
#ifdef SIGILL
  _CHECK_SIGNAL(SIGILL)
#endif
#ifdef SIGTRAP
  _CHECK_SIGNAL(SIGTRAP)
#endif
#ifdef SIGABRT
  _CHECK_SIGNAL(SIGABRT)
#endif
#ifdef SIGBUS
  _CHECK_SIGNAL(SIGBUS)
#endif
#ifdef SIGFPE
  _CHECK_SIGNAL(SIGFPE)
#endif
#ifdef SIGKILL
  _CHECK_SIGNAL(SIGKILL)
#endif
#ifdef SIGUSR1
  _CHECK_SIGNAL(SIGUSR1)
#endif
#ifdef SIGSEGV
  _CHECK_SIGNAL(SIGSEGV)
#endif
#ifdef SIGUSR2
  _CHECK_SIGNAL(SIGUSR2)
#endif
#ifdef SIGPIPE
  _CHECK_SIGNAL(SIGPIPE)
#endif
#ifdef SIGALRM
  _CHECK_SIGNAL(SIGALRM)
#endif
#ifdef SIGTERM
  _CHECK_SIGNAL(SIGTERM)
#endif
#ifdef SIGSTKFLT
  _CHECK_SIGNAL(SIGSTKFLT)
#endif
#ifdef SIGCHLD
  _CHECK_SIGNAL(SIGCHLD)
#endif
#ifdef SIGCONT
  _CHECK_SIGNAL(SIGCONT)
#endif
#ifdef SIGSTOP
  _CHECK_SIGNAL(SIGSTOP)
#endif
#ifdef SIGTSTP
  _CHECK_SIGNAL(SIGTSTP)
#endif
#ifdef SIGTTIN
  _CHECK_SIGNAL(SIGTTIN)
#endif
#ifdef SIGTTOU
  _CHECK_SIGNAL(SIGTTOU)
#endif
#ifdef SIGURG
  _CHECK_SIGNAL(SIGURG)
#endif
#ifdef SIGXCPU
  _CHECK_SIGNAL(SIGXCPU)
#endif
#ifdef SIGXFSZ
  _CHECK_SIGNAL(SIGXFSZ)
#endif
#ifdef SIGVTALRM
  _CHECK_SIGNAL(SIGVTALRM)
#endif
#ifdef SIGPROF
  _CHECK_SIGNAL(SIGPROF)
#endif
#ifdef SIGWINCH
  _CHECK_SIGNAL(SIGWINCH)
#endif
#ifdef SIGPOLL
  _CHECK_SIGNAL(SIGPOLL)
#endif
#ifdef SIGSYS
  _CHECK_SIGNAL(SIGSYS)
#endif
  }

  return nullptr;
}

static const char *syscall_names[/* __NR_syscalls */ 400] = {
#define __SYSCALL(no, name) [no] = #name,
#include <asm-generic/unistd.h>
#undef __SYSCALL
};

const char *name_of_syscall_number(int no) {
  return syscall_names[no];
}

}

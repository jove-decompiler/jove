#define _GNU_SOURCE

#include "tcgcommon.hpp"

#include <tuple>
#include <numeric>
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
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <sys/uio.h>

#include "jove/jove.h"
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

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
    fprintf(stdout,
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

static constexpr bool debugMode = false;

static bool update_view_of_virtual_memory(int child);

static void verify_arch(const obj::ObjectFile &);

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

static std::uintptr_t BinaryLoadAddress = 0;

//
// breakpoint handlers are responsible for emulating the semantics of the
// indirect control flow instructions
//
typedef void (*breakpoint_handler_t)(pid_t);

struct IndirectBranchInfo {
  std::vector<uint8_t> InsnBytes;
  llvm::MCInst Inst;
};

static std::unordered_map<
    std::uintptr_t, std::tuple<function_t *, basic_block_t, IndirectBranchInfo>>
    IndBranchInsns;

typedef std::tuple<llvm::MCDisassembler &,
                   const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &> disas_t;

static void install_breakpoints(pid_t child,
                                binary_t &,
                                disas_t,
                                std::uintptr_t LoadAddress);

// returns the value of the given LLVM MC register in the user struct area
static long LoadReg(pid_t child, unsigned reg);

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

  auto write_decompilation = [&](void) -> void {
    std::ofstream ofs(decompilation_path);

    boost::archive::text_oarchive oa(ofs);
    oa << decompilation;
  };

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

  int AsmPrinterVariant = 1 /* AsmInfo->getAssemblerDialect() */; // Intel
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    fprintf(stderr, "no instruction printer\n");
    return 1;
  }

  //
  // observe the (initial) signal-delivery-stop
  //
  if (debugMode)
    fprintf(stdout, "parent: waiting for initial stop of child %d...\n", child);
  int status;
  do
    waitpid(child, &status, 0);
  while (!WIFSTOPPED(status));
  if (debugMode)
    fprintf(stdout, "parent: initial stop observed\n");

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
  if (debugMode)
    fprintf(stdout, "parent: setting ptrace options...\n");
  ptrace(PTRACE_SETOPTIONS, child, 0, ptrace_options);
  if (debugMode)
    fprintf(stdout, "ptrace options set!\n");

  siginfo_t si;
  long sig = 0;

  for (;;) {
    if (likely(!(child < 0))) {
      if (unlikely(ptrace(BinaryLoadAddress ? PTRACE_CONT : PTRACE_SYSCALL,
                          child, nullptr, reinterpret_cast<void *>(sig)) < 0))
        fprintf(stderr, "failed to resume tracee : %s [%d]\n", strerror(errno),
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
      if (debugMode)
        fprintf(stdout, "waitpid failed : %s\n", strerror(errno));
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
      if (likely(stopsig == (SIGTRAP | 0x80))) {
        //
        // (1) Syscall-enter-stop and syscall-exit-stop are observed by the
        // tracer as waitpid(2) returning with WIFSTOPPED(status) true, and-
        // if the PTRACE_O_TRACESYSGOOD option was set by the tracer- then
        // WSTOPSIG(status) will give the value (SIGTRAP | 0x80).
        //
        long no = ptrace(PTRACE_PEEKUSER, child,
#if defined(__x86_64__)
                         __builtin_offsetof(struct user, regs.orig_rax),
#elif defined(__arm64__)
                         __builtin_offsetof(struct user, regs.r8),
#else
#error "unknown architecture"
#endif
                         nullptr);

        if (no != __NR_mmap)
          continue;

        if (!update_view_of_virtual_memory(child)) {
          fprintf(stderr, "failed to read virtual memory maps of child %d\n",
                  child);
          return 1;
        }

        auto search_address_space = [&](const char *path) -> std::uintptr_t {
          std::uintptr_t Base = 0;

          for (auto &vm_prop_set : vmm) {
            const vm_properties_t &vm_prop = *vm_prop_set.second.begin();
            if (vm_prop.off)
              continue;

            if (vm_prop.nm.empty())
              continue;

            if (fs::equivalent(vm_prop.nm, path)) {
              Base = vm_prop.beg;
              break;
            }
          }

          return Base;
        };

        std::uintptr_t Base = search_address_space(binary_path);
        if (Base) {
          fprintf(stdout, "%s @ %" PRIx64 "\n", binary_path, Base);
          install_breakpoints(child,
                              binary,
                              disas_t(*DisAsm, std::cref(*STI), *IP),
                              Base);

          BinaryLoadAddress = Base;
        }

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
          if (debugMode)
            fprintf(stdout, "ptrace event (PTRACE_EVENT_VFORK) [%d]\n", child);
          break;
        case PTRACE_EVENT_FORK:
          if (debugMode)
            fprintf(stdout, "ptrace event (PTRACE_EVENT_FORK) [%d]\n", child);
          break;
        case PTRACE_EVENT_CLONE: {
          pid_t new_child;
          ptrace(PTRACE_GETEVENTMSG, child, nullptr, &new_child);

          if (debugMode)
            fprintf(stdout, "ptrace event (PTRACE_EVENT_CLONE) -> %d [%d]\n",
                    new_child, child);
          break;
        }
        case PTRACE_EVENT_VFORK_DONE:
          if (debugMode)
            fprintf(stdout, "ptrace event (PTRACE_EVENT_VFORK_DONE) [%d]\n",
                    child);
          break;
        case PTRACE_EVENT_EXEC:
          if (debugMode)
            fprintf(stdout, "ptrace event (PTRACE_EVENT_EXEC) [%d]\n", child);
          break;
        case PTRACE_EVENT_EXIT:
          if (debugMode)
            fprintf(stdout, "ptrace event (PTRACE_EVENT_EXIT) [%d]\n", child);
          break;
        case PTRACE_EVENT_STOP:
          if (debugMode)
            fprintf(stdout, "ptrace event (PTRACE_EVENT_STOP) [%d]\n", child);
          break;
        case PTRACE_EVENT_SECCOMP:
          if (debugMode)
            fprintf(stdout, "ptrace event (PTRACE_EVENT_SECCOMP) [%d]\n",
                    child);
          break;
        default:
          if (ptrace(PTRACE_GETSIGINFO, child, 0l, &si) == -1) {
            fprintf(stderr,
                    "PTRACE_GETSIGINFO failed (unknown ptrace event %u) : %s [%d]\n",
                    event, strerror(errno), child);
          } else {
            //
            // rewind before the breakpoint instruction
            //
            std::uintptr_t pc = 0;
#if defined(TARGET_X86_64) && defined(__x86_64__)
            pc = ptrace(PTRACE_PEEKUSER, child,
                        __builtin_offsetof(struct user, regs.rip), nullptr);

            pc -= 1;
#endif

            auto it = IndBranchInsns.find(pc);
            if (it == IndBranchInsns.end()) {
              fprintf(stderr, "unknown breakpoint @ 0x%lx\n", pc);
              return 1;
            }

            auto &tup = (*it).second;

            function_t &f = *std::get<0>(tup);
            basic_block_t bb = std::get<1>(tup);
            IndirectBranchInfo &IndBrInfo = std::get<2>(tup);

#if defined(TARGET_X86_64) && defined(__x86_64__)
            pc += IndBrInfo.InsnBytes.size();
            ptrace(PTRACE_POKEUSER, child,
                   __builtin_offsetof(struct user, regs.rip), pc);
#endif

            llvm::MCInst &Inst = IndBrInfo.Inst;

            //
            // helpers
            //
            auto RegValue = [&](unsigned r) -> unsigned long {
              return LoadReg(child, r);
            };

            auto LoadAddr = [&](std::uintptr_t a) -> std::uintptr_t {
              uint64_t word;

              long request = PTRACE_PEEKDATA;
              long pid = child;
              unsigned long addr = a;
              unsigned long data = reinterpret_cast<unsigned long>(&word);

              if (syscall(__NR_ptrace, request, pid, addr, data) < 0) {
                fprintf(stderr, "PTRACE_PEEKDATA failed : %s\n",
                        strerror(errno));
                exit(1);
              }

              return word;
            };

            auto StoreWord = [&](std::uintptr_t a, unsigned long word) -> void {
              long request = PTRACE_POKEDATA;
              long pid = child;
              unsigned long addr = a;
              unsigned long data = word;

              if (syscall(__NR_ptrace, request, pid, addr, data) < 0) {
                fprintf(stderr, "PTRACE_POKEDATA failed : %s\n",
                        strerror(errno));
                exit(1);
              }
            };

            auto GetTarget = [&](void) -> std::uintptr_t {
              switch (Inst.getOpcode()) {
#if defined(TARGET_X86_64)
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

#elif defined(TARGET_AARCH64)
#endif
              default:
                fprintf(stderr, "unimplemented indirect branch opcode %u\n",
                        Inst.getOpcode());
                exit(1);
              }
            };

            std::uintptr_t target = GetTarget();

            //
            // if the instruction is a call, we need to emulate the semantics of
            // saving the return address
            //
#if defined(TARGET_X86_64) && defined(__x86_64__)
            if (f[bb].Term.Type == TERMINATOR::INDIRECT_CALL) {
              std::uintptr_t sp =
                  ptrace(PTRACE_PEEKUSER, child,
                         __builtin_offsetof(struct user, regs.rsp), nullptr);
              sp -= sizeof(std::uintptr_t);
              StoreWord(sp, pc);
              ptrace(PTRACE_POKEUSER, child,
                     __builtin_offsetof(struct user, regs.rsp), sp);
            }
#endif

            //fprintf(stdout, "pc=0x%lx opcode=%u target=0x%lx\n", pc,
            //        Inst.getOpcode(), target);

            //
            // set program counter to what it should be (had we not inserted a
            // software breakpoint)
            //
#if defined(TARGET_X86_64) && defined(__x86_64__)
            ptrace(PTRACE_POKEUSER, child,
                   __builtin_offsetof(struct user, regs.rip), target);
#elif defined(TARGET_AARCH64) && defined(__arm64__)
            ptrace(PTRACE_POKEUSER, child,
                   __builtin_offsetof(struct user, regs.pc), target);
#endif
          }
          break;
        }
      } else if (ptrace(PTRACE_GETSIGINFO, child, 0, &si) < 0) {
        //
        // (3) group-stop
        //

        if (debugMode)
          fprintf(stdout, "ptrace group-stop [%d]\n", child);

        // When restarting a tracee from a ptrace-stop other than
        // signal-delivery-stop, recommended practice is to always pass 0 in
        // sig.
      } else {
        //
        // (4) signal-delivery-stop
        //
        if (debugMode) {
          const char *signm = name_of_signal_number(stopsig);
          if (signm)
            fprintf(stdout, "delivering signal %s [%d]\n", signm, child);
          else
            fprintf(stdout, "delivering signal number %d [%d]\n", stopsig,
                    child);
        }

        // deliver it
        sig = stopsig;
      }
    } else {
      //
      // the child terminated
      //
      if (debugMode)
        fprintf(stdout, "child %d terminated\n", child);

      child = -1;
    }
  }

  write_decompilation();
  return 0;
}

static bool _process_vm_readv(pid_t pid,
                              const std::vector<struct iovec> &local_iovs,
                              const std::vector<struct iovec> &remote_iovs);

// returns the offset into the user struct for the given LLVM register obtained
// via the instruction disassembler.
static unsigned long RegOffset(unsigned reg) {
  switch (reg) {
#if defined(TARGET_X86_64) && defined(__x86_64__)
  case llvm::X86::RAX:
    return __builtin_offsetof(struct user, regs.rax);
  case llvm::X86::RBP:
    return __builtin_offsetof(struct user, regs.rbp);
  case llvm::X86::RBX:
    return __builtin_offsetof(struct user, regs.rbx);
  case llvm::X86::RCX:
    return __builtin_offsetof(struct user, regs.rcx);
  case llvm::X86::RDI:
    return __builtin_offsetof(struct user, regs.rdi);
  case llvm::X86::RDX:
    return __builtin_offsetof(struct user, regs.rdx);
  case llvm::X86::RIP:
    return __builtin_offsetof(struct user, regs.rip);
  case llvm::X86::RSI:
    return __builtin_offsetof(struct user, regs.rsi);
  case llvm::X86::RSP:
    return __builtin_offsetof(struct user, regs.rsp);
  case llvm::X86::R8:
    return __builtin_offsetof(struct user, regs.r8);
  case llvm::X86::R9:
    return __builtin_offsetof(struct user, regs.r9);
  case llvm::X86::R10:
    return __builtin_offsetof(struct user, regs.r10);
  case llvm::X86::R11:
    return __builtin_offsetof(struct user, regs.r11);
  case llvm::X86::R12:
    return __builtin_offsetof(struct user, regs.r12);
  case llvm::X86::R13:
    return __builtin_offsetof(struct user, regs.r13);
  case llvm::X86::R14:
    return __builtin_offsetof(struct user, regs.r14);
  case llvm::X86::R15:
    return __builtin_offsetof(struct user, regs.r15);
#elif defined(TARGET_AARCH64) && defined(__arm64__)
  case llvm::AArch64::X0:
    return __builtin_offsetof(struct user, regs.x0);
  case llvm::AArch64::X1:
    return __builtin_offsetof(struct user, regs.x1);
  case llvm::AArch64::X2:
    return __builtin_offsetof(struct user, regs.x2);
  case llvm::AArch64::X3:
    return __builtin_offsetof(struct user, regs.x3);
  case llvm::AArch64::X4:
    return __builtin_offsetof(struct user, regs.x4);
  case llvm::AArch64::X5:
    return __builtin_offsetof(struct user, regs.x5);
#endif
  default:
    fprintf(stderr, "RegOffset: unimplemented reg %u\n", reg);
    exit(1);
  }
}

// returns the value of the given LLVM MC register in the user struct area
long LoadReg(pid_t child, unsigned reg) {
  return ptrace(PTRACE_PEEKUSER, child, RegOffset(reg), nullptr);
}

void install_breakpoints(pid_t child,
                         binary_t &binary,
                         disas_t dis,
                         std::uintptr_t LoadAddress) {
  unsigned M = std::accumulate(
      binary.Analysis.Functions.begin(), binary.Analysis.Functions.end(), 0u,
      [](unsigned acc, const std::pair<std::uintptr_t, function_t> &pair)
          -> unsigned { return acc + boost::num_vertices(pair.second); });

  auto va_of_rva = [LoadAddress](std::uintptr_t Addr) -> std::uintptr_t {
    return Addr + LoadAddress;
  };

  auto initialize_indirect_branch_instructions_map = [&](void) -> void {
    std::vector<struct iovec> remote_iovs;
    std::vector<struct iovec> local_iovs;

    remote_iovs.reserve(M);
    local_iovs.reserve(M);

    for (auto it = binary.Analysis.Functions.begin();
         it != binary.Analysis.Functions.end(); ++it) {
      function_t &f = (*it).second;

      function_t::vertex_iterator vi, vi_end;
      for (std::tie(vi, vi_end) = boost::vertices(f); vi != vi_end; ++vi) {
        basic_block_t bb = *vi;
        basic_block_properties_t bbprop = f[bb];
        if (bbprop.Term.Type != TERMINATOR::INDIRECT_JUMP &&
            bbprop.Term.Type != TERMINATOR::INDIRECT_CALL)
          continue;

        std::uintptr_t termpc = va_of_rva(bbprop.Term.Addr);

        if (IndBranchInsns.find(termpc) != IndBranchInsns.end())
          continue;

        auto &tup = IndBranchInsns[termpc];
        std::get<0>(tup) = &f;
        std::get<1>(tup) = bb;

        struct iovec remote_iov;
        remote_iov.iov_base = reinterpret_cast<void *>(termpc);
        remote_iov.iov_len = bbprop.Size - (bbprop.Term.Addr - bbprop.Addr);

        IndirectBranchInfo &indbr = std::get<2>(IndBranchInsns[termpc]);
        indbr.InsnBytes.resize(remote_iov.iov_len);

        struct iovec local_iov;
        local_iov.iov_base = indbr.InsnBytes.data();
        local_iov.iov_len = indbr.InsnBytes.size();

        remote_iovs.push_back(remote_iov);
        local_iovs.push_back(local_iov);
      }
    }

    if (!_process_vm_readv(child, local_iovs, remote_iovs))
      exit(1);
  };

  auto place_breakpoints = [&](void) -> void {
    //
    // disassemble the indirect branch instructions, figure out what kind they
    // are and how we can deal with them
    //
    llvm::MCDisassembler &DisAsm = std::get<0>(dis);
    const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
    llvm::MCInstPrinter &IP = std::get<2>(dis);
    for (auto it = IndBranchInsns.begin(); it != IndBranchInsns.end(); ++it) {
      IndirectBranchInfo &indbr = std::get<2>((*it).second);
      llvm::MCInst &Inst = indbr.Inst;

      uint64_t InstLen;
      bool Disassembled =
          DisAsm.getInstruction(Inst, InstLen, indbr.InsnBytes,
                                reinterpret_cast<std::uintptr_t>((*it).first),
                                llvm::nulls(), llvm::nulls());

      assert(Disassembled);

#if defined(TARGET_X86_64)
      if (Inst.getOpcode() != llvm::X86::JMP64r &&
          Inst.getOpcode() != llvm::X86::JMP64m &&
          Inst.getOpcode() != llvm::X86::CALL64m &&
          Inst.getOpcode() != llvm::X86::CALL64r) {
        fprintf(stdout, "could not place breakpoint @ 0x%lx\n", (*it).first);

        std::string str;
        {
          llvm::raw_string_ostream StrStream(str);
          IP.printInst(&Inst, StrStream, "", STI);
        }

        fprintf(stdout, "%s\n", str.c_str());
        fprintf(stdout, "[opcode: %u]", Inst.getOpcode());
        for (unsigned i = 0; i < Inst.getNumOperands(); ++i) {
          const llvm::MCOperand &opnd = Inst.getOperand(i);

          char buff[0x100];
          if (opnd.isReg()) {
            snprintf(buff, sizeof(buff), "<reg %u>", opnd.getReg());
          } else if (opnd.isImm()) {
            snprintf(buff, sizeof(buff), "<imm %ld>", opnd.getImm());
          } else if (opnd.isFPImm()) {
            snprintf(buff, sizeof(buff), "<imm %lf>", opnd.getFPImm());
          } else if (opnd.isExpr()) {
            snprintf(buff, sizeof(buff), "<expr>");
          } else if (opnd.isInst()) {
            snprintf(buff, sizeof(buff), "<inst>");
          } else {
            snprintf(buff, sizeof(buff), "<unknown>");
          }

          fprintf(stdout, " %u:%s", i, buff);
        }
        fprintf(stdout, "\n");
        continue;
      }
#endif

      uint64_t word;

      {
        long request = PTRACE_PEEKDATA;
        long pid = child;
        unsigned long addr = reinterpret_cast<unsigned long>((*it).first);
        unsigned long data = reinterpret_cast<unsigned long>(&word);

        if (syscall(__NR_ptrace, request, pid, addr, data) < 0) {
          fprintf(stderr, "PTRACE_PEEKDATA failed : %s\n", strerror(errno));
          continue;
        }
      }

#if defined(TARGET_X86_64) && defined(__x86_64__)
      reinterpret_cast<uint8_t *>(&word)[0] = 0xcc; /* int3 */
#elif defined(TARGET_AARCH64) && defined(__arm64__)
      reinterpret_cast<uint32_t *>(&word)[0] = 0xf2000800;
#endif

      {
        long request = PTRACE_POKEDATA;
        long pid = child;
        unsigned long addr = reinterpret_cast<unsigned long>((*it).first);
        unsigned long data = word;

        if (syscall(__NR_ptrace, request, pid, addr, data) < 0) {
          fprintf(stderr, "PTRACE_POKEDATA failed : %s\n", strerror(errno));
          continue;
        }
      }

      //fprintf(stdout, "breakpoint placed @ 0x%lx\n", (*it).first);
    }
  };

  initialize_indirect_branch_instructions_map();
  place_breakpoints();
}

template <bool IsRead>
static bool _process_vm_rwv(pid_t pid,
                            const std::vector<struct iovec> &local_iovs,
                            const std::vector<struct iovec> &remote_iovs) {
  assert(remote_iovs.size() == local_iovs.size());

  // __IOV_MAX: this macro has different values in different kernel versions.
  // The latest versions of the kernel use 1024 and this is good choice. Since
  // the C library implementation of readv/writev is able to emulate the
  // functionality even if the currently running kernel does not support this
  // large value the readv/writev call will not fail because of this.
  constexpr ssize_t ___IOV_MAX = 1024;

  unsigned idx = 0;
  for (ssize_t left = remote_iovs.size(); left > 0; left -= ___IOV_MAX) {
    ssize_t N = std::min(___IOV_MAX, left);

    ssize_t res = IsRead ? process_vm_readv(pid, &local_iovs[idx], N,
                                            &remote_iovs[idx], N, 0)
                         : process_vm_writev(pid, &local_iovs[idx], N,
                                             &remote_iovs[idx], N, 0);

    ssize_t expected =
        std::accumulate(local_iovs.begin() + idx,
                        local_iovs.begin() + idx + N,
                        0l, [](long acc, const struct iovec &iov) -> unsigned {
                          return acc + iov.iov_len;
                        });

    if (res != expected) {
      if (res < 0)
        fprintf(stderr, "process_vm_%sv failed (expected %ld) : %s (%d)\n",
                IsRead ? "read" : "write", expected, strerror(errno), errno);
      else
        fprintf(stderr,
                "process_vm_%sv transferred %ld bytes, but expected %ld\n",
                IsRead ? "read" : "write", res, expected);

      return false;
    }

    idx += N;
  }

  return true;
}

bool _process_vm_readv(pid_t pid,
                       const std::vector<struct iovec> &local_iovs,
                       const std::vector<struct iovec> &remote_iovs) {
  return _process_vm_rwv<true>(pid, local_iovs, remote_iovs);
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
#if defined(__x86_64__)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::x86_64;
#elif defined(__arm64__)
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

}

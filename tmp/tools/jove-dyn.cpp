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
#define BOOST_ICL_USE_STATIC_BOUNDED_INTERVALS
#include <boost/icl/interval_set.hpp>
#include <boost/icl/split_interval_map.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/dynamic_bitset.hpp>

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

namespace fs = boost::filesystem;
namespace po = boost::program_options;
namespace obj = llvm::object;

namespace jove {

static int ChildProc(int argc, char **argv);
static int ParentProc(pid_t child, int argc, char **argv);
}

int main(int argc, char **argv) {
  llvm::StringRef ToolName = argv[0];
  llvm::sys::PrintStackTraceOnErrorSignal(ToolName);
  llvm::PrettyStackTraceProgram X(argc, argv);
  llvm::llvm_shutdown_obj Y;

  if (argc < 3 || !fs::exists(argv[1]) || !fs::exists(argv[2])) {
    printf("usage: %s <DECOMPILATION.jv> <PROG> [<ARG1> <ARG2> ...]\n"
           "or\n"
           "(git)  %s <DECOMPILATION/> <PROG> [<ARG1> <ARG2> ...]\n",
           argv[0], argv[0]);
    return 1;
  }

  pid_t child = fork();
  if (!child)
    return jove::ChildProc(argc, argv);

  return jove::ParentProc(child, argc, argv);
}

namespace jove {

decompilation_t decompilation;

static constexpr bool debugMode = false;

static bool git = false;

static bool verify_arch(const obj::ObjectFile &);
static bool update_view_of_virtual_memory(int child);

static bool SeenExec = false;

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
  std::unordered_map<std::uintptr_t, function_index_t> FuncMap;
  std::unordered_map<std::uintptr_t, basic_block_index_t> BBMap;
  boost::icl::split_interval_map<std::uintptr_t, section_properties_set_t>
      SectMap;

  struct {
    std::uintptr_t LoadAddr, LoadAddrEnd;
  } dyn;
};

static std::vector<binary_state_t> BinStateVec;
static boost::dynamic_bitset<> BinFoundVec;
static std::unordered_map<std::string, binary_index_t> BinPathToIdxMap;

typedef std::set<binary_index_t> binary_index_set_t;
static boost::icl::split_interval_map<std::uintptr_t, binary_index_set_t>
    AddressSpace;

struct indirect_branch_t {
  binary_index_t binary_idx;
  basic_block_t bb;

  std::vector<uint8_t> InsnBytes;
  llvm::MCInst Inst;
};

static std::unordered_map<std::uintptr_t, indirect_branch_t> IndBrMap;

static const char *name_of_signal_number(int);

static std::uintptr_t va_of_rva(std::uintptr_t Addr, binary_index_t idx) {
  assert(idx < BinStateVec.size());
  assert(BinStateVec[idx].dyn.LoadAddr);

  return Addr + BinStateVec[idx].dyn.LoadAddr;
}

static std::uintptr_t rva_of_va(std::uintptr_t Addr, binary_index_t idx) {
  assert(idx < BinStateVec.size());
  assert(BinStateVec[idx].dyn.LoadAddr);
  assert(Addr >= BinStateVec[idx].dyn.LoadAddr);
  assert(Addr < BinStateVec[idx].dyn.LoadAddrEnd);

  return Addr - BinStateVec[idx].dyn.LoadAddr;
}

typedef std::tuple<llvm::MCDisassembler &, const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &>
    disas_t;

static void search_address_space_for_binaries(pid_t, disas_t &);
static void place_breakpoint_at_indirect_branch(pid_t, std::uintptr_t Addr,
                                                indirect_branch_t &, disas_t &);
static void on_breakpoint(pid_t, tiny_code_generator_t &, disas_t &);

static void _ptrace_pokeuser(pid_t, unsigned user_offset, unsigned long data);
static unsigned long _ptrace_peekuser(pid_t, unsigned user_offset);
static unsigned long _ptrace_peekdata(pid_t, std::uintptr_t addr);
static void _ptrace_pokedata(pid_t, std::uintptr_t addr, unsigned long data);

static int await_process_completion(pid_t);

int ParentProc(pid_t child, int argc, char **argv) {
  const char *decompilation_path = argv[1];

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
  int ptrace_options = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL |
                       PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                       PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;

  //
  // set those options
  //
  if (debugMode)
    fprintf(stdout, "parent: setting ptrace options...\n");
  ptrace(PTRACE_SETOPTIONS, child, 0, ptrace_options);
  if (debugMode)
    fprintf(stdout, "ptrace options set!\n");

  tiny_code_generator_t tcg;

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();

  git = fs::is_directory(decompilation_path);

  //
  // parse the existing decompilation file
  //
  {
    std::ifstream ifs(
        git ? (std::string(decompilation_path) + "/decompilation.jv")
            : decompilation_path);

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
      fprintf(stderr, "failed to open binary %s in given decompilation\n",
              binary.Path.c_str());
      return 1;
    }

    std::unique_ptr<llvm::MemoryBuffer> &Buffer = FileOrErr.get();
    if (binary.Data.size() != Buffer->getBufferSize() ||
        memcmp(&binary.Data[0], Buffer->getBufferStart(), binary.Data.size())) {
      fprintf(stderr, "contents of binary %s have changed\n",
              binary.Path.c_str());
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

      st.BBMap[binary.Analysis.ICFG[bb].Addr] = bb_idx;
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
      fprintf(stderr, "failed to create binary from %s data\n",
              binary.Path.c_str());
      return 1;
    }

    std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

    typedef typename obj::ELF64LEObjectFile ELFO;
    typedef typename obj::ELF64LEFile ELFT;

    if (!llvm::isa<ELFO>(Bin.get())) {
      fprintf(stderr, "%s is not ELF64LEObjectFile\n", binary.Path.c_str());
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
      fprintf(stderr, "error: could not get ELF sections for binary %s\n",
              binary.Path.c_str());
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

      boost::icl::interval<std::uintptr_t>::type intervl =
          boost::icl::interval<std::uintptr_t>::right_open(
              Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

      section_properties_t sectprop;
      sectprop.name = *name;
      sectprop.contents = *contents;

      section_properties_set_t sectprops = {sectprop};
      st.SectMap.add(std::make_pair(intervl, sectprops));

      if (debugMode)
        fprintf(stderr, "%-20s [0x%lx, 0x%lx)\n", sectprop.name.data(),
                intervl.lower(), intervl.upper());
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
    fprintf(stderr, "failed to lookup target: %s\n", Error.c_str());
    return 1;
  }

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;

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

  disas_t dis(*DisAsm, std::cref(*STI), *IP);

  siginfo_t si;
  long sig = 0;

  for (;;) {
    if (likely(!(child < 0))) {
      if (unlikely(ptrace(SeenExec && !BinFoundVec.all() ? PTRACE_SYSCALL
                                                         : PTRACE_CONT,
                          child, nullptr, reinterpret_cast<void *>(sig)) < 0))
        if (debugMode)
          fprintf(stderr, "failed to resume tracee (%s)\n", strerror(errno));
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
      fprintf(stderr, "exiting... (%s)\n", strerror(errno));
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
        {
          unsigned long syscall_num;

          try {
            syscall_num =
                _ptrace_peekuser(child,
#if defined(__x86_64__)
                                 __builtin_offsetof(struct user, regs.orig_rax)
#elif defined(__arm64__)
                                 __builtin_offsetof(struct user, regs.r8)
#endif
                );
          } catch (...) {
            continue;
          }

          if (syscall_num != __NR_mmap)
            continue;
        }

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
            if (debugMode)
              printf("ptrace event (PTRACE_EVENT_VFORK) [%d]\n", child);
            break;
          case PTRACE_EVENT_FORK:
            if (debugMode)
              printf("ptrace event (PTRACE_EVENT_FORK) [%d]\n", child);
            break;
          case PTRACE_EVENT_CLONE: {
            pid_t new_child;
            ptrace(PTRACE_GETEVENTMSG, child, nullptr, &new_child);

            if (debugMode)
              printf("ptrace event (PTRACE_EVENT_CLONE) -> %d [%d]\n",
                     new_child, child);
            break;
          }
          case PTRACE_EVENT_VFORK_DONE:
            if (debugMode)
              printf("ptrace event (PTRACE_EVENT_VFORK_DONE) [%d]\n", child);
            break;
          case PTRACE_EVENT_EXEC:
            if (debugMode)
              printf("ptrace event (PTRACE_EVENT_EXEC) [%d]\n", child);
            SeenExec = true;
            break;
          case PTRACE_EVENT_EXIT:
            if (debugMode)
              printf("ptrace event (PTRACE_EVENT_EXIT) [%d]\n", child);
            break;
          case PTRACE_EVENT_STOP:
            if (debugMode)
              printf("ptrace event (PTRACE_EVENT_STOP) [%d]\n", child);
            break;
          case PTRACE_EVENT_SECCOMP:
            if (debugMode)
              printf("ptrace event (PTRACE_EVENT_SECCOMP) [%d]\n", child);
            break;
          }
        } else {
          try {
            on_breakpoint(child, tcg, dis);
          } catch (const std::exception& e) {
            fprintf(stderr, "failed to process indirect branch target : %s\n",
                    e.what());
          } catch (...) {
            fprintf(stderr, "failed to process indirect branch target\n");
          }
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

  //
  // write decompilation
  //
  {
    std::ofstream ofs(
        git ? (std::string(decompilation_path) + "/decompilation.jv")
            : decompilation_path);

    boost::archive::binary_oarchive oa(ofs);
    oa << decompilation;
  }

  //
  // git commit
  //
  if (git) {
    const pid_t pid = fork();
    if (!pid) { /* child */
      chdir(decompilation_path);

      std::string msg;
      for (unsigned i = 2; i < argc; ++i) {
        if (i != 2)
          msg += '\'';

        msg += argv[i];

        if (i != 2)
          msg += '\'';

        if (i + 1 < argc)
          msg += ' ';
      }

      std::vector<char> _msg;
      _msg.resize(msg.size() + 1);
      strncpy(&_msg[0], msg.c_str(), _msg.size());

      char _argv0[] = {'/', 'u', 's', 'r', '/', 'b', 'i',
                       'n', '/', 'g', 'i', 't', '\0'};
      char _argv1[] = {'c', 'o', 'm', 'm', 'i', 't', '\0'};
      char _argv2[] = {'.', '\0'};
      char _argv3[] = {'-', 'm', '\0'};
      char *_argv4 = &_msg[0];
      char *_argv[6] = {&_argv0[0], &_argv1[0], &_argv2[0],
                        &_argv3[0], &_argv4[0], nullptr};
      return execve(&_argv0[0], _argv, ::environ);
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
        fprintf(stderr, "waitpid failed : %s\n", strerror(errno));
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
                                                 const target_ulong Addr);

static function_index_t translate_function(pid_t child,
                                           binary_index_t binary_idx,
                                           tiny_code_generator_t &tcg,
                                           disas_t &dis,
                                           target_ulong Addr) {
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
      translate_basic_block(child, binary_idx, tcg, dis, Addr);

  return res;
}

basic_block_index_t translate_basic_block(pid_t child,
                                          binary_index_t binary_idx,
                                          tiny_code_generator_t &tcg,
                                          disas_t &dis,
                                          const target_ulong Addr) {
  auto &BBMap = BinStateVec[binary_idx].BBMap;

  {
    auto it = BBMap.find(Addr);
    if (it != BBMap.end())
      return (*it).second;
  }

  auto &SectMap = BinStateVec[binary_idx].SectMap;
  auto sectit = SectMap.find(Addr);
  if (sectit == SectMap.end()) {
    fprintf(stderr, "warning: no section for address 0x%lx\n", Addr);
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
  } while (T.Type == TERMINATOR::NONE);

  if (T.Type == TERMINATOR::UNKNOWN) {
    fprintf(stderr, "error: unknown terminator @ %#lx\n", Addr);

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
        fprintf(stderr, "failed to disassemble %p\n",
                reinterpret_cast<void *>(Addr));
        break;
      }

      std::string str;
      {
        llvm::raw_string_ostream StrStream(str);
        IP.printInst(&Inst, StrStream, "", STI);
      }
      puts(str.c_str());
    }

    tcg.dump_operations();
    fputc('\n', stdout);
    return invalid_basic_block_index;
  }

  auto is_invalid_terminator = [&](void) -> bool {
    if (T.Type == TERMINATOR::CALL) {
      if (SectMap.find(T._call.Target) == SectMap.end()) {
        fprintf(stderr,
                "warning: call to bad address 0x%lx\n",
                T._call.Target);
        return true;
      }
    }

    return false;
  };

  if (is_invalid_terminator()) {
    fprintf(stderr, "assuming unreachable code\n");
    T.Type = TERMINATOR::UNREACHABLE;
  }

  binary_t &binary = decompilation.Binaries[binary_idx];
  basic_block_index_t bbidx = boost::num_vertices(binary.Analysis.ICFG);
  basic_block_t bb = boost::add_vertex(binary.Analysis.ICFG);
  {
    basic_block_properties_t &bbprop = binary.Analysis.ICFG[bb];
    bbprop.Addr = Addr;
    bbprop.Size = Size;
    bbprop.Term.Type = T.Type;
    bbprop.Term.Addr = T.Addr;

    //
    // if it's an indirect branch, we need to (1) add it to the indirect branch
    // map and (2) install a breakpoint at the correct program counter
    //
    if (bbprop.Term.Type == TERMINATOR::INDIRECT_CALL ||
        bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP) {
      std::uintptr_t termpc = va_of_rva(bbprop.Term.Addr, binary_idx);

      indirect_branch_t &indbr = IndBrMap[termpc];
      indbr.binary_idx = binary_idx;
      indbr.bb = bb;
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

      place_breakpoint_at_indirect_branch(child, termpc, indbr, dis);
    }
  }

  BBMap[Addr] = bbidx;

  //
  // conduct analysis of last instruction (the terminator of the block) and
  // (recursively) descend into branch targets, translating basic blocks
  //
  auto control_flow = [&](std::uintptr_t Target) -> void {
    assert(Target);

    basic_block_index_t succidx;

    auto it = BBMap.find(Target);
    succidx = it != BBMap.end()
                  ? (*it).second
                  : translate_basic_block(child, binary_idx, tcg, dis, Target);

    if (succidx != invalid_basic_block_index) {
      basic_block_t succ = boost::vertex(succidx, binary.Analysis.ICFG);
      boost::add_edge(bb, succ, binary.Analysis.ICFG);
    }
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
    function_index_t f_idx =
        translate_function(child, binary_idx, tcg, dis, T._call.Target);

    {
      basic_block_properties_t &bbprop = binary.Analysis.ICFG[bb];
      std::vector<function_index_t> &Callees = bbprop.Term.Callees.Local;

      if (!std::binary_search(Callees.begin(), Callees.end(), f_idx)) {
        Callees.push_back(f_idx);
        std::sort(Callees.begin(), Callees.end());
      }
    }

    control_flow(T._call.NextPC);
    break;
  }

  case TERMINATOR::INDIRECT_CALL:
    control_flow(T._indirect_call.NextPC);
    break;

  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::RETURN:
  case TERMINATOR::UNREACHABLE:
    break;

  default:
    abort();
  }

  return bbidx;
}

static void dump_llvm_mcinst(FILE *, llvm::MCInst &, disas_t &);

void place_breakpoint_at_indirect_branch(pid_t child,
                                         std::uintptr_t Addr,
                                         indirect_branch_t &indbr,
                                         disas_t &dis) {
  llvm::MCInst &Inst = indbr.Inst;

  auto is_opcode_handled = [](unsigned opc) -> bool {
#if defined(TARGET_X86_64)
    return opc == llvm::X86::JMP64r ||
           opc == llvm::X86::JMP64m ||
           opc == llvm::X86::CALL64m ||
           opc == llvm::X86::CALL64r;
#elif defined(TARGET_AARCH64)
    return opc == llvm::AArch64::BLR;
#endif
  };

  if (!is_opcode_handled(Inst.getOpcode())) {
    fprintf(stderr, "could not place breakpoint @ 0x%lx\n", Addr);
    dump_llvm_mcinst(stderr, Inst, dis);
    return;
  }

  // read a word of the branch instruction
  unsigned long word = _ptrace_peekdata(child, Addr);

  // insert breakpoint
#if defined(TARGET_X86_64) && defined(__x86_64__)
  reinterpret_cast<uint8_t *>(&word)[0] = 0xcc; /* int3 */
#elif defined(TARGET_AARCH64) && defined(__arm64__)
  reinterpret_cast<uint32_t *>(&word)[0] = 0xf2000800;
#endif

  // write the word back
  _ptrace_pokedata(child, Addr, word);

  if (debugMode)
    fprintf(stderr, "breakpoint placed @ 0x%lx\n", Addr);
}

static bool describe_program_counter(std::uintptr_t pc);

static constexpr unsigned ProgramCounterUserOffset =
#if defined(__x86_64__)
    __builtin_offsetof(struct user, regs.rip)
#elif defined(__arm64__)
    __builtin_offsetof(struct user, regs.pc)
#endif
    ;

static bool is_address_in_global_offset_table(std::uintptr_t Addr,
                                              binary_index_t);

void on_breakpoint(pid_t child, tiny_code_generator_t &tcg, disas_t &dis) {
  bool __got = false;

  //
  // get program counter
  //
  std::uintptr_t pc = _ptrace_peekuser(child, ProgramCounterUserOffset);

  //
  // rewind before the breakpoint instruction
  //
#if defined(__x86_64__)
  pc -= 1; /* int3 */
#endif

  //
  // lookup indirect branch info
  //
  const std::uintptr_t _pc = pc;

  auto indirect_branch_of_address =
      [](std::uintptr_t addr) -> indirect_branch_t & {
    auto it = IndBrMap.find(addr);
    if (it == IndBrMap.end()) {
      fprintf(stderr, "unknown breakpoint @ 0x%lx", addr);
      abort();
    }

    return (*it).second;
  };

  indirect_branch_t &IndBrInfo = indirect_branch_of_address(_pc);
  binary_t &binary = decompilation.Binaries[IndBrInfo.binary_idx];
  interprocedural_control_flow_graph_t &ICFG = binary.Analysis.ICFG;

  //
  // update program counter so it is as it should be
  //
  pc += IndBrInfo.InsnBytes.size();
  _ptrace_pokeuser(child, ProgramCounterUserOffset, pc);

  //
  // shorthand-functions for reading the tracee's memory and registers
  //
  basic_block_t bb = IndBrInfo.bb;
  llvm::MCInst &Inst = IndBrInfo.Inst;

  auto RegValue = [child](unsigned llreg) -> unsigned long {
    auto UserOffsetOfLLVMReg = [](unsigned llreg) -> unsigned {
      switch (llreg) {
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
        fprintf(stderr, "RegOffset: unimplemented llvm reg %u\n", llreg);
        exit(1);
      }
    };

    return ptrace(PTRACE_PEEKUSER, child, UserOffsetOfLLVMReg(llreg), nullptr);
  };

  auto LoadAddr = [&](std::uintptr_t addr) -> std::uintptr_t {
    return _ptrace_peekdata(child, addr);
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

    case llvm::X86::CALL64m: { /* call qword ptr [rip + 3071542] */
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(3).isImm());
      std::uintptr_t pcptr =
          RegValue(Inst.getOperand(0).getReg()) + Inst.getOperand(3).getImm();
      __got = is_address_in_global_offset_table(pcptr, IndBrInfo.binary_idx);
      return LoadAddr(pcptr);
    }

    case llvm::X86::CALL64r: /* call rax */
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

#elif defined(TARGET_AARCH64)

    case llvm::AArch64::BLR: /* blr x3 */
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

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
  // saving the return address on the stack for certain architectures
  //
#if defined(TARGET_X86_64) && defined(__x86_64__)
  if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL) {
    std::uintptr_t sp =
        _ptrace_peekuser(child, __builtin_offsetof(struct user, regs.rsp));
    sp -= sizeof(std::uintptr_t);
    _ptrace_pokedata(child, sp, pc);
    _ptrace_pokeuser(child, __builtin_offsetof(struct user, regs.rsp), sp);
  }
#endif

  //
  // set program counter to be branch target
  //
  _ptrace_pokeuser(child, ProgramCounterUserOffset, target);

  if (debugMode)
    fprintf(stderr, "target=0x%lx\n", target);

#if 1
  //
  // update the decompilation based on the target
  //
  auto it = AddressSpace.find(target);
  if (it == AddressSpace.end()) {
    if (debugMode)
      fprintf(stderr, "warning: unknown target 0x%lx\n", target);
    return;
  }

  binary_index_t binary_idx = *(*it).second.begin();

  bool isNewTarget = false;
  bool isLocal = IndBrInfo.binary_idx == binary_idx;

  if (isLocal) {
    if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL) {
      function_index_t f_idx = translate_function(
          child, binary_idx, tcg, dis, rva_of_va(target, binary_idx));

      {
        basic_block_properties_t &bbprop = ICFG[bb];
        std::vector<function_index_t> &Callees = bbprop.Term.Callees.Local;

        if (!std::binary_search(Callees.begin(), Callees.end(), f_idx)) {
          isNewTarget = true;

          Callees.push_back(f_idx);
          std::sort(Callees.begin(), Callees.end());
        }
      }
    } else if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP) {
      basic_block_index_t target_bb_idx = translate_basic_block(
          child, binary_idx, tcg, dis, rva_of_va(target, binary_idx));
      basic_block_t target_bb = boost::vertex(target_bb_idx, ICFG);

      isNewTarget = boost::add_edge(bb, target_bb, ICFG).second;
    } else {
      abort();
    }
  } else { /* non-local */
    //fprintf(stderr, "warning: non-local target @ 0x%lx\n", target);
    return;

#if 0
    if (!update_view_of_virtual_memory(child))
      throw std::runtime_error("failed to read virtual memory maps of child");

    auto vmm_it = vmm.find(target);
    if (vmm_it == vmm.end())
      throw std::runtime_error("mysterious non-local pc");

    // we only consider targets which are backed by an executable file
    const vm_properties_t &vmprop = *(*vmm_it).second.cbegin();
    if (!vmprop.nm.empty()) {
      if (debugMode)
        fprintf(stderr, "(non-local target) %s+0x%lx\n", vmprop.nm.c_str(),
                target - vmprop.beg + vmprop.off);

      if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL) {
      } else if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP) {
        // this is a tail call
      } else {
        abort();
      }
    }
#endif
  }
#endif

  if (isNewTarget && !__got)
    describe_program_counter(_pc) && describe_program_counter(target);
}

bool is_address_in_global_offset_table(std::uintptr_t Addr,
                                       binary_index_t binary_idx) {
  if (!(Addr >= BinStateVec[binary_idx].dyn.LoadAddr &&
        Addr < BinStateVec[binary_idx].dyn.LoadAddrEnd))
    return false;

  Addr = rva_of_va(Addr, binary_idx);
  auto &SectMap = BinStateVec[binary_idx].SectMap;

  auto sectit = SectMap.find(Addr);
  if (sectit == SectMap.end())
    return false;

  const section_properties_t &sectprop = *(*sectit).second.begin();
  return sectprop.name == ".got";
}

static const std::unordered_set<std::string> bad_bins = {
#if 0
    "libEGL.so.1.0.0",
    "libGL.so.1.0.0",
    "libGLX.so.0.0.0",
#endif
    "libGLdispatch.so.0.0.0",
    "libX11-xcb.so.1.0.0",    /* XXX BAD */
    "libX11.so.6.3.0",        /* XXX BAD */
#if 0
    "libXau.so.6.0.0",
    "libXcomposite.so.1.0.0",
    "libXcursor.so.1.0.2",
    "libXdamage.so.1.1.0",
    "libXdmcp.so.6.0.0",
    "libXext.so.6.4.0",
    "libXfixes.so.3.1.0",
    "libXi.so.6.1.0",
    "libXinerama.so.1.0.0",
    "libXrandr.so.2.2.0",
    "libXrender.so.1.3.0",
    "libatk-1.0.so.0.22810.1",
    "libatk-bridge-2.0.so.0.0.0",
    "libatspi.so.0.0.1",
    "libblkid.so.1.1.0",
    "libbrotlicommon.so.1.0.4",
    "libbrotlidec.so.1.0.4",
    "libbz2.so.1.0.6",
    "libc-2.27.so",
    "libcairo-gobject.so.2.11512.0",
    "libcairo.so.2.11512.0",
    "libcom_err.so.2.1",
    "libdatrie.so.1.3.3",
    "libdbus-1.so.3.19.7",
    "libdl-2.27.so",
    "libdrm.so.2.4.0",
    "libdw-0.170.so",
    "libelf-0.170.so",
    "libenchant-2.so.2.2.3",
    "libepoxy.so.0.0.0",
    "libexpat.so.1.6.7",
    "libffi.so.6.0.4",
    "libfontconfig.so.1.11.1",
    "libfreetype.so.6.16.1",
    "libfribidi.so.0.4.0",
    "libgbm.so.1.0.0",
    "libgcc_s.so.1",
    "libgcrypt.so.20.2.2",
    "libgdk-3.so.0.2200.30",
    "libgdk_pixbuf-2.0.so.0.3600.12",
    "libglib-2.0.so.0.5600.1",
    "libgio-2.0.so.0.5600.1",
    "libgmodule-2.0.so.0.5600.1",
    "libgobject-2.0.so.0.5600.1",
    "libgpg-error.so.0.24.2",
    "libgraphite2.so.3.0.1",
    "libgssapi_krb5.so.2.2",
    "libgstallocators-1.0.so.0.1401.0",
    "libgstapp-1.0.so.0.1401.0",
    "libgstaudio-1.0.so.0.1401.0",
    "libgstbase-1.0.so.0.1401.0",
    "libgstfft-1.0.so.0.1401.0",
    "libgstgl-1.0.so.0.1401.0",
    "libgstpbutils-1.0.so.0.1401.0",
    "libgstreamer-1.0.so.0.1401.0",
    "libgsttag-1.0.so.0.1401.0",
    "libgstvideo-1.0.so.0.1401.0",
    "libgtk-3.so.0.2200.30",
    "libgudev-1.0.so.0.2.0",
    "libharfbuzz-icu.so.0.10706.0",
    "libharfbuzz.so.0.10706.0",
    "libhyphen.so.0.3.0",
    "libicui18n.so.61.1",
    "libicuuc.so.61.1",
    "libjavascriptcoregtk-4.0.so.18.7.10",
    "libjpeg.so.8.1.2",
    "libk5crypto.so.3.1",
    "libkeyutils.so.1.6",
    "libkrb5.so.3.3",
    "libkrb5support.so.0.1",
    "liblz4.so.1.8.2",
    "liblzma.so.5.2.4",
    "libm-2.27.so",
    "libmount.so.1.1.0",
    "libnotify.so.4.0.0",
    "liborc-0.4.so.0.28.0",
    "libpango-1.0.so.0.4200.1",
    "libpangocairo-1.0.so.0.4200.1",
    "libpangoft2-1.0.so.0.4200.1",
    "libpcre.so.1.2.10",
    "libpixman-1.so.0.34.0",
    "libpng16.so.16.34.0",
    "libpthread-2.27.so",
    "libresolv-2.27.so",
    "librt-2.27.so",
    "libsecret-1.so.0.0.0",
    "libsoup-2.4.so.1.8.0",
    "libsqlite3.so.0.8.6",
    "libstdc++.so.6.0.25",
    "libsystemd.so.0.22.0",
    "libtasn1.so.6.5.5",
    "libthai.so.0.3.0",
    "libudev.so.1.6.10",
    "libunwind.so.8.0.1",
    "libuuid.so.1.3.0",
#endif
    "libwayland-client.so.0.3.0",
    "libwayland-cursor.so.0.0.0",
    "libwayland-egl.so.1.0.0",
    "libwayland-server.so.0.1.0",
    "libwebkit2gtk-4.0.so.37.28.2",
#if 0
    "libwebp.so.7.0.2",
    "libwebpdemux.so.2.0.4",
    "libwoff2common.so.1.0.2",
    "libwoff2dec.so.1.0.2",
#endif
    "libxcb-render.so.0.0.0",
    "libxcb-shm.so.0.0.0",
    "libxcb.so.1.1.0",
    "libxkbcommon.so.0.0.0",
#if 0
    "libxml2.so.2.9.8",
    "libxslt.so.1.1.32",
    "libz.so.1.2.11",
    "surf",
#endif
};

void search_address_space_for_binaries(pid_t child, disas_t &dis) {
  if (!update_view_of_virtual_memory(child)) {
    fprintf(stderr, "failed to read virtual memory maps of child %d\n", child);
    return;
  }

  for (auto &vm_prop_set : vmm) {
    const vm_properties_t &vm_prop = *vm_prop_set.second.begin();

    if (!vm_prop.x)
      continue;
    if (vm_prop.off)
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

      fprintf(stderr, "found binary %s @ [0x%lx, 0x%lx)\n",
              Path.c_str(),
              vm_prop.beg,
              vm_prop.end);

      binary_state_t &st = BinStateVec[binary_idx];

      st.dyn.LoadAddr = vm_prop.beg;
      st.dyn.LoadAddrEnd = vm_prop.end;

      boost::icl::interval<std::uintptr_t>::type intervl =
          boost::icl::interval<std::uintptr_t>::right_open(vm_prop.beg,
                                                           vm_prop.end);
      binary_index_set_t bin_idx_set = {binary_idx};
      AddressSpace.add(std::make_pair(intervl, bin_idx_set));

      if (bad_bins.find(fs::path(Path).filename().string()) != bad_bins.end())
        continue;

      binary_t &binary = decompilation.Binaries[binary_idx];

      // place breakpoints for indirect branches
      llvm::MCDisassembler &DisAsm = std::get<0>(dis);

      unsigned cnt = 0;
      interprocedural_control_flow_graph_t::vertex_iterator vi, vi_end;
      for (std::tie(vi, vi_end) = boost::vertices(binary.Analysis.ICFG);
           vi != vi_end; ++vi) {
        basic_block_t bb = *vi;
        basic_block_properties_t &bbprop = binary.Analysis.ICFG[bb];
        if (bbprop.Term.Type != TERMINATOR::INDIRECT_JUMP &&
            bbprop.Term.Type != TERMINATOR::INDIRECT_CALL)
          continue;

        std::uintptr_t Addr = va_of_rva(bbprop.Term.Addr, binary_idx);

        indirect_branch_t &IndBrInfo = IndBrMap[Addr];
        IndBrInfo.binary_idx = binary_idx;
        IndBrInfo.bb = bb;
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

      fprintf(stderr, "placed %u breakpoints in %s\n", cnt,
              binary.Path.c_str());
    }
  }
}

void _ptrace_pokeuser(pid_t child, unsigned user_offset, unsigned long data) {
  unsigned long _request = PTRACE_POKEUSER;
  unsigned long _pid = child;
  unsigned long _addr = user_offset;
  unsigned long _data = data;

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0) {
    char buff[0x100];
    snprintf(buff, sizeof(buff), "PTRACE_POKEUSER failed : %s",
             strerror(errno));
    throw std::runtime_error(buff);
  }
}

unsigned long _ptrace_peekuser(pid_t child, unsigned user_offset) {
  unsigned long res;

  unsigned long _request = PTRACE_PEEKUSER;
  unsigned long _pid = child;
  unsigned long _addr = user_offset;
  unsigned long _data = reinterpret_cast<unsigned long>(&res);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0) {
    char buff[0x100];
    snprintf(buff, sizeof(buff), "PTRACE_PEEKUSER failed : %s",
             strerror(errno));
    throw std::runtime_error(buff);
  }

  return res;
}

unsigned long _ptrace_peekdata(pid_t child, std::uintptr_t addr) {
  unsigned long res;

  unsigned long _request = PTRACE_PEEKDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = reinterpret_cast<unsigned long>(&res);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0) {
    char buff[0x100];
    snprintf(buff, sizeof(buff), "PTRACE_PEEKDATA failed : %s",
             strerror(errno));
    throw std::runtime_error(buff);
  }

  return res;
}

void _ptrace_pokedata(pid_t child, std::uintptr_t addr, unsigned long data) {
  unsigned long _request = PTRACE_POKEDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = data;

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0) {
    char buff[0x100];
    snprintf(buff, sizeof(buff), "PTRACE_POKEDATA failed : %s",
             strerror(errno));
    throw std::runtime_error(buff);
  }
}

int ChildProc(int argc, char **argv) {
  //
  // child
  //
  char *prog_path = argv[2];

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

  std::vector<char *> _argv;
  _argv.reserve(argc + 1);
  for (unsigned i = 2; i < argc; ++i)
    _argv.push_back(argv[i]);
  _argv.push_back(nullptr);

  return execve(prog_path, _argv.data(), ::environ);
}

bool verify_arch(const obj::ObjectFile &Obj) {
#if defined(TARGET_X86_64)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::x86_64;
#elif defined(TARGET_AARCH64)
  const llvm::Triple::ArchType archty = llvm::Triple::ArchType::aarch64;
#else
#error "unknown architecture"
#endif

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

    boost::icl::interval<std::uintptr_t>::type intervl =
        boost::icl::interval<std::uintptr_t>::right_open(min, max);

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

void dump_llvm_mcinst(FILE *out, llvm::MCInst &Inst, disas_t &dis) {
  const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
  llvm::MCInstPrinter &IP = std::get<2>(dis);

  std::string str;
  {
    llvm::raw_string_ostream StrStream(str);
    IP.printInst(&Inst, StrStream, "", STI);
  }

  fprintf(out, "%s\n", str.c_str());
  fprintf(out, "[opcode: %u]", Inst.getOpcode());
  for (unsigned i = 0; i < Inst.getNumOperands(); ++i) {
    const llvm::MCOperand &opnd = Inst.getOperand(i);

    char buff[0x100];
    if (opnd.isReg())
      snprintf(buff, sizeof(buff), "<reg %u>", opnd.getReg());
    else if (opnd.isImm())
      snprintf(buff, sizeof(buff), "<imm %ld>", opnd.getImm());
    else if (opnd.isFPImm())
      snprintf(buff, sizeof(buff), "<imm %lf>", opnd.getFPImm());
    else if (opnd.isExpr())
      snprintf(buff, sizeof(buff), "<expr>");
    else if (opnd.isInst())
      snprintf(buff, sizeof(buff), "<inst>");
    else
      snprintf(buff, sizeof(buff), "<unknown>");

    fprintf(out, " %u:%s", i, buff);
  }
  fprintf(out, "\n");
}

bool describe_program_counter(std::uintptr_t pc) {
  auto vm_it = vmm.find(pc);
  if (vm_it == vmm.end()) {
    return false;
  } else {
    const vm_properties_set_t &vmprops = (*vm_it).second;
    const vm_properties_t &vmprop = *vmprops.begin();

    if (vmprop.nm.empty())
      return false;

    printf("%s %#lx\n", vmprop.nm.c_str(), pc - vmprop.beg + vmprop.off);
    return true;
  }
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

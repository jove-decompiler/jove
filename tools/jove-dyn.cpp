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
  static cl::opt<std::string> Prog(cl::Positional,
    cl::desc("<program>"),
    cl::Required);

  static cl::list<std::string> Args("args",
    cl::CommaSeparated,
    cl::desc("<arg_1,arg_2,...,arg_n>"));

  static cl::opt<std::string> jv("decompilation",
    cl::desc("Jove decompilation"),
    cl::Required);

  static cl::opt<bool> Verbose("verbose",
    cl::desc("Print extra information on indirect branch targets"));

  static cl::opt<bool> VeryVerbose("veryverbose",
    cl::desc("Print information helpful for debugging ptrace"));
}

namespace jove {

static int ChildProc(void);
static int ParentProc(pid_t child);

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

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
  std::unordered_map<uintptr_t, basic_block_index_t> BBMap;
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
  basic_block_t bb;

  std::vector<uint8_t> InsnBytes;
  llvm::MCInst Inst;
};

static std::unordered_map<uintptr_t, indirect_branch_t> IndBrMap;

static const char *name_of_signal_number(int);

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

static void search_address_space_for_binaries(pid_t, disas_t &);
static void place_breakpoint_at_indirect_branch(pid_t, uintptr_t Addr,
                                                indirect_branch_t &, disas_t &);
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
        llvm::errs() << (fmt("%-20s [0x%lx, 0x%lx)") %
                         std::string(sectprop.name) % intervl.lower() %
                         intervl.upper())
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

        if (syscallno != __NR_mmap && syscallno != __NR_mmap2)
          continue;

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
        if (opts::VeryVerbose) {
          const char *signm = name_of_signal_number(stopsig);
          if (signm)
            llvm::errs() << "delivering signal " << signm << " [" << child
                         << "]\n";
          else
            llvm::errs() << "delivering signal number " << stopsig << " ["
                         << child << "]\n";
        }

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
      uintptr_t termpc = va_of_rva(bbprop.Term.Addr, binary_idx);

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
  auto control_flow = [&](uintptr_t Target) -> void {
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

  case TERMINATOR::CALL:
    binary.Analysis.ICFG[bb].Term._call.Target =
        translate_function(child, binary_idx, tcg, dis, T._call.Target);

    control_flow(T._call.NextPC);
    break;

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

static std::string StringOfMCInst(llvm::MCInst &, disas_t &);

void place_breakpoint_at_indirect_branch(pid_t child,
                                         uintptr_t Addr,
                                         indirect_branch_t &indbr,
                                         disas_t &dis) {
  llvm::MCInst &Inst = indbr.Inst;

  auto is_opcode_handled = [](unsigned opc) -> bool {
#if defined(__x86_64__)
    return opc == llvm::X86::JMP64r ||
           opc == llvm::X86::JMP64m ||
           opc == llvm::X86::CALL64m ||
           opc == llvm::X86::CALL64r;
#elif defined(__i386__)
    return opc == llvm::X86::JMP32r ||
           opc == llvm::X86::JMP32m ||
           opc == llvm::X86::CALL32m ||
           opc == llvm::X86::CALL32r;
#elif defined(__aarch64__)
    return opc == llvm::AArch64::BLR ||
           opc == llvm::AArch64::BR;
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
       % Binary.Path % ICFG[indbr.bb].Addr
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

static std::string description_of_program_counter(uintptr_t);

static bool is_address_in_global_offset_table(uintptr_t Addr, binary_index_t);

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

  auto indirect_branch_of_address = [](uintptr_t addr) -> indirect_branch_t & {
    auto it = IndBrMap.find(addr);
    if (it == IndBrMap.end())
      throw std::runtime_error((fmt("unknown breakpoint @ %#lx") % addr).str());

    return (*it).second;
  };

  indirect_branch_t &IndBrInfo = indirect_branch_of_address(_pc);
  binary_t &binary = decompilation.Binaries[IndBrInfo.binary_idx];
  interprocedural_control_flow_graph_t &ICFG = binary.Analysis.ICFG;

  //
  // update program counter so it is as it should be
  //
  pc += IndBrInfo.InsnBytes.size();

  //
  // shorthand-functions for reading the tracee's memory and registers
  //
  basic_block_t bb = IndBrInfo.bb;
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
    if (opts::Verbose)
      llvm::errs() << "warning: unknown binary for "
                   << description_of_program_counter(target) << '\n';
    return;
  }

  binary_index_t binary_idx = *(*it).second.begin();

  bool isNewTarget = false;
  bool isLocal = IndBrInfo.binary_idx == binary_idx;

  const char *print_prefix = "(call) ";

  if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL) {
    function_index_t f_idx = translate_function(child, binary_idx, tcg, dis,
                                                rva_of_va(target, binary_idx));

    isNewTarget = ICFG[bb].DynTargets.insert({binary_idx, f_idx}).second;
  } else if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP) {
    if (isLocal) {
      basic_block_index_t target_bb_idx = translate_basic_block(
          child, binary_idx, tcg, dis, rva_of_va(target, binary_idx));
      basic_block_t target_bb = boost::vertex(target_bb_idx, ICFG);

      isNewTarget = boost::add_edge(bb, target_bb, ICFG).second;

      print_prefix = "(jump) ";
    } else {
      // it's a tail-call
      function_index_t f_idx = translate_function(
          child, binary_idx, tcg, dis, rva_of_va(target, binary_idx));

      isNewTarget = ICFG[bb].DynTargets.insert({binary_idx, f_idx}).second;
    }
  } else {
    abort();
  }

  llvm::errs() << print_prefix
               << description_of_program_counter(_pc) << " -> "
               << description_of_program_counter(target) << '\n';
}

bool is_address_in_global_offset_table(uintptr_t Addr,
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
    "libGLdispatch.so.0.0.0",
    "libX11-xcb.so.1.0.0",
#endif
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
    "libwayland-client.so.0.3.0",
    "libwayland-cursor.so.0.0.0",
    "libwayland-egl.so.1.0.0",
    "libwayland-server.so.0.1.0",
#endif
    "libwebkit2gtk-4.0.so.37.28.2", /* XXX BAD */
#if 0
    "libwebp.so.7.0.2",
    "libwebpdemux.so.2.0.4",
    "libwoff2common.so.1.0.2",
    "libwoff2dec.so.1.0.2",
    "libxcb-render.so.0.0.0",
    "libxcb-shm.so.0.0.0",
    "libxcb.so.1.1.0",
    "libxkbcommon.so.0.0.0",
    "libxml2.so.2.9.8",
    "libxslt.so.1.1.32",
    "libz.so.1.2.11",
    "surf",
#endif
};

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

      llvm::errs() << (fmt("found binary %s @ [%#lx, %#lx)") %
                       Path %
                       st.dyn.LoadAddr %
                       st.dyn.LoadAddrEnd).str()
                   << '\n';

      boost::icl::interval<uintptr_t>::type intervl =
          boost::icl::interval<uintptr_t>::right_open(vm_prop.beg, vm_prop.end);
      binary_index_set_t bin_idx_set = {binary_idx};
      AddressSpace.add(std::make_pair(intervl, bin_idx_set));

#if 0
      if (bad_bins.find(fs::path(Path).filename().string()) != bad_bins.end())
        continue;
#endif

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

        uintptr_t Addr = va_of_rva(bbprop.Term.Addr, binary_idx);

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

void _qemu_log(const char *cstr) { llvm::errs() << cstr; }

}

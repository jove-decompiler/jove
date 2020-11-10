#include "tcgcommon.hpp"

#include <tuple>
#include <numeric>
#include <memory>
#include <sstream>
#include <fstream>
#include <cinttypes>
#include <array>
#include <thread>
#include <boost/filesystem.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
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
#include <asm/auxvec.h>
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

extern "C" unsigned long getauxval(unsigned long type);

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

static cl::list<std::string>
    Envs("env", cl::CommaSeparated,
         cl::value_desc("KEY_1=VALUE_1,KEY_2=VALUE_2,...,KEY_n=VALUE_n"),
         cl::desc("Extra environment variables"), cl::cat(JoveCategory));

static cl::opt<std::string> jv("decompilation", cl::desc("Jove decompilation"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

static cl::alias jvAlias("d", cl::desc("Alias for -decompilation."),
                         cl::aliasopt(jv), cl::cat(JoveCategory));

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

static cl::opt<bool>
    PrintPtraceEvents("events", cl::desc("Print PTRACE events when they occur"),
                      cl::cat(JoveCategory));

static cl::alias PrintPtraceEventsAlias("e", cl::desc("Alias for -events."),
                                        cl::aliasopt(PrintPtraceEvents),
                                        cl::cat(JoveCategory));

static cl::opt<bool>
    PrintSignals("signals", cl::desc("Print signals when they are delivered"),
                 cl::cat(JoveCategory));

static cl::alias PrintSignalsAlias("s", cl::desc("Alias for -signals."),
                                   cl::aliasopt(PrintSignals),
                                   cl::cat(JoveCategory));

static cl::opt<bool> Syscalls("syscalls", cl::desc("Always trace system calls"),
                              cl::cat(JoveCategory));

} // namespace opts

namespace jove {

static int ChildProc(const char *fifo_path);
static int ParentProc(pid_t child, const char *fifo_path);

}

int main(int argc, char **argv) {
  int _argc = argc;
  char **_argv = argv;

  // argc/argv replacement to handle '--'
  struct {
    std::vector<std::string> s;
    std::vector<const char *> a;
  } arg_vec;

  {
    int prog_args_idx = -1;

    for (int i = 0; i < argc; ++i) {
      if (strcmp(argv[i], "--") == 0) {
        prog_args_idx = i;
        break;
      }
    }

    if (prog_args_idx != -1) {
      for (int i = 0; i < prog_args_idx; ++i)
        arg_vec.s.push_back(argv[i]);

      for (std::string &s : arg_vec.s)
        arg_vec.a.push_back(s.c_str());
      arg_vec.a.push_back(nullptr);

      _argc = prog_args_idx;
      _argv = const_cast<char **>(&arg_vec.a[0]);

      for (int i = prog_args_idx + 1; i < argc; ++i) {
        //llvm::outs() << llvm::formatv("argv[{0}] = {1}\n", i, argv[i]);

        opts::Args.push_back(argv[i]);
      }
    }
  }

  llvm::InitLLVM X(_argc, _argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::ParseCommandLineOptions(_argc, _argv, "Jove Dynamic Analysis\n");

  if (!fs::exists(opts::Prog)) {
    WithColor::error() << "program does not exist\n";
    return 1;
  }

  if (!fs::exists(opts::jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  std::string fifo_path = tmpnam(nullptr);

  if (mkfifo(fifo_path.c_str(), 0666) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("mkfifo failed ({0})\n", strerror(err));
    return 1;
  }

  pid_t child = fork();
  if (!child)
    return jove::ChildProc(fifo_path.c_str());

#ifndef __mips64
  return jove::ParentProc(child, fifo_path.c_str());
#else
  int rc = jove::ParentProc(child, fifo_path.c_str());
  syscall(__NR_exit_group, rc);
  __builtin_trap();
  __builtin_unreachable();
#endif
}

namespace jove {

typedef boost::format fmt;

static decompilation_t decompilation;

static bool verify_arch(const obj::ObjectFile &);
static bool update_view_of_virtual_memory(pid_t child);

#if defined(__mips64) || defined(__mips__)
static uintptr_t ExecutableRegionAddress = 0x0;
static size_t ExecutableRegionUsed = 0;

static std::unordered_map<uint64_t, uintptr_t> TrampolineMap;
#endif

static bool SeenExec = false;

static struct {
  bool Found;
  uintptr_t Addr;

  uintptr_t r_brk;
} _r_debug = {.Found = false, .Addr = 0, .r_brk = 0};

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

  uintptr_t TermAddr;

  std::vector<uint8_t> InsnBytes;
  llvm::MCInst Inst;

#if defined(__mips64) || defined(__mips__)
  struct {
    llvm::MCInst DelaySlotInst;
  } ___mips;
#endif

  bool IsCall;
};

struct return_t {
  binary_index_t binary_idx;

  std::vector<uint8_t> InsnBytes;
  llvm::MCInst Inst;

  uintptr_t TermAddr;
};

static std::unordered_map<uintptr_t, indirect_branch_t> IndBrMap;
static std::unordered_map<uintptr_t, return_t> RetMap;

static uintptr_t va_of_rva(uintptr_t Addr, binary_index_t idx) {
  assert(BinStateVec.at(idx).dyn.LoadAddr);

  binary_t &binary = decompilation.Binaries.at(idx);
  if (binary.IsExecutable && !binary.IsPIC) /* XXX */
    return Addr;

  return Addr + BinStateVec.at(idx).dyn.LoadAddr;
}

static uintptr_t rva_of_va(uintptr_t Addr, binary_index_t idx) {
  assert(BinStateVec[idx].dyn.LoadAddr);

  binary_t &binary = decompilation.Binaries.at(idx);
  if (binary.IsExecutable && !binary.IsPIC) /* XXX */
    return Addr;

  assert(Addr >= BinStateVec.at(idx).dyn.LoadAddr);
  assert(Addr < BinStateVec.at(idx).dyn.LoadAddrEnd);
  return Addr - BinStateVec.at(idx).dyn.LoadAddr;
}

typedef std::tuple<llvm::MCDisassembler &, const llvm::MCSubtargetInfo &,
                   llvm::MCInstPrinter &>
    disas_t;

struct breakpoint_t {
  unsigned long word;

  std::vector<uint8_t> InsnBytes;
  llvm::MCInst Inst;

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

#if defined(__mips64) || defined(__mips__)
struct user_regs_struct {
  uint64_t regs[38];
};
#endif

static void _ptrace_get_gpr(pid_t, struct user_regs_struct &out);
static void _ptrace_set_gpr(pid_t, const struct user_regs_struct &in);

static std::string _ptrace_read_string(pid_t, uintptr_t addr);

static unsigned long _ptrace_peekdata(pid_t, uintptr_t addr);
static void _ptrace_pokedata(pid_t, uintptr_t addr, unsigned long data);

static int await_process_completion(pid_t);

#if defined(__x86_64__) || defined(__aarch64__) || defined(__mips64)
typedef typename obj::ELF64LE ELFT;
#elif defined(__i386__) || defined(__mips__)
typedef typename obj::ELF32LE ELFT;
#else
#error
#endif

typedef typename obj::ELFObjectFile<ELFT> ELFO;
typedef typename obj::ELFFile<ELFT> ELFF;

static void IgnoreCtrlC(void);

#if defined(__mips64) || defined(__mips)
static void fifo_reader(const char *fifo_path);
#endif

static void harvest_reloc_targets(pid_t, tiny_code_generator_t &, disas_t &);
static void rendezvous_with_dynamic_linker(pid_t, disas_t &);

static function_index_t translate_function(pid_t child,
                                           binary_index_t binary_idx,
                                           tiny_code_generator_t &tcg,
                                           disas_t &dis,
                                           target_ulong Addr,
                                           unsigned &brkpt_count);

static bool HasVDSO(void);
static std::pair<void *, unsigned> GetVDSO(void);

static std::string jove_add_path;

int ParentProc(pid_t child, const char *fifo_path) {
  IgnoreCtrlC();

  jove_add_path =
      (boost::dll::program_location().parent_path() / std::string("jove-add"))
          .string();
  if (!fs::exists(jove_add_path))
    WithColor::warning() << "could not find jove-add at " << jove_add_path
                         << '\n';

#if 0
  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDWAIT;
    sa.sa_handler = SIG_DFL;

    if (sigaction(SIGINT, &sa, nullptr) < 0) {
      int err = errno;
      WithColor::error() << llvm::formatv("{0}: sigaction failed ({1})\n",
                                          __func__, strerror(err));
    }
  }
#elif 0
  signal(SIGCHLD, SIG_IGN); /* Silently (and portably) reap children. */
#endif

#if defined(__mips64) || defined(__mips)
  {
    std::thread fifo_thread(fifo_reader, fifo_path);
    fifo_thread.detach(); /* go be free */
  }
#endif

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
  // OMG. this hack is awful. it is here because if a binary is dynamically
  // added to the decompilation, the std::vector will resize if necessary- and
  // if such an event occurs, pointers to the section data will be invalidated
  // because the binary_t::Data will be recopied. TODO
  //
  decompilation.Binaries.reserve(2 * decompilation.Binaries.size());

  //
  // verify that the binaries did not change on-disk
  //
  for (binary_t &binary : decompilation.Binaries) {
    if (binary.IsVDSO) {
      assert(HasVDSO());
      void *vdso;
      unsigned n;

      std::tie(vdso, n) = GetVDSO();

      assert(n);

      if (binary.Data.size() != n ||
          memcmp(&binary.Data[0], vdso, binary.Data.size())) {
        WithColor::error() << "[vdso] has changed\n";
        return 1;
      }

      continue;
    }

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

  //
  // verify that the given executable is identical to the one found in the
  // decompilation
  //
  for (binary_t &binary : decompilation.Binaries) {
    if (!binary.IsExecutable)
      continue;

    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> FileOrErr =
        llvm::MemoryBuffer::getFileOrSTDIN(opts::Prog);

    if (std::error_code EC = FileOrErr.getError()) {
      WithColor::error() << "failed to open given path " << opts::Prog << '\n';
      return 1;
    }

    std::unique_ptr<llvm::MemoryBuffer> &Buffer = FileOrErr.get();
    if (binary.Data.size() != Buffer->getBufferSize() ||
        memcmp(&binary.Data[0], Buffer->getBufferStart(), binary.Data.size())) {
      WithColor::error()
          << "given binary does not match binary in decompilation\n";
      return 1;
    }

    break;
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
    if (binary.IsVDSO)
      BinPathToIdxMap["[vdso]"] = i;
    else
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
      if (opts::Verbose)
        WithColor::error() << llvm::formatv(
            "{0}: failed to create binary from {1}\n", __func__, binary.Path);

      boost::icl::interval<uintptr_t>::type intervl =
          boost::icl::interval<uintptr_t>::right_open(0, binary.Data.size());

      assert(st.SectMap.find(intervl) == st.SectMap.end());

      section_properties_t sectprop;
      sectprop.name = ".text";
      sectprop.contents = binary.Data;
      sectprop.w = false;
      sectprop.x = true;
      st.SectMap.add({intervl, {sectprop}});
    } else {
      std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

      if (!llvm::isa<ELFO>(Bin.get())) {
        WithColor::error() << binary.Path << " is not ELF of expected type\n";
        return 1;
      }

      ELFO &O = *llvm::cast<ELFO>(Bin.get());

      TheTriple = O.makeTriple();
      Features = O.getFeatures();

      const ELFF &E = *O.getELFFile();

      typedef typename ELFF::Elf_Shdr Elf_Shdr;
      typedef typename ELFF::Elf_Shdr_Range Elf_Shdr_Range;

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

        sectprop.w = (Sec.sh_flags & llvm::ELF::SHF_WRITE) != 0;
        sectprop.x = (Sec.sh_flags & llvm::ELF::SHF_EXECINSTR) != 0;

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

        if (opts::VeryVerbose)
          llvm::errs() << (fmt("%-20s [0x%lx, 0x%lx)")
                           % std::string(sectprop.name)
                           % intervl.lower()
                           % intervl.upper())
                              .str()
                       << '\n';
      }
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

  llvm::MCTargetOptions Options;
  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
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

#if defined(__x86_64__) || defined(__i386__)
  int AsmPrinterVariant = 1; // Intel syntax
#else
  int AsmPrinterVariant = AsmInfo->getAssemblerDialect();
#endif
  std::unique_ptr<llvm::MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      llvm::Triple(TripleName), AsmPrinterVariant, *AsmInfo, *MII, *MRI));
  if (!IP) {
    WithColor::error() << "no instruction printer\n";
    return 1;
  }

  disas_t dis(*DisAsm, std::cref(*STI), *IP);

  siginfo_t si;
  long sig = 0;

  try {
    for (;;) {
      if (likely(!(child < 0))) {
        if (unlikely(ptrace(SeenExec && (opts::Syscalls ||
                                         !BinFoundVec.all() ||
                                         BrkMap.find(_r_debug.r_brk) == BrkMap.end() ||
                                         /* TODO !(harvested relocations) || */
#if defined(__mips64) || defined(__mips__)
                                         !ExecutableRegionAddress)
#else
                                         false)
#endif
                                ? PTRACE_SYSCALL
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

          //
          // syscall # and arguments
          //
#if defined(__x86_64__)
          auto &no = gpr.orig_rax;
          auto &a1 = gpr.rdi;
          auto &a2 = gpr.rsi;
          auto &a3 = gpr.rdx;
          auto &a4 = gpr.r10;
          auto &a5 = gpr.r8;
          auto &a6 = gpr.r9;
#elif defined(__i386__)
          auto &no = gpr.orig_eax;
          auto &a1 = gpr.ebx;
          auto &a2 = gpr.ecx;
          auto &a3 = gpr.edx;
          auto &a4 = gpr.esi;
          auto &a5 = gpr.edi;
          auto &a6 = gpr.ebp;
#elif defined(__aarch64__)
          auto &no = gpr.regs[8];
          auto &a1 = gpr.regs[0];
          auto &a2 = gpr.regs[1];
          auto &a3 = gpr.regs[2];
          auto &a4 = gpr.regs[3];
          auto &a5 = gpr.regs[4];
          auto &a6 = gpr.regs[5];
#elif defined(__mips64) || defined(__mips__)
          auto &no = gpr.regs[2];
          auto &a1 = gpr.regs[4];
          auto &a2 = gpr.regs[5];
          auto &a3 = gpr.regs[6];
          auto &a4 = gpr.regs[7];
          auto &a5 = gpr.regs[8];
          auto &a6 = gpr.regs[9];
#else
#error
#endif

          if (no == __NR_rt_sigaction) {
            WithColor::note()
                << llvm::formatv("rt_sigaction({0}, {1:x}, {2:x}, {3})\n",
                                 a1, a2, a3, a4);

            uintptr_t act = a2;
            if (act) {
              uintptr_t handler = _ptrace_peekdata(child, act);

              WithColor::note() << llvm::formatv("handler={0:x}\n", handler);

              if (handler && (void *)handler != SIG_IGN) {
                update_view_of_virtual_memory(child);

                auto it = AddressSpace.find(handler);
                if (it == AddressSpace.end()) {
                  WithColor::warning() << llvm::formatv(
                      "sighandler {0:x} in unknown binary\n", handler);
                } else {
                  binary_index_t handler_binary_idx = *(*it).second.begin();

                  unsigned brkpt_count = 0;
                  function_index_t f_idx = translate_function(
                      child, handler_binary_idx, tcg, dis,
                      rva_of_va(handler, handler_binary_idx), brkpt_count);

                  if (f_idx == invalid_function_index) {
                    WithColor::error() << llvm::formatv(
                        "failed to translate signal handler {0:x}\n", handler);
                  } else {
                    binary_t &binary =
                        decompilation.Binaries[handler_binary_idx];
                    binary.Analysis.Functions[f_idx].IsSignalHandler = true;
                    binary.Analysis.Functions[f_idx].IsABI = true;
                  }
                }
              }
            }
          }

#if defined(__mips64) || defined(__mips__)
          if (ExecutableRegionAddress) {
#else
          if (true) {
#endif
            search_address_space_for_binaries(child, dis);
            rendezvous_with_dynamic_linker(child, dis);
            harvest_reloc_targets(child, tcg, dis);
          } else {
            if (opts::Verbose)
              WithColor::note() << "!ExecutableRegionAddress\n";
          }
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
              if (opts::PrintPtraceEvents)
                llvm::errs() << "ptrace event (PTRACE_EVENT_VFORK) [" << child
                             << "]\n";
              break;
            case PTRACE_EVENT_FORK:
              if (opts::PrintPtraceEvents)
                llvm::errs() << "ptrace event (PTRACE_EVENT_FORK) [" << child
                             << "]\n";
              break;
            case PTRACE_EVENT_CLONE: {
              pid_t new_child;
              ptrace(PTRACE_GETEVENTMSG, child, nullptr, &new_child);

              if (opts::PrintPtraceEvents)
                llvm::errs() << "ptrace event (PTRACE_EVENT_CLONE) -> "
                             << new_child << " [" << child << "]\n";
              break;
            }
            case PTRACE_EVENT_VFORK_DONE:
              if (opts::PrintPtraceEvents)
                llvm::errs() << "ptrace event (PTRACE_EVENT_VFORK_DONE) ["
                             << child << "]\n";
              break;
            case PTRACE_EVENT_EXEC:
              if (opts::PrintPtraceEvents)
                llvm::errs() << "ptrace event (PTRACE_EVENT_EXEC) [" << child
                             << "]\n";
              SeenExec = true;
              break;
            case PTRACE_EVENT_EXIT:
              if (opts::PrintPtraceEvents)
                llvm::errs() << "ptrace event (PTRACE_EVENT_EXIT) [" << child
                             << "]\n";
              break;
            case PTRACE_EVENT_STOP:
              if (opts::PrintPtraceEvents)
                llvm::errs() << "ptrace event (PTRACE_EVENT_STOP) [" << child
                             << "]\n";
              break;
            case PTRACE_EVENT_SECCOMP:
              if (opts::PrintPtraceEvents)
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

          if (opts::PrintPtraceEvents)
            llvm::errs() << "ptrace group-stop [" << child << "]\n";

          // When restarting a tracee from a ptrace-stop other than
          // signal-delivery-stop, recommended practice is to always pass 0 in
          // sig.
        } else {
          //
          // (4) signal-delivery-stop
          //
          if (opts::PrintSignals)
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
  } catch (const std::exception &e) {
    WithColor::note() << llvm::formatv("exception! {0}\n", e.what());
  }

  {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;

    sigaction(SIGINT, &sa, nullptr);
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
      std::string msg("[jove-bootstrap] ");

      for (const std::string &env : opts::Envs) {
        msg.append(env);
        msg.push_back(' ');
      }

      msg.append(opts::Prog);

      for (const std::string &arg : opts::Args) {
        msg.push_back(' ');
        msg.push_back('\'');
        msg.append(arg);
        msg.push_back('\'');
      }

      chdir(opts::jv.c_str());

      const char *arg_arr[] = {
        "/usr/bin/git", "commit", ".", "-m", msg.c_str(),

        nullptr
      };

      return execve(arg_arr[0], const_cast<char **>(&arg_arr[0]), ::environ);
    }

    if (int ret = await_process_completion(pid))
      return ret;
  }

  return 0;
}

#if defined(__mips64) || defined(__mips)
void fifo_reader(const char *fifo_path) {
  int fd = open(fifo_path, O_RDWR);
  if (fd < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("failed to open fifo \"{0}\" ({1})\n",
                                        fifo_path, strerror(err));
  }

  {
    void *addr;
    ssize_t ret;
    do
      ret = read(fd, &addr, sizeof(addr));
    while (ret < 0 && errno == EINTR);

    if (ret == sizeof(addr)) {
      if (opts::VeryVerbose)
        WithColor::note() << llvm::formatv("ExecutableRegionAddress: {0}\n",
                                           addr);
      assert(!ExecutableRegionAddress);

      ExecutableRegionAddress = reinterpret_cast<uintptr_t>(addr);
      /* mb? */

      char confirmation = 'c';
      do
        ret = write(fd, &confirmation, sizeof(confirmation));
      while (ret < 0 && errno == EINTR);
    } else {
      WithColor::error() << llvm::formatv("{0}: read gave {1}\n",
                                          __func__, ret);
    }
  }

  if (close(fd) < 0) {
    int err = errno;
    WithColor::error() << llvm::formatv("{0}: close failed ({1})\n", __func__,
                                        strerror(err));
  }
}
#endif

void IgnoreCtrlC(void) {
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

static void InvalidateAllFunctionAnalyses(void) {
  for (binary_t &binary : decompilation.Binaries)
    for (function_t &f : binary.Analysis.Functions)
      f.InvalidateAnalysis();
}

static basic_block_index_t translate_basic_block(pid_t,
                                                 binary_index_t binary_idx,
                                                 tiny_code_generator_t &,
                                                 disas_t &,
                                                 const target_ulong Addr,
                                                 unsigned &brkpt_count);

function_index_t translate_function(pid_t child,
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
  binary.Analysis.Functions[res].Analysis.Stale = true;
  binary.Analysis.Functions[res].IsABI = false;
  binary.Analysis.Functions[res].IsSignalHandler = false;

  return res;
}

static void place_breakpoint_at_return(pid_t child, uintptr_t Addr,
                                       return_t &Ret);

static bool does_function_definitely_return(binary_index_t, function_index_t);

basic_block_index_t translate_basic_block(pid_t child,
                                          binary_index_t binary_idx,
                                          tiny_code_generator_t &tcg,
                                          disas_t &dis,
                                          const target_ulong Addr,
                                          unsigned &brkpt_count) {
  binary_t &binary = decompilation.Binaries[binary_idx];
  auto &ICFG = binary.Analysis.ICFG;
  auto &BBMap = BinStateVec[binary_idx].BBMap;
  auto &SectMap = BinStateVec[binary_idx].SectMap;

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

      if (opts::Verbose) {
        llvm::outs() << "intervl1: [" << (fmt("%#lx") % intervl1.lower()).str()
                     << ", " << (fmt("%#lx") % intervl1.upper()).str() << ")\n";

        llvm::outs() << "intervl2: [" << (fmt("%#lx") % intervl2.lower()).str()
                     << ", " << (fmt("%#lx") % intervl2.upper()).str() << ")\n";

        llvm::outs() << "orig_intervl: ["
                     << (fmt("%#lx") % orig_intervl.lower()).str() << ", "
                     << (fmt("%#lx") % orig_intervl.upper()).str() << ")\n";
      }

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

  auto sectit = SectMap.find(Addr);
  if (sectit == SectMap.end()) {
    WithColor::error()
        << (fmt("warning: no section for address 0x%lx") % Addr).str() << '\n';
    return invalid_basic_block_index;
  }
  const section_properties_t &sectprop = *(*sectit).second.begin();
  if (!sectprop.x) {
    if (true /* opts::Verbose */)
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

        if (opts::Verbose)
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

        if (opts::Verbose && intervl.upper() != _intervl.upper()) {
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
      bool Disassembled = DisAsm.getInstruction(
          Inst, InstLen, sectprop.contents.slice(Offset), A, llvm::nulls());
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

    //
    // if it's an indirect branch, we need to (1) add it to the indirect branch
    // map and (2) install a breakpoint at the correct program counter
    //
    if (bbprop.Term.Type == TERMINATOR::INDIRECT_CALL ||
        bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP) {
      uintptr_t termpc = va_of_rva(bbprop.Term.Addr, binary_idx);

      assert(IndBrMap.find(termpc) == IndBrMap.end());

      indirect_branch_t &indbr = IndBrMap[termpc];
      indbr.IsCall = bbprop.Term.Type == TERMINATOR::INDIRECT_CALL;
      indbr.binary_idx = binary_idx;
      indbr.TermAddr = bbprop.Term.Addr;
      indbr.InsnBytes.resize(bbprop.Size - (bbprop.Term.Addr - bbprop.Addr));
#if defined(__mips64) || defined(__mips__)
      indbr.InsnBytes.resize(indbr.InsnBytes.size() + 4 /* delay slot */);
      assert(indbr.InsnBytes.size() == sizeof(uint64_t));
#endif
      memcpy(&indbr.InsnBytes[0],
             &sectprop.contents[bbprop.Term.Addr - (*sectit).first.lower()],
             indbr.InsnBytes.size());

      //
      // now that we have the bytes for each indirect branch, disassemble them
      //
      llvm::MCInst &Inst = indbr.Inst;

      llvm::MCDisassembler &DisAsm = std::get<0>(dis);
      {
        uint64_t InstLen;
        bool Disassembled = DisAsm.getInstruction(
            Inst, InstLen, indbr.InsnBytes, bbprop.Term.Addr, llvm::nulls());
        assert(Disassembled);
      }

#if defined(__mips64) || defined(__mips__)
      {
        uint64_t InstLen;
        bool Disassembled = DisAsm.getInstruction(
            indbr.___mips.DelaySlotInst, InstLen,
            llvm::ArrayRef<uint8_t>(indbr.InsnBytes).slice(4),
            bbprop.Term.Addr + 4, llvm::nulls());
        assert(Disassembled);
      }
#endif

      ++brkpt_count;
      place_breakpoint_at_indirect_branch(child, termpc, indbr, dis);
    }

    //
    // if it's a return, we need to (1) add it to the return map and (2) install
    // a breakpoint at the correct pc
    //
    if (bbprop.Term.Type == TERMINATOR::RETURN) {
      uintptr_t termpc = va_of_rva(bbprop.Term.Addr, binary_idx);

      assert(RetMap.find(termpc) == RetMap.end());

      return_t &RetInfo = RetMap[termpc];
      RetInfo.binary_idx = binary_idx;
      RetInfo.TermAddr = bbprop.Term.Addr;

      auto sectit = SectMap.find(bbprop.Term.Addr);
      assert(sectit != SectMap.end());
      const section_properties_t &sectprop = *(*sectit).second.begin();

      RetInfo.InsnBytes.resize(bbprop.Size - (bbprop.Term.Addr - bbprop.Addr));
#if defined(__mips64) || defined(__mips__)
      RetInfo.InsnBytes.resize(RetInfo.InsnBytes.size() + 4 /* delay slot */);
      assert(RetInfo.InsnBytes.size() == sizeof(uint64_t));
#endif
      memcpy(&RetInfo.InsnBytes[0],
             &sectprop.contents[bbprop.Term.Addr - (*sectit).first.lower()],
             RetInfo.InsnBytes.size());

      {
        llvm::MCDisassembler &DisAsm = std::get<0>(dis);

        uint64_t InstLen;
        bool Disassembled =
            DisAsm.getInstruction(RetInfo.Inst, InstLen, RetInfo.InsnBytes,
                                  bbprop.Term.Addr, llvm::nulls());
        assert(Disassembled);
        assert(InstLen == RetInfo.InsnBytes.size());
      }

      place_breakpoint_at_return(child, termpc, RetInfo);
      ++brkpt_count;
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

      basic_block_index_t _bbidx = (*it).second - 1;
      _bb = boost::vertex(_bbidx, ICFG);
      assert(T.Type == ICFG[_bb].Term.Type);
    }

    basic_block_t succ = boost::vertex(succidx, ICFG);
    bool isNewTarget = boost::add_edge(_bb, succ, ICFG).second;
    if (isNewTarget)
      ICFG[_bb].InvalidateAnalysis();
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
    function_index_t FIdx = translate_function(child, binary_idx, tcg, dis,
                                               T._call.Target, brkpt_count);

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

  binary_t &b = decompilation.Binaries.at(BIdx);
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

static std::string StringOfMCInst(llvm::MCInst &, disas_t &);

#if defined(__mips64) || defined(__mips__)
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
#elif defined(__mips64) || defined(__mips__)
    return opc == llvm::Mips::JALR
        || opc == llvm::Mips::JR;
#else
#error
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
       % indbr.TermAddr
       % StringOfMCInst(Inst, dis)).str());
  }

  // read a word of the branch instruction
  unsigned long word = _ptrace_peekdata(child, Addr);

  // insert breakpoint
  arch_put_breakpoint(&word);

#if defined(__mips64) || defined(__mips__)
  {
    /* key is the encoding of INDIRECT BRANCH ; DELAY SLOT INSTRUCTION */
    if (indbr.InsnBytes.size() != sizeof(uint64_t)) {
      binary_t &Binary = decompilation.Binaries[indbr.binary_idx];
      const auto &ICFG = Binary.Analysis.ICFG;
      throw std::runtime_error(
        (fmt("indbr.InsnBytes.size() = %u @ %#lx\n"
             "%s BB %#lx\n"
             "%s")
         % static_cast<unsigned>(indbr.InsnBytes.size())
         % Addr
         % Binary.Path
         % indbr.TermAddr
         % StringOfMCInst(Inst, dis)).str());
    }

    assert(indbr.InsnBytes.size() == sizeof(uint64_t));
    uint64_t key = *((uint64_t *)indbr.InsnBytes.data());

    if (indbr.IsCall) {
      assert(Inst.getOpcode() == llvm::Mips::JALR);
      assert(Inst.getNumOperands() == 2);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(0).getReg() == llvm::Mips::RA);
      assert(Inst.getOperand(1).isReg());

#if 0
        if (Inst.getNumOperands() != 1) {
          WithColor::error() << llvm::formatv(
              "{0}: unknown number ({1}) of operands [{2}]\n", __func__,
              Inst.getNumOperands(), StringOfMCInst(Inst, dis));
        }
#endif

      uint32_t first_insn_replacement =
          encoding_of_jump_to_reg(Inst.getOperand(1).getReg());

      ((uint32_t *)&key)[0] = first_insn_replacement;
    }

    auto it = TrampolineMap.find(key);
    if (it == TrampolineMap.end()) {
      assert(ExecutableRegionAddress);

      uint64_t val = key;
      if (sizeof(long) == sizeof(val)) { /* we can do it with one poke */
        _ptrace_pokedata(child, ExecutableRegionAddress, val);
      } else if (sizeof(long) == sizeof(uint32_t)) { /* two pokes will suffice */
        uint32_t val0 = ((uint32_t *)&val)[0];
        uint32_t val1 = ((uint32_t *)&val)[1];

        _ptrace_pokedata(child, ExecutableRegionAddress, val0);
        _ptrace_pokedata(child, ExecutableRegionAddress + 4, val1);
      } else {
        __builtin_trap();
        __builtin_unreachable();
      }

      TrampolineMap.insert({key, ExecutableRegionAddress});

      ExecutableRegionAddress += sizeof(key);
      ExecutableRegionUsed += sizeof(key);

#define EXECUTABLE_REGION_SIZE (4096 * 16)

      if (opts::VeryVerbose)
        WithColor::note() << llvm::formatv(
            "executable region in tracee has {0} bytes left (used {1} bytes)\n",
            EXECUTABLE_REGION_SIZE - ExecutableRegionUsed,
            ExecutableRegionUsed);
    }
  }
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

  llvm::MCDisassembler &DisAsm = std::get<0>(dis);
  {
    std::vector<uint8_t> InsnBytes;
    InsnBytes.resize(sizeof(word));
    memcpy(&InsnBytes[0], &word, sizeof(word));

    uint64_t InstLen;
    bool Disassembled =
        DisAsm.getInstruction(brk.Inst, InstLen, InsnBytes, 0x0, llvm::nulls());
    assert(Disassembled);
  }

  arch_put_breakpoint(&word);

  // write the word back
  _ptrace_pokedata(child, Addr, word);

  if (opts::VeryVerbose)
    llvm::errs() << (fmt("breakpoint placed @ %#lx") % Addr).str() << '\n';
}

void place_breakpoint_at_return(pid_t child, uintptr_t Addr, return_t &r) {
  // read a word of the instruction
  unsigned long word = _ptrace_peekdata(child, Addr);

  arch_put_breakpoint(&word);

#if defined(__mips64) || defined(__mips__)
  {
    /* key is the encoding of INDIRECT BRANCH ; DELAY SLOT INSTRUCTION */
    assert(r.InsnBytes.size() == sizeof(uint64_t));
    uint64_t key = *((uint64_t *)r.InsnBytes.data());

    auto it = TrampolineMap.find(key);
    if (it == TrampolineMap.end()) {
      assert(ExecutableRegionAddress);

      uint64_t val = key;
      if (sizeof(long) == sizeof(val)) { /* we can do it with one poke */
        _ptrace_pokedata(child, ExecutableRegionAddress, val);
      } else if (sizeof(long) == sizeof(uint32_t)) { /* two pokes will suffice */
        uint32_t val0 = ((uint32_t *)&val)[0];
        uint32_t val1 = ((uint32_t *)&val)[1];

        _ptrace_pokedata(child, ExecutableRegionAddress, val0);
        _ptrace_pokedata(child, ExecutableRegionAddress + 4, val1);
      } else {
        __builtin_trap();
        __builtin_unreachable();
      }

      TrampolineMap.insert({key, ExecutableRegionAddress});

      ExecutableRegionAddress += sizeof(key);
      ExecutableRegionUsed += sizeof(key);

#define EXECUTABLE_REGION_SIZE (4096 * 16)

      if (opts::VeryVerbose)
        WithColor::note() << llvm::formatv(
            "executable region in tracee has {0} bytes left (used {1} bytes)\n",
            EXECUTABLE_REGION_SIZE - ExecutableRegionUsed,
            ExecutableRegionUsed);
    }
  }
#endif

  // write the word back
  _ptrace_pokedata(child, Addr, word);

  if (opts::VeryVerbose)
    llvm::errs() << (fmt("breakpoint placed @ %#lx") % Addr).str() << '\n';
}

static std::string description_of_program_counter(uintptr_t);

static void on_return(pid_t child, uintptr_t AddrOfRet, uintptr_t RetAddr,
                      tiny_code_generator_t &, disas_t &);

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
#elif defined(__mips64) || defined(__mips__)
      gpr.regs[34]
#else
#error
#endif
      ;

  //
  // rewind before the breakpoint instruction (why is this x86-specific?)
  //
#if defined(__x86_64__) || defined(__i386__)
  pc -= 1; /* int3 */
#endif

  //
  // lookup indirect branch info
  //
  const uintptr_t saved_pc = pc;

  //
  // helper function to emulate the semantics of a return instruction
  //
  auto emulate_return = [&](llvm::MCInst &Inst,
                            const std::vector<uint8_t> &InsnBytes) -> void {
#if defined(__x86_64__)
    pc = _ptrace_peekdata(child, gpr.rsp);
    gpr.rsp += sizeof(uint64_t);
#elif defined(__i386__)
    pc = _ptrace_peekdata(child, gpr.esp);
    gpr.esp += sizeof(uint32_t);
#elif defined(__mips64) || defined(__mips__)
    {
      assert(InsnBytes.size() == sizeof(uint64_t));
      uint64_t key = *((uint64_t *)InsnBytes.data());

      auto it = TrampolineMap.find(key);
      if (it == TrampolineMap.end()) {
        WithColor::error() << llvm::formatv(
            "no trampoline for breakpoint @ {0:x}\n", saved_pc);

        throw std::runtime_error(
            (fmt("no trampoline for breakpoint @ %#lx\n") % saved_pc).str());
      } else {
        pc = (*it).second;
      }
    }
#else
#error
#endif

#if defined(__x86_64__) || defined(__i386__)
    if (Inst.getNumOperands() > 0) {
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isImm());

#if defined(__x86_64__)
      gpr.rsp += Inst.getOperand(0).getImm();
#elif defined(__i386__)
      gpr.esp += Inst.getOperand(0).getImm();
#else
#error
#endif
    }
#endif
  };

  {
    if (unlikely(saved_pc == _r_debug.r_brk)) {
      //
      // we assume that this is a 'ret' TODO verify this assumption
      //
      auto it = BrkMap.find(saved_pc);
      assert(it != BrkMap.end());
      breakpoint_t &brk = (*it).second;

      brk.callback(child, tcg, dis);

      emulate_return(brk.Inst, brk.InsnBytes);
      return;
    }
  }

  {
    auto it = RetMap.find(saved_pc);
    if (it != RetMap.end()) {
      return_t &ret = (*it).second;

      emulate_return(ret.Inst, ret.InsnBytes);
      on_return(child, saved_pc, pc, tcg, dis);
      return;
    }
  }

  {
    auto it = BrkMap.find(saved_pc);
    if (it != BrkMap.end()) {
      breakpoint_t &brk = (*it).second;
      brk.callback(child, tcg, dis);

      _ptrace_pokedata(child, saved_pc, brk.word);
      return;
    }
  }

  auto indirect_branch_of_address = [](uintptr_t addr) -> indirect_branch_t & {
    auto it = IndBrMap.find(addr);
    if (it == IndBrMap.end())
      throw std::runtime_error((fmt("unknown breakpoint @ %#lx") % addr).str());

    return (*it).second;
  };

  indirect_branch_t &IndBrInfo = indirect_branch_of_address(saved_pc);
  binary_t &binary = decompilation.Binaries[IndBrInfo.binary_idx];
  auto &BBMap = BinStateVec[IndBrInfo.binary_idx].BBMap;
  auto &ICFG = binary.Analysis.ICFG;

  //
  // push program counter past instruction (on x86_64 this is necessary to make
  // EIP-relative expressions correct)
  //
  pc += IndBrInfo.InsnBytes.size();

  //
  // shorthand-functions for reading the tracee's memory and registers
  //
  basic_block_index_t bbidx;
  basic_block_t bb;

  {
    auto it = BBMap.find(IndBrInfo.TermAddr);
    assert(it != BBMap.end());

    bbidx = (*it).second - 1;
    bb = boost::vertex(bbidx, ICFG);
  }

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

#elif defined(__mips64) || defined(__mips__)

    case llvm::Mips::ZERO: return 0;
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
#if 0
        return LoadAddr(RegValue(Inst.getOperand(0).getReg()) +
                        Inst.getOperand(1).getImm() *
                            RegValue(Inst.getOperand(2).getReg()) +
                        Inst.getOperand(3).getImm());
#endif
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
  pc = target;
#else
  {
    uint64_t key = *((uint64_t *)IndBrInfo.InsnBytes.data());

    if (IndBrInfo.IsCall) {
      llvm::MCInst &Inst = IndBrInfo.Inst;

      assert(Inst.getOpcode() == llvm::Mips::JALR);
      assert(Inst.getNumOperands() == 2);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(0).getReg() == llvm::Mips::RA);
      assert(Inst.getOperand(1).isReg());

#if 0
        if (Inst.getNumOperands() != 1) {
          WithColor::error() << llvm::formatv(
              "{0}: unknown number ({1}) of operands [{2}]\n", __func__,
              Inst.getNumOperands(), StringOfMCInst(Inst, dis));
        }
#endif

      uint32_t first_insn_replacement =
          encoding_of_jump_to_reg(Inst.getOperand(1).getReg());

      ((uint32_t *)&key)[0] = first_insn_replacement;
    }

    auto it = TrampolineMap.find(key);
    if (it == TrampolineMap.end()) {
      WithColor::error() << llvm::formatv(
          "no trampoline for breakpoint @ {0:x}\n", saved_pc);

      throw std::runtime_error(
          (fmt("no trampoline for breakpoint @ %#lx\n") % saved_pc).str());
    } else {
      pc = (*it).second;
    }
  }
#endif

  if (opts::VeryVerbose)
    llvm::errs() << llvm::formatv("{0}: target={1:x} {2} [{3}]"
#if defined(__mips64) || defined(__mips__)
                                  " ; {4} [{5}]"
#endif
                                  "\n",

                                  __func__,
                                  target,
                                  Inst,
                                  StringOfMCInst(Inst, dis),
#if defined(__mips64) || defined(__mips__)
                                  IndBrInfo.___mips.DelaySlotInst,
                                  StringOfMCInst(IndBrInfo.___mips.DelaySlotInst, dis),
#endif
                                  0 /* XXX unused */
                                  );

  if (opts::VeryVerbose && ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL) {
#if defined(__mips64) || defined(__mips__)
    auto ra = gpr.regs[31];

    auto it = AddressSpace.find(ra);
    if (it == AddressSpace.end()) {
      WithColor::warning() << llvm::formatv("{0}: unknown binary for ra {1}\n",
                                            __func__,
                                            description_of_program_counter(ra));
      return;
    }

    binary_index_t binary_idx = *(*it).second.begin();

    llvm::errs() << llvm::formatv("{0}: return address is {1:x}\n",
                                  __func__,
                                  rva_of_va(ra, binary_idx));
#endif
  }

  //
  // update the decompilation based on the target
  //
  binary_index_t binary_idx = invalid_binary_index;
  {
    auto it = AddressSpace.find(target);
    if (it == AddressSpace.end()) {
      update_view_of_virtual_memory(child);

      WithColor::warning() << llvm::formatv("{0} -> {1} (unknown binary)\n",
                                            description_of_program_counter(saved_pc),
                                            description_of_program_counter(target));
      return;
    }

    binary_idx = *(*it).second.begin();
  }

  bool isNewTarget = false;

  const char *print_prefix = "(call) ";

  unsigned brkpt_count = 0;

  if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL) {
    function_index_t f_idx =
        translate_function(child, binary_idx, tcg, dis,
                           rva_of_va(target, binary_idx), brkpt_count);

    isNewTarget = ICFG[bb].DynTargets.insert({binary_idx, f_idx}).second;
  } else if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP) {
    // on an indirect jump, we must determine one of two possibilities.
    //
    // (1) transfers control to a label (i.e. a goto or switch-case statement)
    //
    // or
    //
    // (2) transfers control to a function (i.e. calling a function pointer)
    //
    bool isTailCall =
        boost::out_degree(bb, ICFG) == 0 &&
        (IndBrInfo.binary_idx != binary_idx ||
         BinStateVec[binary_idx].FuncMap.find(rva_of_va(target, binary_idx)) !=
             BinStateVec[binary_idx].FuncMap.end());

    if (isTailCall) {
      function_index_t f_idx =
          translate_function(child, binary_idx, tcg, dis,
                             rva_of_va(target, binary_idx), brkpt_count);

      //
      // the block containing the terminator may have been split underneath us
      //
      {
        auto it = BBMap.find(IndBrInfo.TermAddr);
        assert(it != BBMap.end());

        bbidx = (*it).second - 1;
        bb = boost::vertex(bbidx, ICFG);
      }

      isNewTarget = ICFG[bb].DynTargets.insert({binary_idx, f_idx}).second;
    } else {
      basic_block_index_t target_bb_idx =
          translate_basic_block(child, binary_idx, tcg, dis,
                                rva_of_va(target, binary_idx), brkpt_count);
      basic_block_t target_bb = boost::vertex(target_bb_idx, ICFG);

      //
      // the block containing the terminator may have been split underneath us
      //
      {
        auto it = BBMap.find(IndBrInfo.TermAddr);
        assert(it != BBMap.end());

        bbidx = (*it).second - 1;
        bb = boost::vertex(bbidx, ICFG);
      }

      assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

      isNewTarget = boost::add_edge(bb, target_bb, ICFG).second;
      if (isNewTarget)
        ICFG[bb].InvalidateAnalysis();

      print_prefix = "(goto) ";
    }
  } else {
    abort();
  }

  if (brkpt_count > 0) {
    binary_t &binary = decompilation.Binaries[binary_idx];
    llvm::errs() << "placed " << brkpt_count << " breakpoints in "
                 << binary.Path << '\n';
  }

  if (!opts::Quiet || isNewTarget)
    llvm::errs() << print_prefix
                 << description_of_program_counter(saved_pc) << " -> "
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

//
// TODO refactor the following code
//

static void harvest_irelative_reloc_targets(pid_t child,
                                            tiny_code_generator_t &tcg,
                                            disas_t &dis) {
  for (binary_index_t BIdx = 0; BIdx < decompilation.Binaries.size(); ++BIdx) {
    auto &Binary = decompilation.Binaries[BIdx];

    if (!BinFoundVec[BIdx]) {
#if 0
      WithColor::warning() << __func__ << ": skipping " << Binary.Path << '\n';
#endif
      continue;
    }

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
      if (opts::Verbose)
        WithColor::error() << llvm::formatv(
            "{0}: failed to create binary from {1}\n", __func__, Binary.Path);
      continue;
    }

    std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

    assert(llvm::isa<ELFO>(Bin.get()));
    ELFO &O = *llvm::cast<ELFO>(Bin.get());
    const ELFF &E = *O.getELFFile();

    typedef typename ELFF::Elf_Phdr Elf_Phdr;
    typedef typename ELFF::Elf_Dyn Elf_Dyn;
    typedef typename ELFF::Elf_Dyn_Range Elf_Dyn_Range;
    typedef typename ELFF::Elf_Sym_Range Elf_Sym_Range;
    typedef typename ELFF::Elf_Shdr Elf_Shdr;
    typedef typename ELFF::Elf_Sym Elf_Sym;
    typedef typename ELFF::Elf_Rel Elf_Rel;
    typedef typename ELFF::Elf_Rela Elf_Rela;

    auto process_elf_rela = [&](const Elf_Shdr &Sec,
                                const Elf_Rela &R) -> void {
      constexpr unsigned long irelative_reloc_ty =
#if defined(__x86_64__)
          llvm::ELF::R_X86_64_IRELATIVE
#elif defined(__i386__)
          llvm::ELF::R_386_IRELATIVE
#elif defined(__aarch64__)
          llvm::ELF::R_AARCH64_IRELATIVE
#elif defined(__mips64) || defined(__mips__)
          std::numeric_limits<unsigned long>::max()
#else
#error
#endif
          ;

      unsigned reloc_ty = R.getType(E.isMips64EL());
      if (reloc_ty != irelative_reloc_ty)
        return;

      struct {
        uintptr_t Addr;

        binary_index_t BIdx;
        function_index_t FIdx;
      } Resolved;

      try {
        Resolved.Addr = _ptrace_peekdata(child, va_of_rva(R.r_offset, BIdx));
      } catch (const std::exception &e) {
        if (opts::Verbose)
          WithColor::warning()
              << llvm::formatv("{0}: exception: {1}\n",
                               "harvest_irelative_reloc_targets", e.what());
        return;
      }

      auto it = AddressSpace.find(Resolved.Addr);
      if (it == AddressSpace.end()) {
        if (opts::Verbose)
          WithColor::warning()
              << llvm::formatv("{0}: unknown binary for {1}\n",
                               "harvest_irelative_reloc_targets",
                               description_of_program_counter(Resolved.Addr));
        return;
      }

      Resolved.BIdx = *(*it).second.begin();

      if (opts::Verbose)
        llvm::outs() << llvm::formatv("IFunc dyn target: {0:x}\n",
                                      rva_of_va(Resolved.Addr, Resolved.BIdx));

      unsigned brkpt_count = 0;
      Resolved.FIdx = translate_function(
          child, Resolved.BIdx, tcg, dis,
          rva_of_va(Resolved.Addr, Resolved.BIdx), brkpt_count);

      if (is_function_index_valid(Resolved.FIdx)) {
        Binary.Analysis.IFuncDynTargets[R.r_addend].insert(
            {Resolved.BIdx, Resolved.FIdx});

        Binary.Analysis.RelocDynTargets[R.r_offset].insert(
            {Resolved.BIdx, Resolved.FIdx});
      }
    };

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      if (Sec.sh_type == llvm::ELF::SHT_RELA) {
        for (const Elf_Rela &Rela : unwrapOrError(E.relas(&Sec)))
          process_elf_rela(Sec, Rela);
      } else if (Sec.sh_type == llvm::ELF::SHT_REL) {
        for (const Elf_Rel &Rel : unwrapOrError(E.rels(&Sec))) {
          Elf_Rela Rela;
          Rela.r_offset = Rel.r_offset;
          Rela.r_info = Rel.r_info;
          Rela.r_addend = 0;

          process_elf_rela(Sec, Rela);
        }
      }
    }
  }
}

static void harvest_addressof_reloc_targets(pid_t child,
                                            tiny_code_generator_t &tcg,
                                            disas_t &dis) {
  for (binary_index_t BIdx = 0; BIdx < decompilation.Binaries.size(); ++BIdx) {
    auto &Binary = decompilation.Binaries[BIdx];

    if (!BinFoundVec[BIdx]) {
#if 0
      WithColor::warning() << __func__ << ": skipping " << Binary.Path << '\n';
#endif
      continue;
    }

#if 0
    llvm::outs() << "harvesting relocation targets for " << Binary.Path << '\n';
#endif

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
      if (opts::Verbose)
        WithColor::error() << llvm::formatv(
            "{0}: failed to create binary from {1}\n", __func__, Binary.Path);
      continue;
    }

    std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

    assert(llvm::isa<ELFO>(Bin.get()));
    ELFO &O = *llvm::cast<ELFO>(Bin.get());
    const ELFF &E = *O.getELFFile();

    typedef typename ELFF::Elf_Phdr Elf_Phdr;
    typedef typename ELFF::Elf_Dyn Elf_Dyn;
    typedef typename ELFF::Elf_Dyn_Range Elf_Dyn_Range;
    typedef typename ELFF::Elf_Sym_Range Elf_Sym_Range;
    typedef typename ELFF::Elf_Shdr Elf_Shdr;
    typedef typename ELFF::Elf_Sym Elf_Sym;
    typedef typename ELFF::Elf_Rela Elf_Rela;
    typedef typename ELFF::Elf_Rel Elf_Rel;

    auto process_elf_rela = [&](const Elf_Shdr &Sec,
                                const Elf_Rela &R) -> void {
      // TODO code duplication XXX
      constexpr unsigned long jump_slot_reloc_ty =
#if defined(__x86_64__)
          llvm::ELF::R_X86_64_JUMP_SLOT
#elif defined(__i386__)
          llvm::ELF::R_386_JUMP_SLOT
#elif defined(__aarch64__)
          llvm::ELF::R_AARCH64_JUMP_SLOT
#elif defined(__mips64) || defined(__mips__)
          llvm::ELF::R_MIPS_JUMP_SLOT
#else
#error
#endif
          ;

      constexpr unsigned long glob_dat_reloc_ty =
#if defined(__x86_64__)
          llvm::ELF::R_X86_64_GLOB_DAT
#elif defined(__i386__)
          llvm::ELF::R_386_GLOB_DAT
#elif defined(__aarch64__)
          llvm::ELF::R_AARCH64_GLOB_DAT
#elif defined(__mips64) || defined(__mips__)
          llvm::ELF::R_MIPS_GLOB_DAT
#else
#error
#endif
          ;

      constexpr unsigned long abs_reloc_ty =
#if defined(__x86_64__)
          llvm::ELF::R_X86_64_64
#elif defined(__i386__)
          llvm::ELF::R_386_32
#elif defined(__aarch64__)
          llvm::ELF::R_AARCH64_ABS64
#elif defined(__mips64)
          llvm::ELF::R_MIPS_64
#elif defined(__mips__)
          llvm::ELF::R_MIPS_32
#else
#error
#endif
          ;

      unsigned reloc_ty = R.getType(E.isMips64EL());
      if (reloc_ty != jump_slot_reloc_ty &&
          reloc_ty != glob_dat_reloc_ty &&
          reloc_ty != abs_reloc_ty)
        return;

      const Elf_Shdr *SymTab = unwrapOrError(E.getSection(Sec.sh_link));
      const Elf_Sym *Sym = unwrapOrError(E.getRelocationSymbol(&R, SymTab));

      if (Sym->getType() != llvm::ELF::STT_FUNC)
        return;
      if (!Sym->isUndefined())
        return;

      llvm::StringRef StrTable =
          unwrapOrError(E.getStringTableForSymtab(*SymTab));
      std::string SymName = unwrapOrError(Sym->getName(StrTable));

      if (opts::Verbose)
        llvm::outs() << llvm::formatv("{0} SymName={1}\n", __func__, SymName);

      struct {
        uintptr_t Addr;

        binary_index_t BIdx;
        function_index_t FIdx;
      } Resolved;

      try {
        Resolved.Addr = _ptrace_peekdata(child, va_of_rva(R.r_offset, BIdx));
      } catch (const std::exception &e) {
        if (opts::Verbose)
          WithColor::warning()
              << llvm::formatv("{0}: exception: {1}\n",
                               "harvest_addressof_reloc_targets", e.what());

        return;
      }

      auto it = AddressSpace.find(Resolved.Addr);
      if (it == AddressSpace.end()) {
        if (opts::Verbose)
          WithColor::warning()
              << llvm::formatv("{0}: unknown binary for {1}\n",
                               "harvest_addressof_reloc_targets",
                               description_of_program_counter(Resolved.Addr));

        return;
      }

      Resolved.BIdx = *(*it).second.begin();

      if (Resolved.BIdx == BIdx) /* _dl_fixup... */
        return;

      unsigned brkpt_count = 0;
      Resolved.FIdx = translate_function(
          child, Resolved.BIdx, tcg, dis,
          rva_of_va(Resolved.Addr, Resolved.BIdx), brkpt_count);

      if (is_function_index_valid(Resolved.FIdx)) {
        auto &SymDynTargets = Binary.Analysis.SymDynTargets[SymName];
        auto &RelocDynTargets = Binary.Analysis.RelocDynTargets[R.r_offset];

        RelocDynTargets.insert({Resolved.BIdx, Resolved.FIdx});
        SymDynTargets.insert({Resolved.BIdx, Resolved.FIdx});
      }
    };

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      if (Sec.sh_type == llvm::ELF::SHT_RELA) {
        for (const Elf_Rela &Rela : unwrapOrError(E.relas(&Sec)))
          process_elf_rela(Sec, Rela);
      } else if (Sec.sh_type == llvm::ELF::SHT_REL) {
        for (const Elf_Rel &Rel : unwrapOrError(E.rels(&Sec))) {
          Elf_Rela Rela;
          Rela.r_offset = Rel.r_offset;
          Rela.r_info = Rel.r_info;
          Rela.r_addend = 0;

          process_elf_rela(Sec, Rela);
        }
      }
    }
  }
}

void harvest_reloc_targets(pid_t child,
                           tiny_code_generator_t &tcg,
                           disas_t &dis) {
  harvest_irelative_reloc_targets(child, tcg, dis);
  harvest_addressof_reloc_targets(child, tcg, dis);
}

static void on_binary_loaded(pid_t, disas_t &, binary_index_t,
                             const vm_properties_t &);

void search_address_space_for_binaries(pid_t child, disas_t &dis) {
  if (BinFoundVec.all())
    return; /* there is no need */

  if (unlikely(!update_view_of_virtual_memory(child))) {
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
    if (vm_prop.nm[0] != '/') {
      if (vm_prop.nm.find("[stack]") != std::string::npos)
        continue;
      if (vm_prop.nm.find("[heap]") != std::string::npos)
        continue;
      if (vm_prop.nm.find("[vsyscall]") != std::string::npos)
        continue; /* if a dynamic target is in [vsyscall], we'll know */
    }
    if (vm_prop.nm.find("libjove_dyn_preload.so") != std::string::npos)
      continue;

    // thus, if we get here, it's either a file or [vdso]
    auto it = BinPathToIdxMap.find(vm_prop.nm);
    if (it == BinPathToIdxMap.end()) {
      WithColor::warning() << llvm::formatv("what is this? \"{0}\"\n",
                                            vm_prop.nm);
    }

    if (it != BinPathToIdxMap.end() && !BinFoundVec.test((*it).second)) {
      binary_index_t BIdx = (*it).second;
      BinFoundVec.set(BIdx);

      on_binary_loaded(child, dis, BIdx, vm_prop);
    }
  }
}

static void on_dynamic_linker_loaded(pid_t child,
                                     disas_t &dis,
                                     binary_index_t BIdx,
                                     const vm_properties_t &vm_prop);

void on_binary_loaded(pid_t child,
                      disas_t &dis,
                      binary_index_t BIdx,
                      const vm_properties_t &vm_prop) {
  binary_state_t &st = BinStateVec[BIdx];

  st.dyn.LoadAddr = vm_prop.beg - vm_prop.off;
  st.dyn.LoadAddrEnd = vm_prop.end;

  llvm::errs() << (fmt("found binary %s @ [%#lx, %#lx)")
                   % vm_prop.nm
                   % st.dyn.LoadAddr
                   % st.dyn.LoadAddrEnd).str()
               << '\n';

  boost::icl::interval<uintptr_t>::type intervl =
      boost::icl::interval<uintptr_t>::right_open(vm_prop.beg, vm_prop.end);
  binary_index_set_t bin_idx_set = {BIdx};
  AddressSpace.add(std::make_pair(intervl, bin_idx_set));

  binary_t &binary = decompilation.Binaries[BIdx];

  //
  // if Prog has been loaded, set a breakpoint on the entry point of prog
  //
  if (binary.IsExecutable) {
    assert(is_function_index_valid(binary.Analysis.EntryFunction));

    basic_block_t entry_bb = boost::vertex(
        binary.Analysis.Functions[binary.Analysis.EntryFunction].Entry,
        binary.Analysis.ICFG);
    uintptr_t entry_rva = binary.Analysis.ICFG[entry_bb].Addr;
    uintptr_t Addr = va_of_rva(entry_rva, BIdx);

#if 0
    llvm::outs() << llvm::formatv("entry_rva={0:x} Addr={1:x}\n",
                                  entry_rva, Addr);
#endif

    breakpoint_t &brk = BrkMap[Addr];
    brk.callback = harvest_reloc_targets;

    place_breakpoint(child, Addr, brk, dis);
  }

  //
  // if it's the dynamic linker, we need to set a breakpoint on the address of a
  // function internal to the run-time linker, that will always be called when
  // the linker begins to map in a library or unmap it, and again when the
  // mapping change is complete.
  //
  if (binary.IsDynamicLinker)
    on_dynamic_linker_loaded(child, dis, BIdx, vm_prop);

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

    uintptr_t Addr = va_of_rva(bbprop.Term.Addr, BIdx);

    assert(IndBrMap.find(Addr) == IndBrMap.end());

    indirect_branch_t &IndBrInfo = IndBrMap[Addr];
    IndBrInfo.IsCall = bbprop.Term.Type == TERMINATOR::INDIRECT_CALL;
    IndBrInfo.binary_idx = BIdx;
    IndBrInfo.TermAddr = bbprop.Term.Addr;
    IndBrInfo.InsnBytes.resize(bbprop.Size - (bbprop.Term.Addr - bbprop.Addr));
#if defined(__mips64) || defined(__mips__)
    IndBrInfo.InsnBytes.resize(IndBrInfo.InsnBytes.size() + 4 /* delay slot */);
    assert(IndBrInfo.InsnBytes.size() == sizeof(uint64_t));
#endif

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

    {
      uint64_t InstLen;
      bool Disassembled = DisAsm.getInstruction(
          Inst, InstLen, IndBrInfo.InsnBytes, bbprop.Term.Addr,
          llvm::nulls());
      assert(Disassembled);
    }

#if defined(__mips64) || defined(__mips__)
    {
      uint64_t InstLen;
      bool Disassembled = DisAsm.getInstruction(
          IndBrInfo.___mips.DelaySlotInst, InstLen,
          llvm::ArrayRef<uint8_t>(IndBrInfo.InsnBytes).slice(4),
          bbprop.Term.Addr + 4,
          llvm::errs());
      assert(Disassembled);
    }
#endif

    place_breakpoint_at_indirect_branch(child, Addr, IndBrInfo, dis);
    ++cnt;
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
    RetInfo.binary_idx = BIdx;
    RetInfo.TermAddr = bbprop.Term.Addr;

    auto sectit = st.SectMap.find(bbprop.Term.Addr);
    assert(sectit != st.SectMap.end());
    const section_properties_t &sectprop = *(*sectit).second.begin();

    RetInfo.InsnBytes.resize(bbprop.Size - (bbprop.Term.Addr - bbprop.Addr));
#if defined(__mips64) || defined(__mips__)
    RetInfo.InsnBytes.resize(RetInfo.InsnBytes.size() + 4 /* delay slot */);
    assert(RetInfo.InsnBytes.size() == sizeof(uint64_t));
#endif
    memcpy(&RetInfo.InsnBytes[0],
           &sectprop.contents[bbprop.Term.Addr - (*sectit).first.lower()],
           RetInfo.InsnBytes.size());

    {
      uint64_t InstLen;
      bool Disassembled =
          DisAsm.getInstruction(RetInfo.Inst, InstLen, RetInfo.InsnBytes,
                                bbprop.Term.Addr, llvm::nulls());
      assert(Disassembled);
      assert(InstLen <= RetInfo.InsnBytes.size());
    }

    if (opts::VeryVerbose)
      llvm::outs() << llvm::formatv("return: {0}\n", RetInfo.Inst);

    place_breakpoint_at_return(child, Addr, RetInfo);
    ++cnt;
  }

  if (cnt > 0)
    llvm::errs() << llvm::formatv("placed {0} breakpoints in {1}\n", cnt,
                                  binary.Path);
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
                      .iov_len = sizeof(struct user_regs_struct)};

  unsigned long _request = PTRACE_GETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_GETREGSET failed : ") +
                             std::string(strerror(errno)));
#endif
}

void _ptrace_set_gpr(pid_t child, const struct user_regs_struct &in) {
#if defined(__mips64) || defined(__mips__)
  unsigned long _request = PTRACE_SETREGS;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&in.regs[0]);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_SETREGS failed : ") +
                             std::string(strerror(errno)));
#else
  struct iovec iov = {.iov_base = const_cast<struct user_regs_struct *>(&in),
                      .iov_len = sizeof(struct user_regs_struct)};

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

int ChildProc(const char *fifo_path) {
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

  std::vector<const char *> arg_vec;
  arg_vec.push_back(opts::Prog.c_str());

  for (const std::string &Arg : opts::Args)
    arg_vec.push_back(Arg.c_str());

  arg_vec.push_back(nullptr);

  std::vector<const char *> env_vec;
  for (char **env = ::environ; *env; ++env)
    env_vec.push_back(*env);
  env_vec.push_back("LD_BIND_NOW=1");

#if defined(__mips64) || defined(__mips__)
  std::string jove_dyn_preload_lib_path =
      fs::canonical(boost::dll::program_location().parent_path() /
                    "libjove_dyn_preload.so")
          .string();

  if (!fs::exists(jove_dyn_preload_lib_path)) {
    WithColor::error() << llvm::formatv(
        "could not find libjove_dyn_preload.so at {0}\n",
        jove_dyn_preload_lib_path.c_str());

    return 1;
  }

  std::string jove_dyn_preload_lib_arg =
      "LD_PRELOAD=" + jove_dyn_preload_lib_path;
  env_vec.push_back(jove_dyn_preload_lib_arg.c_str());

  std::string fifo_path_arg = std::string("JOVE_DYN_FIFO_PATH=") + fifo_path;
  env_vec.push_back(fifo_path_arg.c_str());
#endif

#if defined(__x86_64__)
  // <3 glibc
  env_vec.push_back("GLIBC_TUNABLES=glibc.cpu.hwcaps="
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

  for (const std::string &Env : opts::Envs)
    env_vec.push_back(Env.c_str());

  env_vec.push_back(nullptr);

  execve(arg_vec[0],
         const_cast<char **>(&arg_vec[0]),
         const_cast<char **>(&env_vec[0]));

  /* if we got here, execve failed */
  int err = errno;
  WithColor::error() << llvm::formatv("failed to execve (reason: {0})",
                                      strerror(err));
  return 1;
}

bool verify_arch(const obj::ObjectFile &Obj) {
  const llvm::Triple::ArchType archty =
#if defined(__x86_64__)
      llvm::Triple::ArchType::x86_64
#elif defined(__i386__)
      llvm::Triple::ArchType::x86;
#elif defined(__aarch64__)
      llvm::Triple::ArchType::aarch64
#elif defined(__mips64)
      llvm::Triple::ArchType::mips64el
#elif defined(__mips__)
      llvm::Triple::ArchType::mipsel
#else
#error
#endif
      ;

  return Obj.getArch() == archty;
}

bool update_view_of_virtual_memory(pid_t child) {
  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", static_cast<int>(child));

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

struct link_map {
  /* These first few members are part of the protocol with the debugger.
     This is the same format used in SVR4.  */

  unsigned long l_addr; /* Difference between the address in the ELF file and
                           the addresses in memory.  */
  char *l_name;         /* Absolute file name object was found in.  */
  unsigned long *l_ld;  /* Dynamic section of the shared object.  */
  struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
};

/// Represents a contiguous uniform range in the file. We cannot just create a
/// range directly because when creating one of these from the .dynamic table
/// the size, entity size and virtual address are different entries in arbitrary
/// order (DT_REL, DT_RELSZ, DT_RELENT for example).
struct DynRegionInfo {
  DynRegionInfo() = default;
  DynRegionInfo(const void *A, uint64_t S, uint64_t ES)
      : Addr(A), Size(S), EntSize(ES) {}

  /// Address in current address space.
  const void *Addr = nullptr;
  /// Size in bytes of the region.
  uint64_t Size = 0;
  /// Size of each entity in the region.
  uint64_t EntSize = 0;

  template <typename Type>
    llvm::ArrayRef<Type> getAsArrayRef() const {
    const Type *Start = reinterpret_cast<const Type *>(Addr);
    if (!Start)
      return {Start, Start};
    if (EntSize != sizeof(Type) || Size % EntSize)
      abort();
    return {Start, Start + (Size / EntSize)};
  }
};

static void add_binary(pid_t child, tiny_code_generator_t &, disas_t &,
                       const char *path);

static ssize_t _ptrace_memcpy(pid_t, void *dest, const void *src, size_t n);

static void on_rtld_breakpoint(pid_t child,
                               tiny_code_generator_t &tcg,
                               disas_t &dis) {
  struct r_debug r_dbg;

  {
    ssize_t ret = _ptrace_memcpy(child,
                                 &r_dbg,
                                 (void *)_r_debug.Addr,
                                 sizeof(struct r_debug));

    if (ret != sizeof(struct r_debug)) {
      WithColor::error() << __func__ << ": couldn't read r_debug structure\n";
      return;
    }
  }

  if (r_dbg.r_state == r_debug::RT_ADD ||
      r_dbg.r_state == r_debug::RT_DELETE)
    return;

  assert(r_dbg.r_state == r_debug::RT_CONSISTENT);

#if defined(__mips64) || defined(__mips__)
  if (!ExecutableRegionAddress) {
    if (opts::Verbose)
      WithColor::note() << "!ExecutableRegionAddress\n";
    return;
  }
#endif

  struct link_map *lmp = r_dbg.r_map;
  do {
    struct link_map lm;

    ssize_t ret = _ptrace_memcpy(child, &lm, lmp, sizeof(struct link_map));

    if (ret != sizeof(struct link_map)) {
      WithColor::error() << __func__ << ": couldn't read link_map structure\n";
      return;
    }

    std::string s = _ptrace_read_string(child,
                                        reinterpret_cast<uintptr_t>(lm.l_name));

    if (opts::Verbose)
      llvm::outs() << llvm::formatv("[link_map] l_addr={0}, l_name={1}\n",
                                    lm.l_addr, s);

    if (!s.empty() && s.front() == '/' && fs::exists(s)) {
      fs::path path = fs::canonical(s);

      auto it = BinPathToIdxMap.find(path.c_str());
      if (it == BinPathToIdxMap.end()) {
        llvm::outs() << llvm::formatv("adding \"{0}\" to decompilation\n",
                                      path.c_str());
        add_binary(child, tcg, dis, path.c_str());
      }
    }

    lmp = lm.l_next;
  } while (lmp && lmp != r_dbg.r_map);

  search_address_space_for_binaries(child, dis);
  harvest_reloc_targets(child, tcg, dis);
  // getting here implies we have already rendezvous with dynamic linker
}

static void print_command(std::vector<const char *> &arg_vec);

void add_binary(pid_t child, tiny_code_generator_t &tcg, disas_t &dis,
                const char *path) {
  char tmpdir[] = {'/', 't', 'm', 'p', '/', 'X', 'X', 'X', 'X', 'X', 'X', '\0'};

  if (!mkdtemp(tmpdir)) {
    WithColor::error() << "mkdtemp failed : " << strerror(errno) << '\n';
    return;
  }

  std::string jvfp = std::string(tmpdir) + path + ".jv";
  fs::create_directories(fs::path(jvfp).parent_path());

  //
  // run jove-add on the DSO
  //
  pid_t pid = fork();
  if (!pid) {
    std::vector<const char *> argv = {
      jove_add_path.c_str(),
      "-o", jvfp.c_str(),
      "-i", path,
      nullptr
    };

    print_command(argv);

    std::string stdoutfp = std::string(tmpdir) + path + ".txt";
    int outfd = open(stdoutfp.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
    dup2(outfd, STDOUT_FILENO);
    dup2(outfd, STDERR_FILENO);

    close(STDIN_FILENO);
    execve(argv[0], const_cast<char **>(&argv[0]), ::environ);

    int err = errno;
    throw std::runtime_error(
        (fmt("execve failed: %s\n") % strerror(err)).str());
  }

  if (int ret = await_process_completion(pid)) {
    WithColor::error() << __func__ << ": jove-add failed\n";
    return;
  }

  {
    decompilation_t new_decompilation;
    {
      std::ifstream ifs(jvfp);

      boost::archive::binary_iarchive ia(ifs);
      ia >> new_decompilation;
    }

    if (new_decompilation.Binaries.size() != 1) {
      WithColor::error() << "invalid intermediate result " << jvfp << '\n';
      return;
    }

    decompilation.Binaries.push_back(new_decompilation.Binaries.front());
    decompilation.Binaries.back().IsDynamicallyLoaded = true;
  }

  binary_index_t BIdx = decompilation.Binaries.size() - 1;

  BinFoundVec.resize(BinFoundVec.size() + 1, false);
  BinPathToIdxMap[decompilation.Binaries.back().Path] = BIdx;
  BinStateVec.resize(BinStateVec.size() + 1);

  //
  // initialize state associated with every binary
  //
  // TODO duplicated code here
  {
    binary_t &binary = decompilation.Binaries[BIdx];
    binary_state_t &st = BinStateVec[BIdx];

    // add to path -> index map
    if (binary.IsVDSO)
      BinPathToIdxMap["[vdso]"] = BIdx;
    else
      BinPathToIdxMap[binary.Path] = BIdx;

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
      if (opts::Verbose)
        WithColor::error() << llvm::formatv(
            "{0}: failed to create binary from {1}\n", __func__, binary.Path);

      boost::icl::interval<uintptr_t>::type intervl =
          boost::icl::interval<uintptr_t>::right_open(0, binary.Data.size());

      assert(st.SectMap.find(intervl) == st.SectMap.end());

      section_properties_t sectprop;
      sectprop.name = ".text";
      sectprop.contents = binary.Data;
      sectprop.w = false;
      sectprop.x = true;
      st.SectMap.add({intervl, {sectprop}});
    } else {
      std::unique_ptr<obj::Binary> &Bin = BinOrErr.get();

      if (!llvm::isa<ELFO>(Bin.get())) {
        WithColor::error() << binary.Path << " is not ELF of expected type\n";
        return;
      }

      ELFO &O = *llvm::cast<ELFO>(Bin.get());

      const ELFF &E = *O.getELFFile();

      typedef typename ELFF::Elf_Shdr Elf_Shdr;
      typedef typename ELFF::Elf_Shdr_Range Elf_Shdr_Range;

      llvm::Expected<Elf_Shdr_Range> sections = E.sections();
      if (!sections) {
        WithColor::error() << "could not get ELF sections for binary "
                           << binary.Path << '\n';
        return;
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

        sectprop.w = (Sec.sh_flags & llvm::ELF::SHF_WRITE) != 0;
        sectprop.x = (Sec.sh_flags & llvm::ELF::SHF_EXECINSTR) != 0;

        boost::icl::interval<uintptr_t>::type intervl =
            boost::icl::interval<uintptr_t>::right_open(
                Sec.sh_addr, Sec.sh_addr + Sec.sh_size);

        {
          auto it = st.SectMap.find(intervl);
          if (it != st.SectMap.end()) {
            WithColor::error() << "the following sections intersect: "
                               << (*(*it).second.begin()).name << " and "
                               << sectprop.name << '\n';
            abort();
          }
        }

        st.SectMap.add({intervl, {sectprop}});

        if (opts::VeryVerbose)
          llvm::errs() << (fmt("%-20s [0x%lx, 0x%lx)\n")
                           % std::string(sectprop.name)
                           % intervl.lower()
                           % intervl.upper()).str();
      }
    }
  }
}

void print_command(std::vector<const char *> &arg_vec) {
  for (const char *s : arg_vec) {
    if (!s)
      continue;

    llvm::outs() << s << ' ';
  }

  llvm::outs() << '\n';
}

void on_dynamic_linker_loaded(pid_t child,
                              disas_t &dis,
                              binary_index_t BIdx,
                              const vm_properties_t &vm_prop) {
  binary_t &binary = decompilation.Binaries[BIdx];

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
    WithColor::error() << llvm::formatv(
        "{0}: failed to create binary from {1}\n", __func__, binary.Path);
    return;
  }

  std::unique_ptr<obj::Binary> &BinRef = BinOrErr.get();

  std::unique_ptr<obj::Binary> &ObjectFile = BinRef;

  assert(llvm::isa<ELFO>(ObjectFile.get()));
  ELFO &O = *llvm::cast<ELFO>(ObjectFile.get());

  const ELFF &E = *O.getELFFile();

  typedef typename ELFF::Elf_Phdr Elf_Phdr;
  typedef typename ELFF::Elf_Dyn Elf_Dyn;
  typedef typename ELFF::Elf_Dyn_Range Elf_Dyn_Range;
  typedef typename ELFF::Elf_Sym_Range Elf_Sym_Range;
  typedef typename ELFF::Elf_Shdr Elf_Shdr;
  typedef typename ELFF::Elf_Sym Elf_Sym;
  typedef typename ELFF::Elf_Rela Elf_Rela;
  typedef typename ELFF::Elf_Rel Elf_Rel;

  auto checkDRI = [&E](DynRegionInfo DRI) -> DynRegionInfo {
    if (DRI.Addr < E.base() ||
        (const uint8_t *)DRI.Addr + DRI.Size > E.base() + E.getBufSize())
      abort();
    return DRI;
  };

  llvm::SmallVector<const Elf_Phdr *, 4> LoadSegments;
  DynRegionInfo DynamicTable;
  {
    auto createDRIFrom = [&E, &checkDRI](const Elf_Phdr *P,
                                         uint64_t EntSize) -> DynRegionInfo {
      return checkDRI({E.base() + P->p_offset, P->p_filesz, EntSize});
    };

    for (const Elf_Phdr &Phdr : unwrapOrError(E.program_headers())) {
      if (Phdr.p_type == llvm::ELF::PT_DYNAMIC) {
        DynamicTable = createDRIFrom(&Phdr, sizeof(Elf_Dyn));
        continue;
      }
      if (Phdr.p_type != llvm::ELF::PT_LOAD || Phdr.p_filesz == 0)
        continue;
      LoadSegments.push_back(&Phdr);
    }
  }

  assert(DynamicTable.Addr);

  DynRegionInfo DynSymRegion;
  llvm::StringRef DynSymtabName;
  llvm::StringRef DynamicStringTable;

  {
    auto createDRIFrom = [&E, &checkDRI](const Elf_Shdr *S) -> DynRegionInfo {
      return checkDRI({E.base() + S->sh_offset, S->sh_size, S->sh_entsize});
    };

    for (const Elf_Shdr &Sec : unwrapOrError(E.sections())) {
      switch (Sec.sh_type) {
      case llvm::ELF::SHT_DYNSYM:
        DynSymRegion = createDRIFrom(&Sec);
        DynSymtabName = unwrapOrError(E.getSectionName(&Sec));
        DynamicStringTable = unwrapOrError(E.getStringTableForSymtab(Sec));
        break;
      }
    }
  }

  //
  // parse dynamic table
  //
  {
    auto dynamic_table = [&DynamicTable](void) -> Elf_Dyn_Range {
      return DynamicTable.getAsArrayRef<Elf_Dyn>();
    };

    auto toMappedAddr = [&](uint64_t VAddr) -> const uint8_t * {
      const Elf_Phdr *const *I =
          std::upper_bound(LoadSegments.begin(), LoadSegments.end(), VAddr,
                           [](uint64_t VAddr, const Elf_Phdr *Phdr) {
                             return VAddr < Phdr->p_vaddr;
                           });
      if (I == LoadSegments.begin())
        abort();
      --I;
      const Elf_Phdr &Phdr = **I;
      uint64_t Delta = VAddr - Phdr.p_vaddr;
      if (Delta >= Phdr.p_filesz)
        abort();
      return E.base() + Phdr.p_offset + Delta;
    };

    const char *StringTableBegin = nullptr;
    uint64_t StringTableSize = 0;
    for (const Elf_Dyn &Dyn : dynamic_table()) {
      switch (Dyn.d_tag) {
      case llvm::ELF::DT_STRTAB:
        StringTableBegin = (const char *)toMappedAddr(Dyn.getPtr());
        break;
      case llvm::ELF::DT_STRSZ:
        StringTableSize = Dyn.getVal();
        break;
      }
    };

    if (StringTableBegin)
      DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
  }

  auto dynamic_symbols = [&DynSymRegion](void) -> Elf_Sym_Range {
    return DynSymRegion.getAsArrayRef<Elf_Sym>();
  };

  for (const Elf_Sym &Sym : dynamic_symbols()) {
    if (Sym.isUndefined())
      continue;

    llvm::StringRef SymName = unwrapOrError(Sym.getName(DynamicStringTable));
    if (SymName != "_r_debug")
      continue;

    _r_debug.Addr = va_of_rva(Sym.st_value, BIdx);
    _r_debug.Found = true;

    rendezvous_with_dynamic_linker(child, dis);
    break;
  }
}

void rendezvous_with_dynamic_linker(pid_t child, disas_t &dis) {
  if (!_r_debug.Found)
    return;

  //
  // _r_debug is the "Rendezvous structure used by the run-time dynamic linker
  // to communicate details of shared object loading to the debugger."
  //
  if (!_r_debug.r_brk) {
    struct r_debug r_dbg;

    ssize_t ret = _ptrace_memcpy(child, &r_dbg,
                                 (void *)_r_debug.Addr,
                                 sizeof(struct r_debug));

    if (ret != sizeof(struct r_debug)) {
      if (ret < 0) {
        int err = errno;
        WithColor::error() << llvm::formatv("couldn't read r_debug structure ({0})\n",
                                            strerror(err));
      } else {
        WithColor::error() << llvm::formatv("couldn't read r_debug structure [{0}]\n",
                                            ret);
      }
      return;
    }

    _r_debug.r_brk = r_dbg.r_brk;
  }

  if (_r_debug.r_brk) {
    if (BrkMap.find(_r_debug.r_brk) == BrkMap.end()) {
      try {
        breakpoint_t brk;
        brk.callback = on_rtld_breakpoint;

        place_breakpoint(child, _r_debug.r_brk, brk, dis);

        BrkMap.insert({_r_debug.r_brk, brk});
      } catch (const std::exception &e) {
        WithColor::error() << llvm::formatv(
            "{0}: couldn't place breakpoint at r_brk ({1})\n", __func__,
            _r_debug.r_brk);
      }
    }
  }
}

void on_return(pid_t child, uintptr_t AddrOfRet, uintptr_t RetAddr,
               tiny_code_generator_t &tcg, disas_t &dis) {
  //
  // examine AddrOfRet
  //
  {
    uintptr_t pc = AddrOfRet;
    binary_index_t BIdx = invalid_binary_index;
    {
      auto it = AddressSpace.find(pc);
      if (it == AddressSpace.end()) {
        update_view_of_virtual_memory(child);

        if (opts::Verbose)
          WithColor::warning()
              << llvm::formatv("{0}: unknown binary for {1}\n", __func__,
                               description_of_program_counter(pc));
      } else {
        BIdx = *(*it).second.begin();

        auto &BBMap = BinStateVec[BIdx].BBMap;

        binary_t &binary = decompilation.Binaries.at(BIdx);
        auto &ICFG = binary.Analysis.ICFG;

        uintptr_t rva = rva_of_va(pc, BIdx);

        auto it = BBMap.find(rva);
        assert(it != BBMap.end());
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
  {
    uintptr_t pc = RetAddr;
    binary_index_t BIdx = invalid_binary_index;
    {
      auto it = AddressSpace.find(pc);
      if (it == AddressSpace.end()) {
        update_view_of_virtual_memory(child);

        if (opts::Verbose)
          WithColor::warning()
              << llvm::formatv("{0}: unknown binary for {1}\n", __func__,
                               description_of_program_counter(pc));
      } else {
        BIdx = *(*it).second.begin();

        auto &BBMap = BinStateVec[BIdx].BBMap;

        binary_t &binary = decompilation.Binaries.at(BIdx);
        auto &ICFG = binary.Analysis.ICFG;

        uintptr_t rva = rva_of_va(pc, BIdx);

        unsigned brkpt_count = 0;
        basic_block_index_t next_bb_idx =
            translate_basic_block(child, BIdx, tcg, dis, rva, brkpt_count);
        assert(is_basic_block_index_valid(next_bb_idx));

        if (brkpt_count > 0)
          llvm::errs() << llvm::formatv("placed {0} breakpoints in {1}\n",
                                        brkpt_count, binary.Path);

        basic_block_t bb;

        {
          constexpr unsigned delay_slot =
#if defined(__mips64) || defined(__mips__)
              4
#else
              0
#endif
              ;

          auto it = BBMap.find(rva - delay_slot - 1);
          if (it == BBMap.end()) {
            //
            // we have no preceeding call
            //
            if (opts::Verbose)
              WithColor::warning() << llvm::formatv(
                  "{0}: could not find preceeding call @ {1:x}\n", __func__,
                  rva);
            return;
          }

          basic_block_index_t bbidx = (*it).second - 1;
          bb = boost::vertex(bbidx, ICFG);
        }

        bool isCall = ICFG[bb].Term.Type == TERMINATOR::CALL;
        bool isIndirectCall = ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL;

#if !defined(__x86_64__) && defined(__i386__)
        if (!isCall && !isIndirectCall) /* this can occur on i386 because of
                                           hack in tcg.hpp */
          return;
#endif

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
          InvalidateAllFunctionAnalyses();
      }
    }
  }
}

std::string _ptrace_read_string(pid_t child, uintptr_t Addr) {
  std::string res;

  for (;;) {
    unsigned long word = _ptrace_peekdata(child, Addr);

    char ch = *reinterpret_cast<char *>(&word);

    if (ch == '\0')
      break;

    // one character at-a-time
    res.push_back(ch);
    ++Addr;
  }

  return res;
}

std::string StringOfMCInst(llvm::MCInst &Inst, disas_t &dis) {
  const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
  llvm::MCInstPrinter &IP = std::get<2>(dis);

  std::string res;

  {
    llvm::raw_string_ostream ss(res);

    IP.printInst(&Inst, 0x0 /* XXX */, "", STI, ss);

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

std::string description_of_program_counter(uintptr_t pc) {
#if defined(__mips64) || defined(__mips__)
  if (ExecutableRegionAddress &&
      pc >= (ExecutableRegionAddress - ExecutableRegionUsed) &&
      pc < (ExecutableRegionAddress - ExecutableRegionUsed) + EXECUTABLE_REGION_SIZE) {
    uintptr_t off = pc - (ExecutableRegionAddress - ExecutableRegionUsed);
    return (fmt("[exeregion]+%#lx") % off).str();
  }
#endif

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

ssize_t _ptrace_memcpy(pid_t child, void *dest, const void *src, size_t n) {
  for (unsigned i = 0; i < n; ++i) {
    unsigned long word =
        _ptrace_peekdata(child, reinterpret_cast<uintptr_t>(src) + i);

    ((uint8_t *)dest)[i] = *((uint8_t *)&word);
  }

  return n;
}

void arch_put_breakpoint(void *code) {
#if defined(__x86_64__) || defined(__i386__)
  reinterpret_cast<uint8_t *>(code)[0] = 0xcc; /* int3 */
#elif defined(__aarch64__)
  reinterpret_cast<uint32_t *>(code)[0] = 0xd4200000; /* brk */
#elif defined(__mips64) || defined(__mips__)
  reinterpret_cast<uint32_t *>(code)[0] = 0x0000000d; /* break */
#else
#error
#endif
}

bool HasVDSO(void) {
  bool res = false;

  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  fp = fopen("/proc/self/maps", "r");
  assert(fp);

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

    if (strcmp(path, "[vdso]") == 0) {
      res = true;
      break;
    }
  }

  free(line);
  fclose(fp);

  return res;
}

std::pair<void *, unsigned> GetVDSO(void) {
  struct {
    void *first;
    unsigned second;
  } res;

  res.first = nullptr;
  res.second = 0;

  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  fp = fopen("/proc/self/maps", "r");
  assert(fp);

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

    if (strcmp(path, "[vdso]") == 0) {
      res.first = (void *)min;
      res.second = max - min;
      break;
    }
  }

  free(line);
  fclose(fp);

  return std::make_pair(res.first, res.second);
}


}

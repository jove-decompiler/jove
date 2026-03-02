#pragma once
#include "tool.h"
#include "fd.h"
#include "B.h"
#include "ptrace.h"

#include <boost/container/flat_set.hpp>

namespace llvm {
class MCInst;
}

namespace jove {

namespace cl = llvm::cl;

struct tiny_code_generator_t;
struct disas_t;
struct symbolizer_t;
struct ptrace_emulator_t;
struct trapped_t;

using indirect_branch_t = trapped_t;
using return_t          = trapped_t;
using breakpoint_t      = trapped_t;

struct binary_state_t {
  bool Skip = false;

  taddr_t LoadAddr = std::numeric_limits<taddr_t>::max();
  taddr_t LoadOffset = std::numeric_limits<taddr_t>::max();

  bool Loaded(void) const {
    return LoadAddr != std::numeric_limits<taddr_t>::max() &&
           LoadOffset != std::numeric_limits<taddr_t>::max();
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

struct child_syscall_state_t {
  unsigned no = ~0u;
  unsigned dir : 1;

  union {
    struct {
      uint64_t args[6];
      uint64_t pc;
    } _64;

    struct {
      uint32_t args[6];
      uint32_t pc;
    } _32;
  };

  child_syscall_state_t() : dir(0) {}
};

struct proc_map_t {
  uint64_t beg = ~0ul;
  uint64_t end = ~0ul;
  uint64_t off = ~0ul;

  bool r, w, x; /* unix permissions */
  bool p;       /* private memory? (i.e. not shared) */

  std::string nm;

  bool operator==(const proc_map_t &pm) const {
    return beg == pm.beg && end == pm.end;
  }

  bool operator<(const proc_map_t &pm) const { return beg < pm.beg; }
};

enum PTraceStop {
  Unknown,
  Event,
  Group,
  SignalDelivery,
  SyscallEnter,
  SyscallExit
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

  bool Engaged = false;

  const bool IsCOFF;
  unordered_set<pid_t> forked;
  unordered_set<pid_t> exited;

  std::unique_ptr<ptrace_emulator_t> emulator;

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

  struct {
#if 0
    std::set<pid_t> set;
#endif
    unordered_map<pid_t, bool> is_target_map;
    unordered_map<pid_t, scoped_fd> mem_fdmap;
  } children;

  unordered_map<taddr_t, trapped_t> trapmap;

  struct {
    bool Found = false;

    taddr_t ptr = 0;
    taddr_t brk = 0;

    void Reset(void) {
      Found = false;

      ptr = 0;
      brk = 0;
    }
  } _r_debug;

  unordered_map<pid_t, child_syscall_state_t> children_syscall_state_map;

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

  void Reset(void);

public:
  BootstrapTool()
      : opts(JoveCategory),
        IsCOFF(B::is_coff(state.for_binary(jv.Binaries.at(0)).Bin.get())) {}
  ~BootstrapTool();

  int Run(void) override;

  int TracerLoop(pid_t child);

  template <bool Compat>
  enum PTraceStop on_syscall_enter_or_exit(pid_t);

  bool handle_breakpoint(void);

  bool is_child_target(pid_t);
  bool is_child_compat(pid_t);

  // breakpoints aren't placed until on_binary_loaded()

  template <bool ValidatePath>
  binary_index_t BinaryFromPath(pid_t, const char *path);
  binary_index_t BinaryFromData(pid_t, std::string_view data,
                                const char *name = nullptr);

  void on_new_basic_block(binary_t &, bbprop_t &, basic_block_index_t);
  void on_new_function(binary_t &, function_t &);

  void place_breakpoint_at_indirect_branch(pid_t, taddr_t pc,
                                           indirect_branch_t &);

  void place_breakpoint_at_return(pid_t child, taddr_t pc, return_t &Ret);

  void on_binary_loaded(pid_t, binary_index_t, const proc_map_t &);

  void on_dynamic_linker_loaded(pid_t, binary_index_t, const proc_map_t &);

  trapped_t &place_breakpoints_in_block(binary_t &, bbprop_t &, basic_block_index_t);
  void place_breakpoint(pid_t, taddr_t Addr, breakpoint_t &);
  void on_breakpoint(pid_t, ptrace::target_tracee_state_t &);
  void on_return(pid_t child,
                 binary_index_t RetBIdx,
                 taddr_t AddrOfRet,
                 taddr_t RetAddr);

  void rendezvous_with_dynamic_linker(pid_t);
  void scan_rtld_link_map(pid_t);

  bool UpdateVM(pid_t);
  void ScanAddressSpace(pid_t child, bool VMUpdate = true);

  taddr_t pc_of_offset(taddr_t off, binary_index_t BIdx);
  taddr_t pc_of_va(taddr_t Addr, binary_index_t BIdx);
  taddr_t va_of_pc(taddr_t Addr, binary_index_t BIdx);

  binary_index_t binary_at_program_counter(pid_t, taddr_t valid_pc);
  block_t
  block_at_program_counter(pid_t, taddr_t valid_pc);
  std::pair<binary_index_t, function_index_t>
  function_at_program_counter(pid_t, taddr_t valid_pc);

  std::pair<binary_index_t, basic_block_index_t>
  existing_block_at_program_counter(pid_t child, taddr_t pc);

  std::string description_of_program_counter(taddr_t,
                                             bool Verbose = false,
                                             bool Symbolize = true);
  std::string StringOfMCInst(llvm::MCInst &);

  pid_t saved_child = -1;
  std::atomic<bool> ToggleTurbo = false;

  static_assert(sizeof(binary_index_t) + sizeof(basic_block_index_t) == 8);

  bool DidAttach(void) {
    return opts.PID != 0;
  }

  void DropPrivileges(void);

  scoped_fd &mem_for_child(void);

  template <bool Throw = true>
  ssize_t peek(const taddr_t src,
               uint8_t *const dst,
               const size_t len);

  template <bool Throw = true>
  ssize_t poke(const taddr_t dst, const uint8_t *src, const size_t len);
};

}

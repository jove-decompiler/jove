#pragma once
#include "tool.h"
#include "fd.h"
#include "B.h"
#include "ptrace.h"
#include "tcg.h"
#include "kernel.h"
#include "procmap_query.h"

#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/DebugInfo/DWARF/DWARFCompileUnit.h>

#include <boost/container/flat_set.hpp>

namespace llvm {
class MCInst;
}

namespace jove {

namespace cl = llvm::cl;

struct disas_t;
struct symbolizer_t;
struct ptrace_emulator_t;
struct trapped_t;

using indirect_branch_t = trapped_t;
using return_t          = trapped_t;
using breakpoint_t      = trapped_t;


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

struct BootstrapTool : public JVTool<ToolKind::Standard> {
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
    cl::opt<bool> PrintSyscalls;
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
    cl::opt<std::string> ShowMeOnExec;
    cl::list<unsigned> NoShow;
    cl::opt<bool> Symbolize;
    cl::opt<bool> Addr2Line;
    cl::opt<std::string> Group;
    cl::alias GroupAlias;
    cl::opt<std::string> User;
    cl::alias UserAlias;
    cl::list<std::string> SkipBins;
    cl::opt<bool> TrapDirectCalls;
    cl::alias TrapDirectCallsAlias;

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

          PrintSyscalls("print-syscalls", cl::desc("Always print system calls"),
                        cl::cat(JoveCategory)),

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

          ShowMeOnExec("show-me-exec",
                       cl::desc("Control whether to print when code is "
                                "recovered, following at least a single exec "
                                "(after the initial one)."),
                       cl::value_desc("(n)ever|(a)lways|(s)ometimes"),
                       cl::init(""), cl::cat(JoveCategory)),

          NoShow("no-show",
                 cl::desc("Specify a subset of binaries to never show code "
                          "recovered in"),
                 cl::value_desc("idx_0,idx_1,...,idx_n"), cl::CommaSeparated,
                 cl::cat(JoveCategory)),

          Symbolize("symbolize", cl::desc("Whether to run addr2line"),
                    cl::cat(JoveCategory)),

          Group("group", cl::desc("Run as given group"), cl::cat(JoveCategory)),

          GroupAlias("g", cl::desc("Alias for --group"), cl::aliasopt(Group),
                     cl::cat(JoveCategory)),

          User("user", cl::desc("Run as given user"), cl::cat(JoveCategory)),

          UserAlias("u", cl::desc("Alias for --user"), cl::aliasopt(User),
                    cl::cat(JoveCategory)),

          SkipBins("skip-binaries", cl::CommaSeparated, cl::value_desc("name"),
                   cl::cat(JoveCategory)),

          TrapDirectCalls("direct-calls", cl::desc("Trap direct calls"),
                          cl::cat(JoveCategory)),

          TrapDirectCallsAlias("dc", cl::desc("Alias for --direct-calls."),
                               cl::aliasopt(TrapDirectCalls),
                               cl::cat(JoveCategory))
          {}
  } opts;

  template <typename Key, typename Value>
  using unordered_map = boost::unordered::unordered_flat_map<Key, Value>;

  template <typename Key, typename Value>
  using unordered_stable_map = boost::unordered::unordered_node_map<Key, Value>;

  template <typename T>
  using unordered_set = boost::unordered::unordered_flat_set<T>;

  struct section_extra_t {
    bool Loaded = false;
  };

  struct binary_state_t {
    bool Skip = false;

    taddr_t LoadAddr = std::numeric_limits<taddr_t>::max();
    std::atomic<unsigned> NumSectionsLoaded = 0;

    B::addr_pair bounds;
    B::cached::type<section_extra_t> cb;
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

      std::unique_ptr<llvm::DWARFContext> upDwarfCtx;
    } _elf;

    const B::unique_ptr &Bin(void) const { return cb.first; }
    B::unique_ptr &Bin(void) { return cb.first; }

    const B::sections_t<section_extra_t> &sections(void) const { return cb.second; }
    B::sections_t<section_extra_t> &sections(void) { return cb.second; }

    void Reset(void) {
      this->LoadAddr = std::numeric_limits<taddr_t>::max();
      this->NumSectionsLoaded.store(0, std::memory_order_relaxed);
      for (auto &section : this->sections().svec)
        section.extra.Loaded = false;
    }

    bool HasLoadAddr(void) const {
      return this->LoadAddr != std::numeric_limits<taddr_t>::max();
    }

    bool Loaded(void) const {
      return this->HasLoadAddr() &&
             this->NumSectionsLoaded.load(std::memory_order_relaxed) == this->sections().svec.size();
    }

    binary_state_t(const binary_t &b) {
      //
      // for the purposes of mapping addresses to file offsets, the segments
      // provide a quicker determination (but ignoring the sections can lead to
      // less-meaningful resolution of debug information).
      //
      const bool segments = true; /* FIXME */

      cb.first = B::Create(b.data());
      B::_coff(cb.first.get(), [&](COFFO &O) { coff::sections(O, cb.second.svec); });
      B::_elf(cb.first.get(),  [&](ELFO &O)  { elf::segments(O, cb.second.svec); });
      B::cached::from_svec(cb.second, cb.second.svec);
      bounds = B::cached::bounds_of_binary(cb);

      B::_elf(Bin().get(), [&](ELFO &Obj) {
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

      bool Result = true;
      auto NoOpErrorHandler = [&](llvm::Error E) {
        Result = false;
        llvm::consumeError(std::move(E));
      };

      _elf.upDwarfCtx = llvm::DWARFContext::create(
          Obj, llvm::DWARFContext::ProcessDebugRelocations::Ignore, nullptr, "",
          NoOpErrorHandler, NoOpErrorHandler);
#if 0
        DwarfCtx.setParseCUTUIndexManually(true);
#endif
      });
    }
  };

  struct basic_block_state_t {
    taddr_t RepresentativeAddress = invalid_taddr;

    basic_block_state_t(const binary_t &b, bb_t bb, const binary_state_t &x) {
      B::_elf(x.Bin().get(), [&](ELFO &Obj) {
        const bbprop_t &bbprop = b.Analysis.ICFG[bb];

        const auto Addr = bbprop.Addr();
        const auto Size = bbprop.Size;
        const auto End = Addr + Size;
        const auto TermType = bbprop.Term.Type;
        const auto TermAddr = bbprop.Term.Addr;

        if (true /*FIXME*/ /* b.Analysis.IsFunctionEntrypoint(bb) */) {
          this->RepresentativeAddress = Addr;
          return;
        }

        //
        // using heuristics, determine the program counter in this block which
        // is optimal (criteria being, "meaningful")
        //
        llvm::DWARFContext &DwarfCtx = *x._elf.upDwarfCtx;
        auto *const CU = DwarfCtx.getCompileUnitForAddress(Addr);
        if (!CU)
          return;

        auto *const LT = DwarfCtx.getLineTableForUnit(CU);
        if (!LT)
          return;

        llvm::object::SectionedAddress TheSectionedAddress;

        const auto &svec = x.cb.second.svec;
        const auto &amap = x.cb.second.amap;
        auto ait = intvl_map_find(amap, Addr);
        if (ait == amap.end()) {
          TheSectionedAddress = {Addr,
                                 llvm::object::SectionedAddress::UndefSection};
        } else {
          const unsigned idx = (*ait).second;
          auto &section = svec[idx];
          TheSectionedAddress = {Addr - section.addr(), idx};
        }

        std::vector<uint32_t> Indices;
        if (!LT->lookupAddressRange(TheSectionedAddress, Size, Indices))
          return;

        auto RowVA = [&](const llvm::DWARFDebugLine::Row &Row) -> taddr_t {
          const auto &SA = Row.Address;
          if (SA.SectionIndex == llvm::object::SectionedAddress::UndefSection)
            return SA.Address;

          assert(SA.SectionIndex < svec.size());
          return svec.at(SA.SectionIndex).addr() + SA.Address;
        };

        std::stable_sort(Indices.begin(),
                         Indices.end(),
                         [&](uint32_t L, uint32_t R) {
                           return RowVA(LT->Rows[L]) < RowVA(LT->Rows[R]);
                         }); /* by address */

        auto InBlock = [&](const llvm::DWARFDebugLine::Row &Row) {
          const auto RowAddr = RowVA(Row);
          return !Row.EndSequence && Addr <= RowAddr && RowAddr < End;
        };

        std::optional<taddr_t> MaybeFirstStmt;
        std::optional<taddr_t> MaybeLastStmtBeforeTerm;
        std::optional<taddr_t> MaybeLastStmtBeforeEpilogue;
        std::optional<taddr_t> MaybeEntryBasicBlock;
        std::optional<taddr_t> MaybePrologueEnd;
        std::optional<taddr_t> MaybeEpilogueBegin;

        const auto EpilogueIt =
            std::find_if(Indices.begin(),
                         Indices.end(), [&](uint32_t Index) {
              const auto &Row = LT->Rows[Index];
              return Row.EpilogueBegin && InBlock(Row);
            });

        if (EpilogueIt != Indices.end())
          MaybeEpilogueBegin = RowVA(LT->Rows[*EpilogueIt]);

        for (uint32_t Index : Indices) {
          const auto &Row = LT->Rows[Index];
          if (!InBlock(Row))
            continue;

          const auto RowAddr = RowVA(Row);

          // A boundary marker can be useful even when Row.Line == 0.
          if (Row.PrologueEnd && !MaybePrologueEnd)
            MaybePrologueEnd = RowAddr;

          if (Row.Line == 0 || !LT->hasFileAtIndex(Row.File))
            continue;

          if (Row.BasicBlock && RowAddr == Addr)
            MaybeEntryBasicBlock = RowAddr;

          if (!Row.IsStmt)
            continue;

          if (!MaybeFirstStmt)
            MaybeFirstStmt = RowAddr;
          if (RowAddr <= TermAddr)
            MaybeLastStmtBeforeTerm = RowAddr;
          if (RowAddr < MaybeEpilogueBegin.value_or(End))
            MaybeLastStmtBeforeEpilogue = RowAddr;
        }

        //
        // The effective row at the terminator can precede the terminator,
        // or even precede this block's first instruction.
        //
        const auto terminator_has_line = [&] {
          const auto it = std::find_if(
              Indices.rbegin(),
              Indices.rend(), [&](uint32_t Index) {
                return RowVA(LT->Rows[Index]) <= TermAddr;
              });

          if (it == Indices.rend())
            return false;

          const auto &Row = LT->Rows[*it];

          return !Row.EndSequence &&
                 Row.Line != 0 &&
                 LT->hasFileAtIndex(Row.File);
        };

        auto TheRepresentativeAddress = [&](taddr_t TheAddr) -> void {
          assert(Addr <= TheAddr && TheAddr < End);
          assert(TheAddr - Addr < UINT32_MAX);
          this->RepresentativeAddress = TheAddr;
        };

        switch (TermType) {
        case TERMINATOR::INDIRECT_JUMP:
          if (IsDefinitelyTailCall(b.Analysis.ICFG, bb)) {
            TheRepresentativeAddress(TermAddr);
            break;
          }
          [[fallthrough]];

        case TERMINATOR::CONDITIONAL_JUMP:
          if (terminator_has_line())
            TheRepresentativeAddress(TermAddr);
          else if (MaybeLastStmtBeforeTerm)
            TheRepresentativeAddress(*MaybeLastStmtBeforeTerm);
          else if (MaybePrologueEnd)
            TheRepresentativeAddress(*MaybePrologueEnd);
          else
            TheRepresentativeAddress(Addr);
          break;

        case TERMINATOR::CALL:
        case TERMINATOR::INDIRECT_CALL:
          TheRepresentativeAddress(TermAddr);
          break;

        case TERMINATOR::RETURN:
          TheRepresentativeAddress(MaybeLastStmtBeforeEpilogue.value_or(Addr));
          break;

        case TERMINATOR::UNCONDITIONAL_JUMP:
        case TERMINATOR::UNREACHABLE:
        case TERMINATOR::NONE:
        case TERMINATOR::UNKNOWN:
          if (MaybePrologueEnd)
            TheRepresentativeAddress(*MaybePrologueEnd);
          else if (MaybeEntryBasicBlock)
            TheRepresentativeAddress(*MaybeEntryBasicBlock);
          else if (MaybeFirstStmt)
            TheRepresentativeAddress(*MaybeFirstStmt);
          else
            TheRepresentativeAddress(Addr);
          break;
        }
      });
    };
  };

  jv_state_t<binary_state_t, void, basic_block_state_t, IsToolMT, IsToolMinSize,
             StateOpt::LazyInitialization | StateOpt::SubjectToChange,
             StateOpt::LazyInitialization | StateOpt::SubjectToChange | StateOpt::Spin>
      state;

  bool Engaged = false;

  const bool IsCOFF;
  const bool has_ProcMapQuery;

  unordered_set<pid_t> forked;
#if 0
  unordered_set<pid_t> ignore_sigchld;
  unordered_set<pid_t> ignore_sigstop;
#endif
  unordered_set<pid_t> exited;

  std::unique_ptr<ptrace_emulator_t> emulator;

  std::unique_ptr<tcg_t<>> tcg;
  std::unique_ptr<disas_t> disas;
  std::unique_ptr<symbolizer_t> symbolizer;
  std::unique_ptr<explorer_t<IsToolMT, IsToolMinSize>> E;

  std::vector<struct proc_map_t> cached_proc_maps;

  typedef boost::container::flat_map<addr_intvl, unsigned, addr_intvl_cmp>
      pmm_t;

  pmm_t pmm;

  unordered_set<binary_index_t> Loaded;
  bool AllLoaded(void) const { return Loaded.size() == jv.Binaries.size(); }

  struct SafeAddressSpace_t : public ip_base_rw_accessible_spin<IsToolMT> {
    address_space_t m;
  } SafeAddressSpace;

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
    unordered_map<pid_t, scoped_fd> maps_fdmap;
  } children;

#if 0
  boost::unordered::concurrent_flat_map<taddr_t, trapped_t> trapmap;
#else
  struct safe_trapmap_t : public ip_base_rw_accessible_spin<IsToolMT> {
    unordered_map<taddr_t, trapped_t> m;
  } safe_trapmap;
#endif

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


  struct SafeDoNotShow_t : public ip_base_rw_accessible_spin<IsToolMT> {
    boost::dynamic_bitset<unsigned long> x;
  } SafeDoNotShow;

  binary_index_t found_binary(const taddr_t vma_start,
                              const taddr_t vma_end,
                              const taddr_t off,
                              const binary_index_t);

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
        state(jv),
        IsCOFF(B::is_coff(state.for_binary(jv.Binaries.at(0)).Bin().get())),
        has_ProcMapQuery(kernel::has_ProcMapQuery()) {}

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

  void on_section_loaded(pid_t, binary_t &, auto &section);
  void on_binary_loaded(pid_t, binary_t &);

  void on_dynamic_linker_loaded(pid_t, const binary_index_t);

  void place_breakpoint_in_block(binary_t &, bbprop_t &, basic_block_index_t);

  // returns true if notrap_exception would be raised
  bool on_breakpoint(pid_t, ptrace::target_tracee_state_t &);
  void on_return(pid_t child,
                 binary_index_t RetBIdx,
                 taddr_t AddrOfRet,
                 taddr_t RetAddr);

  void rendezvous_with_dynamic_linker(pid_t);
  void scan_rtld_link_map(pid_t);

  bool UpdateVM(pid_t, std::string *pmaps = nullptr);
  void ScanAddressSpace(pid_t child, bool VMUpdate = true);

  taddr_t compute_load_address(binary_t &b,
                               binary_state_t &x,
                               const taddr_t vma_start,
                               const taddr_t off);

  taddr_t pc_of_offset(taddr_t off, const binary_index_t BIdx);
  taddr_t pc_of_va(taddr_t addr, const binary_index_t BIdx);
  taddr_t va_of_pc(taddr_t pc, const binary_index_t BIdx);

  binary_index_t binary_at_program_counter(pid_t, taddr_t valid_pc);
  block_t
  block_at_program_counter(pid_t, taddr_t valid_pc);
  std::pair<binary_index_t, function_index_t>
  function_at_program_counter(pid_t, taddr_t valid_pc);

  std::pair<binary_index_t, basic_block_index_t>
  existing_block_at_program_counter(pid_t child, taddr_t pc);

  std::string description_of_program_counter(taddr_t,
                                             bool ForceVerbose = false,
                                             bool DoNotSymbolize = false);
  std::string StringOfMCInst(llvm::MCInst &);

  bool ShouldTrapTerminator(TERMINATOR TermType) {
    if (opts.TrapDirectCalls && TermType == TERMINATOR::CALL)
      return true;

    return IsTerminatorIndirect(TermType);
  }

  pid_t saved_child = -1;
  std::atomic<bool> ToggleTurbo = false;

  static_assert(sizeof(binary_index_t) + sizeof(basic_block_index_t) == 8);

  bool DidAttach(void) {
    return opts.PID != 0;
  }

  void DropPrivileges(void);

  scoped_fd &maps_for_child(void);
  scoped_fd &mem_for_child(void);

  template <bool Throw = true>
  ssize_t peek(const taddr_t src,
               uint8_t *const dst,
               const size_t len);

  template <bool Throw = true>
  ssize_t poke(const taddr_t dst, const uint8_t *src, const size_t len);

#ifdef JOVE_BOOTSTRAP_EAGER_INVALIDATION
  void invalidate_block(bbprop_t &, binary_t &);
#endif

  [[always_inline]]
  void vvmsg(const std::string &s) {
    if (IsVeryVerbose())
      this->msg(s);
  }

  void msg(const std::string &);

  void ShowMe(const char ch) {
    ShowMeN = ch == 'n';
    ShowMeA = ch == 'a';
    ShowMeS = ch == 's';

#if 0
    WARN_ON(!ShowMeN && !ShowMeA && !ShowMeS);
#endif
  }
};
}

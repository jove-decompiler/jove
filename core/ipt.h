#pragma once
#if defined(__x86_64__) && (defined(TARGET_X86_64) || defined(TARGET_I386))
#include "B.h"
#include "augmented_raw_syscalls.h"
#include "concurrent.h"
#include "explore.h"
#include "jove/jove.h"
#include "locator.h"
#include "objdump.h"
#include "perf.h"
#include "sideband.h"
#include "misaligned.h"

#include <array>
#include <cstdio>
#include <inttypes.h>
#include <memory>
#include <type_traits>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/for_each_product.hpp>
#include <boost/preprocessor/seq/seq.hpp>
#include <boost/preprocessor/variadic/size.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <boost/unordered/unordered_flat_set.hpp>
#include <boost/unordered/unordered_node_map.hpp>

#include <intel-pt.h>
extern "C" {
#include "pevent.h"
#include "pt_last_ip.h"
#include "pt_time.h"
}

#if 1
static void hexdump(FILE *stream, const void *ptr, int buflen) {
  const unsigned char *buf = (const unsigned char *)ptr;
  int i, j;
  for (i = 0; i < buflen; i += 16) {
    fprintf(stream, "%06x: ", i);
    for (j = 0; j < 16; j++)
      if (i + j < buflen)
        fprintf(stream, "%02x ", buf[i + j]);
      else
        fprintf(stream, "   ");
    printf(" ");
    for (j = 0; j < 16; j++)
      if (i + j < buflen)
        fprintf(stream, "%c", isprint(buf[i + j]) ? buf[i + j] : '.');
    fprintf(stream, "\n");
  }
}
#endif

////////////////////////////////////////////////////////////////////////////////
#define VERY_UNIQUE_BASE 0xfffffff
#define VERY_UNIQUE_NUM() (VERY_UNIQUE_BASE + __COUNTER__)

#define ___SYSCALL(nr, nm)                                                     \
  static const unsigned nr64_##nm = nr;                                        \
  static const char *const nr64_##nm##_nm = #nm;

#include <arch/x86_64/syscalls.inc.h>
static const unsigned nr64_clone3 = VERY_UNIQUE_NUM();
static const unsigned nr64_mmap_pgoff = VERY_UNIQUE_NUM();

#define ___SYSCALL(nr, nm)                                                     \
  static const unsigned nr32_##nm = nr;                                        \
  static const char *const nr32_##nm##_nm = #nm;
#include <arch/i386/syscalls.inc.h>
static const unsigned nr32_mmap = VERY_UNIQUE_NUM();
////////////////////////////////////////////////////////////////////////////////

namespace jove {

class explorer_t;

namespace perf {
class sideband_parser;
}

struct tnt_error {};
struct infinite_loop_exception {};
struct truncated_aux_exception {};

#define IsVerbose() (Verbosity >= 1)
#define IsVeryVerbose() (Verbosity >= 2)

template <bool DoNotGoFurther, bool InfiniteLoopThrow, bool MT, unsigned Verbosity = 0>
static std::pair<basic_block_index_t, bool>
StraightLineGo(const auto &b,
               basic_block_index_t Res,
               taddr_t GoNoFurther = 0,
    std::function<basic_block_index_t(const basic_block_properties_t &, basic_block_index_t)> on_final_block = [](const basic_block_properties_t &, basic_block_index_t Res) -> basic_block_index_t { return Res; },
    std::function<void(const basic_block_properties_t &, basic_block_index_t)> on_block = [](const basic_block_properties_t &, basic_block_index_t) -> void {}) {
  const auto &ICFG = b.Analysis.ICFG;

  std::reference_wrapper<const basic_block_properties_t> the_bbprop =
      ICFG[basic_block_of_index(Res, b)];

  basic_block_index_t ResSav = Res;
  for ((void)({
         const basic_block_properties_t &bbprop = the_bbprop.get();

         if constexpr (MT) {
           if (!bbprop.pub.is.load(std::memory_order_acquire))
             bbprop_t::pub_shared_lock_guard<MT>(bbprop.pub.mtx);
         }
         bbprop.lock_sharable<MT>(); /* don't change on us */

         on_block(bbprop, Res);
         0;
       });
       ; (void)({
         the_bbprop.get().mtx.unlock_sharable();

         //
         // cycle detection: the code might infinitely loop. FIXME
         //
         // an example seen in the wild is at the end of start_thread() in
         // glibc/nptl/pthread_create.c...
         //
         // while (1)
         //   INTERNAL_SYSCALL_CALL (exit, 0);
         //
         if (unlikely(ResSav == Res)) {
           if constexpr (InfiniteLoopThrow)
             throw infinite_loop_exception();
           else
             return std::make_pair(invalid_basic_block_index, false);
         }

         ResSav = Res;

         basic_block_t newbb = basic_block_of_index(Res, b);
         const basic_block_properties_t &new_bbprop = ICFG[newbb];
         the_bbprop = new_bbprop;

         if constexpr (MT) {
           if (!new_bbprop.pub.is.load(std::memory_order_acquire))
             bbprop_t::pub_shared_lock_guard<MT>(new_bbprop.pub.mtx);
         }
         new_bbprop.lock_sharable<MT>(); /* don't change on us */

         on_block(new_bbprop, Res);
         0;
       })) {
    basic_block_t bb = basic_block_of_index(Res, b);
    const basic_block_properties_t &bbprop = the_bbprop.get();

    const auto Addr = bbprop.Addr;
    const auto Size = bbprop.Size;
    const auto TermType = bbprop.Term.Type;

    if constexpr (DoNotGoFurther) {
      if (Addr == GoNoFurther ||
          /* the following assumes that GoNoFurther sits cleanly in the block.
           * to verify this, we'd have to disassemble the instructions.
           *
           * NOTE: this happens to "resolve" a problem encountered with the
           * trace output, where an invalid IP follows a twirl. i.e., given the
           * code:
           *
           * 18d70:       f3 0f 1e fb             endbr32
           * 18d74:       e8 00 00 00 00          call   18d79
           * 18d79:       58                      pop    %eax
           * 18d7a:       05 23 b2 ff ff          add    $0xffffb223,%eax
           * 18d7f:       8b 80 38 00 00 00       mov    0x38(%eax),%eax
           *
           * we might have the following sequence:
           *
           *   on_ip(0x18d70);
           *   on_ip(0x18d76);  // <-- WTF, middle of twirl instruction
           *
           * this has been confirmed to confuse the hell out of ptxed.
           *
           **/
          unlikely(GoNoFurther >= Addr && GoNoFurther < Addr + Size)) {
        bbprop_t::shared_lock_guard<MT> s_lck_bb(
            bbprop.mtx, boost::interprocess::accept_ownership);
        return std::make_pair(
            on_final_block(bbprop, basic_block_of_index(Res, b)), true);
      }
    }

    switch (TermType) {
    default:
      break;
    case TERMINATOR::UNCONDITIONAL_JUMP:
    case TERMINATOR::NONE: {
      if (unlikely(ICFG.template out_degree<false>(bb) == 0)) {
        if constexpr (IsVerbose())
          fprintf(
              stderr, "cant proceed past NONE @ %s+%" PRIx64 " [size=%u] %s\n",
              b.Name.c_str(), static_cast<uint64_t>(Addr),
              static_cast<unsigned>(Size), description_of_terminator(TermType));
        break;
      }

      basic_block_index_t NewRes =
          index_of_basic_block(ICFG, ICFG.template adjacent_front<false>(bb));

      Res = NewRes;
      continue;
    }
    case TERMINATOR::CALL: {
      function_index_t CalleeIdx = bbprop.Term._call.Target;
      if (unlikely(!is_function_index_valid(CalleeIdx)))
        break;

      basic_block_index_t EntryBBIdx = b.Analysis.Functions.at(CalleeIdx).Entry;
      if (!unlikely(is_basic_block_index_valid(EntryBBIdx))) {
        if constexpr (IsVerbose())
          fprintf(stderr, "cant proceed past CALL @ %s+%" PRIx64 "\n",
                  b.Name.c_str(), static_cast<uint64_t>(Addr));
        break;
      }
      Res = EntryBBIdx;
      assert(is_basic_block_index_valid(Res));
      continue;
    }
    case TERMINATOR::CONDITIONAL_JUMP:
      //
      // recognize this:
      //
      // ┌─────────────────────────────────────┐
      // │                                     │ ───┐
      // │ rep  stosq qword ptr es:[rdi], rax  │    │
      // │                                     │ ◀──┘
      // └─────────────────────────────────────┘
      //
      // there are no TNT packets for this "single-instruction" loop. we just
      // need to move past it.
      //
      if (unlikely(bbprop.IsSingleInstruction())) {
        if (likely(ICFG.template out_degree<false>(bb) == 2)) {
          auto succ = ICFG.template adjacent_n<2, false>(bb);
          if (succ[0] == bb) {
            Res = index_of_basic_block(ICFG, succ[1]);
            continue;
          } else if (succ[1] == bb) {
            Res = index_of_basic_block(ICFG, succ[0]);
            continue;
          }
        }
      }
      break;
    }

    bbprop_t::shared_lock_guard<MT> s_lck_bb(
        bbprop.mtx, boost::interprocess::accept_ownership);
    return std::make_pair(on_final_block(bbprop, basic_block_of_index(Res, b)),
                          false);
  }

  abort();
}

#define IPT_PARAMETERS                                                         \
  ((unsigned, Verbosity, (0)(1)(2)))                                           \
  ((bool, Caching, (false)(true)))                                             \
  ((bool, Objdump, (false)(true)))                                             \
  ((bool, ExeOnly, (false)(true)))                                             \
  ((bool, MT, (false)(true)))

#define IPT_PARAM_DECL(r, data, i, elem)                                       \
  BOOST_PP_COMMA_IF(i)                                                         \
  BOOST_PP_TUPLE_ELEM(3, 0, elem) /* Type */                                   \
  /* space */                                                                  \
  BOOST_PP_TUPLE_ELEM(3, 1, elem) /* Name */

#define IPT_PARAMETERS_DCL                                                     \
  BOOST_PP_SEQ_FOR_EACH_I(IPT_PARAM_DECL, _, IPT_PARAMETERS)

#define IPT_PARAM_NAME(r, data, i, elem)                                       \
  BOOST_PP_COMMA_IF(i)                                                         \
  BOOST_PP_TUPLE_ELEM(3, 1, elem)

#define IPT_PARAMETERS_DEF                                                     \
  BOOST_PP_SEQ_FOR_EACH_I(IPT_PARAM_NAME, _, IPT_PARAMETERS)

template <typename Derived> struct ipt_traits {
  using packet_type = void;
};

struct end_of_trace_exception {};
struct error_decoding_exception {};

/* reference IPT decoder */
template <IPT_PARAMETERS_DCL, typename Derived> struct ipt_t {
  using packet_type = typename ipt_traits<Derived>::packet_type;


protected:
  int ptdump_argc;
  char **ptdump_argv;
  const uint8_t *const aux_begin;
  const uint8_t *const aux_end;

  jv_file_t &jv_file;
  jv_base_t<MT> &jv;
  explorer_t &explorer;

  perf::data_reader<false> &sb;
  perf::event_iterator sb_it;
  perf::sideband_parser &sb_parser;

  struct pt_config config;

  struct {
    struct pt_last_ip last_ip;
    struct pt_time_cal tcal;
    struct pt_time time;

#if 0
    uint64_t tsc = 0ull; /* The last estimated TSC. */
    uint64_t fcr = 0ull; /* The last calibration value. */
#endif

    uint32_t in_header = 0; /* Header vs. normal decode. */
  } tracking;

  static const uint64_t dummy_time;
  struct pev_event incoming_event;

  using straight_line_t = basic_block_properties_t::Analysis_t::straight_line_t;

  struct basic_block_state_t {
    straight_line_t theSL;

    basic_block_state_t(const binary_base_t<MT> &b, basic_block_t the_bb) {
      if constexpr (!Caching)
        return;

      auto &ICFG = b.Analysis.ICFG;

      const basic_block_index_t Idx = index_of_basic_block(b, the_bb);
      assert(is_basic_block_index_valid(Idx));

      auto &SL = this->theSL;

      auto on_block = [&](const basic_block_properties_t &bbprop,
                          basic_block_index_t BBIdx) -> void {
        intvl_set_add(SL.addrng, addr_intvl(bbprop.Addr, bbprop.Size));
      };

      SL.BBIdx =
          StraightLineGo<false, true, MT, Verbosity>(
              b, Idx, 0 /* unused */,
              [&](const basic_block_properties_t &bbprop,
                  basic_block_index_t BBIdx) -> basic_block_index_t {
                SL.Addr = bbprop.Addr;
                SL.TermType = bbprop.Term.Type;
                SL.TermAddr = bbprop.Term.Addr;

                {
                  icfg_t::adjacency_iterator it, it_end;
                  std::tie(it, it_end) =
                      ICFG.adjacent_vertices(basic_block_of_index(BBIdx, b));

                  unsigned N = std::distance(it, it_end);
                  if (N == 1) {
                    SL.adj.push_back(*it);
                    SL.adj.push_back(*it);
                  } else if (N == 2 &&
                             SL.TermType == TERMINATOR::CONDITIONAL_JUMP) {
                    basic_block_index_t succ0 = *it++;
                    basic_block_index_t succ1 = *it++;

                    bool Is0NotTaking =
                        ICFG[succ0].Addr == bbprop.Addr + bbprop.Size;
                    if (Is0NotTaking) {
                      SL.adj.push_back(succ0);
                      SL.adj.push_back(succ1);
                    } else {
                      SL.adj.push_back(succ1);
                      SL.adj.push_back(succ0);
                    }
                  } else {
                    ;
                  }
                }

                return BBIdx;
              },
              on_block)
              .first;

      assert(is_basic_block_index_valid(SL.BBIdx));
    }
  };

  template <bool X = Caching>
  std::enable_if_t<X, const straight_line_t &>
  SLForBlock(const binary_base_t<MT> &b, basic_block_t bb) {
    return state.for_basic_block(b, bb).theSL;
  }
  static constexpr bool Lazy = true;

  struct binary_state_t {
    std::unique_ptr<llvm::object::Binary> Bin;

    binary_state_t(const binary_base_t<MT> &b) {
      Bin = B::Create(b.data());

      if constexpr (Objdump) {
        if (b.Analysis.objdump.empty()) {
          auto e_lck = b.Analysis.objdump.exclusive_access();

          if (b.Analysis.objdump.empty_unlocked())
            binary_base_t<MT>::Analysis_t::objdump_output_type::generate(
                const_cast<binary_base_t<MT> &>(b).Analysis.objdump,
                b.is_file() ? b.Name.c_str() : nullptr, *Bin);
        }
      }
    }
  };

  using BBState = std::conditional_t<Caching, basic_block_state_t, void>;

  jv_state_t<binary_state_t, void, BBState, false, Lazy, false, true, MT> state;

  const unsigned PageSize;
  const bool IsCOFF;

  struct file_descriptor_state_t {
    std::string path;
    uint64_t pos;
  };

  struct process_state_t {
    boost::container::flat_map<addr_intvl, std::pair<binary_index_t, uint64_t>,
                               addr_intvl_cmp>
        addrspace;
    boost::container::flat_map<addr_intvl, std::pair<binary_index_t, uint64_t>,
                               addr_intvl_cmp>
        addrspace_sav;
    boost::unordered::unordered_flat_map<int, file_descriptor_state_t> fdmap;
  };

  boost::unordered::unordered_node_map<pid_t, process_state_t> pid_map;

  process_state_t dummy_process_state;
  std::reference_wrapper<process_state_t> process_state;

  static constexpr uint32_t sb_dump_flags = 1; /* compact */

  struct {
    unsigned cpu = ~0u;
    unsigned pid = ~0u;
    boost::unordered_flat_set<unsigned> pids;
  } Our;

  struct {
    unsigned pid = ~0u;
    unsigned ExecBits = 8 * sizeof(taddr_t);
  } Curr;

  binary_base_t<MT> &exe;

  class Point_t {
    std::reference_wrapper<binary_base_t<MT>> b;
    basic_block_index_t Idx = invalid_basic_block_index;

    struct {
      taddr_t Addr = uninit_taddr;
      taddr_t TermAddr = uninit_taddr;
    } Cached;

  public:
    Point_t(binary_base_t<MT> &b) : b(b) {}

    binary_base_t<MT> &Binary(void) const { return b; }
    binary_index_t BinaryIndex(void) const { return index_of_binary(b.get()); }

    basic_block_index_t BlockIndex(void) const { return Idx; }
    void SetBlockIndex(basic_block_index_t NewIdx) {
      assert(is_basic_block_index_valid(NewIdx));
      Idx = NewIdx;
    }

    basic_block_t Block(void) const {
      return basic_block_of_index(BlockIndex(), b.get());
    }

    taddr_t GetTermAddr(void) const {
      assert(is_taddr_init(Cached.TermAddr));
      return Cached.TermAddr; /* may be invalid */
    }
    void SetTermAddr(taddr_t NewTermAddr) { Cached.TermAddr = NewTermAddr; }

    void SetAddr(taddr_t Addr) {
      assert(is_taddr_valid(Addr));
      Cached.Addr = Addr;
    }
    taddr_t GetAddr(void) const {
      assert(is_taddr_init(Cached.Addr));
      assert(is_taddr_valid(Cached.Addr));
      return Cached.Addr;
    }

    bool Valid(void) const {
      return is_basic_block_index_valid(Idx) &&
#ifdef NDEBUG
             true
#else
             is_taddr_valid(Cached.Addr) && is_taddr_init(Cached.TermAddr)
#endif
          ;
    }

    void Invalidate(void) {
      Idx = invalid_basic_block_index;

#ifndef NDEBUG
      Cached.Addr = uninit_taddr;
      Cached.TermAddr = uninit_taddr;
#endif
    }

    void SetBinary(binary_base_t<MT> &newb) {
      b = newb;
#ifndef NDEBUG
      Cached.Addr = uninit_taddr;
      Cached.TermAddr = uninit_taddr;
#endif
    }
  } CurrPoint;

  struct ExeAddressRange {
    taddr_t beg, end;
  };

  std::conditional_t<ExeOnly, ExeAddressRange, std::monostate> exeOnly;

  const std::string path_to_wine_bin;
  static inline const std::string wine_env_of_interest = "WINELOADERNOEXEC=1";

  bool IsRightProcess(unsigned pid) const {
    // the following is equivalent to pid != 0UL && pid != ~0UL
    // return !!((pid + unsigned(1)) & unsigned(~1ull));
    return Our.pids.contains(pid);
  }

  bool RightProcess(void) const { return IsRightProcess(Curr.pid); }

  bool RightExecMode(void) const {
    return Curr.ExecBits == 8 * sizeof(taddr_t);
  }

  bool Engaged = false;
  bool CheckEngaged(void) {
    return (Engaged = RightExecMode() && RightProcess());
  }

  const bool ignore_trunc_aux;
  const bool gathered_bins;

  void on_mmap(uint64_t offset,
               const pid_t pid,
               const uint64_t ret,
               const uint64_t len,
               const uint64_t pgoff,
               const char *const filename,
               const char *const src) {
    namespace fs = boost::filesystem;

    auto &pstate = pid_map[pid];
    auto &AddressSpace = pstate.addrspace;

    const addr_intvl intvl(ret, len);

    const bool anon = strcmp(filename, "//anon") == 0;
    if (anon) {
      intvl_map_clear(AddressSpace, intvl);

      if constexpr (IsVeryVerbose()) {
        std::string as(addr_intvl2str(intvl));

        fprintf(stderr, "+\t%s\t\"//anon\"\t<%s>\n", as.c_str(), src);
      }
      return;
    }

    binary_index_t BIdx = invalid_binary_index;
    bool isNew = false;
    if (filename[0] == '/' && !gathered_bins) {
      if (!fs::exists(filename)) {
        if constexpr (IsVeryVerbose())
          fprintf(stderr, "%s: \"%s\" does not exist\n", src, filename);
        return;
      }

      std::tie(BIdx, isNew) = jv.AddFromPath(explorer, jv_file, filename);
    } else {
      binary_index_set BIdxSet;
      if (!jv.LookupByName(filename, BIdxSet))
        return;
      assert(!BIdxSet.empty());

      BIdx = *(BIdxSet).rbegin(); /* most recent (XXX?) */
      isNew = false;
    }
    if (!is_binary_index_valid(BIdx))
      return;

    if constexpr (IsVeryVerbose()) {
      std::string as(addr_intvl2str(intvl));

      fprintf(stderr, "+\t%s\t\"%s\"+0x%" PRIx64 "\t<%s>\n", as.c_str(),
              jv.Binaries.at(BIdx).Name.c_str(), pgoff, src);
    }

    intvl_map_clear(AddressSpace, intvl);
    intvl_map_add(AddressSpace, intvl, std::make_pair(BIdx, pgoff));
  }

  void examine_sb_event(const struct pev_event &event, uint64_t offset) {
    namespace fs = boost::filesystem;

#define unexpected_rest()                                                      \
  do {                                                                         \
    fprintf(stderr, "unexpected rest (%" PRIu32 ")\n", event.type);            \
    assert(false);                                                             \
    abort();                                                                   \
  } while (0)

    auto get_pid = [&](void) -> uint32_t {
      assert(event.sample.pid);
      return *event.sample.pid;
    };
    auto get_tid = [&](void) -> uint32_t {
      assert(event.sample.tid);
      return *event.sample.tid;
    };

    auto get_cpu = [&](void) -> unsigned {
      assert(event.sample.cpu);
      return *event.sample.cpu;
    };

    bool is_pgoff = false;

    uint64_t fd_pos = 0;

    switch (event.type) {
    case PERF_RECORD_AUX: {
      const struct pev_record_aux *aux = event.record.aux;
      assert(aux);
      auto cpu = get_cpu();
      if (aux->flags & PERF_AUX_FLAG_TRUNCATED) {
        if (cpu == Our.cpu) {
          if (!ignore_trunc_aux)
            throw truncated_aux_exception();
        }
      }
      break;
    }

    case PERF_RECORD_COMM: {
#if 0
		const struct pev_record_comm *comm = event.record.comm;
                assert(comm);
      if (event.misc & PERF_RECORD_MISC_COMM_EXEC) {
        do_comm_exec(*comm);
      CheckEngaged();
      }
#endif
      break;
    }

    case PERF_RECORD_FORK: {
      const struct pev_record_fork *fork = event.record.fork;
      assert(fork);

      auto pid = get_pid();

      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\tfork (from %u) %u/%u, %u/%u\n", offset,
                pid, fork->pid, fork->tid, fork->ppid, fork->ptid);

      if (pid == 0)
        break;

      if (!IsRightProcess(pid))
        break;

      if constexpr (IsVeryVerbose())
        fprintf(stderr, "our pid: %u\n", (unsigned)fork->pid);

      Our.pids.insert(fork->pid);
      pid_map[fork->pid] = pid_map[pid];

      break;
    }

    case PERF_RECORD_LOST_SAMPLES: {
      const struct pev_record_lost_samples *lost_samples =
          event.record.lost_samples;
      assert(lost_samples);

      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\tlost_samples %" PRIx64 "\n", offset,
                lost_samples->lost);
      break;
    }

    case PERF_RECORD_ITRACE_START: {
      const struct pev_record_itrace_start *itrace_start =
          event.record.itrace_start;
      assert(itrace_start);

      auto cpu = get_cpu();
      if (cpu == Our.cpu) {
        Curr.pid = itrace_start->pid;

        if constexpr (IsVeryVerbose())
          fprintf(stderr, "itrace switch (%u)\n", (unsigned)itrace_start->pid);

        CheckEngaged();
      }
      break;
    }

    case PERF_RECORD_EXIT: {
      const struct pev_record_exit *exit = event.record.exit;
      assert(exit);

      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\texit %u/%u, %u/%u\n", offset,
                exit->pid, exit->tid, exit->ppid, exit->ptid);

      break;
    }

    case PERF_RECORD_SWITCH_CPU_WIDE: {
      const struct pev_record_switch_cpu_wide *switch_cpu_wide =
          event.record.switch_cpu_wide;
      assert(switch_cpu_wide);
      auto pid = get_pid();
      auto cpu = get_cpu();
      if (event.misc & PERF_RECORD_MISC_SWITCH_OUT) {
        if (cpu == Our.cpu) {
          if constexpr (IsVeryVerbose())
            fprintf(stderr, "switch out\n");

          Curr.pid = ~0u;
          process_state = dummy_process_state;
          Engaged = false;
        }
      } else {
        if (cpu == Our.cpu) {
          if constexpr (IsVeryVerbose())
            fprintf(stderr, "switch (%u)\n", (unsigned)pid);

          Curr.pid = pid;
          process_state = pid_map[pid];
          CheckEngaged();
        }
      }
      break;
    }

    case PERF_RECORD_SWITCH: {
      auto pid = get_pid();
      auto cpu = get_cpu();
      if (event.misc & PERF_RECORD_MISC_SWITCH_OUT) {
        if (cpu == Our.cpu) {
          if constexpr (IsVeryVerbose())
            fprintf(stderr, "switch out\n");

          Curr.pid = ~0u;
          process_state = dummy_process_state;
          Engaged = false;
        }
      } else {
        if (cpu == Our.cpu) {
          if constexpr (IsVeryVerbose())
            fprintf(stderr, "switch (%u)\n", (unsigned)pid);

          Curr.pid = pid;
          process_state = pid_map[pid];
          CheckEngaged();
        }
      }
      break;
    }

    case PERF_RECORD_SAMPLE: {
      assert(event.name);
      assert(event.record.raw);
      assert(event.sample.ip);
      auto pid = get_pid();
      const char *const name = event.name;
      const uint64_t ip = *event.sample.ip;

      if (strcmp(name, "__jove_augmented_syscalls__") != 0) {
        unexpected_rest();
        break;
      }

      auto on_syscall = [&]<typename T>(const T *payload) -> void {
        const auto &hdr = payload->hdr;

        auto nr = hdr.syscall_nr;
        auto ret = hdr.ret;

        const auto arg0 = JOVE_MISALIGNED_LOAD(hdr.args[0]);
        const auto arg1 = JOVE_MISALIGNED_LOAD(hdr.args[1]);
        const auto arg2 = JOVE_MISALIGNED_LOAD(hdr.args[2]);
        const auto arg3 = JOVE_MISALIGNED_LOAD(hdr.args[3]);
        const auto arg4 = JOVE_MISALIGNED_LOAD(hdr.args[4]);
        const auto arg5 = JOVE_MISALIGNED_LOAD(hdr.args[5]);

#if 0
        constexpr bool Is64 = std::is_same_v<T, struct augmented_syscall_payload64>;
        using sys_uint_t = std::conditional_t<Is64, uint64_t, uint32_t>;
#endif

#define RIGHT_PROCESS_GET                                                      \
  auto &pstate = pid_map[pid];                                                 \
  auto &AddressSpace = pstate.addrspace

#define IS_RIGHT_PROCESS_GET                                                   \
  assert(~pid != 0u);                                                          \
  if (!IsRightProcess(pid))                                                    \
    break;                                                                     \
  RIGHT_PROCESS_GET
        //
        // we can assume that the syscall successfully completed (XXX except
        // exec)
        //

#define nr_for(sysnm)                                                          \
  (std::is_same_v<T, struct augmented_syscall_payload64> ? nr64_##sysnm        \
                                                         : nr32_##sysnm)
        switch (nr) {
        case nr_for(munmap): {
          IS_RIGHT_PROCESS_GET;

          auto addr = arg0;
          auto len  = arg1;

          const addr_intvl intvl(addr, len);

          if constexpr (IsVeryVerbose()) {
            std::string as(addr_intvl2str(intvl));

            fprintf(stderr, "-\t%s\t\t<munmap(2)>\n", as.c_str());
          }

          intvl_map_clear(AddressSpace, intvl);
          break;
        }

        case nr_for(mmap_pgoff):
          is_pgoff = true;
        case nr_for(mmap): {
          IS_RIGHT_PROCESS_GET;

          auto addr  = arg0;
          auto len   = arg1;
          auto prot  = arg2;
          auto flags = arg3;
          auto fd    = arg4;
          auto off   = arg5;

          (void)addr;
          (void)prot;
          (void)flags;

          if (is_pgoff)
            off *= PageSize;

          const addr_intvl intvl(ret, len);

          const char *filename = nullptr;
          const bool anon = static_cast<int>(fd) < 0;
          if (anon) {
            filename = "//anon";
          } else {
            // do we know the path?
            auto it = pstate.fdmap.find(fd);
            if (it == pstate.fdmap.end()) {
              if constexpr (IsVeryVerbose()) {
                std::string as(addr_intvl2str(intvl));

                fprintf(stderr, "+\t%s\t??%d??\t<mmap(2)>\n", as.c_str(),
                        (int)fd);
              }
              break;
            } else {
              filename = (*it).second.path.c_str();
            }
          }

          assert(filename);
          on_mmap(offset, pid, ret, len, off, filename, "mmap(2)");
          break;
        }

        case nr_for(close): {
          IS_RIGHT_PROCESS_GET;

          auto fd = arg0;

          if constexpr (IsVeryVerbose())
            fprintf(stderr, "close(%d) = %ld\n", (int)fd, (long)ret);

          pstate.fdmap.erase(fd);
          break;
        }

        case nr_for(openat):
        case nr_for(open): {
          IS_RIGHT_PROCESS_GET;

          if constexpr (IsVeryVerbose())
            fprintf(stderr, "open(\"%s\") = %ld\n", payload->str, (long)ret);

          pstate.fdmap[ret].path = payload->str;
          break;
        }

        case nr_for(pread64):
          fd_pos = arg3;

        case nr_for(read): {
          IS_RIGHT_PROCESS_GET;

          auto fd = arg0;

          auto &fdmap = pstate.fdmap;
          auto it = fdmap.find(fd);
          if (it == fdmap.end())
            break;

          const auto &filename = (*it).second.path;

          binary_index_t BIdx;
          bool isNew;

          if (gathered_bins) {
            binary_index_set BIdxSet;
            if (jv.LookupByName(filename.c_str(), BIdxSet)) {
              BIdx = *BIdxSet.cbegin();
              (void)isNew;
            } else {
              break;
            }
          } else {
            std::tie(BIdx, isNew) =
                jv.AddFromPath(explorer, jv_file, filename.c_str());
            if (!is_binary_index_valid(BIdx))
              break;
          }

          if constexpr (IsVerbose())
            if (is_binary_index_valid(BIdx))
              llvm::errs() << llvm::formatv(
                  "read of {0} (offset {1}) to {2:x}\n", filename, fd_pos,
                  arg1);

          (*it).second.pos += ret;
          break;
        }

        case nr_for(execve):
        case nr_for(execveat): {
          if (ret == 1) {
            // XXX exec never returns 1; we use this value to just say that an
            // exec is being attempted. the exit will be reported even if it
            // fails.
            //
            // we do this here because the MMAP records come before the exec
            // has completed
            if constexpr (IsVeryVerbose())
              fprintf(stderr, "(enter exec)\n");

            auto it = pid_map.find(pid);
            if (it != pid_map.end()) {
              auto &pstate = (*it).second;
              pstate.addrspace_sav = pstate.addrspace;
              pstate.addrspace.clear(); /* entering exec */
            }
            break;
          }
          if (static_cast<int>(ret) == -1) {
            // exec failed, undo our clear of the address space
            if constexpr (IsVeryVerbose())
              fprintf(stderr, "(exec failed)\n");

            auto it = pid_map.find(pid);
            if (it != pid_map.end()) {
              auto &pstate = (*it).second;
              pstate.addrspace = pstate.addrspace_sav;
              pstate.addrspace_sav.clear();
            }
            break;
          }

          const uint64_t n = payload->hdr.str_len;

          const char *const beg = &payload->str[0];
          const char *const end = &payload->str[n];

          const char *const pathname = beg;

          if constexpr (ExeOnly) {
            if (fs::equivalent(pathname, exe.Name.c_str())) {
              if constexpr (IsVerbose())
                fprintf(stderr, "our exe pid: %u\n", (unsigned)pid);

              Our.pids.insert(pid);
            }
          } else {
            if constexpr (IsVerbose())
              fprintf(stderr, "our pid: %u\n", (unsigned)pid);

            Our.pids.insert(pid);
          }
          CheckEngaged();

          std::vector<const char *> argvec;
          std::vector<const char *> envvec;

          const char *eon;

          eon = (char *)memchr(pathname, '\0', n);
          assert(eon);

          for (const char *arg = eon + 1; *arg; arg = eon + 1) {
            argvec.push_back(arg);

            assert(arg >= beg);
            assert(n >= (arg - beg));

            uint64_t left = n - (arg - beg);
            eon = (const char *)memchr(arg, '\0', left);
            assert(eon);
          }
          assert(eon < end);
          ++eon;
          assert(eon < end);
          assert(*eon == '\0');
        args_done:
          for (const char *env = eon + 1; env < end; env = eon + 1) {
            envvec.push_back(env);

            assert(env >= beg);
            assert(n >= (env - beg));

            uint64_t left = n - (env - beg);
            eon = (const char *)memchr(env, '\0', left);
            assert(eon);
          }
        envs_done:

          const unsigned nowBits = payload->hdr.is32 ? 32u : 64u;

          if constexpr (IsVerbose()) {
            fprintf(stderr, "nargs=%u nenvs=%u (%u / %u) <%u> [%u] exec:",
                    (unsigned)argvec.size(),
                    (unsigned)envvec.size(),
                    (unsigned)(sizeof(payload->hdr) + n),
                    TWOTIMESMAXLEN,
                    (unsigned)pid,
                    (unsigned)nowBits);
            if constexpr (IsVeryVerbose()) {
              for (const char *env : envvec)
                fprintf(stderr, " \"%s\"", env);
            }
            fprintf(stderr, " \"%s\"", pathname);
            for (const char *arg : argvec)
              fprintf(stderr, " \"%s\"", arg);
            fprintf(stderr, "\n");
          }

          const bool rightBits = nowBits == sizeof(taddr_t) * 8;
          if (!rightBits)
            break;

          break;
        }

        default:
          fprintf(stderr, "unhandled syscall %u!\n", (unsigned)nr);
          break;
        }
      };

      unsigned bytes_size = event.record.raw->size;
      const uint8_t *const bytes = (const uint8_t *)event.record.raw->data;

      const bool was32 = !!(bytes[MAGIC_LEN] & 1u);

#if 0
          const unsigned size_of_struct =
              was32 ? sizeof(struct augmented_syscall_payload32)
                    : sizeof(struct augmented_syscall_payload64);

          bool bad = false;
          if (!(bytes[0] == 'J' &&
                bytes[1] == 'O' &&
                bytes[2] == 'V' &&
                bytes[3] == 'E')) {
            fprintf(stderr, "offset at %" PRIu64 " does not start with magic1! bytes_size=%u sizeof(struct)=%u\n", offset, bytes_size, size_of_struct);
            bad = true;
          }

          if (!(bytes[bytes_size - 1] == 'E' &&
                bytes[bytes_size - 2] == 'V' &&
                bytes[bytes_size - 3] == 'O' &&
                bytes[bytes_size - 4] == 'J')) {
            fprintf(stderr, "offset at %" PRIu64 " does not end with magic2! bytes_size=%u sizeof(struct)=%u\n", offset, bytes_size, size_of_struct);
            bad = true;
          }

          if (bad) {
            fprintf(stderr, "\n");
            hexdump(stderr, bytes, bytes_size);
            fprintf(stderr, "\n");
          }
#endif

      if (was32) {
        on_syscall.template operator()<struct augmented_syscall_payload32>(
            reinterpret_cast<const struct augmented_syscall_payload32 *>(
                bytes));
      } else {
        on_syscall.template operator()<struct augmented_syscall_payload64>(
            reinterpret_cast<const struct augmented_syscall_payload64 *>(
                bytes));
      }
      break;
    }

    case PERF_RECORD_MMAP: {
      if ((event.misc & PERF_RECORD_MISC_CPUMODE_MASK) ==
          PERF_RECORD_MISC_KERNEL)
        break;

      const struct pev_record_mmap *mmap = event.record.mmap;
      assert(mmap);
      assert(mmap->pid == get_pid());

      on_mmap(offset, mmap->pid, mmap->addr, mmap->len, mmap->pgoff,
              mmap->filename, "MMAP");
      break;
    }

    case PERF_RECORD_MMAP2: {
      if ((event.misc & PERF_RECORD_MISC_CPUMODE_MASK) ==
          PERF_RECORD_MISC_KERNEL)
        break;

      const struct pev_record_mmap2 *mmap2 = event.record.mmap2;
      assert(mmap2);

      auto pid = get_pid();
      if (pid <= 1) /* ignore kernel/init */
        break;

      assert(mmap2->pid == pid);

      //
      // we want to consider all MMAP2 records because on a succesful exec they
      // will appear *before* the successful exec appears
      //
#if 0
      if (!IsRightProcess(pid))
        break;
#endif

      on_mmap(offset, mmap2->pid, mmap2->addr, mmap2->len, mmap2->pgoff,
              mmap2->filename, "MMAP2");
      break;
    }

    default:
      break;
    }
#undef unexpected_rest
  }

  int track_time(uint64_t offset) {
    uint64_t tsc;
    int errcode = pt_time_query_tsc(&tsc, NULL, NULL, &tracking.time);
    if ((errcode < 0) && (errcode != -pte_no_time)) {
      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\ttime tracking error (%s)\n",
                offset,
                pt_errstr(pt_errcode(errcode)));
      return 1;
    }

    for (;;) {
      // (if an event has a NULL time or zero tsc, we want to examine at once)
      if (incoming_event.sample.time &&
          tsc < incoming_event.sample.tsc)
        break;

      examine_sb_event(incoming_event, offset);

      if (++sb_it == sb.end()) {
        //
        // no more sideband records.
        //
        incoming_event.sample.time = &dummy_time;
        incoming_event.sample.tsc =
            std::numeric_limits<decltype(incoming_event.sample.tsc)>::max();
        return 1;
      }

      //
      // load the next one up
      //
      incoming_event.sample.time = nullptr;
      incoming_event.sample.tsc =
          std::numeric_limits<decltype(incoming_event.sample.tsc)>::max();
      sb_parser.load(incoming_event, *sb_it);
    }

    return 1;
  }

  int on_ip(const uint64_t IP, const uint64_t offset) {
    taddr_t Addr = uninit_taddr;
    binary_index_t BIdx = 0;
    std::reference_wrapper<binary_base_t<MT>> refb = exe;
    if constexpr (ExeOnly) {
      if (!(IP >= exeOnly.beg && IP < exeOnly.end))
        return 0;
    } else {
      auto &AddressSpace = process_state.get().addrspace;

      auto it = intvl_map_find(AddressSpace, IP);
      if (unlikely(it == AddressSpace.end())) {
        if constexpr (IsVeryVerbose())
          fprintf(stderr, "%016" PRIx64 "\tunknown IP %016" PRIx64 "\n", offset,
                  (uint64_t)IP);

        CurrPoint.Invalidate();
        return 1;
      }

      BIdx = (*it).second.first;
      if (unlikely(!is_binary_index_valid(BIdx))) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%016" PRIx64 "\tambiguous IP %016" PRIx64 "\n",
                  offset, (uint64_t)IP);

        CurrPoint.Invalidate();
        return 1;
      }

      auto &b = jv.Binaries.at(BIdx);
      refb = b;

      struct {
        taddr_t Base;
        uint64_t Offset;
      } mapping;

      mapping.Base = addr_intvl_lower((*it).first);
      mapping.Offset = (*it).second.second;

      try {
        binary_state_t &x = state.for_binary(b);

        assert(~mapping.Offset);
        assert(static_cast<uint64_t>(mapping.Base) >= mapping.Offset);
        assert(IP >= (mapping.Base - mapping.Offset));

        uint64_t off = IP - (mapping.Base - mapping.Offset);

        Addr = B::va_of_offset(*x.Bin, off);
      } catch (...) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%016" PRIx64 "\tno section for %016" PRIx64 "\n",
                  offset, static_cast<uint64_t>(IP));

        CurrPoint.Invalidate();
        return 0;
      }
    }

    binary_base_t<MT> &b = refb.get();
    binary_state_t &x = state.for_binary(b);

    if constexpr (Objdump) {
      if (!b.bbbmap.contains(Addr)) {
        const bool bad = b.Analysis.objdump.is_addr_bad(Addr);

        if (unlikely(bad)) {
          if constexpr (IsVerbose())
            fprintf(stderr,
                    "%016" PRIx64 "\tBADIP O[%016" PRIx64 "] %s+%" PRIx64 "\n",
                    offset, IP, b.Name.c_str(), (uint64_t)Addr);

          CurrPoint.Invalidate();
          return 1;
        }
      }
    }

    if constexpr (IsVeryVerbose())
      fprintf(stderr, "%016" PRIx64 "\t<IP> %016" PRIx64 " %s+%" PRIx64 "\n",
              offset, (uint64_t)IP, b.Name.c_str(), (uint64_t)Addr);

    if (CurrPoint.Valid()) {
      auto grab_addresses =
          [&](const basic_block_properties_t &bbprop,
              basic_block_index_t BBIdx) -> basic_block_index_t {
        CurrPoint.SetAddr(bbprop.Addr);
        CurrPoint.SetTermAddr(bbprop.Term.Addr);
        return BBIdx;
      };
      if (CurrPoint.BinaryIndex() == BIdx) {
        bool WentNoFurther = false;

        if constexpr (Caching) {
          try {
            const auto &SL = SLForBlock(b, CurrPoint.Block());
            CurrPoint.SetBlockIndex(SL.BBIdx);
            CurrPoint.SetAddr(SL.Addr);
            CurrPoint.SetTermAddr(SL.TermAddr);
            WentNoFurther = intvl_set_contains(SL.addrng, Addr);
          } catch (const infinite_loop_exception &) {
            CurrPoint.Invalidate();
          }
        } else {
          basic_block_index_t NewBBIdx;
          std::tie(NewBBIdx, WentNoFurther) = StraightLineUntilSlow<false>(
              b, CurrPoint.BlockIndex(), Addr, grab_addresses);
          CurrPoint.SetBlockIndex(NewBBIdx);
        }

        // assert(CurrPoint.Valid());
        if (WentNoFurther) {
          if constexpr (IsVeryVerbose())
            fprintf(stderr, "no further %s+%" PRIx64 "\n</IP>\n",
                    b.Name.c_str(), (uint64_t)Addr);
          return 0;
        }
      } else {
        if constexpr (Caching) {
          try {
            const auto &SL = SLForBlock(CurrPoint.Binary(), CurrPoint.Block());
            CurrPoint.SetBlockIndex(SL.BBIdx);
            CurrPoint.SetAddr(SL.Addr);
            CurrPoint.SetTermAddr(SL.TermAddr);
          } catch (const infinite_loop_exception &) {
            CurrPoint.Invalidate();
          }
        } else {
          CurrPoint.SetBlockIndex(StraightLineSlow<false>(
              CurrPoint.Binary(), CurrPoint.BlockIndex(), grab_addresses));
          assert(CurrPoint.Valid());
        }
      }
    }

    const auto PrevPoint = CurrPoint;
    try {
      auto obp = [&](basic_block_t bb,
                     basic_block_properties_t &bbprop) -> void {
        CurrPoint.SetAddr(bbprop.Addr);
        CurrPoint.SetTermAddr(bbprop.Term.Addr);

        if constexpr (IsVeryVerbose())
          on_block(b, bbprop, bb);
      };
      auto obp_u = [&](basic_block_index_t BBIdx) -> void {
        basic_block_properties_t &bbprop =
            b.Analysis.ICFG[basic_block_of_index(BBIdx, b.Analysis.ICFG)];

        auto s_lck = bbprop.shared_access<MT>();
        obp(basic_block_of_index(BBIdx, b.Analysis.ICFG), bbprop);
      };

      CurrPoint.SetBinary(b);
      CurrPoint.SetBlockIndex(
          explorer.explore_basic_block(b, *x.Bin, Addr, obp, obp_u));
      assert(CurrPoint.Valid());
    } catch (const invalid_control_flow_exception &) {
      if constexpr (1 /* IsVerbose() */)
        fprintf(stderr,
                "BADIP %016" PRIx64 "\t<IP> %016" PRIx64 " %s+%" PRIx64 "\n",
                offset, (uint64_t)IP, b.Name.c_str(), (uint64_t)Addr);

      if constexpr (IsVeryVerbose())
        fprintf(stderr, "</IP>\n");

      CurrPoint.Invalidate();
      return 1;
    }

    if (PrevPoint.Valid() && CurrPoint.Valid()) {
      const taddr_t PrevTermAddr = PrevPoint.GetTermAddr();

      if (likely(is_taddr_valid(PrevTermAddr))) {
        block_transfer(PrevPoint.Binary(), PrevTermAddr,
                       CurrPoint.Binary(), CurrPoint.GetAddr());
      } else {
        if constexpr (IsVerbose()) {
          auto &prevb = PrevPoint.Binary();
          auto &prevprop = prevb.Analysis.ICFG[PrevPoint.Block()];

          fprintf(stderr,
                  "PrevPoint has invalid terminator address %" PRIx64
                  " @ %s+%" PRIx64 "\n",
                  (uint64_t)PrevTermAddr, prevb.Name.c_str(),
                  (uint64_t)prevprop.Addr);
        }
      }
    }

    if constexpr (IsVeryVerbose())
      fprintf(stderr, "</IP>\n");

    return 0;
  }

  template <bool InfiniteLoopThrow = false>
  std::pair<basic_block_index_t, bool> StraightLineUntilSlow(
      const binary_base_t<MT> &b,
      basic_block_index_t From,
      taddr_t GoNoFurther,
      std::function<basic_block_index_t(const basic_block_properties_t &, basic_block_index_t)> on_final_block = [](const basic_block_properties_t &, basic_block_index_t Res) -> basic_block_index_t {
        return Res;
      }) {
    return StraightLineGo<true, InfiniteLoopThrow, MT, Verbosity>(
        b, From, GoNoFurther, on_final_block);
  }

  template <bool InfiniteLoopThrow = false>
  basic_block_index_t StraightLineSlow(const binary_base_t<MT> &b,
                                       basic_block_index_t From,
                                       std::function<basic_block_index_t(const basic_block_properties_t &, basic_block_index_t)> on_final_block = [](const basic_block_properties_t &, basic_block_index_t Res) -> basic_block_index_t {
        return Res;
      }) {
    return StraightLineGo<false, InfiniteLoopThrow, MT, Verbosity>(
               b, From, 0 /* unused */, on_final_block)
        .first;
  }

  void TNTAdvance(uint64_t tnt, uint8_t n) {
    if constexpr (IsVeryVerbose())
      fprintf(stderr, "<TNT>\n");

    assert(n > 0);
    assert(CurrPoint.Valid());

    binary_base_t<MT> &b = CurrPoint.Binary();
    basic_block_index_t Res = CurrPoint.BlockIndex();

    const auto &ICFG = b.Analysis.ICFG;
    do {
      const bool Taken = !!(tnt & (1ull << (n - 1)));

      if constexpr (Caching) {
        basic_block_t bb = basic_block_of_index(Res, b);
        const auto &SL = SLForBlock(b, bb);
        if (unlikely(SL.adj.empty())) {
          if constexpr (IsVerbose())
            fprintf(stderr,
                    "not/invalid conditional branch @ %s+%" PRIx64 " (%s)\n",
                    b.Name.c_str(),
                    static_cast<uint64_t>(
                        ICFG[basic_block_of_index(SL.BBIdx, b)].Addr),
                    string_of_terminator(SL.TermType));
          throw tnt_error();
        }
        assert(SL.adj.size() == 2);
        Res = SL.adj[static_cast<unsigned>(Taken)];
      } else {
        Res = StraightLineSlow<true>(
            b, Res,
            [&](const basic_block_properties_t &bbprop,
                basic_block_index_t BBIdx) -> basic_block_index_t {
              basic_block_t bb = basic_block_of_index(BBIdx, b);

              unsigned out_deg = ICFG.template out_degree<false>(bb);

              if (unlikely(bbprop.Term.Type != TERMINATOR::CONDITIONAL_JUMP) ||
                  unlikely(out_deg == 0)) {
                if constexpr (IsVerbose())
                  fprintf(stderr,
                          "not/invalid conditional branch @ %s+%" PRIx64
                          " (%s)\n",
                          b.Name.c_str(), static_cast<uint64_t>(bbprop.Addr),
                          string_of_terminator(bbprop.Term.Type));
                throw tnt_error();
              }

              if (unlikely(out_deg == 1))
                return index_of_basic_block(
                    ICFG, ICFG.template adjacent_front<false>(bb));

              assert(out_deg == 2);

              auto succ = ICFG.template adjacent_n<2, false>(bb);
              const bool Is0NotTaking =
                  ICFG[succ[0]].Addr == bbprop.Addr + bbprop.Size;

              basic_block_index_t TheRes = index_of_basic_block(
                  ICFG, Taken ? (Is0NotTaking ? succ[1] : succ[0])
                              : (Is0NotTaking ? succ[0] : succ[1]));
              return TheRes;
            });
      }

      if constexpr (IsVeryVerbose()) {
        basic_block_t bb = basic_block_of_index(Res, b);
        const auto &bbprop = ICFG[bb];

        auto s_lck = bbprop.template shared_access<MT>();

        on_block(b, bbprop, bb);
      }

#if 0
    const char *extra = n > 1 ? " " : "";
    fprintf(stderr, "%d%s", (int)Taken, extra);
#endif
    } while (--n);

    if constexpr (Caching) {
      basic_block_t bb = basic_block_of_index(Res, b);
      const auto &SL = SLForBlock(b, bb);
      CurrPoint.SetBlockIndex(SL.BBIdx);
      CurrPoint.SetAddr(SL.Addr);
      CurrPoint.SetTermAddr(SL.TermAddr);
    } else {
      CurrPoint.SetBlockIndex(StraightLineSlow<true>(
          b, Res,
          [&](const basic_block_properties_t &bbprop,
              basic_block_index_t BBIdx) -> basic_block_index_t {
            CurrPoint.SetAddr(bbprop.Addr);
            CurrPoint.SetTermAddr(bbprop.Term.Addr);
            return BBIdx;
          }));
    }

    if constexpr (IsVeryVerbose())
      fprintf(stderr, "</TNT>\n");
  }

  struct {
    struct {
      binary_index_t BIdx = invalid_binary_index;
      basic_block_index_t BBIdx = invalid_basic_block_index;
    } Last;
  } OnBlock;

  void on_block(const binary_base_t<MT> &b,
                const basic_block_properties_t &bbprop,
                basic_block_t bb) {
    if constexpr (IsVeryVerbose()) {
      auto &ICFG = b.Analysis.ICFG;
      if (index_of_binary(b) == OnBlock.Last.BIdx &&
          index_of_basic_block(ICFG, bb) == OnBlock.Last.BBIdx) {
        fputs(".", stderr);
      } else {
        const auto Addr = bbprop.Addr;

        fprintf(stderr, "%s+%016" PRIx64 "\n", b.Name.c_str(), (uint64_t)Addr);
        // fprintf(stdout, "%s+%016" PRIx64 "\n", b.Name.c_str(),
        // (uint64_t)Addr);
      }

      OnBlock.Last.BIdx = index_of_binary(b);
      OnBlock.Last.BBIdx = index_of_basic_block(ICFG, bb);
    }
  }

  void block_transfer(binary_base_t<MT> &fr_b, taddr_t FrTermAddr,
                      binary_base_t<MT> &to_b, taddr_t ToAddr) {
    const binary_index_t FrBIdx = index_of_binary(fr_b);
    const binary_index_t ToBIdx = index_of_binary(to_b);

    auto &fr_ICFG = fr_b.Analysis.ICFG;
    auto &to_ICFG = to_b.Analysis.ICFG;

    if constexpr (IsVeryVerbose())
      fprintf(stderr,
              "%s+%" PRIx64 " ==> "
              "%s+%" PRIx64 "\n",
              fr_b.Name.c_str(), (uint64_t)FrTermAddr, to_b.Name.c_str(),
              (uint64_t)ToAddr);

    TERMINATOR TermType;
    bool Term_indirect_jump_IsLj;

    ({
      auto fr_s_lck_bbmap = fr_b.bbmap_shared_access();

      const auto &Term = fr_ICFG[basic_block_at_address(FrTermAddr, fr_b)].Term;

      TermType = Term.Type;
      Term_indirect_jump_IsLj = Term._indirect_jump.IsLj;
    });

    basic_block_t to_bb = basic_block_starting_at_address(ToAddr, to_b);

    auto handle_indirect_call = [&](void) -> void {
      function_index_t FIdx =
          explorer.explore_function(to_b, *state.for_binary(to_b).Bin, ToAddr);

      if (!is_function_index_valid(FIdx))
        return;

      auto fr_s_lck = fr_b.bbmap_shared_access();

      basic_block_t fr_bb = basic_block_at_address(FrTermAddr, fr_b);
      basic_block_properties_t &fr_bbprop = fr_ICFG[fr_bb];

      fr_bbprop.insertDynTarget(FrBIdx, std::make_pair(ToBIdx, FIdx), jv_file,
                                jv);
    };

    switch (TermType) {
    case TERMINATOR::INDIRECT_JUMP: {
      if (Term_indirect_jump_IsLj)
        break;

      const bool TailCall = ({
        auto fr_s_lck_bbmap = fr_b.bbmap_shared_access();

        IsDefinitelyTailCall(fr_ICFG, basic_block_at_address(FrTermAddr, fr_b));
      });

      if (TailCall) {
        handle_indirect_call();
      } else if (FrBIdx != ToBIdx) {
        handle_indirect_call();
        fr_b.FixAmbiguousIndirectJump(FrTermAddr, explorer,
                                      *state.for_binary(fr_b).Bin, jv_file, jv);
      } else {
        assert(FrBIdx == ToBIdx);

        auto fr_s_lck_bbmap = fr_b.bbmap_shared_access();

        fr_ICFG.add_edge(basic_block_at_address(FrTermAddr, fr_b), to_bb);
      }

      break;
    }

    case TERMINATOR::INDIRECT_CALL: {
      handle_indirect_call();
      break;
    }

    case TERMINATOR::RETURN: {
      {
        auto fr_s_lck_bbmap = fr_b.bbmap_shared_access();

        concurrent::set(fr_ICFG[basic_block_at_address(FrTermAddr, fr_b)]
                            .Term._return.Returns);
      }

      //
      // what came before?
      //
      const taddr_t before_pc = ToAddr - 1;

      auto to_s_lck_bbmap = to_b.bbmap_shared_access();

      if (!exists_basic_block_at_address(before_pc, to_b))
        break;

      basic_block_t before_bb = basic_block_at_address(before_pc, to_b);
      basic_block_properties_t &before_bbprop = to_ICFG.at(before_bb);
      auto &before_Term = before_bbprop.Term;

      bool isCall = before_Term.Type == TERMINATOR::CALL;
      bool isIndirectCall = before_Term.Type == TERMINATOR::INDIRECT_CALL;
      if (isCall || isIndirectCall) {
        assert(to_ICFG.out_degree(before_bb) <= 1);

        if (isCall) {
          if (likely(is_function_index_valid(before_Term._call.Target)))
            concurrent::set(
                to_b.Analysis.Functions.at(before_Term._call.Target).Returns);
        }

        to_ICFG.add_edge(before_bb, to_bb); /* connect */
      }
      break;
    }

    default:
      return;
    }
  }

public:
  ipt_t(int ptdump_argc,
        char **ptdump_argv,
        jv_base_t<MT> &jv,
        explorer_t &explorer,
        jv_file_t &jv_file,
        unsigned cpu,
        perf::data_reader<false> &sb,
        perf::sideband_parser &sb_parser,
        const uint8_t *const aux_begin,
        const uint8_t *const aux_end,
        const char *sb_filename,
        unsigned verbose,
        bool gathered_bins = false,
        bool ignore_trunc_aux = false)
      : ptdump_argc(ptdump_argc),
        ptdump_argv(ptdump_argv),
        aux_begin(aux_begin),
        aux_end(aux_end),
        jv_file(jv_file),
        jv(jv),
        explorer(explorer),
        sb(sb),
        sb_it(sb.begin()),
        sb_parser(sb_parser),
        state(jv),
        PageSize(sysconf(_SC_PAGESIZE)),
        IsCOFF(B::is_coff(*state.for_binary(jv.Binaries.at(0)).Bin)),
        exe(jv.Binaries.at(0)),
        CurrPoint(exe),
        ignore_trunc_aux(ignore_trunc_aux),
        gathered_bins(gathered_bins),
        process_state(dummy_process_state),
        path_to_wine_bin(locator_t::wine(IsTarget32)) {
    setvbuf(stderr, NULL, _IOLBF, 0); /* automatically flush on new-line */

    Our.cpu = cpu;

    pt_config_init(&this->config);
    this->ptdump_tracking_init();

    if (this->process_args(this->ptdump_argc, this->ptdump_argv) != 0)
      throw std::runtime_error("failed to process ptdump arguments");

    if (this->config.cpu.vendor) {
      int errcode = pt_cpu_errata(&this->config.errata, &this->config.cpu);
      if (errcode < 0)
        throw std::runtime_error("failed to determine errata");

      std::vector<uint8_t> zeros(sizeof(this->config.errata), 0);
      if (memcmp(&this->config.errata, &zeros[0], sizeof(this->config.errata)) != 0) {
        fprintf(stderr, "WARNING! CPU errata detected:");

#define __ERRATA(x)                                                            \
  do {                                                                         \
    if (this->config.errata.x)                                                 \
      fprintf(stderr, " " #x);                                                 \
  } while (false)

        __ERRATA(bdm70);
        __ERRATA(bdm64);
        __ERRATA(skd007);
        __ERRATA(skd022);
        __ERRATA(skd010);
        __ERRATA(skl014);
        __ERRATA(apl12);
        __ERRATA(apl11);
        __ERRATA(skl168);
        __ERRATA(skz84);

#undef __ERRATA

        fprintf(stderr, "\n");
      }
    }

    this->config.begin = const_cast<uint8_t *>(this->aux_begin);
    this->config.end = const_cast<uint8_t *>(this->aux_end);

    if constexpr (ExeOnly) {
      binary_base_t<MT> &exe = jv.Binaries.at(0);

      if (!exe.IsPIC) {
        std::tie(exeOnly.beg, exeOnly.end) =
            B::bounds_of_binary(*state.for_binary(exe).Bin);

        if constexpr (IsVerbose())
          fprintf(stderr, "looking for [%016" PRIx64 ", %016" PRIx64 ")\n",
                  (uint64_t)exeOnly.beg, (uint64_t)exeOnly.end);
      }
    }

    memset(&incoming_event, 0, sizeof(incoming_event));
    if (sb_it == sb.end()) {
      incoming_event.sample.time = &dummy_time;
      incoming_event.sample.tsc =
          std::numeric_limits<decltype(incoming_event.sample.tsc)>::max();
    } else {
      sb_parser.load(incoming_event, *sb_it);
    }
  }
  virtual ~ipt_t() {}

  static int pt_parse_sample_config(struct pt_sb_pevent_config *pevent,
                                    const char *arg) {
    struct pev_sample_config *sample_config;
    uint64_t identifier, sample_type;
    uint8_t nstypes;
    char *rest;
    const char *name;

    if (!pevent || !arg)
      return -pte_internal;

    errno = 0;
    identifier = strtoull(arg, &rest, 0);
    if (errno || (rest == arg))
      return -pte_invalid;

    arg = rest;
    if (arg[0] != ':')
      return -pte_invalid;

    arg += 1;
    sample_type = strtoull(arg, &rest, 0);
    if (errno)
      return -pte_invalid;

    arg = rest;
    if (arg[0] != ':')
      return -pte_invalid;

    arg += 1;
    name = arg;

    sample_config = pevent->sample_config;
    if (!sample_config) {
      sample_config =
          (struct pev_sample_config *)malloc(sizeof(*sample_config));
      if (!sample_config)
        return -pte_nomem;

      memset(sample_config, 0, sizeof(*sample_config));
      pevent->sample_config = sample_config;
    }

    nstypes = sample_config->nstypes;
    sample_config = (struct pev_sample_config *)realloc(
        sample_config, sizeof(*sample_config) +
                           ((nstypes + 1) * sizeof(struct pev_sample_type)));
    if (!sample_config)
      return -pte_nomem;

    sample_config->stypes[nstypes].identifier = identifier;
    sample_config->stypes[nstypes].sample_type = sample_type;
    sample_config->nstypes = nstypes + 1;

    strncpy(sample_config->stypes[nstypes].name, name,
            sizeof(sample_config->stypes[nstypes].name));

    pevent->sample_config = sample_config;

    return 0;
  }

  static int pt_cpu_parse(struct pt_cpu *cpu, const char *s) {
    const char sep = '/';
    char *endptr;
    long family, model, stepping;

    if (!cpu || !s)
      return -pte_invalid;

    family = strtol(s, &endptr, 0);
    if (s == endptr || *endptr == '\0' || *endptr != sep)
      return -pte_invalid;

    if (family < 0 || family > USHRT_MAX)
      return -pte_invalid;

    /* skip separator */
    s = endptr + 1;

    model = strtol(s, &endptr, 0);
    if (s == endptr || (*endptr != '\0' && *endptr != sep))
      return -pte_invalid;

    if (model < 0 || model > UCHAR_MAX)
      return -pte_invalid;

    if (*endptr == '\0')
      /* stepping was omitted, it defaults to 0 */
      stepping = 0;
    else {
      /* skip separator */
      s = endptr + 1;

      stepping = strtol(s, &endptr, 0);
      if (*endptr != '\0')
        return -pte_invalid;

      if (stepping < 0 || stepping > UCHAR_MAX)
        return -pte_invalid;
    }

    cpu->vendor = pcv_intel;
    cpu->family = (uint16_t)family;
    cpu->model = (uint8_t)model;
    cpu->stepping = (uint8_t)stepping;

    return 0;
  }

  static int get_arg_uint64(uint64_t *value, const char *option,
                            const char *arg, const char *prog) {
    char *rest;

    if (!value || !option || !prog) {
      fprintf(stderr, "%s: internal error.\n", prog ? prog : "?");
      return 0;
    }

    if (!arg || arg[0] == 0 || (arg[0] == '-' && arg[1] == '-')) {
      fprintf(stderr, "%s: %s: missing argument.\n", prog, option);
      return 0;
    }

    errno = 0;
    *value = strtoull(arg, &rest, 0);
    if (errno || *rest) {
      fprintf(stderr, "%s: %s: bad argument: %s.\n", prog, option, arg);
      return 0;
    }

    return 1;
  }

  static int get_arg_uint32(uint32_t *value, const char *option,
                            const char *arg, const char *prog) {
    uint64_t val;

    if (!get_arg_uint64(&val, option, arg, prog))
      return 0;

    if (val > UINT32_MAX) {
      fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option, arg);
      return 0;
    }

    *value = (uint32_t)val;

    return 1;
  }

  static int get_arg_uint16(uint16_t *value, const char *option,
                            const char *arg, const char *prog) {
    uint64_t val;

    if (!get_arg_uint64(&val, option, arg, prog))
      return 0;

    if (val > UINT16_MAX) {
      fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option, arg);
      return 0;
    }

    *value = (uint16_t)val;

    return 1;
  }

  static int get_arg_uint8(uint8_t *value, const char *option, const char *arg,
                           const char *prog) {
    uint64_t val;

    if (!get_arg_uint64(&val, option, arg, prog))
      return 0;

    if (val > UINT8_MAX) {
      fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option, arg);
      return 0;
    }

    *value = (uint8_t)val;

    return 1;
  }

  int process_args(int argc, char **argv) {
    struct pt_sb_pevent_config pevent;
    int idx, errcode;

    memset(&pevent, 0, sizeof(pevent));
    pevent.size = sizeof(pevent);
    pevent.time_mult = 1;

    for (idx = 1; idx < argc; ++idx) {
      if (strcmp(argv[idx], "--pevent:sample-type") == 0) {
        if (!get_arg_uint64(&pevent.sample_type, "--pevent:sample-type",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--pevent:sample-config") == 0) {
        errcode = pt_parse_sample_config(&pevent, argv[++idx]);
        if (errcode < 0) {
          fprintf(stderr, "%s: bad sample config %s: %s.\n", argv[0],
                  argv[idx - 1], pt_errstr(pt_errcode(errcode)));
          return -1;
        }
      } else if (strcmp(argv[idx], "--pevent:time-zero") == 0) {
        if (!get_arg_uint64(&pevent.time_zero, "--pevent:time-zero",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--pevent:time-shift") == 0) {
        if (!get_arg_uint16(&pevent.time_shift, "--pevent:time-shift",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--pevent:time-mult") == 0) {
        if (!get_arg_uint32(&pevent.time_mult, "--pevent:time-mult",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--pevent:tsc-offset") == 0) {
        if (!get_arg_uint64(&pevent.tsc_offset, "--pevent:tsc-offset",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--pevent:kernel-start") == 0) {
        if (!get_arg_uint64(&pevent.kernel_start, "--pevent:kernel-start",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--cpu") == 0) {
        const char *arg;

        arg = argv[++idx];
        if (!arg) {
          fprintf(stderr, "%s: --cpu: missing argument.\n", argv[0]);
          return -1;
        }

        if (strcmp(arg, "none") == 0) {
          memset(&this->config.cpu, 0, sizeof(this->config.cpu));
          continue;
        }

        errcode = pt_cpu_parse(&this->config.cpu, arg);
        if (errcode < 0) {
          fprintf(stderr, "%s: cpu must be specified as f/m[/s]\n", argv[0]);
          return -1;
        }
      } else if (strcmp(argv[idx], "--mtc-freq") == 0) {
        if (!get_arg_uint8(&this->config.mtc_freq, "--mtc-freq", argv[++idx],
                           argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--nom-freq") == 0) {
        if (!get_arg_uint8(&this->config.nom_freq, "--nom-freq", argv[++idx],
                           argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--cpuid-0x15.eax") == 0) {
        if (!get_arg_uint32(&this->config.cpuid_0x15_eax, "--cpuid-0x15.eax",
                            argv[++idx], argv[0]))
          return -1;
      } else if (strcmp(argv[idx], "--cpuid-0x15.ebx") == 0) {
        if (!get_arg_uint32(&this->config.cpuid_0x15_ebx, "--cpuid-0x15.ebx",
                            argv[++idx], argv[0]))
          return -1;
      } else {
        throw std::runtime_error(std::string("unknown option \"") + argv[idx] +
                                 std::string("\""));
      }
    }

    return 0;
  }

  __attribute__((always_inline)) Derived *get_this(void) {
    return static_cast<Derived *>(this);
  }

  int explore(void) {
    packet_type packet;
    get_this()->packet_sync(packet);

    try {
      for (;;) {
        for (;;) {
          const uint64_t offset = get_this()->next_packet(packet);
          try {
            get_this()->process_packets_unengaged(offset, packet);
            break;
          } catch (const error_decoding_exception &) {
            if constexpr (IsVeryVerbose())
              fprintf(stderr, "%016" PRIx64 "\tdecoding error (not engaged)\n", offset);
          }
          get_this()->packet_sync(packet);
        }
        for (;;) {
          const uint64_t offset = get_this()->next_packet(packet);
          try {
            get_this()->process_packets_engaged(offset, packet);
            break;
          } catch (const error_decoding_exception &) {
            if constexpr (IsVeryVerbose())
              fprintf(stderr, "%016" PRIx64 "\tdecoding error (engaged)\n", offset);
          }
          get_this()->packet_sync(packet);
        }
      }
    } catch (const end_of_trace_exception &) {
      return 0;
    }

    return 0;
  }

  void ptdump_tracking_init(void) {
    pt_last_ip_init(&tracking.last_ip);
    pt_tcal_init(&tracking.tcal);
    pt_time_init(&tracking.time);

#if 0
    tracking.tsc = 0ull;
    tracking.fcr = 0ull;
#endif
    tracking.in_header = 0;
  }

  void ptdump_tracking_reset(void) {
    pt_last_ip_init(&tracking.last_ip);
    pt_tcal_init(&tracking.tcal);
    pt_time_init(&tracking.time);

#if 0
    tracking.tsc = 0ull;
    tracking.fcr = 0ull;
#endif
    tracking.in_header = 0;
  }

  int track_tsc(uint64_t offset, const struct pt_packet_tsc *packet) {
    int errcode;

    if (1 /* !options->no_tcal */) {
      errcode = tracking.in_header
                    ? pt_tcal_header_tsc(&tracking.tcal, packet, &config)
                    : pt_tcal_update_tsc(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVeryVerbose())
          fprintf(stderr, "%016" PRIx64 "\ttsc: error calibrating time (%s)\n",
                  offset, pt_errstr(pt_errcode(errcode)));
      }
    }

    errcode = pt_time_update_tsc(&tracking.time, packet, &config);
    if (unlikely(errcode < 0)) {
      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\ttsc: error updating time (%s)\n",
                offset, pt_errstr(pt_errcode(errcode)));
    }

    return this->track_time(offset);
  }

  int track_cbr(uint64_t offset, const struct pt_packet_cbr *packet) {
    int errcode;

    if (1 /* !options->no_tcal */) {
      errcode = tracking.in_header
                    ? pt_tcal_header_cbr(&tracking.tcal, packet, &config)
                    : pt_tcal_update_cbr(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVeryVerbose())
          fprintf(stderr, "%016" PRIx64 "\tcbr: error calibrating time (%s)\n",
                  offset, pt_errstr(pt_errcode(errcode)));
      }
    }

    errcode = pt_time_update_cbr(&tracking.time, packet, &config);
    if (unlikely(errcode < 0)) {
      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\tcbr: error updating time (%s)\n",
                offset, pt_errstr(pt_errcode(errcode)));
    }

    return this->track_time(offset);
  }

  int track_tma(uint64_t offset, const struct pt_packet_tma *packet) {
    int errcode;

    if (1 /* !options->no_tcal */) {
      errcode = pt_tcal_update_tma(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVeryVerbose())
          fprintf(stderr, "%016" PRIx64 "\ttma: error calibrating time (%s)\n",
                  offset, pt_errstr(pt_errcode(errcode)));
      }
    }

    errcode = pt_time_update_tma(&tracking.time, packet, &config);
    if (unlikely(errcode < 0)) {
      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\ttma: error updating time (%s)\n",
                offset, pt_errstr(pt_errcode(errcode)));
    }

    return this->track_time(offset);
  }

  int track_mtc(uint64_t offset, const struct pt_packet_mtc *packet) {
    int errcode;

    if (1 /* !options->no_tcal */) {
      errcode = pt_tcal_update_mtc(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVeryVerbose())
          fprintf(stderr, "%016" PRIx64 "\tmtc: error calibrating time (%s)\n",
                  offset, pt_errstr(pt_errcode(errcode)));
      }
    }

    errcode = pt_time_update_mtc(&tracking.time, packet, &config);
    if (unlikely(errcode < 0)) {
      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\tmtc: error updating time (%s)\n",
                offset, pt_errstr(pt_errcode(errcode)));
    }

    return this->track_time(offset);
  }

  int track_cyc(uint64_t offset, const struct pt_packet_cyc *packet) {
    uint64_t fcr;
    int errcode;

    /* Initialize to zero in case of calibration errors. */
    fcr = 0ull;

    if (1 /* !options->no_tcal */) {
      errcode = pt_tcal_fcr(&fcr, &tracking.tcal);

      if (unlikely(errcode < 0)) {
        if constexpr (IsVeryVerbose())
          fprintf(stderr, "%016" PRIx64 "\tcyc: calibration error (%s)\n",
                  offset, pt_errstr(pt_errcode(errcode)));
      }

      errcode = pt_tcal_update_cyc(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVeryVerbose())
          fprintf(stderr, "%016" PRIx64 "\tcyc: error calibrating time (%s)\n",
                  offset, pt_errstr(pt_errcode(errcode)));
      }
    }

    errcode = pt_time_update_cyc(&tracking.time, packet, &config, fcr);
    if (unlikely(errcode < 0)) {
      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\tcyc: error updating time (%s)\n",
                offset, pt_errstr(pt_errcode(errcode)));
    } else if (!fcr) {
      if constexpr (IsVeryVerbose())
        fprintf(stderr,
                "%016" PRIx64 "\tcyc: error updating time: no calibration\n",
                offset);
    }

    return this->track_time(offset);
  }

  uint64_t track_ip(uint64_t offset, const struct pt_packet_ip &packet) {
    int errcode;
    uint64_t IP;

    errcode = pt_last_ip_update_ip(&this->tracking.last_ip, &packet,
                                   &this->config);
    if (unlikely(errcode < 0))
      throw std::runtime_error(
          std::string("reference_ipt: error (1) tracking last-ip at offset ") +
          std::to_string(offset));

    errcode = pt_last_ip_query(&IP, &this->tracking.last_ip);
    if (likely(errcode == 0)) {
      if constexpr (IsVeryVerbose())
        fprintf(stderr, "%016" PRIx64 "\tIP %016" PRIx64 "\n", offset, IP);
      return IP;
    }

    if constexpr (IsVeryVerbose()) {
      if (errcode == -pte_ip_suppressed)
        fprintf(stderr, "%016" PRIx64 "\tIP suppressed\n", offset);
    }

    return 0;
  }

  void handle_mode(const struct pt_packet_mode &mode, uint64_t offset) {
    switch (mode.leaf) {
    case pt_mol_exec: {
      const auto SavedExecBits = this->Curr.ExecBits;
      switch (pt_get_exec_mode(&mode.bits.exec)) {
      case ptem_64bit:
        this->Curr.ExecBits = 64;
        break;

      case ptem_32bit:
        this->Curr.ExecBits = 32;
        break;

      case ptem_16bit:
        this->Curr.ExecBits = 16;
        break;

      case ptem_unknown:
        this->Curr.ExecBits = ~0u;
        break;
      }

      if constexpr (IsVeryVerbose())
        if (this->Curr.ExecBits != SavedExecBits)
          fprintf(stderr, "%016" PRIx64 "\tbits %u -> %u\n", offset,
                  SavedExecBits, this->Curr.ExecBits);

      bool IsNowEng = CheckEngaged();
#if 0
      if (IsNowEng) {
      int errcode;

      //
      // look ahead and, if IP packet, deal with it but don't examine IP,
      // because IIRC (from reading libipt) whatever it is would have been
      // reachable anyway without examining the trace- plus it might be BOGUS.
      //
      offset = next_packet(packet);
      if (packet.type == ppt_fup) {
          errcode = pt_last_ip_update_ip(&this->tracking.last_ip,
                                         &packet.payload.ip, &this->config);
          if (unlikely(errcode < 0))
            throw std::runtime_error(
                std::string("reference_ipt: error tracking last-ip at offset ") +
                std::to_string(offset));

          if constexpr (IsVeryVerbose()) {
            uint64_t IP;
            if (pt_last_ip_query(&IP, &this->tracking.last_ip) >= 0)
              fprintf(stderr, "%016" PRIx64 "\tskipping IP %016" PRIx64 "\n", offset, (uint64_t)IP);
          }

          CurrPoint.Invalidate();
          break;
      }

      // process normally
      __attribute__((musttail)) return process_packets(offset, packet);
      } else
#endif
      break;
    }

    case pt_mol_tsx:
      // assuming this is followed by a mode.exec, there's nothing we need to
      // do
      break;

    default:
      throw std::runtime_error(
          std::string("reference_ipt: unknown mode leaf at offset ") +
          std::to_string(offset));
    }
  }
};

#undef IsVerbose
#undef IsVeryVerbose

template <IPT_PARAMETERS_DCL, typename Derived>
const uint64_t ipt_t<IPT_PARAMETERS_DEF, Derived>::dummy_time =
    std::numeric_limits<uint64_t>::max();

} // namespace jove

#define IPT_PROCESS_GTFO_IF_ENGAGED_CHANGED(ISENG)                             \
  do {                                                                         \
    if constexpr (ISENG) {                                                     \
      if (!this->Engaged)                                                      \
        return;                                                                \
    } else {                                                                   \
      if (this->Engaged)                                                       \
        return;                                                                \
    }                                                                          \
  } while (false)

#endif /* x86 */

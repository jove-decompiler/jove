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

    uint64_t tsc = 0ull; /* The last estimated TSC. */
    uint64_t fcr = 0ull; /* The last calibration value. */

    uint32_t in_header = 0; /* Header vs. normal decode. */
  } tracking;

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

    struct {
      taddr_t LoadAddr = ~0UL;
    } _coff;

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

    struct {
      bool two = true;

      unsigned pid, tid;
      uint64_t addr, len, pgoff;
      const char *filename;
    } _mmap;

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

          auto addr = hdr.args[0];
          auto len = hdr.args[1];

          const addr_intvl intvl(addr, len);

          if constexpr (IsVerbose()) {
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

          auto addr = hdr.args[0];
          auto len = hdr.args[1];
          auto prot = hdr.args[2];
          auto flags = hdr.args[3];
          auto fd = hdr.args[4];
          auto off = hdr.args[5];

          if (is_pgoff)
            off *= PageSize;

          const addr_intvl intvl(ret, len);

          const bool anon = static_cast<int>(fd) < 0;
          if (anon) {
            intvl_map_clear(AddressSpace, intvl);

            if constexpr (IsVeryVerbose()) {
              std::string as(addr_intvl2str(intvl));

              fprintf(stderr, "+\t%s\t\"//anon\"\t<mmap(2)>\n", as.c_str());
            }
          } else {
            // do we know the path?
            auto it = pstate.fdmap.find(fd);
            if (it == pstate.fdmap.end()) {
              if constexpr (IsVerbose()) {
                std::string as(addr_intvl2str(intvl));

                fprintf(stderr, "+\t%s\t??%d??\t<mmap(2)>\n", as.c_str(),
                        (int)fd);
              }
            } else {
              binary_index_t BIdx;
              bool isNew;

              const std::string &path = (*it).second.path;
              if (path.empty() || path.front() != '/') {
                fprintf(stderr, "bogus path \"%s\" (nr=%ld) (ret=%lx)\n",
                        path.c_str(), (long)nr, (unsigned long)ret);
                break;
              }

              assert(path[0] == '/');

              if (gathered_bins) {
                binary_index_set BIdxSet;
                if (jv.LookupByName(path.c_str(), BIdxSet)) {
                  BIdx = *BIdxSet.cbegin();
                  (void)isNew;
                } else {
                  break;
                }
              } else {
                std::tie(BIdx, isNew) =
                    jv.AddFromPath(explorer, jv_file, path.c_str());
                if (!is_binary_index_valid(BIdx))
                  break;
              }

              if constexpr (IsVerbose()) {
                std::string as(addr_intvl2str(intvl));

                fprintf(stderr, "+\t%s\t\"%s\"+%#x\t<mmap(2)>\n", as.c_str(),
                        jv.Binaries.at(BIdx).Name.c_str(), (unsigned)off);
              }

              intvl_map_clear(AddressSpace, intvl);
              intvl_map_add(AddressSpace, intvl, std::make_pair(BIdx, off));
            }
          }
          break;
        }

        case nr_for(close): {
          IS_RIGHT_PROCESS_GET;

          auto fd = hdr.args[0];

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
          fd_pos = hdr.args[3];

        case nr_for(read): {
          IS_RIGHT_PROCESS_GET;

          auto fd = hdr.args[0];

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
                  hdr.args[1]);

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

          Our.pids.insert(pid);
          RIGHT_PROCESS_GET;
          CheckEngaged();

          std::vector<const char *> argvec;
          std::vector<const char *> envvec;

          const uint64_t n = payload->hdr.str_len;

          const char *const beg = &payload->str[0];
          const char *const end = &payload->str[n];

          const char *eon;
          const char *const pathname = beg;

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

          if constexpr (IsVeryVerbose()) {
            fprintf(stderr, "nargs=%u nenvs=%u (%u / %u) <%u> [%u] exec:",
                    (unsigned)argvec.size(),
                    (unsigned)envvec.size(),
                    (unsigned)(sizeof(payload->hdr) + n),
                    TWOTIMESMAXLEN,
                    (unsigned)pid,
                    (unsigned)nowBits);
            for (const char *env : envvec)
              fprintf(stderr, " \"%s\"", env);
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

      _mmap.two = false;

      _mmap.pid = mmap->pid;
      _mmap.tid = mmap->tid;
      _mmap.addr = mmap->addr;
      _mmap.len = mmap->len;
      _mmap.pgoff = mmap->pgoff;
      _mmap.filename = mmap->filename;
    } /* fallthrough */
    case PERF_RECORD_MMAP2: {
      if ((event.misc & PERF_RECORD_MISC_CPUMODE_MASK) ==
          PERF_RECORD_MISC_KERNEL)
        break;

      if (_mmap.two) {
        const struct pev_record_mmap2 *mmap2 = event.record.mmap2;
        assert(mmap2);

        assert(mmap2->prot & PROT_EXEC);

        _mmap.pid = mmap2->pid;
        _mmap.tid = mmap2->tid;
        _mmap.addr = mmap2->addr;
        _mmap.len = mmap2->len;
        _mmap.pgoff = mmap2->pgoff;
        _mmap.filename = mmap2->filename;
      }

      auto pid = get_pid();
      if (pid <= 1) /* ignore kernel/init */
        break;

      if (_mmap.pid != pid) {
        fprintf(stderr, "_mmap.pid %u != pid %u %u %s\n",
                _mmap.pid,
                pid,
                (unsigned)_mmap.two,
                _mmap.filename);
      }
      assert(_mmap.pid == pid);

      //
      // we want to see all records since they will be encountered before the
      // exec of a process of interest happens
      //
#if 0
      if (!IsRightProcess(pid))
        break;
#endif

      auto &pstate = pid_map[pid];
      auto &AddressSpace = pstate.addrspace;

      std::string name(_mmap.filename);

      const addr_intvl intvl(_mmap.addr, _mmap.len);

      const bool anon = name == "//anon";
      if (anon) {
        intvl_map_clear(AddressSpace, intvl);

        if constexpr (IsVerbose()) {
          std::string as(addr_intvl2str(intvl));

          fprintf(stderr, "+\t%s\t\"//anon\"\t<MMAP%s>\n", as.c_str(),
                  _mmap.two ? "2" : "");
        }
        break;
      }

      binary_index_t BIdx;
      bool isNew;
      if (name[0] == '/') {
        if (!fs::exists(name)) {
          if constexpr (IsVeryVerbose())
            fprintf(stderr, "\"%s\" does not exist\n", name.c_str());
          break;
        }

        if (gathered_bins) {
          binary_index_set BIdxSet;
          if (jv.LookupByName(name.c_str(), BIdxSet)) {
            BIdx = *BIdxSet.cbegin();
            (void)isNew;
          } else {
            break;
          }
        } else {
          std::tie(BIdx, isNew) =
              jv.AddFromPath(explorer, jv_file, name.c_str());
          if (!is_binary_index_valid(BIdx))
            break;
        }
      } else {
        binary_index_set BIdxSet;
        if (!jv.LookupByName(name.c_str(), BIdxSet))
          break;
        assert(!BIdxSet.empty());

        BIdx = *(BIdxSet).rbegin(); /* most recent (XXX?) */
        isNew = false;
      }

      if constexpr (IsVerbose()) {
        std::string as(addr_intvl2str(intvl));

        fprintf(stderr, "+\t%s\t\"%s\"+%#x\t<MMAP%s>\n",
                as.c_str(),
                name.c_str(),
                (unsigned)_mmap.pgoff,
                _mmap.two ? "2" : "");
      }

      auto &b = jv.Binaries.at(BIdx);
      binary_state_t &x = state.for_binary(b);

      intvl_map_clear(AddressSpace, intvl);
      intvl_map_add(AddressSpace, intvl, std::make_pair(BIdx, _mmap.pgoff));
      break;
    }

    default:
      break;
    }
#undef unexpected_rest
  }

  int track_time(uint64_t offset, uint64_t tsc) {
#if 0
    if constexpr (IsVeryVerbose())
      print_time(offset);
#endif

    for (;;) {
      auto etsc = incoming_event.sample.tsc;

      if (tsc < etsc)
        return 1;

      examine_sb_event(incoming_event, offset);

      if (++sb_it == sb.end()) {
        incoming_event.sample.time = nullptr;
        incoming_event.sample.tsc =
            std::numeric_limits<decltype(incoming_event.sample.tsc)>::max();
        return 1;
      }

      for (;;) {
        incoming_event.sample.time = nullptr;
        incoming_event.sample.tsc =
            std::numeric_limits<decltype(incoming_event.sample.tsc)>::max();
        sb_parser.load(incoming_event, *sb_it);

        if (incoming_event.sample.time && incoming_event.sample.tsc)
          break;

        examine_sb_event(incoming_event, offset);
        ++sb_it;
      }
    }

    return 1;
  }

  int on_ip(const taddr_t IP, const uint64_t offset) {
    taddr_t Addr = IP;
    binary_index_t BIdx = 0;
    std::reference_wrapper<binary_base_t<MT>> refb = exe;
    if constexpr (ExeOnly) {
      if (!(IP >= exeOnly.beg && IP < exeOnly.end))
        return 0;
    } else {

#if 0
  if (sizeof(taddr_t) == 4)
    assert(IP < 0xffffffffull);
#endif

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

      Addr = ({
        binary_state_t &x = state.for_binary(b);
        B::_X(
            *x.Bin,
            [&](ELFO &O) -> uint64_t {
              assert(~mapping.Offset != 0);
              assert(IP >= mapping.Base);
              assert(static_cast<uint64_t>(mapping.Base) >= mapping.Offset);

              uint64_t off = IP - (mapping.Base - mapping.Offset);
              try {
                return elf::va_of_offset(O, off);
              } catch (...) {
                std::string as(addr_intvl2str((*it).first));
                fprintf(stderr,
                        "WTFF! %" PRIx64 " in %s: off=%" PRIx64
                        " in \"%s\" mapping.Base=%" PRIx64
                        " mapping.Offset=%" PRIx64 " \n",
                        (uint64_t)IP, as.c_str(), off, b.Name.c_str(),
                        (uint64_t)mapping.Base, mapping.Offset);
                abort();
              }
            },
            [&](COFFO &O) -> uint64_t {
              try {
                if (~x._coff.LoadAddr == 0) {
                  assert(~mapping.Offset != 0);
                  uint64_t off = IP - (mapping.Base - mapping.Offset);
                  return coff::va_of_offset(O, off);
                } else {
                  const taddr_t hmod = x._coff.LoadAddr;
                  assert(IP >= hmod);
                  taddr_t RVA = IP - hmod;
                  return coff::va_of_rva(O, RVA);
                }
              } catch (...) {
                std::string as(addr_intvl2str((*it).first));
                fprintf(stderr,
                        "WTFF! %" PRIx64
                        " in %s in \"%s\" mapping.Base=%" PRIx64
                        " mapping.Offset=%" PRIx64 " \n",
                        (uint64_t)IP, as.c_str(), b.Name.c_str(),
                        (uint64_t)mapping.Base, mapping.Offset);
                abort();
              }
            });
      });
    }

    binary_base_t<MT> &b = refb.get();

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

    binary_state_t &x = state.for_binary(b);
    if constexpr (Objdump) {
      if (!b.bbbmap.contains(Addr)) {
        const bool bad = b.Analysis.objdump.is_addr_bad(Addr);

        if (unlikely(bad)) {
          if constexpr (IsVerbose())
            fprintf(stderr,
                    "OBJDUMP SAYS \"BADIP!\" %016" PRIx64 "\t<IP> %016" PRIx64
                    " %s+%" PRIx64 "\n",
                    offset, (uint64_t)IP, b.Name.c_str(), (uint64_t)Addr);

          if constexpr (IsVeryVerbose())
            fprintf(stderr, "</IP>\n");

          CurrPoint.Invalidate();
          return 1;
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
    Our.cpu = cpu;

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

    if (sb_it == sb.end()) {
      incoming_event.sample.time = nullptr;
      incoming_event.sample.tsc =
          std::numeric_limits<decltype(incoming_event.sample.tsc)>::max();
    } else {
      sb_parser.load(incoming_event, *sb_it);
      if (!incoming_event.sample.time)
        incoming_event.sample.tsc = 0;
    }
  }
  virtual ~ipt_t() {}

  __attribute__((always_inline)) Derived *get_this(void) {
    return static_cast<Derived *>(this);
  }

  int explore(void) {
    get_this()->packet_sync();

    try {
      packet_type packet;
      for (;;) {
        for (;;) {
          try {
            get_this()->process_packets_while_not_engaged(
                get_this()->next_packet(packet), packet);
            break;
          } catch (const error_decoding_exception &) {
          }
          get_this()->packet_sync();
        }
        for (;;) {
          try {
            get_this()->process_packets_while_engaged(
                get_this()->next_packet(packet), packet);
            break;
          } catch (const error_decoding_exception &) {
          }
          get_this()->packet_sync();
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

    tracking.tsc = 0ull;
    tracking.fcr = 0ull;
    tracking.in_header = 0;
  }

  void ptdump_tracking_reset(void) {
    pt_last_ip_init(&tracking.last_ip);
    pt_tcal_init(&tracking.tcal);
    pt_time_init(&tracking.time);

    tracking.tsc = 0ull;
    tracking.fcr = 0ull;
    tracking.in_header = 0;
  }

  int track_tsc(uint64_t offset, const struct pt_packet_tsc *packet) {
    int errcode;

    if (1 /* !options->no_tcal */) {
      errcode = tracking.in_header
                    ? pt_tcal_header_tsc(&tracking.tcal, packet, &config)
                    : pt_tcal_update_tsc(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%s: error calibrating time\n", __PRETTY_FUNCTION__);
      }
    }

    errcode = pt_time_update_tsc(&tracking.time, packet, &config);
    assert(errcode == 0);

    assert(tracking.time.have_tsc);
    this->track_time(offset, tracking.time.tsc);

    return 0;
  }

  int track_cbr(uint64_t offset, const struct pt_packet_cbr *packet) {
    int errcode;

    if (1 /* !options->no_tcal */) {
      errcode = tracking.in_header
                    ? pt_tcal_header_cbr(&tracking.tcal, packet, &config)
                    : pt_tcal_update_cbr(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%s: error calibrating time\n", __PRETTY_FUNCTION__);
      }
    }

    errcode = pt_time_update_cbr(&tracking.time, packet, &config);
    if (unlikely(errcode < 0)) {
      if constexpr (IsVerbose())
        fprintf(stderr, "%s: error updating time\n", __PRETTY_FUNCTION__);
    }

    if (likely(tracking.time.have_tsc))
      this->track_time(offset, tracking.time.tsc);
    return 0;
  }

  int track_tma(uint64_t offset, const struct pt_packet_tma *packet) {
    int errcode;

    if (1 /* !options->no_tcal */) {
      errcode = pt_tcal_update_tma(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%s: error calibrating time\n", __PRETTY_FUNCTION__);
      }
    }

    errcode = pt_time_update_tma(&tracking.time, packet, &config);
    if (unlikely(errcode < 0)) {
      if constexpr (IsVerbose())
        fprintf(stderr, "%s: error updating time\n", __PRETTY_FUNCTION__);
    }

    if (likely(tracking.time.have_tsc))
      this->track_time(offset, tracking.time.tsc);
    return 0;
  }

  int track_mtc(uint64_t offset, const struct pt_packet_mtc *packet) {
    int errcode;

    if (1 /* !options->no_tcal */) {
      errcode = pt_tcal_update_mtc(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%s: error calibrating time: %s\n",
                  __PRETTY_FUNCTION__, pt_errstr(pt_errcode(errcode)));
      }
    }

    errcode = pt_time_update_mtc(&tracking.time, packet, &config);
    if (unlikely(errcode < 0)) {
      if constexpr (IsVerbose())
        fprintf(stderr, "%s: error updating time: %s\n", __PRETTY_FUNCTION__,
                pt_errstr(pt_errcode(errcode)));
    }

    if (likely(tracking.time.have_tsc))
      this->track_time(offset, tracking.time.tsc);
    return 0;
  }

  int track_cyc(uint64_t offset, const struct pt_packet_cyc *packet) {
    uint64_t fcr;
    int errcode;

    /* Initialize to zero in case of calibration errors. */
    fcr = 0ull;

    if (1 /* !options->no_tcal */) {
      errcode = pt_tcal_fcr(&fcr, &tracking.tcal);

      if (unlikely(errcode < 0)) {
#if 0
			if constexpr (IsVerbose())
                                fprintf(stderr, "%s: calibration error (1): %s\n",
                                        __func__,
                                        pt_errstr(pt_errcode(errcode)));
#endif
      }

      errcode = pt_tcal_update_cyc(&tracking.tcal, packet, &config);
      if (unlikely(errcode < 0)) {
        if constexpr (IsVerbose())
          fprintf(stderr, "%s: error calibrating time (2): %s\n", __func__,
                  pt_errstr(pt_errcode(errcode)));
      }
    }

    errcode = pt_time_update_cyc(&tracking.time, packet, &config, fcr);

    if (unlikely(errcode < 0)) {
      if constexpr (IsVerbose())
        fprintf(stderr, "%s: error updating time (3): %s\n", __func__,
                pt_errstr(pt_errcode(errcode)));
    } else if (!fcr) {
#if 0
		if constexpr (IsVerbose())
                        fprintf(stderr,
                                "%s: error updating time (4): no calibration\n",
                                __func__);
#endif
    }

    if (likely(tracking.time.have_tsc))
      this->track_time(offset, tracking.time.tsc);
    return 0;
  }
};

#undef IsVerbose
#undef IsVeryVerbose

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

#pragma once
#if (defined(__x86_64__) || defined(__i386__)) &&                              \
    (defined(TARGET_X86_64) || defined(TARGET_I386))
#include "jove/jove.h"
#include "B.h"
#include <memory>
#include <cstdio>
#include <array>
#include <boost/preprocessor/seq/for_each_product.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/seq.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <boost/unordered/unordered_node_map.hpp>
#include <boost/unordered/unordered_flat_set.hpp>

struct pt_config;
struct pt_sb_session;
struct pt_packet_decoder;
struct pt_sb_pevent_config;
struct pt_packet;
struct pt_packet_cyc;
struct pt_packet_tnt;
struct pt_packet_tsc;
struct pt_packet_cbr;
struct pt_packet_mtc;
struct pt_packet_tma;
struct pt_last_ip;
struct pt_time_cal;
struct pt_time;
struct pev_event;

namespace jove {

class explorer_t;

#define IPT_PARAMETERS \
  ((unsigned, Verbosity, (0)(1)(2))) \
  ((bool, Caching, (false)(true)))    \
  ((bool, Objdump, (false)(true)))

#define IPT_PARAM_DECL(r, data, i, elem)                                       \
  BOOST_PP_COMMA_IF(i)                                                         \
  BOOST_PP_TUPLE_ELEM(3, 0, elem) /* Type */                                   \
  /* space */                                                                  \
  BOOST_PP_TUPLE_ELEM(3, 1, elem) /* Name */

#define IPT_PARAMETERS_DCL                                                \
  BOOST_PP_SEQ_FOR_EACH_I(IPT_PARAM_DECL, _, IPT_PARAMETERS)

#define IPT_PARAM_NAME(r, data, i, elem)                                       \
  BOOST_PP_COMMA_IF(i)                                                         \
  BOOST_PP_TUPLE_ELEM(3, 1, elem)

#define IPT_PARAMETERS_DEF                                                \
  BOOST_PP_SEQ_FOR_EACH_I(IPT_PARAM_NAME, _, IPT_PARAMETERS)

/* reference IPT decoder */
template <IPT_PARAMETERS_DCL>
class IntelPT {
  jv_t &jv;
  explorer_t &explorer;

  std::unique_ptr<struct pt_config> config;
  struct pt_packet_decoder *decoder = NULL;

  struct {
    struct pt_sb_session *session = NULL;

    std::unique_ptr<struct pt_last_ip> last_ip;
    std::unique_ptr<struct pt_time_cal> tcal;
    std::unique_ptr<struct pt_time> time;

    uint64_t tsc = 0ull; /* The last estimated TSC. */
    uint64_t fcr = 0ull; /* The last calibration value. */

    uint32_t in_header = 0; /* Header vs. normal decode. */
  } tracking;

  using straight_line_t = basic_block_properties_t::Analysis_t::straight_line_t;

#if 0
  class basic_block_state_t {
    basic_block_properties_t &prop;

  public:
    basic_block_state_t(const binary_t &b, basic_block_t bb)
        : prop(const_cast<basic_block_properties_t &>(b.Analysis.ICFG[bb])) {}

    const straight_line_t &SL(const binary_t &b, basic_block_t bb);
  };

  template <bool X = Caching>
  std::enable_if_t<X, const straight_line_t &> SLForBlock(const binary_t &b,
                                                          basic_block_t bb) {
    return state.for_basic_block(b, bb).SL(b, bb);
  }

  static constexpr bool Lazy = false;
#else
  struct basic_block_state_t {
    straight_line_t theSL;

    basic_block_state_t(const binary_t &b, basic_block_t bb);
  };

  template <bool X = Caching>
  std::enable_if_t<X, const straight_line_t &> SLForBlock(const binary_t &b,
                                                          basic_block_t bb) {
    return state.for_basic_block(b, bb).theSL;
  }
  static constexpr bool Lazy = true;
#endif

  struct binary_state_t {
    std::unique_ptr<llvm::object::Binary> Bin;

    struct {
      taddr_t LoadAddr = ~0UL;
    } _coff;

    std::conditional_t<Objdump && Caching, objdump_output_t<false>,
                       std::monostate>
        m_objdump;

    binary_state_t(const binary_t &b);
  };

  using BBState = std::conditional_t<Caching, basic_block_state_t, void>;

  jv_state_t<binary_state_t, void, BBState, false, Lazy> state;

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
    unsigned ExecBits = 8*sizeof(taddr_t);
  } Curr;

  class Point_t {
    std::reference_wrapper<binary_t> b;
    basic_block_index_t Idx = invalid_basic_block_index;

    struct {
      taddr_t Addr = uninit_taddr;
      taddr_t TermAddr = uninit_taddr;
    } Cached;

  public:
    Point_t(binary_t &b) : b(b) {}

    binary_t &Binary(void) const { return b; }
    binary_index_t BinaryIndex(void) const { return index_of_binary(b); }

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
             is_taddr_valid(Cached.Addr) &&
             is_taddr_init(Cached.TermAddr)
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

    void SetBinary(binary_t &newb) {
      b = newb;
#ifndef NDEBUG
      Cached.Addr = uninit_taddr;
      Cached.TermAddr = uninit_taddr;
#endif
    }
  } CurrPoint;

  const std::string path_to_wine_bin;
  static inline const std::string wine_env_of_interest = "WINELOADERNOEXEC=1";

  bool IsRightProcess(unsigned pid) const {
    // the following is equivalent to pid != 0UL && pid != ~0UL
    //return !!((pid + unsigned(1)) & unsigned(~1ull));
    return Our.pids.contains(pid);
  }

  bool RightProcess(void) const {
    return IsRightProcess(Curr.pid);
  }

  bool RightExecMode(void) const {
    return Curr.ExecBits == 8*sizeof(taddr_t);
  }

  bool Engaged = false;
  bool CheckEngaged(void) {
    return (Engaged = RightExecMode() && RightProcess());
  }

  const bool ignore_trunc_aux;

  void examine_sb_event(const struct pev_event &, uint64_t offset);

  void ptdump_tracking_init(void);
  void ptdump_tracking_reset(void);

  int process_packet(uint64_t offset, struct pt_packet *);
  int track_cyc(uint64_t offset, const struct pt_packet_cyc *);
  int sb_track_time(uint64_t offset);
  int track_time(uint64_t offset);
  int track_tsc(uint64_t offset, const struct pt_packet_tsc *);
  int track_cbr(uint64_t offset, const struct pt_packet_cbr *);
  int track_tma(uint64_t offset, const struct pt_packet_tma *);
  int track_mtc(uint64_t offset, const struct pt_packet_mtc *);

  int tnt_payload(const struct pt_packet_tnt &, const uint64_t offset);
  int on_ip(const taddr_t ip, const uint64_t offset);

  int ptdump_sb_pevent(const char *filename, const struct pt_sb_pevent_config *);
  int process_args(int argc, char **argv, const char *sideband_filename);

  template <bool InfiniteLoopThrow = false>
  std::pair<basic_block_index_t, bool>
  StraightLineUntilSlow(const binary_t &,
                        basic_block_index_t,
                        taddr_t GoNoFurther,
                        std::function<basic_block_index_t(const basic_block_properties_t &, basic_block_index_t)> on_final_block = [](const basic_block_properties_t &, basic_block_index_t Res) -> basic_block_index_t { return Res; });

  template <bool InfiniteLoopThrow = false>
  basic_block_index_t
  StraightLineSlow(const binary_t &,
                   basic_block_index_t,
                   std::function<basic_block_index_t(const basic_block_properties_t &, basic_block_index_t)> on_final_block = [](const basic_block_properties_t &, basic_block_index_t Res) -> basic_block_index_t { return Res; });

  void TNTAdvance(uint64_t tnt, uint8_t n);

  struct {
    struct {
      binary_index_t BIdx = invalid_binary_index;
      basic_block_index_t BBIdx = invalid_basic_block_index;
    } Last;
  } OnBlock;

  void on_block(const binary_t &, const basic_block_properties_t &,
                basic_block_t);
  void block_transfer(binary_t &from, taddr_t FromAddr,
                      binary_t &to, taddr_t ToAddr);

public:
  IntelPT(int ptdump_argc, char **ptdump_argv, jv_t &, explorer_t &,
          unsigned cpu, void *begin,
          void *end, const char *sb_filename, unsigned verbose,
          bool ignore_trunc_aux = false);
  ~IntelPT();

  int explore(void);
  int explore_packets(void);

  int ptdump_print_error(int errcode, const char *filename, uint64_t offset);
};

struct truncated_aux_exception {};

}

#endif /* x86 */

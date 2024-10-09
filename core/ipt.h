#pragma once
#if (defined(__x86_64__) || defined(__i386__)) &&                              \
    (defined(TARGET_X86_64) || defined(TARGET_I386))
#include "jove/jove.h"
#include "B.h"
#include <memory>
#include <cstdio>
#include <array>

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

namespace jove {

class explorer_t;

/* reference IPT decoder */
template <unsigned Verbosity>
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

  struct binary_state_t {
    std::unique_ptr<llvm::object::Binary> Bin;

    struct {
      taddr_t LoadAddr = ~0UL;
    } _coff;

    binary_state_t(const binary_t &b); /* runs objdump */
  };

  jv_state_t<binary_state_t, void, void> state;

  const bool IsCOFF;

  const address_space_t AddressSpaceInit;
  boost::container::flat_map<addr_intvl, std::pair<binary_index_t, uint64_t>,
                             addr_intvl_cmp>
      AddressSpace;

  struct {
    std::string s1, s2;
    std::vector<uint8_t> u8v;
  } __buff;

  struct syscall_state_t {
    long nr = -1;
    std::array<taddr_t, 6> args;
    int8_t dir = -1;
  };

  std::unordered_map<uint32_t, syscall_state_t> syscall_state_map;

  struct {
    FILE *os = NULL;

    char *ptr = NULL;
    size_t len = 0UL;
  } sideband;

  static constexpr uint32_t sb_dump_flags = 1; /* compact */

  struct {
    unsigned cpu = ~0u;
    unsigned pid = ~0u;
  } Our;

  struct {
    unsigned pid = ~0u;
    unsigned ExecBits = 8*sizeof(taddr_t);

    block_t Block = invalid_block;
    taddr_t TermAddr = ~0UL;
  } Curr;

  struct {
    unsigned ExecCount = 0; /* FIXME when and why does wine exec twice... */
  } _wine;

  bool RightWineExecCount(void) const {
    return _wine.ExecCount == 2;
  }

  bool IsRightProcess(unsigned pid) const {
    return pid == Our.pid && !(IsCOFF && !RightWineExecCount());
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

  void examine_sb(void);

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

  int tnt_payload(const struct pt_packet_tnt *);
  int on_ip(const taddr_t ip, const uint64_t offset);

  int ptdump_sb_pevent(char *filename, const struct pt_sb_pevent_config *conf,
                       const char *prog);
  int process_args(int argc, char **argv);

  template <bool DoNotGoFurther>
  __attribute__((always_inline))
  std::pair<basic_block_index_t, bool>
  DoStraightLineAdvance(block_t, taddr_t GoNoFurther = 0);

  std::pair<basic_block_index_t, bool>
  StraightLineAdvance(block_t, taddr_t GoNoFurther);

  std::pair<basic_block_index_t, bool>
  StraightLineAdvance(block_t);

  basic_block_index_t TNTAdvance(block_t, uint64_t tnt, uint8_t n);

  void on_block(block_t);
  void block_transfer(binary_index_t FromBIdx, taddr_t FromAddr,
                      binary_index_t ToBIdx, taddr_t ToAddr);

public:
  IntelPT(int ptdump_argc, char **ptdump_argv, jv_t &, explorer_t &,
          unsigned cpu, const address_space_t &AddressSpaceInit, void *begin,
          void *end, unsigned verbose, bool ignore_trunc_aux = false);
  ~IntelPT();

  __attribute__((always_inline))
  bool IsVerbose(void) const {
    return Verbosity >= 1;
  }

  __attribute__((always_inline))
  bool IsVeryVerbose(void) const {
    return Verbosity >= 2;
  }

  int explore(void);
  int explore_packets(void);

  int ptdump_print_error(int errcode, const char *filename, uint64_t offset);
};

struct truncated_aux_exception {};

}

#endif /* x86 */

#pragma once
#if defined(__x86_64__) || defined(__i386__) /* x86 only */
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
struct pt_packet_ip;
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
    uint64_t SectsStartAddr, SectsEndAddr;

    binary_state_t(const binary_t &b) {
      Bin = B::Create(b.data());

      std::tie(SectsStartAddr, SectsEndAddr) = B::bounds_of_binary(*Bin);
    }
  };

  jv_state_t<binary_state_t, void, void> state;

  const address_space_t AddressSpaceInit;
  boost::container::flat_map<addr_intvl, std::pair<binary_index_t, uint64_t>,
                             addr_intvl_cmp>
      AddressSpace;

  struct syscall_state_t {
    long nr;
    std::array<taddr_t, 6> args;
    unsigned dir : 1;

    syscall_state_t() : dir(0) {}
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
//  unsigned tid = ~0u;
  } Our;

  struct {
    unsigned pid = ~0u - 1;
//  unsigned tid = ~0u - 1;
    bool exec = 4;

    block_t Block = invalid_block;
    taddr_t TermAddr = ~0UL;
  } Curr;

  bool Engaged = false;
  void CheckEngaged(void) {
    bool RightExecMode = Curr.exec == IsTarget32;
    //bool RightThread = Curr.tid == Our.tid;
    bool RightProcess = Curr.pid == Our.pid;

    Engaged = /* RightCpu && */
              RightExecMode &&
              /* RightThread && */
              RightProcess;
  }

  const bool v, vv;

  const bool ignore_trunc_aux;

  void examine_sb(void);

  void ptdump_tracking_init(void);
  void ptdump_tracking_reset(void);

  int process_packet(uint64_t offset, const struct pt_packet *);
  int track_last_ip(const struct pt_packet_ip *, uint64_t offset);
  int track_cyc(uint64_t offset, const struct pt_packet_cyc *);
  int sb_track_time(uint64_t offset);
  int track_time(uint64_t offset);
  int track_tsc(uint64_t offset, const struct pt_packet_tsc *);
  int track_cbr(uint64_t offset, const struct pt_packet_cbr *);
  int track_tma(uint64_t offset, const struct pt_packet_tma *);
  int track_mtc(uint64_t offset, const struct pt_packet_mtc *);

  int tnt_payload(const struct pt_packet_tnt *);
  int on_ip(const uint64_t ip, const uint64_t offset);

  int ptdump_sb_pevent(char *filename, const struct pt_sb_pevent_config *conf,
                       const char *prog);
  int process_args(int argc, char **argv);

  std::pair<basic_block_index_t, bool>
  StraightLineAdvance(block_t, uint64_t GoNoFurther = 0);

  basic_block_index_t Advance(block_t, uint64_t tnt, uint8_t n);

  void on_block(block_t);
  void block_transfer(binary_index_t FromBIdx, taddr_t FromAddr,
                      binary_index_t ToBIdx, taddr_t ToAddr);

public:
  IntelPT(int ptdump_argc, char **ptdump_argv, jv_t &, explorer_t &,
          unsigned cpu, const address_space_t &AddressSpaceInit, void *begin,
          void *end, unsigned verbose, bool ignore_trunc_aux = false);
  ~IntelPT();

  bool IsVerbose(void) const {
    return unlikely(v);
  }

  bool IsVeryVerbose(void) const {
    return unlikely(vv);
  }

  int explore(void);
  int explore_packets(void);

  int ptdump_print_error(int errcode, const char *filename, uint64_t offset);

  struct truncated_aux_exception {};
};

}

#endif /* x86 */

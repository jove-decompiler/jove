#pragma once
#if defined(__x86_64__) || defined(__i386__) /* x86 only */
#include "jove/jove.h"
#include "B.h"
#include <memory>

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
  };

  jv_state_t<binary_state_t, void, void> state;

  const address_space_t &AddressSpace;

  bool RightExecMode = false;

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
  int on_ip(const uint64_t ip);

  int ptdump_sb_pevent(char *filename, const struct pt_sb_pevent_config *conf,
                       const char *prog);
  int process_args(int argc, char **argv);

public:
  IntelPT(int ptdump_argc, char **ptdump_argv, jv_t &, explorer_t &,
          const address_space_t &AddressSpace, void *begin, void *end);
  ~IntelPT();

  int explore(void);
  int explore_packets(void);

  int ptdump_print_error(int errcode, const char *filename, uint64_t offset);
};

}

#endif /* x86 */

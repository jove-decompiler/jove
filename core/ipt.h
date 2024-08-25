#pragma once
#if defined(__x86_64__) || defined(__i386__) /* x86 only */
#include "jove/jove.h"
#include <memory>

struct pt_config;
struct pt_packet_decoder;
struct pt_packet;
struct pt_packet_ip;
struct pt_packet_tnt;
struct pt_last_ip;
#if 0
struct pt_sb_session;
#endif

namespace jove {

class IntelPT {
  jv_t &jv;

  std::unique_ptr<struct pt_config> config;
#if 0
  struct pt_sb_session *session = NULL;
#endif
  struct pt_packet_decoder *decoder = NULL;

  std::unique_ptr<struct pt_last_ip> last_ip;

  int process_packet(uint64_t offset, const struct pt_packet *);
  int track_last_ip(const struct pt_packet_ip *, uint64_t offset);
  int tnt_payload(const struct pt_packet_tnt *);

public:
  IntelPT(jv_t &, void *begin, void *end);
  ~IntelPT();

  int visit_all(void);
  int visit_packets(void);
};

}

#endif /* x86 */

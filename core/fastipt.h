#pragma once
#if defined(__x86_64__) || defined(__i386__) /* x86 only */
#include "jove/jove.h"

namespace jove {

class explorer_t;

/* winafl IPT decoder */
template <bool MT>
class FastIPT {
  jv_base_t<MT> &jv;
  explorer_t &explorer;

  void *begin;
  void *end;

  uint32_t previous_offset = 0;
  uint64_t previous_ip = 0;

public:
  FastIPT(jv_base_t<MT> &, explorer_t &, unsigned cpu,
          const address_space_t &AddressSpace, void *begin, void *end,
          bool ignore_trunc_aux = false);

  uint64_t decode_ip(unsigned char *data);

  void explore(void);
};

}
#endif /* x86 */

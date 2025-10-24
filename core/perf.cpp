#include "perf.h"
#include "mmap.h"
#include "fd.h"

namespace jove {
namespace perf {

static const char *__magic1 = "PERFFILE";
static const uint64_t __magic2    = 0x32454c4946524550ULL;
static const uint64_t __magic2_sw = 0x50455246494c4532ULL;

static bool is_magic(uint64_t magic) {
  if (!memcmp(&magic, __magic1, sizeof(magic))
      || magic == __magic2
      || magic == __magic2_sw)
  return true;

  return false;
}

template <bool HasHeader>
template <bool H, typename>
bool data_reader<HasHeader>::check_magic(void) const {
  return is_magic(*reinterpret_cast<const uint64_t *>(&get_header().magic[0]));
}

template struct data_reader<false>;
template struct data_reader<true>;

}
}

#include "prefetch.h"

#include <thread>
#include <sys/mman.h>

namespace jove {

void _async_populate_read_forever(void* addr, size_t len) {
  std::thread([addr, len] {
    (void)::madvise(addr, len, MADV_POPULATE_READ);
  }).detach();
}

}

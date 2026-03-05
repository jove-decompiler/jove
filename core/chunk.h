#pragma once
#include "assert.h"

#include <unistd.h>

namespace jove {

struct chunked_thing {
  const unsigned chunk_size;
  chunked_thing() : chunk_size(sysconf(_SC_PAGESIZE)) {
    aassert(chunk_size >= 4096);
  }
};

}

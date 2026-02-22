#include "perf.h"
#include "mmap.h"
#include "fd.h"

namespace jove {
namespace perf {

template struct data_reader<false>;
template struct data_reader<true>;

}
}

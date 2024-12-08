#include "perf.h"
#include "mmap.h"
#include "fd.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/WithColor.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/FormatVariadic.h>

#include <stdexcept>

#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

namespace fs = boost::filesystem;

namespace jove {
namespace perf {

template <bool HasHeader>
data_reader<HasHeader>::data_reader(const char *filename, bool sequential) {
  contents.fd = std::make_unique<scoped_fd>(::open(filename, O_RDONLY));
  if (!(*contents.fd))
    throw std::runtime_error(std::string("failed to open \"") + filename + "\"");

  auto len = fs::file_size(filename);
  contents.mmap = std::make_unique<scoped_mmap>(
      nullptr, len, PROT_READ, MAP_PRIVATE, contents.fd->get(), 0);
  if (!(*contents.mmap))
    throw std::runtime_error(std::string("mmap failed: ") + strerror(errno));

  if constexpr (HasHeader)
    if (!check_magic())
      throw std::runtime_error(std::string("\"") + filename +
                               std::string("\" is not perf.data"));

  if (sequential)
    if (::madvise(contents.mmap->ptr, contents.mmap->len, MADV_SEQUENTIAL) < 0)
      throw std::runtime_error(std::string("madvise failed: ") +
                               strerror(errno));
}

template <bool HasHeader>
data_reader<HasHeader>::~data_reader() {}

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

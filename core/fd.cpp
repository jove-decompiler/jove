#include "fd.h"

#include <cstring>

#include <unistd.h>
#include <limits.h>

namespace jove {

std::string scoped_fd::readlink_path(void) const noexcept(false) {
  std::string res;
  res.resize(2 * PATH_MAX);

  std::string proc_path = "/proc/self/fd/" + std::to_string(this->get());

  ssize_t len = ::readlink(proc_path.c_str(), &res[0], res.size() - 1);
  if (len < 0) {
    const int err = errno;
    throw std::runtime_error("readlink() failed: " + std::string(strerror(err)));
  }

  assert(len < res.size());
  res.resize(len);

  return res;
}

}

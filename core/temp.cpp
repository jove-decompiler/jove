#include "temp.h"

#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace jove {

temp_executable::temp_executable(const void *contents, size_t size,
                                 const std::string &temp_prefix)
    : contents(contents), size(size) {
  int fd = -1;

#ifdef JOVE_HAVE_MEMFD
  fd = ::memfd_create(temp_prefix.c_str(), MFD_CLOEXEC);
  if (fd < 0)
    throw std::runtime_error(std::string("memfd_create failed: ") + strerror(errno));

  _path = "/proc/self/fd/" + std::to_string(fd);
#else
  _path = "/tmp/" + temp_prefix + ".XXXXXX";

  fd = mkstemp(&_path[0]);
  if (fd < 0)
    throw std::runtime_error(std::string("mkstemp failed: ") + strerror(errno));
#endif

  _fd = std::make_unique<scoped_fd>(fd);
}

void temp_executable::store(void) {
  if (::fchmod(_fd->get(), 0777) < 0)
    throw std::runtime_error(std::string("temp_executable: fchmod failed: ") +
                             strerror(errno));

  long ret = robust_write(_fd->get(), contents, size);
  if (ret != size)
    throw std::runtime_error("temp_executable: robust_write gave " +
                             std::to_string(ret));

#ifndef JOVE_HAVE_MEMFD
  _fd.reset();
#endif
}

temp_executable::~temp_executable() {
#ifndef JOVE_HAVE_MEMFD
  ::unlink(_path.c_str());
#endif
}

}

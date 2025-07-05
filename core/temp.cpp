#include "temp.h"

#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

namespace jove {

temp_file::temp_file(const void *contents, size_t N,
                     const std::string &temp_prefix, bool close_on_exec)
    : contents(contents), N(N), fd(({
        int fd_ = -1;

#ifdef JOVE_HAVE_MEMFD
        unsigned flags = 0;
        if (close_on_exec)
          flags |= MFD_CLOEXEC;
        fd_ = ::memfd_create(temp_prefix.c_str(), flags);
        if (fd_ < 0)
          throw std::runtime_error(std::string("memfd_create failed: ") +
                                   strerror(errno));
#else
	std::string path = "/tmp/" + temp_prefix + ".XXXXXX";

	fd_ = mkostemp(&path[0], O_CLOEXEC);
	if (fd_ < 0)
          throw std::runtime_error(std::string("mkstemp failed: ") +
                                   strerror(errno));
#endif
        fd_;
      })),

      path_(
#ifdef JOVE_HAVE_MEMFD
          "/proc/self/fd/" + std::to_string(fd.get())
#else
          fd.readlink_path()
#endif
      ) {
}

void temp_file::store(void) noexcept(false) {
  ssize_t ret = robust_write(fd.get(), contents, this->N);
  if (ret != this->N)
    throw std::runtime_error("temp_file: robust_write gave " +
                             std::to_string(ret));

#ifndef JOVE_HAVE_MEMFD
  fd.close();
#endif
}

temp_file::~temp_file() {
#ifndef JOVE_HAVE_MEMFD
  ::unlink(path_.c_str());
#endif
}

void temp_exe::store(void) noexcept(false) {
  if (::fchmod(fd.get(), 0777) < 0)
    throw std::runtime_error(std::string("temp_exe: fchmod failed: ") +
                             strerror(errno));

  temp_file::store();
}

}

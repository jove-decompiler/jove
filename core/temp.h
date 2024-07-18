#pragma once
#include "fd.h"
#include <memory>
#include <string>

namespace jove {

// this class creates an executable with known contents at an accessible path
// (suitable for execve) and removes it on destruction
struct temp_executable {
  const void *const contents;
  const size_t size;

  std::unique_ptr<scoped_fd> _fd;
  std::string _path;

  temp_executable(const void *contents, size_t size,
                  const std::string &temp_prefix);
  ~temp_executable();

  void store(void);

  const std::string &path(void) { return _path; }
};

}

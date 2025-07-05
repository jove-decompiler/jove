#pragma once
#include "fd.h"
#include <memory>
#include <string>

namespace jove {

//
// this class creates a file with known contents at an accessible path and
// removes it on destruction
//
class temp_file {
  const void *const contents;
  const size_t N;

protected:
  scoped_fd fd;

private:
  const std::string path_;

public:
  temp_file(const void *contents, size_t N,
	    const std::string &temp_prefix,
            bool close_on_exec = true);
  virtual ~temp_file(); /* removes from filesystem */

  virtual void store(void) noexcept(false);

  //
  // if JOVE_HAVE_MEMFD, path will be of the form: /proc/self/fd/n
  // otherwise:                                    /tmp/temp_prefix.XXXXXX
  //
  const std::string &path(void) const noexcept { return path_; }
};


//
// this class creates an executable with known contents at an accessible path,
// suitable for use with execve(2)
//
struct temp_exe : public temp_file {
  template <typename... Args>
  temp_exe(Args &&...args) : temp_file(std::forward<Args>(args)...) {}

  void store(void) noexcept(false) override;
};

}

#include "pipe.h"
#include "fd.h"
#include "eintr.h"

#include <cstring>
#include <stdexcept>

#include <unistd.h>

namespace jove {

pipe_line_reader::pipe_line_reader() : chunk_size(sysconf(_SC_PAGESIZE)) {
  aassert(chunk_size >= 4096);
}

std::optional<std::string> pipe_line_reader::get_line(int fd) {
  for (;;) {
    // search only the unconsumed region
    size_t pos = buff.find('\n', start);

    if (pos != std::string::npos) {
      std::string line(buff.data() + start, pos - start);
      start = pos + 1;
      return line;
    }

    // occasionally compact buffer
    if (start > 65536) {
      buff.erase(0, start);
      start = 0;
    }

    size_t old = buff.size();
    buff.resize(old + chunk_size);

    ssize_t n = sys::retry_eintr(::read, fd, buff.data() + old, chunk_size);

    if (n < 0)
      throw std::runtime_error("pipe read failed");

    if (n == 0)
      break;

    buff.resize(old + n);
  }

  return std::nullopt;
}

}

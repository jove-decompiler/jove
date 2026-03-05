#include "pipe.h"
#include "fd.h"
#include "eintr.h"

#include <cstring>
#include <stdexcept>

#include <unistd.h>

namespace jove {

std::string pipe_reader::get(void) {
  std::string out;

  for (;;) {
    const size_t old = out.size();

    out.resize(old + chunk_size);
    ssize_t n = sys::retry_eintr(::read, fd, &out[old], chunk_size);
    if (n < 0) {
      int err = errno;
      if (err == EINTR)
        continue;

      throw std::runtime_error(std::string(__func__) + ": " + strerror(err));
    }

    if (n == 0) {
      out.resize(old);
      break;
    }

    out.resize(old + n);
  }

  return out;
}

std::optional<std::string> pipe_line_reader::get_line(void) {
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

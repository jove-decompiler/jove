#include "pipe.h"
#include "fd.h"

#include <cstring>
#include <stdexcept>

namespace jove {

std::optional<std::string> pipe_line_reader::get_line(int rfd) {
  std::string res;
  for (;;) {
    // do we have a line ready to go?
    ssize_t pos;
    if ((pos = buff.find('\n')) != std::string::npos) {
      res = buff.substr(0, pos);
      buff.erase(0, pos + 1);
      break;
    }

    tmpbuff.resize(4096);

    ssize_t ret;
    do
      ret = ::read(rfd, &tmpbuff[0], tmpbuff.size());
    while (ret < 0 && errno == EINTR);

    if (ret < 0)
      throw std::runtime_error("failed to read pipe: " + std::string(strerror(errno)));

    if (ret == 0)
      return std::optional<std::string>(std::nullopt);

    tmpbuff.resize(ret);
    buff.append(tmpbuff);
  }

  return res;
}

}

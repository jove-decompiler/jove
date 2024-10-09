#pragma once
#include <string>
#include <optional>

namespace jove {

struct pipe_line_reader {
  std::string tmpbuff;
  std::string buff;

  std::optional<std::string> get_line(int fd);
};

}

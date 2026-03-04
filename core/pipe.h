#pragma once
#include <string>
#include <optional>

namespace jove {

struct pipe_line_reader {
  std::string buff;
  size_t start = std::string::npos;
  const unsigned chunk_size;

  pipe_line_reader();

  std::optional<std::string> get_line(int fd);
};

}

#pragma once
#include "chunk.h"

#include <string>
#include <optional>

namespace jove {

struct fd_thing_t {
  const int fd = -1;

  fd_thing_t(int fd) : fd(fd) {}
};


struct pipe_reader : public chunked_thing, public fd_thing_t {
  pipe_reader(int fd) : fd_thing_t(fd) {}

  std::string get(void);
};

struct pipe_line_reader : public chunked_thing, public fd_thing_t {
  std::string buff;
  size_t start = std::string::npos;

  pipe_line_reader(int fd) : fd_thing_t(fd) {}

  std::optional<std::string> get_line(void);
};

}

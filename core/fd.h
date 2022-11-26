#pragma once

namespace jove {

class scoped_fd {
  int fd;

public:
  scoped_fd(int fd) : fd(fd) {}
  ~scoped_fd();
};

}

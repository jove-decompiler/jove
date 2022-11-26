#include "fd.h"

#include <unistd.h>

namespace jove {

scoped_fd::~scoped_fd() {
  ::close(this->fd);
}

}

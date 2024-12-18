#pragma once
#include <cstdint>

namespace jove {

int cp_reflink(int src_fd, int dst_fd, uint64_t len = 0);
int cp_reflink_to(int src_fd, const char *dst_filename, uint64_t len = 0);

}

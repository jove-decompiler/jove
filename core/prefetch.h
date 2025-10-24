#pragma once
#include <cstddef>

namespace jove {

// NOTE: it is assumed that the given memory region will never be unmapped
// (hence the leading underscore)
void _async_populate_read(void* addr, size_t len);

}

#pragma once
#include <cstddef>

namespace jove {

static constexpr size_t KiB = 1ull << 10;
static constexpr size_t MiB = KiB << 10;
static constexpr size_t GiB = MiB << 10;

static_assert(sizeof(size_t)*8 >= 31);

}

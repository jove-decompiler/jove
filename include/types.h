#pragma once
#include <cstdint>
#include <string>

namespace jove {
typedef uint64_t address_t;
typedef unsigned section_number_t;
struct symbol_t {
  address_t addr;
  std::string name;
};
}

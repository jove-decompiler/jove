#pragma once
#include "jove/jove.h"
#include <utility>

namespace jove {

struct tiny_code_generator_private_t;

class tiny_code_generator_t {
public:
  tiny_code_generator_t();

  void set_elf(const void *e);

  std::pair<unsigned, terminator_info_t> translate(tcg_uintptr_t pc,
                                                   tcg_uintptr_t pc_end = 0);

  void dump_operations(void);

  tiny_code_generator_private_t *priv;
};

}

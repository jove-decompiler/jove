#pragma once
#include "jove/jove.h"
#include <memory>

namespace jove {

struct tiny_code_generator_private_t;

struct tiny_code_generator_t {
  std::unique_ptr<tiny_code_generator_private_t> priv;

  tiny_code_generator_t();
  ~tiny_code_generator_t();

  void set_elf(const void *e);

  std::pair<unsigned, terminator_info_t> translate(tcg_uintptr_t pc,
                                                   tcg_uintptr_t pc_end = 0);

  void dump_operations(void);
};

}

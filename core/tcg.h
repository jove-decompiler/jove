#pragma once
#include "jove/jove.h"
#include "elf.h"
#include <memory>
#include <utility>

namespace jove {

struct tiny_code_generator_private_t;

struct tiny_code_generator_t {
  std::unique_ptr<tiny_code_generator_private_t> priv;

  tiny_code_generator_t();
  ~tiny_code_generator_t();

  void set_binary(llvm::object::Binary &);

  std::pair<unsigned, terminator_info_t> translate(tcg_uintptr_t pc,
                                                   tcg_uintptr_t pc_end = 0);

  void dump_operations(void);
};

}

#pragma once
#include "jove/jove.h"
#include "elf.h"

#include <memory>
#include <utility>

namespace jove {

struct g2h_exception {
  uint64_t pc;

  g2h_exception(uint64_t pc) : pc(pc) {}
};

struct tiny_code_generator_private_t;

struct tiny_code_generator_t {
  tiny_code_generator_t();
  ~tiny_code_generator_t();

  void set_binary(llvm::object::Binary &);

  std::pair<unsigned, terminator_info_t> translate(uint64_t pc,
                                                   uint64_t pc_end = 0);

  void dump_operations(void);

  void print_shit(void);
};

}

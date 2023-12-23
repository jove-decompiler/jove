#pragma once
#include "disas.h"
#include "tcg.h"
#include <llvm/Object/ELFObjectFile.h>
#include <functional>

namespace jove {

struct explorer_t {
  disas_t &disas;
  tiny_code_generator_t &tcg;
  jv_file_t &jv_file;
  ip_void_allocator_t Alloc;

  explorer_t(disas_t &disas, tiny_code_generator_t &tcg, jv_file_t &jv_file)
      : disas(disas), tcg(tcg), jv_file(jv_file),
        Alloc(ip_void_allocator_t(jv_file.get_segment_manager())) {}

  basic_block_index_t explore_basic_block(binary_t &b,
                                          llvm::object::Binary &B,
                                          const uint64_t Addr,
                                          fnmap_t &,
                                          bbmap_t &,
                                          std::function<void(binary_t &, basic_block_t)> on_newbb_proc = [](binary_t &, basic_block_t){});

  function_index_t explore_function(binary_t &b,
                                    llvm::object::Binary &B,
                                    const uint64_t Addr,
                                    fnmap_t &,
                                    bbmap_t &,
                                    std::function<void(binary_t &, basic_block_t)> on_newbb_proc = [](binary_t &, basic_block_t){});
};

}

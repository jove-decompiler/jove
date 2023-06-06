#pragma once
#include "disas.h"
#include "tcg.h"
#include <llvm/Object/ELFObjectFile.h>
#include <functional>

namespace jove {

basic_block_index_t explore_basic_block(binary_t &b,
                                        llvm::object::Binary &B,
                                        tiny_code_generator_t &,
                                        disas_t &,
                                        const uint64_t Addr,
                                        fnmap_t &,
                                        bbmap_t &,
                                        std::function<void(binary_t &, basic_block_t)> on_newbb_proc = [](binary_t &, basic_block_t){});

function_index_t explore_function(binary_t &b,
                                  llvm::object::Binary &B,
                                  tiny_code_generator_t &tcg,
                                  disas_t &,
                                  const uint64_t Addr,
                                  fnmap_t &fnmap,
                                  bbmap_t &bbmap,
                                  std::function<void(binary_t &, basic_block_t)> on_newbb_proc = [](binary_t &, basic_block_t){});


}

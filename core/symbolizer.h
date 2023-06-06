#pragma once
#include "jove/jove.h"
#include <memory>

namespace llvm {
namespace symbolize {
class LLVMSymbolizer;
}
}

namespace jove {

class symbolizer_t {
  std::unique_ptr<llvm::symbolize::LLVMSymbolizer> Symbolizer;

public:
  symbolizer_t();
  ~symbolizer_t();

  std::string addr2line(const binary_t &, uint64_t Addr);
  std::string addr2desc(const binary_t &, uint64_t Addr);
};

}

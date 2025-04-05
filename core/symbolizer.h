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

  template <bool MT>
  std::string addr2line(const binary_base_t<MT> &, uint64_t Addr);
  template <bool MT>
  std::string addr2desc(const binary_base_t<MT> &, uint64_t Addr);
};

}

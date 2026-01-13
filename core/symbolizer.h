#pragma once
#include "jove/jove.h"
#include "locator.h"
#include <memory>

namespace llvm {
namespace symbolize {
class LLVMSymbolizer;
}
}

namespace jove {

class symbolizer_t {
  std::mutex mtx; // LLVMSymbolizer is *not* thread-safe.
  std::unique_ptr<llvm::symbolize::LLVMSymbolizer> Symbolizer;

  locator_t &locator;
  bool Addr2Line = false;

public:
  symbolizer_t(locator_t &locator, bool Addr2Line = false);
  ~symbolizer_t();

  template <bool MT, bool MinSize>
  std::string addr2line(const binary_base_t<MT, MinSize> &, uint64_t Addr);
  template <bool MT, bool MinSize>
  std::string addr2desc(const binary_base_t<MT, MinSize> &, uint64_t Addr);
};

}

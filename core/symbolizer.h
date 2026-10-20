#pragma once
#include "jove/jove.h"
#include "locator.h"
#include "B.h"
#include <memory>

namespace llvm {
namespace symbolize {
class LLVMSymbolizer;
}
}

namespace jove {

template <bool MT, bool MinSize>
class symbolizer_base_t {
  using jv_t = jv_base_t<MT, MinSize>;

  std::mutex mtx; // LLVMSymbolizer is *not* thread-safe.
  std::unique_ptr<llvm::symbolize::LLVMSymbolizer> Symbolizer;

  locator_t &locator;
  bool Addr2Line = false;

  struct binary_state_t {
    B::unique_ptr Bin;

    binary_state_t(const auto &b) { Bin = B::Create(b.data()); }
  };

  jv_state_t<binary_state_t, void, void, MT, MinSize> state;

public:
  symbolizer_base_t(const jv_t &, locator_t &, bool Addr2Line = false);
  ~symbolizer_base_t();

  std::string addr2line(const binary_base_t<MT, MinSize> &, uint64_t Addr);
  std::string addr2desc(const binary_base_t<MT, MinSize> &, uint64_t Addr);
};

}

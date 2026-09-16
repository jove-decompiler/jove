#pragma once
#include "jove/tcg.h"

#include <array>
#include <atomic>
#include <memory>

namespace llvm {
class LLVMContext;
class Module;
class Function;
}

struct TCGHelperInfo;

namespace jove {

struct tiny_code_generator_t;
struct analyzer_options_t;
struct SafeLLVMContext;

struct tcg_helper_analysis_t {
  int EnvArgNo = -1;
  bool Simple = false;
  tcg_global_set_t InGlbs, OutGlbs;
};

struct tcg_helper_t {
  TCGHelperInfo &Info;
  tcg_helper_analysis_t Analysis;

  std::unique_ptr<const llvm::Module> llvm_upModule;

  tcg_helper_t(TCGHelperInfo &Info) : Info(Info) {}

  llvm::Function &CloneInto(llvm::Module &) const;
};

struct tcg_helpers_t {
  std::array<std_atomic_unique_ptr<tcg_helper_t>, tcg_helper_count> table;

  struct {
    const void *memset = nullptr;
    const void *lookup_tb_ptr = nullptr;

    const void *syscall_helper = nullptr;
  } Funcs;

  analyzer_options_t &options;

  SafeLLVMContext &SafeContext;

  tcg_helpers_t(tiny_code_generator_t &,
                SafeLLVMContext &,
                analyzer_options_t &);

  const tcg_helper_t &
  lookup(TCGHelperInfo &, void *Op /* FIXME */, bool IsCOFF);
};

}

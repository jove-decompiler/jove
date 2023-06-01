#pragma once
#include <string>

namespace jove {

struct locator_t {
  std::string tool();

  std::string runtime(void); // libjove_rt.so
  std::string starter_bitcode(void); // jove.bc
  std::string helper_bitcode(const std::string &name);

  std::string cbe(void); // llvm-cbe
  std::string dis(void); // llvm-dis
  std::string llc(void);
  std::string opt(void);
  std::string lld(void);
  std::string clang(void);
  std::string builtins(void);
  std::string atomics(void);

  std::string dfsan_runtime(void);
  std::string dfsan_abilist(void);

  std::string klee(void);

  std::string graph_easy(void);

  std::string scripts(void);
  std::string ida_scripts(void);
};

}

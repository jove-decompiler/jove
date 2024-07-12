#pragma once
#include <string>

namespace jove {

struct locator_t {
  std::string tool();

  std::string runtime_so(bool mt); // libjove_rt.so
  std::string runtime_dll(bool mt); // libjove_rt.dll
  std::string starter_bitcode(bool mt); // jove.bc
  std::string helper_bitcode(const std::string &name);

  std::string softfloat_bitcode(bool IsCOFF);

  std::string cbe(void); // llvm-cbe
  std::string dis(void); // llvm-dis
  std::string dlltool(void); // llvm-dlltool
  std::string llc(void);
  std::string opt(void);
  std::string lld(void);
  std::string lld_link(void);
  std::string ld_gold(void);
  std::string ld_bfd(void);
  std::string clang(void);
  std::string builtins(void);
  std::string atomics(void);

  std::string dfsan_runtime(void);
  std::string dfsan_abilist(void);

  std::string klee(void);

  std::string graph_easy(void);

  std::string scripts(void);
  std::string ida_scripts(void);

  std::string starter_bin(void);

  std::string gdb(void);
  std::string gdbserver(void);

  std::string perf(void);

  std::string sudo(void);

  /* NOT the preloader- the exe the preloader loads */
  std::string wine(bool Is32);
  std::string wine_dll(bool Is32, const std::string &name);
};

}

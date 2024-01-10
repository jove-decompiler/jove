#include "locator.h"

#include <boost/filesystem.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <stdexcept>

namespace fs = boost::filesystem;

namespace jove {

static std::string must_exist(const fs::path &p) {
  if (!fs::exists(p))
    throw std::runtime_error("could not locate " + p.string());

  return p.string();
}

static fs::path tool_path(void) {
  return boost::dll::program_location();
}

std::string locator_t::tool(void) {
  return must_exist(tool_path());
}

static fs::path jove_path(void) {
  return tool_path()
      .parent_path()
      .parent_path()
      .parent_path()
      .parent_path();
}

static fs::path arch_bin_path(void) {
  return jove_path() / "bin" / TARGET_ARCH_NAME;
}

static fs::path prebuilts_path(void) { return jove_path() / "prebuilts"; }

std::string locator_t::runtime(void) {
  return must_exist(arch_bin_path() / "libjove_rt.so");
}

std::string locator_t::starter_bitcode(void) {
  return must_exist(arch_bin_path() / "jove.bc");
}

std::string locator_t::helper_bitcode(const std::string &name) {
  return must_exist(arch_bin_path() / "helpers" / (name + ".bc"));
}

#define JUST_IN_PARENT_DIR(fn, name)                                           \
  std::string locator_t::fn(void) {                                            \
    return must_exist(tool_path().parent_path() / name);                       \
  }

JUST_IN_PARENT_DIR(cbe, "llvm-cbe")
JUST_IN_PARENT_DIR(dis, "llvm-dis")
JUST_IN_PARENT_DIR(clang, "clang")
JUST_IN_PARENT_DIR(lld, "ld.lld")
JUST_IN_PARENT_DIR(llc, "llc")
JUST_IN_PARENT_DIR(opt, "opt")

#undef JUST_IN_PARENT_DIR

std::string locator_t::builtins(void) {
  return must_exist(prebuilts_path() / "obj" /
                    ("libclang_rt.builtins-" TARGET_ARCH_NAME ".a"));
}

std::string locator_t::atomics(void) {
  return (prebuilts_path() / "obj" / ("libatomic-" TARGET_ARCH_NAME ".a"))
      .string();
}

std::string locator_t::dfsan_runtime(void) {
  return must_exist(prebuilts_path() / "lib" /
                    ("libclang_rt.dfsan.jove-" TARGET_ARCH_NAME ".so"));
}

std::string locator_t::dfsan_abilist(void) {
  return (arch_bin_path() / "dfsan_abilist.txt").string();
}

std::string locator_t::klee(void) {
  return must_exist(jove_path() / "klee" / "build" / "bin" / "klee");
}

std::string locator_t::graph_easy(void) {
  return fs::exists("/usr/bin/vendor_perl/graph-easy")
             ? "/usr/bin/vendor_perl/graph-easy"
             : "/usr/bin/graph-easy";
}

static fs::path scripts_path(void) {
  return jove_path() / "scripts";
}

std::string locator_t::scripts(void) {
  return must_exist(scripts_path());
}

std::string locator_t::ida_scripts(void) {
  return must_exist(scripts_path()  / "ida" / "_");
}

std::string locator_t::softfloat_bitcode(void) {
  return must_exist(prebuilts_path() / "lib" /
                    ("libfpu_soft-" TARGET_ARCH_NAME "-linux-user.a"));
}

std::string locator_t::gdb(void) {
  return must_exist(prebuilts_path() / "static_bin" /
                    (TARGET_ARCH_NAME "-gdb"));
}

std::string locator_t::gdbserver(void) {
  return must_exist(prebuilts_path() / "static_bin" /
                    (TARGET_ARCH_NAME "-gdbserver"));
}

std::string locator_t::perf(void) {
  return must_exist("/usr/bin/perf");
}

}

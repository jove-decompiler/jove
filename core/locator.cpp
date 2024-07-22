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

std::string locator_t::runtime_so(bool mt) {
  const char *fnm = mt ? "libjove_rt.mt.so" : "libjove_rt.st.so";
  return must_exist(arch_bin_path() / fnm);
}

std::string locator_t::runtime_dll(bool mt) {
  const char *fnm = mt ? "libjove_rt.mt.dll" : "libjove_rt.st.dll";
  return must_exist(arch_bin_path() / fnm);
}

std::string locator_t::runtime_implib(bool mt) {
  const char *fnm = mt ? "libjove_rt.mt.lib" : "libjove_rt.st.lib";
  return must_exist(arch_bin_path() / fnm);
}

std::string locator_t::starter_bitcode(bool mt, bool IsCOFF) {
  std::string fnm("jove.");
  fnm.append(IsCOFF ? "coff" : "elf");
  fnm.push_back('.');
  fnm.append(mt ? "mt" : "st");
  fnm.append(".bc");

  return must_exist(arch_bin_path() / fnm);
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
JUST_IN_PARENT_DIR(dlltool, "llvm-dlltool")
JUST_IN_PARENT_DIR(clang, "clang")
JUST_IN_PARENT_DIR(lld, "ld.lld")
JUST_IN_PARENT_DIR(lld_link, "lld-link")
JUST_IN_PARENT_DIR(llc, "llc")
JUST_IN_PARENT_DIR(opt, "opt")

#undef JUST_IN_PARENT_DIR

std::string locator_t::builtins(bool IsCOFF) {
  fs::path p(prebuilts_path());
  p /= "obj";
  if (IsCOFF)
    p /= "coff";
  p /= ("libclang_rt.builtins-" TARGET_ARCH_NAME ".a");

  return must_exist(p);
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

std::string locator_t::ld_gold(void) { return must_exist("/usr/bin/ld.gold"); }
std::string locator_t::ld_bfd(void) { return must_exist("/usr/bin/ld.bfd"); }

std::string locator_t::graph_easy(void) {
  try {
    return must_exist("/usr/bin/vendor_perl/graph-easy");
  } catch (...) {
    return must_exist("/usr/bin/graph-easy");
  }
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

std::string locator_t::softfloat_bitcode(bool IsCOFF) {
  fs::path p = prebuilts_path();

  p /= "lib";
  if (IsCOFF)
    p /= "coff";
  p /= "libfpu_soft-" TARGET_ARCH_NAME "-linux-user.a";

  return must_exist(p);
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

std::string locator_t::sudo(void) {
  return must_exist("/usr/bin/sudo");
}

std::string locator_t::wine(bool Is32) {
  try {
    return must_exist("/usr/lib/wine/wine" + std::string(Is32 ? "" : "64"));
  } catch (...) {
    return must_exist("/usr/bin/wine" + std::string(Is32 ? "" : "64"));
  }
}

std::string locator_t::wine_dll(bool Is32, const std::string &name) {
  try {
    const char *dir = Is32 ? "/usr/lib32/wine/i386-windows/"
                           : "/usr/lib/wine/x86_64-windows/";
    return must_exist(dir + name);
  } catch (...) {
    const char *dir = Is32 ? "/usr/lib/i386-linux-gnu/wine/i386-windows/"
                           : "/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/";
    return must_exist(dir + name);
  }
}

std::string locator_t::mingw_addr2line(bool Is32) {
  if (Is32) {
    return must_exist("/usr/bin/i686-w64-mingw32-addr2line");
  } else {
    return must_exist("/usr/bin/x86_64-w64-mingw32-addr2line");
  }
}

}

#include "locator.h"
#include "tool.h"

#include <boost/filesystem.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/algorithm/string/predicate.hpp>
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
      .parent_path()
      .parent_path();
}

static fs::path arch_bin_path(void) {
  return jove_path() / "bin" / TARGET_ARCH_NAME;
}

static fs::path linux_path(void) {
  return jove_path() / "linux";
}

static fs::path wine_path(void) {
  return jove_path() / "wine";
}

static fs::path prebuilts_path(void) { return jove_path() / "prebuilts"; }
static fs::path qemu_path(void) { return jove_path() / "qemu"; }

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

std::string locator_t::helper_bitcode(bool IsCOFF, const std::string &name) {
  return must_exist(arch_bin_path() / "helpers" / (IsCOFF ? "win" : "linux") /
                    (name + ".bc"));
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


  if (IsCOFF) {
#if defined(TARGET_X86_64)
    return must_exist("/usr/lib/gcc/x86_64-w64-mingw32/12-posix/libgcc.a");
#elif defined(TARGET_I386)
    return must_exist("/usr/lib/gcc/i686-w64-mingw32/12-posix/libgcc.a");
#else
    throw std::runtime_error("unrecognized COFF target");
#endif
  } else {
#if defined(TARGET_AARCH64)
    return must_exist("/usr/lib/gcc-cross/aarch64-linux-gnu/12/libgcc.a");
#elif defined(TARGET_X86_64)
    return must_exist("/usr/lib/gcc/x86_64-linux-gnu/12/libgcc.a");
#elif defined(TARGET_I386)
    return must_exist("/usr/lib/gcc-cross/i686-linux-gnu/12/libgcc.a");
#elif defined(TARGET_MIPS64)
    return must_exist("/usr/lib/gcc-cross/mips64el-linux-gnuabi64/12/libgcc.a");
#elif defined(TARGET_MIPSEL)
    return must_exist(p);
    return must_exist("/usr/lib/gcc-cross/mipsel-linux-gnu/12/libgcc.a");
#elif defined(TARGET_MIPS)
    return must_exist("/usr/lib/gcc-cross/mips-linux-gnu/12/libgcc.a");
#else
#error
#endif
  }
}

std::string locator_t::atomics(bool IsCOFF) {
#if 0
  return (prebuilts_path() / "obj" / ("libatomic-" TARGET_ARCH_NAME ".a"))
      .string();
#endif

  if (IsCOFF) {
#if defined(TARGET_X86_64)
    return must_exist("/usr/lib/gcc/x86_64-w64-mingw32/12-posix/libatomic.a");
#elif defined(TARGET_I386)
    return must_exist("/usr/lib/gcc/i686-w64-mingw32/12-posix/libatomic.a");
#else
    throw std::runtime_error("unrecognized COFF target");
#endif
  } else {
#if defined(TARGET_AARCH64)
    return must_exist("/usr/lib/gcc-cross/aarch64-linux-gnu/12/libatomic.a");
#elif defined(TARGET_X86_64)
    return must_exist("/usr/lib/gcc/x86_64-linux-gnu/12/libatomic.a");
#elif defined(TARGET_I386)
    return must_exist("/usr/lib/gcc/x86_64-linux-gnu/12/32/libatomic.a");
#elif defined(TARGET_MIPS64)
    return must_exist("/usr/lib/gcc-cross/mips64el-linux-gnuabi64/12/libatomic.a");
#elif defined(TARGET_MIPSEL)
    return must_exist("/usr/lib/gcc-cross/mipsel-linux-gnu/12/libatomic.a");
#elif defined(TARGET_MIPS)
    return must_exist("/usr/lib/gcc-cross/mips-linux-gnu/12/libatomic.a");
#else
#error
#endif
  }
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
  return must_exist(
      qemu_path() /
      (std::string(TARGET_ARCH_NAME) + "_softfpu" +
       std::string(IsCOFF ? "_win" : "_linux")
       + "_build") /
      (std::string("libfpu_soft-") + TARGET_ARCH_NAME + "-linux-user.a.p") /
      "fpu_softfloat.c.o");
}

std::string locator_t::softfloat_obj(bool IsCOFF) {
  fs::path p = arch_bin_path();
  return must_exist(
      p / ("softfpu-" + std::string(IsCOFF ? "win" : "linux") + ".o"));
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
  return must_exist(linux_path() / "tools" / "perf" / "perf");
}

std::string locator_t::sudo(void) {
  return must_exist("/usr/bin/sudo");
}

std::string locator_t::wine_prefix(bool Is32) {
  std::string dir = Tool::home_dir();
  dir += "/.wine";
  dir += (Is32 ? "32" : "64");

  return dir;
}

std::string locator_t::wine(bool Is32) {
  try {
    return must_exist(wine_path() / ("build" + std::string(Is32 ? "" : "64")) /
                      "loader" / "wine");
  } catch (...) {}
  try {
    return must_exist("/usr/lib/wine/wine" + std::string(Is32 ? "" : "64"));
  } catch (...) {}
  return must_exist("/usr/bin/wine" + std::string(Is32 ? "" : "64"));
}

std::string locator_t::wine_dll(bool Is32, const std::string &name) {
  try {
    if (!boost::algorithm::ends_with(name, ".dll"))
      throw -1;

    std::string name_ =
        name.substr(0, name.size() - sizeof(".dll") + 1); /* chop it off */

    return must_exist(
        wine_path() / ("build" + std::string(Is32 ? "" : "64")) / "dlls" /
        name_ / std::string(Is32 ? "i386-windows" : "x86_64-windows") / name);
  } catch (...) {}

  try {
    const char *dir = Is32 ? "/usr/lib32/wine/i386-windows/"
                           : "/usr/lib/wine/x86_64-windows/";
    return must_exist(dir + name);
  } catch (...) {}

  const char *dir = Is32 ? "/usr/lib/i386-linux-gnu/wine/i386-windows/"
                         : "/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/";
  return must_exist(dir + name);
}

std::string locator_t::mingw_addr2line(bool Is32) {
  if (Is32) {
    return must_exist("/usr/bin/i686-w64-mingw32-addr2line");
  } else {
    return must_exist("/usr/bin/x86_64-w64-mingw32-addr2line");
  }
}

std::string locator_t::vim(void) {
  return must_exist("/usr/bin/vim");
}

std::string locator_t::libipt_scripts(void) {
  return must_exist(jove_path() / "libipt" / "script");
}

std::string locator_t::objdump(bool IsCOFF) {
  try {
    std::string prefix =

#if defined(TARGET_AARCH64)
        "aarch64-linux-gnu"
#elif defined(TARGET_X86_64)
        IsCOFF ? "x86_64-w64-mingw32" : "x86_64-linux-gnu"
#elif defined(TARGET_I386)
        IsCOFF ? "i686-w64-mingw32" : "i686-linux-gnu"
#elif defined(TARGET_MIPS64)
        "mips64el-linux-gnuabi64"
#elif defined(TARGET_MIPSEL)
        "mipsel-linux-gnu"
#elif defined(TARGET_MIPS)
        "mips-linux-gnu"
#else
#error
#endif
        ;

    return must_exist("/usr/bin/" + prefix + "-objdump");
  } catch (...) {}

  return must_exist("/usr/bin/objdump");
}

}

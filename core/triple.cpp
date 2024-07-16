#include "triple.h"

namespace jove {

llvm::Triple getTargetTriple(bool IsCOFF) {
  llvm::Triple res;

  res.setObjectFormat(IsCOFF ? llvm::Triple::COFF : llvm::Triple::ELF);
  res.setOS(IsCOFF ? llvm::Triple::Win32 : llvm::Triple::Linux);

  llvm::Triple::EnvironmentType Env;
  if (IsCOFF) {
    Env = llvm::Triple::MSVC;
  } else {
    Env =
#if defined(TARGET_MIPS64)
        llvm::Triple::GNUABI64
#else
        llvm::Triple::GNU
#endif
        ;
  }

  res.setEnvironment(Env);
  res.setArch(
#if defined(TARGET_AARCH64)
      llvm::Triple::aarch64
#elif defined(TARGET_X86_64)
      llvm::Triple::x86_64
#elif defined(TARGET_I386)
      llvm::Triple::x86
#elif defined(TARGET_MIPS64)
      llvm::Triple::mips64el
#elif defined(TARGET_MIPSEL)
      llvm::Triple::mipsel
#elif defined(TARGET_MIPS)
      llvm::Triple::mips
#else
#error "unknown target"
#endif
  );

  return res;
}
}

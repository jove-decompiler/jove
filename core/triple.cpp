#include "triple.h"

namespace jove {

llvm::Triple getTargetTriple(void) {
  llvm::Triple res;

  res.setObjectFormat(llvm::Triple::ELF);
  res.setOS(llvm::Triple::Linux);
  res.setEnvironment(llvm::Triple::GNU);
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

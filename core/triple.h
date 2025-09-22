#pragma once
#include <jove/jove.h>
#include <llvm/ADT/Triple.h>

namespace jove {

static constexpr llvm::Triple::ArchType TripleArchType =
    llvm::Triple::ArchType::
#if defined(TARGET_X86_64)
        x86_64
#elif defined(TARGET_I386)
        x86
#elif defined(TARGET_AARCH64)
        aarch64
#elif defined(TARGET_MIPS64)
        mips64el
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPSEL)
        mipsel
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPS)
        mips
#else
#error
#endif
    ;

static constexpr const char *
TargetNameOfArchType(llvm::Triple::ArchType TheTripleArchType) {
  switch (TheTripleArchType) {
  case llvm::Triple::ArchType::x86_64:   return "x86_64";
  case llvm::Triple::ArchType::x86:      return "i386";
  case llvm::Triple::ArchType::aarch64:  return "aarch64";
  case llvm::Triple::ArchType::mips64el: return "mips64el";
//case llvm::Triple::ArchType::mips:     return "mips";
  case llvm::Triple::ArchType::mipsel:   return "mipsel";
  }

  throw std::runtime_error("unrecognized llvm::Triple::ArchType!");
}

llvm::Triple getTargetTriple(bool IsCOFF = false);

}

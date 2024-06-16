#pragma once
#include "elf.h"
#include "coff.h"
#include "util.h"

#include <llvm/Object/Binary.h>

#include <functional>
#include <memory>

namespace jove {
namespace B {

std::unique_ptr<llvm::object::Binary> Create(llvm::StringRef Data);

template <typename T>
static inline std::unique_ptr<llvm::object::Binary>
CreateFromFile(const char *path, T &bytes) {
  read_file_into_thing<T>(path, bytes);

  return Create(llvm::StringRef((const char *)bytes.data(), bytes.size()));
}

template <class Proc>
constexpr void _elf(llvm::object::Binary &Bin, Proc proc) {
  if (!llvm::isa<ELFO>(&Bin))
    return;

  return proc(*llvm::cast<ELFO>(&Bin));
}

template <class Proc>
constexpr void _coff(llvm::object::Binary &Bin, Proc proc) {
  if (!llvm::isa<COFFO>(&Bin))
    return;

  return proc(*llvm::cast<COFFO>(&Bin));
}

template <class ELFProc, class COFFProc>
constexpr auto _X(llvm::object::Binary &Bin,
                  ELFProc eproc,
                  COFFProc cproc) {
  if (llvm::isa<ELFO>(&Bin)) {
    return eproc(*llvm::cast<ELFO>(&Bin));
  } else if (llvm::isa<COFFO>(&Bin)) {
    return cproc(*llvm::cast<COFFO>(&Bin));
  } else {
    abort();
  }

  __builtin_trap();
  __builtin_unreachable();
}

constexpr const void *toMappedAddr(llvm::object::Binary &Bin,
                                   uint64_t Addr) {
  return _X(
      Bin,

      [&](ELFO &O) -> const void * {
        const ELFF &Elf = O.getELFFile();

        llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(Addr);
        if (!ExpectedPtr)
          throw std::runtime_error(llvm::toString(ExpectedPtr.takeError()));

        return *ExpectedPtr;
      },

      [&](COFFO &O) -> const void * {
        uintptr_t UIntPtr = ~0UL;

        if (llvm::Error E = O.getVaPtr(Addr, UIntPtr))
          throw std::runtime_error(llvm::toString(std::move(E)));

        return reinterpret_cast<const void *>(UIntPtr);
      });
}
}
}

#pragma once
#include "elf.h"
#include "coff.h"
#include "util.h"

#include <llvm/Object/Binary.h>
#include <llvm/Support/DataExtractor.h>
#include <boost/preprocessor/variadic/size.hpp>

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
constexpr auto _must_be_elf(llvm::object::Binary &Bin, Proc proc) {
  if (!llvm::isa<ELFO>(&Bin))
    throw std::runtime_error("unexpected non-ELF binary");

  return proc(*llvm::cast<ELFO>(&Bin));
}

template <class Proc>
constexpr void _coff(llvm::object::Binary &Bin, Proc proc) {
  if (!llvm::isa<COFFO>(&Bin))
    return;

  return proc(*llvm::cast<COFFO>(&Bin));
}

template <class Proc>
constexpr auto _must_be_coff(llvm::object::Binary &Bin, Proc proc) {
  if (!llvm::isa<COFFO>(&Bin)) {
    throw std::runtime_error("unexpected non-COFF binary");
  }

  return proc(*llvm::cast<COFFO>(&Bin));
}

constexpr bool is_elf(llvm::object::Binary &Bin) {
  return llvm::isa<ELFO>(&Bin);
}

constexpr bool is_coff(llvm::object::Binary &Bin) {
  return llvm::isa<COFFO>(&Bin);
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

#define BFUNCTION_2(rett, name)                                                \
  constexpr rett name(llvm::object::Binary &Bin) {                             \
    return _X(Bin,                                                             \
        [&](ELFO &O) -> rett { return elf::name(O); },                         \
        [&](COFFO &O) -> rett { return coff::name(O); });                      \
  }

#define BFUNCTION_4(rett, name, t1, a1)                                        \
  constexpr rett name(llvm::object::Binary &Bin, t1 a1) {                      \
    return _X(Bin,                                                             \
        [&](ELFO &O) -> rett { return elf::name(O, a1); },                     \
        [&](COFFO &O) -> rett { return coff::name(O, a1); });                  \
  }

#define BFUNCTION(...)                                                         \
  BOOST_PP_CAT(BFUNCTION_, BOOST_PP_VARIADIC_SIZE(__VA_ARGS__))(__VA_ARGS__)

typedef std::pair<uint64_t, uint64_t> addr_pair;

BFUNCTION(addr_pair, bounds_of_binary)
BFUNCTION(uint64_t, va_of_offset, uint64_t, off)
BFUNCTION(const void *, toMappedAddr, uint64_t, Addr)
BFUNCTION(uint64_t, extractAddress, const void *, ptr)
BFUNCTION(bool, needed_libs, std::vector<std::string> &, out)

static inline uint64_t offset_of_va(llvm::object::Binary &Bin, uint64_t va) {
  const void *Ptr = toMappedAddr(Bin, va);

  return reinterpret_cast<const uint8_t *>(Ptr) -
         reinterpret_cast<const uint8_t *>(Bin.getMemoryBufferRef().getBufferStart());
}

}
}

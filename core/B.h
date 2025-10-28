#pragma once
#include "jove/jove.h"
#include "elf.h"
#include "coff.h"
#include "util.h"
#include "tagged2.h"

#include <llvm/Object/Binary.h>
#include <llvm/Support/DataExtractor.h>
#include <boost/preprocessor/variadic/size.hpp>

#include <functional>
#include <memory>
#include <cstdint>

namespace jove {
namespace B {

enum TagMeaning {
  ELFTag = 0,
  COFFTag = 1
};

using unique_ptr = tagged_unique_ptr2<llvm::object::Binary, TagBits>;
using ptr = typename unique_ptr::pointer;

unique_ptr Create(llvm::StringRef Data);

template <typename T>
static inline unique_ptr
CreateFromFile(const char *path, T &bytes) {
  read_file_into_thing<T>(path, bytes);

  return Create(llvm::StringRef((const char *)bytes.data(), bytes.size()));
}

static inline void _elf(ref Bin, std::function<void(ELFO &)> proc) {
  if (Bin.tag() == ELFTag) {
    assert(llvm::isa<ELFO>(&Bin.get()));

    return proc(*llvm::cast<ELFO>(&Bin.get()));
  }
}

template <typename Result>
static inline Result _must_be_elf(ref Bin, std::function<Result(ELFO &)> proc) {
  aassert(Bin.tag() == ELFTag);
  assert(llvm::isa<ELFO>(&Bin.get()));

  return proc(*llvm::cast<ELFO>(&Bin.get()));
}

template <class Proc>
static inline void _coff(ref Bin, Proc proc) {
  if (Bin.tag() == COFFTag) {
    assert(llvm::isa<COFFO>(&Bin.get()));

    return proc(*llvm::cast<COFFO>(&Bin.get()));
  }
}

template <typename Result>
static inline Result _must_be_coff(ref Bin, std::function<Result(COFFO &)> proc) {
  aassert(Bin.tag() == COFFTag);
  assert(llvm::isa<COFFO>(&Bin.get()));

  return proc(*llvm::cast<COFFO>(&Bin.get()));
}

static inline bool is_elf(ref Bin) {
  const bool res = Bin.tag() == ELFTag;
  assert(res ? llvm::isa<ELFO>(&Bin.get()) : true);
  return res;
}

static inline bool is_coff(ref Bin) {
  const bool res = Bin.tag() == COFFTag;
  assert(res ? llvm::isa<COFFO>(&Bin.get()) : true);
  return res;
}

static inline ref from_ref(llvm::object::Binary &TheRef) {
  aassert(llvm::isa<llvm::object::ObjectFile>(&TheRef));

  ref res(TheRef);
  if (llvm::isa<COFFO>(&TheRef)) {
    res.set_tag(COFFTag);
    return res;
  } else if (llvm::isa<ELFO>(&TheRef)) {
    res.set_tag(ELFTag);
    return res;
  }

  throw std::runtime_error("unrecognized llvm::object::ObjectFile!");
}

template <typename Result>
static inline Result _X(ref Bin,
                        std::function<Result(ELFO &)> eproc,
                        std::function<Result(COFFO &)> cproc) {
  const auto TheTag = Bin.tag();
  if (TheTag == ELFTag) {
    assert(llvm::isa<ELFO>(&Bin.get()));
    return eproc(*llvm::cast<ELFO>(&Bin.get()));
  }

  assert(TheTag == COFFTag);
  assert(llvm::isa<COFFO>(&Bin.get()));
  return cproc(*llvm::cast<COFFO>(&Bin.get()));
}

#define BFUNCTION2(rett, name)                            \
  static inline rett name(ref Bin) {                      \
    return _X<rett>(Bin,                                  \
        [&](ELFO &O) -> rett { return elf::name(O); },    \
        [&](COFFO &O) -> rett { return coff::name(O); }); \
  }

#define BFUNCTION4(rett, name, t1, a1)                        \
  static inline rett name(ref Bin, t1 a1) {                   \
    return _X<rett>(Bin,                                      \
        [&](ELFO &O) -> rett { return elf::name(O, a1); },    \
        [&](COFFO &O) -> rett { return coff::name(O, a1); }); \
  }

#define BFUNCTION(...)                                                         \
  BOOST_PP_CAT(BFUNCTION,BOOST_PP_VARIADIC_SIZE(__VA_ARGS__))(__VA_ARGS__)

typedef std::pair<uint64_t, uint64_t> addr_pair;

BFUNCTION(addr_pair, bounds_of_binary)
BFUNCTION(uint64_t, va_of_offset, uint64_t, off)
BFUNCTION(const void *, toMappedAddr, uint64_t, Addr)
BFUNCTION(uint64_t, extractAddress, const void *, p)
BFUNCTION(bool, needed_libs, std::vector<std::string> &, out)

static inline uint64_t offset_of_va(ref Bin, uint64_t va) {
  const void *Ptr = toMappedAddr(Bin, va);
  if (!Ptr)
    return UINT64_MAX;

  return reinterpret_cast<const uint8_t *>(Ptr) -
         reinterpret_cast<const uint8_t *>(Bin.get().getMemoryBufferRef().getBufferStart());
}

}
}

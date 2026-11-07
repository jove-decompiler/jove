#pragma once
#include "jove/jove.h"
#include "elf.h"
#include "coff.h"
#include "util.h"
#include "tagged2.h"

#include <llvm/Object/Binary.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/DataExtractor.h>
#include <boost/preprocessor/variadic/size.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <ranges>
#include <utility>

namespace jove {
namespace B {

enum TagMeaning {
  ELFTag = 0,
  COFFTag = 1
};

static constexpr std::size_t TagBits = 1;

using ref = tagged_reference_wrapper2<llvm::object::Binary, TagBits>;
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

//
//   ┌───────────────────────┐  ←──────────── bounds(b).first
//   │         .text         │
//   └───────────────────────┘
//
//   ┌───────────────────────┐
//   │        .rodata        │
//   └───────────────────────┘
//   ┌───────────────────────┐
//   │         .data         │
//   └───────────────────────┘
//
//   ┌───────────────────────┐
//   │         .bss          │
//   └───────────────────────┘  ←──────────── bounds(b).second
//
BFUNCTION(addr_pair, bounds_of_binary)
BFUNCTION(uint64_t, va_of_offset, uint64_t, off)
BFUNCTION(const void *, toMappedAddr, uint64_t, Addr)
BFUNCTION(uint64_t, extractAddress, const void *, p)
BFUNCTION(bool, needed_libs, std::vector<std::string> &, out)

template <typename extra_t>
BFUNCTION(bool, sections, section_vec_t<extra_t> &, out)

static inline uint64_t offset_of_va(ref Bin, uint64_t va) {
  const void *ptr = toMappedAddr(Bin, va);
  if (!ptr)
    return UINT64_MAX;

  const auto *const base = Bin.get().getMemoryBufferRef().getBufferStart();

  return reinterpret_cast<const uint8_t *>(ptr) -
         reinterpret_cast<const uint8_t *>(base);
}

// NOTE: returned ArrayRef's size may be less than the length of the section.
static inline llvm::ArrayRef<uint8_t> contents_of_section(ref Bin, const auto &section) {
  const auto N = section.size();
  if (!N)
    return {};
  const auto off = section.off();

  const size_t M = Bin.get().getMemoryBufferRef().getBufferSize();

//aassert(M >= N);
  aassert(off < M);
  const size_t left = M - off;
  const auto *const base = Bin.get().getMemoryBufferRef().getBufferStart();

  llvm::ArrayRef<uint8_t> res(
      reinterpret_cast<const uint8_t *>(base) + off,
      std::min<size_t>(N, left));
  return res;
}

namespace cached {

template <typename extra_t = std::monostate>
using type = std::pair<B::unique_ptr, sections_t<extra_t>>;

static inline addr_pair bounds_of_binary(auto &cb) {
  assert(!cb.second.svec.empty());

  auto sorted_range = cb.second.sorted_by_addr();

  const auto &the_front = sorted_range.front();
  const auto &the_back = sorted_range.back();

  return std::make_pair(the_front.addr(), the_back.addr() + the_back.length());
}

static inline uint64_t va_of_offset(const auto &cb, uint64_t off) {
  auto &Bin      = cb.first;
  auto &sections = cb.second;

  auto it = intvl_map_find(sections.omap, off);
  aassert(it != sections.omap.end());

  const unsigned idx = (*it).second;
  const auto &section = sections.svec[idx];

  assert(off >= section.off());
  const auto soff = off - section.off();

  return section.addr() + soff;
}

static inline const void *toMappedAddr(const auto &cb, uint64_t addr) {
  auto &Bin      = cb.first;
  auto &sections = cb.second;

  auto it = intvl_map_find(sections.amap, addr);
  aassert(it != sections.amap.end());

  const unsigned idx = (*it).second;
  const auto &section = sections.svec[idx];

  assert(addr >= section.addr());
  const auto soff = addr - section.addr();

  const auto *const base = Bin.get()->getMemoryBufferRef().getBufferStart();
  return reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(base) + section.off() + soff);
}

static inline uint64_t offset_of_va(const auto &cb, uint64_t va) {
  auto &Bin      = cb.first;
  auto &sections = cb.second;

  const void *ptr = cached::toMappedAddr(cb, va);
  if (!ptr)
    return UINT64_MAX;

  const auto *const base = Bin.get()->getMemoryBufferRef().getBufferStart();

  return reinterpret_cast<const uint8_t *>(ptr) -
         reinterpret_cast<const uint8_t *>(base);
}

template <typename extra_t>
void from_svec(sections_t<extra_t> &out, const section_vec_t<extra_t> &svec) {
  static_assert(section_omap_t::allocator_traits_type::propagate_on_container_move_assignment::value);
  static_assert(section_amap_t::allocator_traits_type::propagate_on_container_move_assignment::value);

  const auto *const svec_base = svec.data();

  {
    auto pairs =
        svec | std::views::transform([svec_base](const auto &section) {
          return section_amap_t::value_type(section.ai, &section - svec_base);
        });

    out.amap = section_amap_t(pairs.begin(), pairs.end(), addr_intvl_cmp{});
  }

  {
    auto pairs =
        svec | std::views::transform([svec_base](const auto &section) {
          return section_omap_t::value_type(section.oi, &section - svec_base);
        });

    out.omap = section_omap_t(pairs.begin(), pairs.end(), addr_intvl_cmp{});
  }
}

static inline void create(auto &out, llvm::StringRef Data) {
  out.first = B::Create(Data);
  B::sections(out.first.get(), out.second.svec);
  B::cached::from_svec(out.second, out.second.svec);
}

static inline void create_from_file(auto &out, const char *path, std::vector<uint8_t> &Data) {
  out.first = B::CreateFromFile(path, Data);
  B::sections(out.first.get(), out.second.svec);
  B::cached::from_svec(out.second, out.second.svec);
}

}

}
}

#pragma once
#include "section.h"

#include <llvm/Object/COFF.h>
#include <llvm/Support/DataExtractor.h>

#include <functional>

namespace jove {
typedef llvm::object::COFFObjectFile COFFO;

namespace coff {

constexpr uint64_t va_of_rva(COFFO &O, uint64_t rva) { return rva + O.getImageBase(); }
constexpr uint64_t rva_of_va(COFFO &O, uint64_t rva) { return rva - O.getImageBase(); }

uint64_t va_of_offset(COFFO &, uint64_t off);

typedef std::pair<uint64_t, uint64_t> addr_pair;
addr_pair bounds_of_binary(COFFO &);

static inline const void *toMappedAddr(COFFO &O, uint64_t Addr) {
  const uint64_t ImageBase = O.getImageBase();
  if (!(Addr >= ImageBase))
    return nullptr;

  const uint64_t Rva = Addr - ImageBase;
  if (!(Rva <= UINT32_MAX))
    return nullptr;

  uintptr_t UIntPtr = ~0UL;
  if (llvm::errorToBool(O.getRvaPtr((uint32_t)Rva, UIntPtr)))
    return nullptr;

  return reinterpret_cast<const void *>(UIntPtr);
}

static inline uint64_t extractAddress(COFFO &O, const void *p) {
  const unsigned AddrBytes = O.getBytesInAddress();

  uint64_t Offset = 0;
  llvm::DataExtractor DE(
      llvm::ArrayRef<uint8_t>(static_cast<const uint8_t *>(p), 2 * AddrBytes),
      true /* little endian */, AddrBytes);

  return DE.getAddress(&Offset);
}

bool isCode(COFFO &, uint64_t va);
bool isRVACode(COFFO &, uint64_t rva);

bool needed_libs(COFFO &, std::vector<std::string> &out);
bool needed_delay_libs(COFFO &, std::vector<std::string> &out);

void for_each_imported_function(
    COFFO &, std::function<void(llvm::StringRef DLL, uint32_t Ordinal,
                                llvm::StringRef Name, uint64_t RVA)> proc);

void for_each_exported_function(
    COFFO &, std::function<void(uint32_t Ordinal,
                                llvm::StringRef Name, uint64_t RVA)> proc);

void for_each_base_relocation(COFFO &,
  std::function<void(uint8_t Type, uint64_t RVA)> proc);

void gen_module_definition_for_dll(COFFO &, llvm::StringRef DLL, std::ostream &);

std::string unique_symbol_for_ordinal_in_dll(llvm::StringRef DLL,
                                             uint16_t Ordinal);

std::string link_subsystem(COFFO &);

std::string getBaseRelocTypeName(uint8_t Type);

template <typename extra_t>
static inline bool sections(COFFO &O, B::section_vec_t<extra_t> &out) {
  const size_t M = O.getMemoryBufferRef().getBufferSize();

  const auto beg = O.section_begin();
  const auto end = O.section_end();

  out.reserve(std::distance(beg, end));

  for (auto it = beg; it != end; ++it) {
    const llvm::object::SectionRef &SectionRef = *it;
    const llvm::object::coff_section &Sect = *O.getCOFFSection(SectionRef);

    const auto size = Sect.SizeOfRawData;
    if (!size)
      continue;

    const auto length = Sect.VirtualSize;
    if (size > length)
      continue;

    const auto off = Sect.PointerToRawData;
    if (off >= M)
      continue;

    const unsigned idx = out.size();
    auto &section = out.emplace_back(off, size, va_of_rva(O, Sect.VirtualAddress), length);

    const char *const pbeg = &Sect.Name[0];
    const char *pend = (const char *)memchr(pbeg, '\0', sizeof(Sect.Name));
    if (!pend)
      pend = &Sect.Name[sizeof(Sect.Name)];

    section.Name = llvm::StringRef(Sect.Name, pend - pbeg);

    const auto Characteristics = Sect.Characteristics;

    section.perm.r = !!(Characteristics & llvm::COFF::IMAGE_SCN_MEM_READ);
    section.perm.w = !!(Characteristics & llvm::COFF::IMAGE_SCN_MEM_WRITE);
    section.perm.x = !!(Characteristics & llvm::COFF::IMAGE_SCN_MEM_EXECUTE);

    const bool code = !!(Characteristics & llvm::COFF::IMAGE_SCN_CNT_CODE);
    if (!section.perm.x && code)
      section.perm.x = 1; /* FIXME? */
  }

  return !out.empty();
}

}
}

#pragma once
#include <llvm/Object/COFF.h>
#include <llvm/Support/DataExtractor.h>

#include <functional>

namespace jove {

typedef llvm::object::COFFObjectFile COFFO;

namespace coff {

constexpr uint64_t va_of_rva(COFFO &O, uint64_t rva) { return rva + O.getImageBase(); }
constexpr uint64_t rva_of_va(COFFO &O, uint64_t rva) { return rva - O.getImageBase(); }

uint64_t va_of_offset(COFFO &, uint64_t off);
uint64_t offset_of_va(COFFO &, uint64_t va);

typedef std::pair<uint64_t, uint64_t> addr_pair;
addr_pair bounds_of_binary(COFFO &);

static inline const void *toMappedAddr(COFFO &O, uint64_t Addr) {
  uintptr_t UIntPtr = ~0UL;

  if (llvm::Error E = O.getVaPtr(Addr, UIntPtr))
    throw std::runtime_error(llvm::toString(std::move(E)));

  return reinterpret_cast<const void *>(UIntPtr);
}

static inline uint64_t extractAddress(COFFO &O, const void *ptr) {
  const unsigned AddrBytes = O.getBytesInAddress();

  uint64_t Offset = 0;
  llvm::DataExtractor DE(
      llvm::ArrayRef<uint8_t>(reinterpret_cast<const uint8_t *>(ptr),
                              2 * AddrBytes),
      true /* little endian */, AddrBytes);

  return DE.getAddress(&Offset);
}

bool isCode(COFFO &, uint64_t va);

bool needed_libs(COFFO &, std::vector<std::string> &out);

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
}
}

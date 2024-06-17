#pragma once
#include <llvm/Object/COFF.h>
#include <llvm/Support/DataExtractor.h>

namespace jove {

typedef llvm::object::COFFObjectFile COFFO;

namespace coff {

constexpr uint64_t va_of_rva(COFFO &O, uint64_t rva) {
  return rva + O.getImageBase();
}

constexpr uint64_t va_of_offset(COFFO &O, uint64_t off) {
  return va_of_rva(O, off);
}

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

bool isCode(COFFO &O, uint64_t RVA);

}

}

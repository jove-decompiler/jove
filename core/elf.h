#pragma once
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/DataExtractor.h>
#include <llvm/ADT/PointerIntPair.h>
#include <utility>

namespace jove {

#if defined(TARGET_X86_64) || defined(TARGET_AARCH64) || defined(TARGET_MIPS64)
typedef typename llvm::object::ELF64LE ELFT;
#elif defined(TARGET_I386) || (defined(TARGET_MIPS32) && defined(TARGET_MIPSEL))
typedef typename llvm::object::ELF32LE ELFT;
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPS)
typedef typename llvm::object::ELF32BE ELFT;
#else
#error
#endif

typedef typename llvm::object::ELFObjectFile<ELFT> ELFO;
typedef typename llvm::object::ELFFile<ELFT> ELFF;

typedef typename ELFT::Addr Elf_Addr;
typedef typename ELFT::CGProfile Elf_CGProfile;
typedef typename ELFT::Dyn Elf_Dyn;
typedef typename ELFT::DynRange Elf_Dyn_Range;
typedef typename ELFT::Ehdr Elf_Ehdr;
typedef typename ELFF::Elf_Dyn Elf_Dyn;
typedef typename ELFF::Elf_Dyn_Range Elf_Dyn_Range;
typedef typename ELFF::Elf_Phdr Elf_Phdr;
typedef typename ELFF::Elf_Phdr_Range Elf_Phdr_Range;
typedef typename ELFF::Elf_Rel Elf_Rel;
typedef typename ELFF::Elf_Rela Elf_Rela;
typedef typename ELFF::Elf_Shdr Elf_Shdr;
typedef typename ELFF::Elf_Shdr_Range Elf_Shdr_Range;
typedef typename ELFF::Elf_Sym Elf_Sym;
typedef typename ELFF::Elf_Sym_Range Elf_Sym_Range;
typedef typename ELFF::Elf_Verdef Elf_Verdef;
typedef typename ELFF::Elf_Vernaux Elf_Vernaux;
typedef typename ELFF::Elf_Verneed Elf_Verneed;
typedef typename ELFF::Elf_Versym Elf_Versym;
typedef typename ELFF::Elf_Word Elf_Word;
typedef typename ELFT::GnuHash Elf_GnuHash;
typedef typename ELFT::Half Elf_Half;
typedef typename ELFT::Hash Elf_Hash;
typedef typename ELFT::Note Elf_Note;
typedef typename ELFT::Phdr Elf_Phdr;
typedef typename ELFT::Rel Elf_Rel;
typedef typename ELFT::RelRange Elf_Rel_Range;
typedef typename ELFT::Rela Elf_Rela;
typedef typename ELFT::RelaRange Elf_Rela_Range;
typedef typename ELFT::Relr Elf_Relr;
typedef typename ELFT::RelrRange Elf_Relr_Range;
typedef typename ELFT::Shdr Elf_Shdr;
typedef typename ELFT::Sym Elf_Sym;
typedef typename ELFT::SymRange Elf_Sym_Range;
typedef typename ELFT::Verdaux Elf_Verdaux;
typedef typename ELFT::Verdef Elf_Verdef;
typedef typename ELFT::Vernaux Elf_Vernaux;
typedef typename ELFT::Verneed Elf_Verneed;
typedef typename ELFT::Versym Elf_Versym;
typedef typename ELFT::Word Elf_Word;
typedef typename ELFT::uint uintX_t;

namespace elf {

/// Represents a contiguous uniform range in the file. We cannot just create a
/// range directly because when creating one of these from the .dynamic table
/// the size, entity size and virtual address are different entries in arbitrary
/// order (DT_REL, DT_RELSZ, DT_RELENT for example).
struct DynRegionInfo {
  DynRegionInfo() : Obj(nullptr) {}
  DynRegionInfo(const ELFO &Owner) : Obj(&Owner) {}
  DynRegionInfo(const ELFO &Owner, const uint8_t *A,
                uint64_t S, uint64_t ES)
      : Addr(A), Size(S), EntSize(ES), Obj(&Owner) {}

  /// Address in current address space.
  const uint8_t *Addr = nullptr;
  /// Size in bytes of the region.
  uint64_t Size = 0;
  /// Size of each entity in the region.
  uint64_t EntSize = 0;

  /// Owner object. Used for error reporting.
  const ELFO *Obj;

  template <typename Type> llvm::ArrayRef<Type> getAsArrayRef() const {
    const Type *Start = reinterpret_cast<const Type *>(Addr);
    if (!Start)
      return {Start, Start};
    if (EntSize != sizeof(Type) || Size % EntSize) {
#ifdef WARN
      WARN();
#endif

#if 0
      return {Start, Start};
#else
      /* fallthrough */
#endif
    }

    return {Start, Start + (Size / EntSize)};
  }
};

std::optional<llvm::ArrayRef<uint8_t>> getBuildID(const ELFF &Obj);

uintX_t loadDynamicTable(const ELFO &, DynRegionInfo &DynamicTable);

class VersionMapEntry : public llvm::PointerIntPair<const void *, 1> {
public:
  // If the integer is 0, this is an Elf_Verdef*.
  // If the integer is 1, this is an Elf_Vernaux*.
  VersionMapEntry() : PointerIntPair<const void *, 1>(nullptr, 0) {}
  VersionMapEntry(const Elf_Verdef *verdef)
      : PointerIntPair<const void *, 1>(verdef, 0) {}
  VersionMapEntry(const Elf_Vernaux *vernaux)
      : PointerIntPair<const void *, 1>(vernaux, 1) {}

  bool isNull() const { return getPointer() == nullptr; }
  bool isVerdef() const { return !isNull() && getInt() == 0; }
  bool isVernaux() const { return !isNull() && getInt() == 1; }
  const Elf_Verdef *getVerdef() const {
    return isVerdef() ? (const Elf_Verdef *)getPointer() : nullptr;
  }
  const Elf_Vernaux *getVernaux() const {
    return isVernaux() ? (const Elf_Vernaux *)getPointer() : nullptr;
  }
};

std::optional<DynRegionInfo> loadDynamicSymbols(const ELFO &,
                                                const DynRegionInfo &DynamicTable,
                                                llvm::StringRef &DynamicStringTable,
                                                const Elf_Shdr *&SymbolVersionSection,
                                                std::vector<VersionMapEntry> &VersionMap);

llvm::StringRef getSymbolVersionByIndex(std::vector<VersionMapEntry> &VersionMap,
                                        llvm::StringRef StrTab,
                                        uint32_t SymbolVersionIndex,
                                        bool &IsDefault);

void loadDynamicRelocations(const ELFO &,
                            const DynRegionInfo &DynamicTable,
                            DynRegionInfo &DynRelRegion,
                            DynRegionInfo &DynRelaRegion,
                            DynRegionInfo &DynRelrRegion,
                            DynRegionInfo &DynPLTRelRegion);

class Relocation {
public:
  Relocation(const Elf_Rel &R, bool IsMips64EL)
      : Type(R.getType(IsMips64EL)), Symbol(R.getSymbol(IsMips64EL)),
        Offset(R.r_offset), Info(R.r_info) {}

  Relocation(const typename ELFT::Rela &R, bool IsMips64EL)
      : Relocation((const typename ELFT::Rel &)R, IsMips64EL) {
    Addend = R.r_addend;
  }

  uint32_t Type;
  uint32_t Symbol;
  typename ELFT::uint Offset;
  typename ELFT::uint Info;
  std::optional<int64_t> Addend;
};

struct RelSymbol {
  RelSymbol(const typename ELFT::Sym *S, llvm::StringRef N)
      : Sym(S), Name(N.str()) {}
  const Elf_Sym *Sym;
  std::string Name;
  std::string Vers;
  bool IsVersionDefault;
};

RelSymbol getSymbolForReloc(const ELFO &,
                            Elf_Sym_Range dynamic_symbols,
                            llvm::StringRef DynamicStringTable,
                            const Relocation &Reloc);

void for_each_dynamic_relocation(const ELFF &,
                                 DynRegionInfo &DynRelRegion,
                                 DynRegionInfo &DynRelaRegion,
                                 DynRegionInfo &DynRelrRegion,
                                 DynRegionInfo &DynPLTRelRegion,
                                 std::function<void(const Relocation &)> proc);

inline
void for_each_dynamic_relocation_if(const ELFF &Elf,
                                    DynRegionInfo &DynRelRegion,
                                    DynRegionInfo &DynRelaRegion,
                                    DynRegionInfo &DynRelrRegion,
                                    DynRegionInfo &DynPLTRelRegion,
                                    std::function<bool(const Relocation &)> pred,
                                    std::function<void(const Relocation &)> proc) {
  for_each_dynamic_relocation(Elf,
                              DynRelRegion,
                              DynRelaRegion,
                              DynRelrRegion,
                              DynPLTRelRegion,
                              [&](const Relocation &R) {
                                if (pred(R))
                                  proc(R);
                              });
}

static inline uint64_t extractAddress(ELFO &O, const void *ptr) {
  constexpr unsigned TargetArchWordSize = ELFT::Is64Bits ? 8 : 4;

  uint64_t Offset = 0;
  llvm::DataExtractor DE(
      llvm::ArrayRef<uint8_t>(reinterpret_cast<const uint8_t *>(ptr),
                              2 * TargetArchWordSize),
      ELFT::TargetEndianness == llvm::support::endianness::little,
      TargetArchWordSize);

  return DE.getAddress(&Offset);
}

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)

class MipsGOTParser {
public:
  using Entry = typename ELFT::Addr;
  using Entries = llvm::ArrayRef<Entry>;

  const bool IsStatic;
  const ELFF &Obj;

  MipsGOTParser(const ELFF &Obj, llvm::StringRef FileName);
  llvm::Error findGOT(Elf_Dyn_Range DynTable, Elf_Sym_Range DynSyms);
#if 0
  llvm::Error findPLT(Elf_Dyn_Range DynTable);
#endif

  bool isGotEmpty() const { return GotEntries.empty(); }
  bool isPltEmpty() const { return PltEntries.empty(); }

  uint64_t getGp() const;

  const Entry *getGotLazyResolver() const;
  const Entry *getGotModulePointer() const;
  const Entry *getPltLazyResolver() const;
  const Entry *getPltModulePointer() const;

  Entries getLocalEntries() const;
  Entries getGlobalEntries() const;
  Entries getOtherEntries() const;
  Entries getPltEntries() const;

  uint64_t getGotAddress(const Entry * E) const;
  int64_t getGotOffset(const Entry * E) const;
  const Elf_Sym *getGotSym(const Entry *E) const;

  uint64_t getPltAddress(const Entry * E) const;
  const Elf_Sym *getPltSym(const Entry *E) const;

  llvm::StringRef getPltStrTable() const { return PltStrTable; }
  const Elf_Shdr *getPltSymTable() const { return PltSymTable; }

private:
  uint64_t GotSecAddr = 0;
  const Elf_Shdr *GotSec;
  size_t LocalNum;
  size_t GlobalNum;

  const Elf_Shdr *PltSec;
  const Elf_Shdr *PltRelSec;
  const Elf_Shdr *PltSymTable;
  llvm::StringRef FileName;

  Elf_Sym_Range GotDynSyms;
  llvm::StringRef PltStrTable;

  Entries GotEntries;
  Entries PltEntries;
};
#endif

uint64_t va_of_offset(ELFO &, uint64_t off);
uint64_t offset_of_va(ELFO &, uint64_t va);

typedef std::pair<uint64_t, uint64_t> addr_pair;
addr_pair bounds_of_binary(ELFO &);

static inline const void *toMappedAddr(ELFO &O, uint64_t Addr) {
  const ELFF &Elf = O.getELFFile();

  llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(Addr);
  if (!ExpectedPtr)
    throw std::runtime_error(llvm::toString(ExpectedPtr.takeError()));

  return *ExpectedPtr;
}

std::optional<std::string> program_interpreter_of_elf(const ELFO &);
std::optional<std::string> soname_of_elf(const ELFO &);

bool needed_libs(ELFO &, std::vector<std::string> &out);

}

}

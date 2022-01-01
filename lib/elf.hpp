/// Represents a contiguous uniform range in the file. We cannot just create a
/// range directly because when creating one of these from the .dynamic table
/// the size, entity size and virtual address are different entries in arbitrary
/// order (DT_REL, DT_RELSZ, DT_RELENT for example).
struct DynRegionInfo {
  DynRegionInfo() {}
  DynRegionInfo(llvm::StringRef ObjName) : FileName(ObjName) {}
  DynRegionInfo(const void *A, uint64_t S, uint64_t ES, llvm::StringRef ObjName)
      : Addr(A), Size(S), EntSize(ES), FileName(ObjName) {}

  /// Address in current address space.
  const void *Addr = nullptr;
  /// Size in bytes of the region.
  uint64_t Size = 0;
  /// Size of each entity in the region.
  uint64_t EntSize = 0;

  /// Name of the file. Used for error reporting.
  llvm::StringRef FileName;

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

template <class T>
static T unwrapOrError(llvm::Expected<T> EO) {
  if (EO)
    return *EO;

  std::string Buf;
  {
    llvm::raw_string_ostream OS(Buf);
    llvm::logAllUnhandledErrors(EO.takeError(), OS, "");
  }
  llvm::WithColor::error() << Buf << '\n';
  abort();
}

#if defined(TARGET_X86_64) || defined(TARGET_AARCH64) || defined(TARGET_MIPS64)
typedef typename llvm::object::ELF64LE ELFT;
#elif defined(TARGET_I386) || (defined(TARGET_MIPS32) && !defined(HOST_WORDS_BIGENDIAN))
typedef typename llvm::object::ELF32LE ELFT;
#elif defined(TARGET_MIPS32) && defined(HOST_WORDS_BIGENDIAN)
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

static std::pair<const typename ELFT::Phdr *, const typename ELFT::Shdr *>
findDynamic(const ELFO *, const ELFF *);

static DynRegionInfo checkDRI(DynRegionInfo DRI, const ELFO *ObjF) {
  const ELFF *Obj = ObjF->getELFFile();
  if (DRI.Addr < Obj->base() ||
      reinterpret_cast<const uint8_t *>(DRI.Addr) + DRI.Size >
          Obj->base() + Obj->getBufSize()) {
    llvm::WithColor::error() << llvm::formatv("{0}: check failed. bug?\n", __func__);
  }
  return DRI;
}

static DynRegionInfo createDRIFrom(const Elf_Phdr *P, uintX_t EntSize, const ELFO *ObjF) {
  return checkDRI({ObjF->getELFFile()->base() + P->p_offset, P->p_filesz,
                   EntSize, ObjF->getFileName()}, ObjF);
}

static DynRegionInfo createDRIFrom(const Elf_Shdr *S, const ELFO *ObjF) {
  return checkDRI({ObjF->getELFFile()->base() + S->sh_offset, S->sh_size,
                   S->sh_entsize, ObjF->getFileName()}, ObjF);
}

static llvm::Expected<DynRegionInfo>
createDRI(const ELFO *ObjF, uint64_t Offset, uint64_t Size, uint64_t EntSize) {
  const ELFF *Obj = ObjF->getELFFile();

  if (Offset + Size < Offset || Offset + Size > Obj->getBufSize())
    return llvm::object::createError("offset greater than file size");

  return DynRegionInfo(Obj->base() + Offset, Size, EntSize, ObjF->getFileName());
}

static uintptr_t loadDynamicTable(const ELFF *Obj,
                                  const ELFO *ObjF,
                                  DynRegionInfo &DynamicTable) {
  const Elf_Phdr *DynamicPhdr;
  const Elf_Shdr *DynamicSec;
  std::tie(DynamicPhdr, DynamicSec) = findDynamic(ObjF, Obj);
  if (!DynamicPhdr && !DynamicSec)
    return 0;

  uintptr_t res = 0;

  DynRegionInfo FromPhdr(ObjF->getFileName());
  bool IsPhdrTableValid = false;
  if (DynamicPhdr) {
    FromPhdr = createDRIFrom(DynamicPhdr, sizeof(Elf_Dyn), ObjF);
    IsPhdrTableValid = !FromPhdr.getAsArrayRef<Elf_Dyn>().empty();

    res = DynamicPhdr->p_vaddr;
  }

  // Locate the dynamic table described in a section header.
  // Ignore sh_entsize and use the expected value for entry size explicitly.
  // This allows us to dump dynamic sections with a broken sh_entsize
  // field.
  DynRegionInfo FromSec(ObjF->getFileName());
  bool IsSecTableValid = false;
  if (DynamicSec) {
    FromSec =
        checkDRI({ObjF->getELFFile()->base() + DynamicSec->sh_offset,
                  DynamicSec->sh_size, sizeof(Elf_Dyn), ObjF->getFileName()}, ObjF);
    IsSecTableValid = !FromSec.getAsArrayRef<Elf_Dyn>().empty();

    res = DynamicSec->sh_addr;
  }

  // When we only have information from one of the SHT_DYNAMIC section header or
  // PT_DYNAMIC program header, just use that.
  if (!DynamicPhdr || !DynamicSec) {
    if ((DynamicPhdr && IsPhdrTableValid) || (DynamicSec && IsSecTableValid)) {
      DynamicTable = DynamicPhdr ? FromPhdr : FromSec;
    } else {
      llvm::WithColor::warning() << llvm::formatv(
          "no valid dynamic table was found for {0}\n", ObjF->getFileName());
    }
    return res;
  }

  // At this point we have tables found from the section header and from the
  // dynamic segment. Usually they match, but we have to do sanity checks to
  // verify that.

  if (FromPhdr.Addr != FromSec.Addr) {
    llvm::WithColor::warning() << llvm::formatv("SHT_DYNAMIC section header and PT_DYNAMIC "
                                          "program header disagree about "
                                          "the location of the dynamic table for {0}\n",
                                          ObjF->getFileName());
  }

  if (!IsPhdrTableValid && !IsSecTableValid) {
    llvm::WithColor::warning() << llvm::formatv("no valid dynamic table was found for {0}\n",
                                          ObjF->getFileName());
    return res;
  }

  // Information in the PT_DYNAMIC program header has priority over the information
  // in a section header.
  if (IsPhdrTableValid) {
    if (!IsSecTableValid) {
#ifdef WARN
      llvm::WithColor::warning()
          << llvm::formatv("SHT_DYNAMIC dynamic table is invalid: PT_DYNAMIC "
                           "will be used for {0}\n",
                           ObjF->getFileName());
#endif
    }

    DynamicTable = FromPhdr;
  } else {
#ifdef WARN
    llvm::WithColor::warning() <<
      llvm::formatv("PT_DYNAMIC dynamic table is invalid: SHT_DYNAMIC will be used for {0}\n",
                    ObjF->getFileName());
#endif

    DynamicTable = FromSec;
  }

  return res;
}

std::pair<const typename ELFT::Phdr *, const typename ELFT::Shdr *>
findDynamic(const ELFO *ObjF, const ELFF *Obj) {
  // Try to locate the PT_DYNAMIC header.
  const Elf_Phdr *DynamicPhdr = nullptr;
  for (const Elf_Phdr &Phdr : unwrapOrError(Obj->program_headers())) {
    if (Phdr.p_type != llvm::ELF::PT_DYNAMIC)
      continue;
    DynamicPhdr = &Phdr;
    break;
  }

  // Try to locate the .dynamic section in the sections header table.
  const Elf_Shdr *DynamicSec = nullptr;
  for (const Elf_Shdr &Sec : unwrapOrError(Obj->sections())) {
    if (Sec.sh_type != llvm::ELF::SHT_DYNAMIC)
      continue;
    DynamicSec = &Sec;
    break;
  }

  if (DynamicPhdr && DynamicPhdr->p_offset + DynamicPhdr->p_filesz >
                         ObjF->getMemoryBufferRef().getBufferSize()) {
    llvm::WithColor::warning() <<
      llvm::formatv("{0}: PT_DYNAMIC segment offset + size exceeds the size of the file\n", __func__);

    // Don't use the broken dynamic header.
    DynamicPhdr = nullptr;
  }

  if (DynamicPhdr && DynamicSec) {
    llvm::StringRef Name = unwrapOrError(Obj->getSectionName(DynamicSec));
    if (DynamicSec->sh_addr + DynamicSec->sh_size >
            DynamicPhdr->p_vaddr + DynamicPhdr->p_memsz ||
        DynamicSec->sh_addr < DynamicPhdr->p_vaddr)
      llvm::WithColor::warning() <<
        llvm::formatv("The SHT_DYNAMIC section '{0}' is not contained within the PT_DYNAMIC segment\n", Name);

    if (DynamicSec->sh_addr != DynamicPhdr->p_vaddr)
      llvm::WithColor::warning() <<
        llvm::formatv("The SHT_DYNAMIC section '{0}' is not at the start of PT_DYNAMIC segment\n", Name);
  }

  return std::make_pair(DynamicPhdr, DynamicSec);
}

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

static llvm::Optional<DynRegionInfo> loadDynamicSymbols(const ELFF *Obj,
                                                        const ELFO *ObjF,
                                                        const DynRegionInfo &DynamicTable,
                                                        llvm::StringRef &DynamicStringTable,
                                                        const Elf_Shdr *&SymbolVersionSection,
                                                        llvm::SmallVector<VersionMapEntry, 16> &VersionMap) {
  llvm::Optional<DynRegionInfo> DynSymRegion;
  const Elf_Hash *HashTable = nullptr;
  const Elf_Shdr *DotDynsymSec = nullptr;

  SymbolVersionSection = nullptr;                     // .gnu.version
  const Elf_Shdr *SymbolVersionNeedSection = nullptr; // .gnu.version_r
  const Elf_Shdr *SymbolVersionDefSection = nullptr;  // .gnu.version_d

  auto dynamic_table = [&](void) -> Elf_Dyn_Range {
    return DynamicTable.getAsArrayRef<Elf_Dyn>();
  };

  //
  // examine the sections
  //
  llvm::Expected<Elf_Shdr_Range> ExpectedSections = Obj->sections();
  if (ExpectedSections && !(*ExpectedSections).empty()) {
    for (const Elf_Shdr &Sec : *ExpectedSections) {
      switch (Sec.sh_type) {
      case llvm::ELF::SHT_DYNSYM:
        if (!DotDynsymSec)
          DotDynsymSec = &Sec;

        if (!DynSymRegion) {
          llvm::Expected<DynRegionInfo> RegOrErr =
              createDRI(ObjF, Sec.sh_offset, Sec.sh_size, Sec.sh_entsize);
          if (RegOrErr) {
            DynSymRegion = *RegOrErr;

            if (llvm::Expected<llvm::StringRef> E = Obj->getStringTableForSymtab(Sec))
              DynamicStringTable = *E;
            else
              llvm::WithColor::warning()
                  << __func__ << ": unable to get the string table\n";
          } else {
            llvm::WithColor::warning()
                << __func__ << ": unable to read dynamic symbols from ELF\n";
          }
        }
        break;

      case llvm::ELF::SHT_GNU_versym:
        SymbolVersionSection = &Sec;
        break;

      case llvm::ELF::SHT_GNU_verdef:
        SymbolVersionDefSection = &Sec;
        break;

      case llvm::ELF::SHT_GNU_verneed:
        SymbolVersionNeedSection = &Sec;
        break;
      }
    }
  }

  //
  // examine the dynamic table
  //
  const char *StringTableBegin = nullptr;
  uint64_t StringTableSize = 0;
  llvm::Optional<DynRegionInfo> DynSymFromTable;
  for (const Elf_Dyn &Dyn : dynamic_table()) {
    if (Dyn.d_tag == llvm::ELF::DT_NULL)
      break; /* marks end of dynamic table. */

    switch (Dyn.d_tag) {
    case llvm::ELF::DT_STRTAB:
      if (llvm::Expected<const uint8_t *> ExpectedPtr = Obj->toMappedAddr(Dyn.getPtr()))
        StringTableBegin = reinterpret_cast<const char *>(*ExpectedPtr);
      break;
    case llvm::ELF::DT_STRSZ:
      StringTableSize = Dyn.getVal();
      break;
    case llvm::ELF::DT_SYMTAB:
      if (llvm::Expected<const uint8_t *> ExpectedPtr = Obj->toMappedAddr(Dyn.getPtr())) {
        DynSymFromTable.emplace(ObjF->getFileName());
        DynSymFromTable->Addr = *ExpectedPtr;
        DynSymFromTable->EntSize = sizeof(Elf_Sym);
      }
      break;
    case llvm::ELF::DT_SYMENT: {
      uint64_t Val = Dyn.getVal();
      if (Val != sizeof(Elf_Sym))
        llvm::WithColor::warning() << llvm::formatv(
            "DT_SYMENT value of {0} is not the size of a symbol ({1})",
            Val, sizeof(Elf_Sym));
      break;
    }
    case llvm::ELF::DT_HASH:
      if (llvm::Expected<const uint8_t *> ExpectedHashTable = Obj->toMappedAddr(Dyn.getPtr()))
        HashTable = reinterpret_cast<const Elf_Hash *>(*ExpectedHashTable);
      break;

    default:
      break;
    }
  }

  if (StringTableBegin) {
    const uint64_t FileSize = Obj->getBufSize();
    const uint64_t Offset = (const uint8_t *)StringTableBegin - Obj->base();
    if (StringTableSize > FileSize - Offset) {
#ifdef WARN
      WARN();
#endif
    } else {
      DynamicStringTable = llvm::StringRef(StringTableBegin, StringTableSize);
    }
  }

  auto getHashTableEntSize = [&](void) -> unsigned {
    // EM_S390 and ELF::EM_ALPHA platforms use 8-bytes entries in SHT_HASH
    // sections. This violates the ELF specification.
    if (Obj->getHeader()->e_machine == llvm::ELF::EM_S390 ||
        Obj->getHeader()->e_machine == llvm::ELF::EM_ALPHA)
      return 8;
    return 4;
  };

  const bool IsHashTableSupported = getHashTableEntSize() == 4;
  if (DynSymRegion) {
    // Often we find the information about the dynamic symbol table
    // location in the SHT_DYNSYM section header. However, the value in
    // DT_SYMTAB has priority, because it is used by dynamic loaders to
    // locate .dynsym at runtime. The location we find in the section header
    // and the location we find here should match.
    if (DynSymFromTable && DynSymFromTable->Addr != DynSymRegion->Addr)
      llvm::WithColor::warning()
          << "SHT_DYNSYM section header and DT_SYMTAB disagree about "
             "the location of the dynamic symbol table";

    // According to the ELF gABI: "The number of symbol table entries should
    // equal nchain". Check to see if the DT_HASH hash table nchain value
    // conflicts with the number of symbols in the dynamic symbol table
    // according to the section header.
    if (HashTable && IsHashTableSupported) {
      if (DynSymRegion->EntSize == 0)
        llvm::WithColor::warning() << "SHT_DYNSYM section has sh_entsize == 0";
      else if (HashTable->nchain != DynSymRegion->Size / DynSymRegion->EntSize)
        llvm::WithColor::warning() << "hash table nchain differs from symbol count "
                                "derived from SHT_DYNSYM section header";
    }
  }

  // Delay the creation of the actual dynamic symbol table until now, so that
  // checks can always be made against the section header-based properties,
  // without worrying about tag order.
  if (DynSymFromTable) {
    if (!DynSymRegion) {
      DynSymRegion = DynSymFromTable;
    } else {
      DynSymRegion->Addr = DynSymFromTable->Addr;
      DynSymRegion->EntSize = DynSymFromTable->EntSize;
    }
  }

  // Derive the dynamic symbol table size from the DT_HASH hash table, if
  // present.
  if (HashTable && IsHashTableSupported && DynSymRegion) {
    const uint64_t FileSize = Obj->getBufSize();
    const uint64_t DerivedSize =
        (uint64_t)HashTable->nchain * DynSymRegion->EntSize;
    const uint64_t Offset = (const uint8_t *)DynSymRegion->Addr - Obj->base();
    if (DerivedSize > FileSize - Offset)
      llvm::WithColor::warning() << llvm::formatv(
          "the size ({0:x}) of the dynamic symbol table at {1:x}, derived from "
          "the hash table, goes past the end of the file ({2:x}) and will be "
          "ignored\n",
          DerivedSize, Offset, FileSize);
    else
      DynSymRegion->Size = HashTable->nchain * DynSymRegion->EntSize;
  }

  //
  // GNU symbol versions
  //
  auto LoadVersionDefs = [&](const Elf_Shdr *Sec) -> void {
    unsigned VerdefSize = Sec->sh_size;    // Size of section in bytes
    unsigned VerdefEntries = Sec->sh_info; // Number of Verdef entries
    const uint8_t *VerdefStart =
        reinterpret_cast<const uint8_t *>(Obj->base() + Sec->sh_offset);
    const uint8_t *VerdefEnd = VerdefStart + VerdefSize;
    // The first Verdef entry is at the start of the section.
    const uint8_t *VerdefBuf = VerdefStart;
    for (unsigned VerdefIndex = 0; VerdefIndex < VerdefEntries; ++VerdefIndex) {
      if (VerdefBuf + sizeof(Elf_Verdef) > VerdefEnd) {
#if 0
        report_fatal_error("Section ended unexpectedly while scanning "
                           "version definitions.");
#else
        abort();
#endif
      }

      const Elf_Verdef *Verdef =
          reinterpret_cast<const Elf_Verdef *>(VerdefBuf);
      if (Verdef->vd_version != llvm::ELF::VER_DEF_CURRENT) {
#if 0
        report_fatal_error("Unexpected verdef version");
#else
        abort();
#endif
      }

      size_t Index = Verdef->vd_ndx & llvm::ELF::VERSYM_VERSION;
      if (Index >= VersionMap.size())
        VersionMap.resize(Index + 1);
      VersionMap[Index] = VersionMapEntry(Verdef);
      VerdefBuf += Verdef->vd_next;
    }
  };

  auto LoadVersionNeeds = [&](const Elf_Shdr *Sec) -> void {
    unsigned VerneedSize = Sec->sh_size;    // Size of section in bytes
    unsigned VerneedEntries = Sec->sh_info; // Number of Verneed entries
    const uint8_t *VerneedStart =
        reinterpret_cast<const uint8_t *>(Obj->base() + Sec->sh_offset);
    const uint8_t *VerneedEnd = VerneedStart + VerneedSize;
    // The first Verneed entry is at the start of the section.
    const uint8_t *VerneedBuf = VerneedStart;
    for (unsigned VerneedIndex = 0; VerneedIndex < VerneedEntries;
         ++VerneedIndex) {
      if (VerneedBuf + sizeof(Elf_Verneed) > VerneedEnd) {
#if 0
        report_fatal_error("Section ended unexpectedly while scanning "
                           "version needed records.");
#else
        abort();
#endif
      }
      const Elf_Verneed *Verneed =
          reinterpret_cast<const Elf_Verneed *>(VerneedBuf);
      if (Verneed->vn_version != llvm::ELF::VER_NEED_CURRENT) {
#if 0
        report_fatal_error("Unexpected verneed version");
#else
        abort();
#endif
      }
      // Iterate through the Vernaux entries
      const uint8_t *VernauxBuf = VerneedBuf + Verneed->vn_aux;
      for (unsigned VernauxIndex = 0; VernauxIndex < Verneed->vn_cnt;
           ++VernauxIndex) {
        if (VernauxBuf + sizeof(Elf_Vernaux) > VerneedEnd) {
#if 0
          report_fatal_error(
              "Section ended unexpected while scanning auxiliary "
              "version needed records.");
#else
          abort();
#endif
        }
        const Elf_Vernaux *Vernaux =
            reinterpret_cast<const Elf_Vernaux *>(VernauxBuf);
        size_t Index = Vernaux->vna_other & llvm::ELF::VERSYM_VERSION;
        if (Index >= VersionMap.size())
          VersionMap.resize(Index + 1);
        VersionMap[Index] = VersionMapEntry(Vernaux);
        VernauxBuf += Vernaux->vna_next;
      }
      VerneedBuf += Verneed->vn_next;
    }
  };

  if (DynSymRegion && DynSymRegion->Addr && SymbolVersionSection) {
    assert(VersionMap.empty());

    // The first two version indexes are reserved.
    // Index 0 is LOCAL, index 1 is GLOBAL.
    VersionMap.push_back(VersionMapEntry());
    VersionMap.push_back(VersionMapEntry());

    if (SymbolVersionDefSection)
      LoadVersionDefs(SymbolVersionDefSection);

    if (SymbolVersionNeedSection)
      LoadVersionNeeds(SymbolVersionNeedSection);
  }

  return DynSymRegion;
}

llvm::StringRef getSymbolVersionByIndex(llvm::SmallVector<VersionMapEntry, 16> &VersionMap,
                                        llvm::StringRef StrTab,
                                        uint32_t SymbolVersionIndex,
                                        bool &IsDefault) {
  size_t VersionIndex = SymbolVersionIndex & llvm::ELF::VERSYM_VERSION;

  // Special markers for unversioned symbols.
  if (VersionIndex == llvm::ELF::VER_NDX_LOCAL ||
      VersionIndex == llvm::ELF::VER_NDX_GLOBAL) {
    IsDefault = false;
    return "";
  }

  // Lookup this symbol in the version table.
  if (VersionIndex >= VersionMap.size() ||
      VersionMap[VersionIndex].isNull()) {
    llvm::WithColor::error() << "Invalid version entry\n";
    exit(1);
  }

  const VersionMapEntry &Entry = VersionMap[VersionIndex];

  // Get the version name string.
  size_t NameOffset;
  if (Entry.isVerdef()) {
    // The first Verdaux entry holds the name.
    NameOffset = Entry.getVerdef()->getAux()->vda_name;
    IsDefault = !(SymbolVersionIndex & llvm::ELF::VERSYM_HIDDEN);
  } else {
    NameOffset = Entry.getVernaux()->vna_name;
    IsDefault = false;
  }

  if (NameOffset >= StrTab.size()) {
    llvm::WithColor::error() << "Invalid string offset\n";
    return "";
  }

  return StrTab.data() + NameOffset;
};

static const typename ELFT::Shdr *
findSectionByName(const ELFF &Obj, llvm::StringRef Name) {
  for (const Elf_Shdr &Shdr : llvm::cantFail(Obj.sections())) {
    if (llvm::Expected<llvm::StringRef> NameOrErr = Obj.getSectionName(&Shdr)) {
      if (*NameOrErr == Name)
        return &Shdr;
    } else {
      llvm::WithColor::warning() << llvm::formatv(
          "unable to read the name of section: {0}\n",
          llvm::toString(NameOrErr.takeError()));
    }
  }
  return nullptr;
}

static const typename ELFO::Elf_Shdr *
findNotEmptySectionByAddress(const ELFF &Obj, llvm::StringRef FileName,
                             uint64_t Addr) {
  for (const typename ELFO::Elf_Shdr &Shdr : llvm::cantFail(Obj.sections()))
    if (Shdr.sh_addr == Addr && Shdr.sh_size > 0)
      return &Shdr;
  return nullptr;
}

static std::string describe(const ELFF &Obj, const typename ELFT::Shdr &Sec) {
  unsigned SecNdx = &Sec - &llvm::cantFail(Obj.sections()).front();
  std::string SecTyNm = llvm::object::getELFSectionTypeName(
      Obj.getHeader()->e_machine, Sec.sh_type);

  char buff[256];
  snprintf(buff,
           sizeof(buff),
           "%s section with index %u",
           SecTyNm.c_str(),
           SecNdx);

  return std::string(buff);
}

static void loadDynamicRelocations(const ELFF *Obj,
                                   const ELFO *ObjF,
                                   const DynRegionInfo &DynamicTable,
                                   DynRegionInfo &DynRelRegion,
                                   DynRegionInfo &DynRelaRegion,
                                   DynRegionInfo &DynRelrRegion,
                                   DynRegionInfo &DynPLTRelRegion) {
  auto dynamic_table = [&](void) -> Elf_Dyn_Range {
    return DynamicTable.getAsArrayRef<Elf_Dyn>();
  };

  for (const Elf_Dyn &Dyn : dynamic_table()) {
    if (Dyn.d_tag == llvm::ELF::DT_NULL)
      break; /* marks end of dynamic table. */

    switch (Dyn.d_tag) {
    case llvm::ELF::DT_RELA:
      if (llvm::Expected<const uint8_t *> ExpectedPtr = Obj->toMappedAddr(Dyn.getPtr()))
        DynRelaRegion.Addr = *ExpectedPtr;
      break;
    case llvm::ELF::DT_RELASZ:
      DynRelaRegion.Size = Dyn.getVal();
      break;
    case llvm::ELF::DT_RELAENT:
      DynRelaRegion.EntSize = Dyn.getVal();
      break;
    case llvm::ELF::DT_REL:
      if (llvm::Expected<const uint8_t *> ExpectedPtr = Obj->toMappedAddr(Dyn.getPtr()))
        DynRelRegion.Addr = *ExpectedPtr;
      break;
    case llvm::ELF::DT_RELSZ:
      DynRelRegion.Size = Dyn.getVal();
      break;
    case llvm::ELF::DT_RELENT:
      DynRelRegion.EntSize = Dyn.getVal();
      break;
    case llvm::ELF::DT_RELR:
    case llvm::ELF::DT_ANDROID_RELR:
      if (llvm::Expected<const uint8_t *> ExpectedPtr = Obj->toMappedAddr(Dyn.getPtr()))
        DynRelrRegion.Addr = *ExpectedPtr;
      break;
    case llvm::ELF::DT_RELRSZ:
    case llvm::ELF::DT_ANDROID_RELRSZ:
      DynRelrRegion.Size = Dyn.getVal();
      break;
    case llvm::ELF::DT_RELRENT:
    case llvm::ELF::DT_ANDROID_RELRENT:
      DynRelrRegion.EntSize = Dyn.getVal();
      break;
    case llvm::ELF::DT_PLTREL:
      if (Dyn.getVal() == llvm::ELF::DT_REL)
        DynPLTRelRegion.EntSize = sizeof(Elf_Rel);
      else if (Dyn.getVal() == llvm::ELF::DT_RELA)
        DynPLTRelRegion.EntSize = sizeof(Elf_Rela);
      else
        llvm::WithColor::warning() << (llvm::Twine("unknown DT_PLTREL value of ") +
                                       llvm::Twine((uint64_t)Dyn.getVal()));
      break;
    case llvm::ELF::DT_JMPREL:
      if (llvm::Expected<const uint8_t *> ExpectedPtr = Obj->toMappedAddr(Dyn.getPtr()))
        DynPLTRelRegion.Addr = *ExpectedPtr;
      break;
    case llvm::ELF::DT_PLTRELSZ:
      DynPLTRelRegion.Size = Dyn.getVal();
      break;
    }
  }
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

MipsGOTParser::MipsGOTParser(const ELFF &Obj, llvm::StringRef FileName)
    : IsStatic(false /* XXX */), Obj(Obj),
      GotSec(nullptr), LocalNum(0), GlobalNum(0), PltSec(nullptr),
      PltRelSec(nullptr), PltSymTable(nullptr),
      FileName(FileName) {}

llvm::Error MipsGOTParser::findGOT(Elf_Dyn_Range DynTable,
                                   Elf_Sym_Range DynSyms) {
  // See "Global Offset Table" in Chapter 5 in the following document
  // for detailed GOT description.
  // ftp://www.linux-mips.org/pub/linux/mips/doc/ABI/mipsabi.pdf

  // Find static GOT secton.
  if (IsStatic) {
    GotSec = findSectionByName(Obj, ".got");
    if (!GotSec)
      return llvm::Error::success();

    llvm::ArrayRef<uint8_t> Content =
        unwrapOrError(Obj.getSectionContents(GotSec));
    GotEntries = Entries(reinterpret_cast<const Entry *>(Content.data()),
                         Content.size() / sizeof(Entry));
    LocalNum = GotEntries.size();
    return llvm::Error::success();
  }

  // Lookup dynamic table tags which define the GOT layout.
  llvm::Optional<uint64_t> DtPltGot;
  llvm::Optional<uint64_t> DtLocalGotNum;
  llvm::Optional<uint64_t> DtGotSym;
  for (const auto &Entry : DynTable) {
    if (Entry.getTag() == llvm::ELF::DT_NULL)
      break; /* marks end of dynamic table. */

    switch (Entry.getTag()) {
    case llvm::ELF::DT_PLTGOT:
      DtPltGot = Entry.getVal();
      break;
    case llvm::ELF::DT_MIPS_LOCAL_GOTNO:
      DtLocalGotNum = Entry.getVal();
      break;
    case llvm::ELF::DT_MIPS_GOTSYM:
      DtGotSym = Entry.getVal();
      break;
    }
  }

  if (!DtPltGot && !DtLocalGotNum && !DtGotSym)
    return llvm::Error::success();

  if (!DtPltGot)
    return llvm::object::createError("cannot find PLTGOT dynamic tag");
  if (!DtLocalGotNum)
    return llvm::object::createError("cannot find MIPS_LOCAL_GOTNO dynamic tag");
  if (!DtGotSym)
    return llvm::object::createError("cannot find MIPS_GOTSYM dynamic tag");

  size_t DynSymTotal = DynSyms.size();
  if (*DtGotSym > DynSymTotal)
    return llvm::object::createError("DT_MIPS_GOTSYM value (" + llvm::Twine(*DtGotSym) +
                       ") exceeds the number of dynamic symbols (" +
                       llvm::Twine(DynSymTotal) + ")");

  LocalNum = *DtLocalGotNum;
  GlobalNum = DynSymTotal - *DtGotSym;

  GotSec = findNotEmptySectionByAddress(Obj, FileName, *DtPltGot);
  if (GotSec) {
    llvm::ArrayRef<uint8_t> Content =
        unwrapOrError(Obj.getSectionContents(GotSec));
    GotEntries = Entries(reinterpret_cast<const Entry *>(Content.data()),
                         Content.size() / sizeof(Entry));
  } else {
    GotSecAddr = *DtPltGot;

    llvm::Expected<const uint8_t *> ExpectedContents = Obj.toMappedAddr(GotSecAddr);
    if (!ExpectedContents) {
      return llvm::object::createError("GotSecAddr does not exist in any load segment");
    }

    GotEntries = Entries(reinterpret_cast<const Entry *>(*ExpectedContents),
                         GlobalNum + LocalNum);
  }

  GotDynSyms = DynSyms.drop_front(*DtGotSym);

  return llvm::Error::success();
}

#if 0

llvm::Error MipsGOTParser::findPLT(Elf_Dyn_Range DynTable) {
  // Lookup dynamic table tags which define the PLT layout.
  llvm::Optional<uint64_t> DtMipsPltGot;
  llvm::Optional<uint64_t> DtJmpRel;
  for (const auto &Entry : DynTable) {
    switch (Entry.getTag()) {
    case llvm::ELF::DT_MIPS_PLTGOT:
      DtMipsPltGot = Entry.getVal();
      break;
    case llvm::ELF::DT_JMPREL:
      DtJmpRel = Entry.getVal();
      break;
    }
  }

  if (!DtMipsPltGot && !DtJmpRel)
    return llvm::Error::success();

  // Find PLT section.
  if (!DtMipsPltGot)
    return llvm::object::createError("cannot find MIPS_PLTGOT dynamic tag");
  if (!DtJmpRel)
    return llvm::object::createError("cannot find JMPREL dynamic tag");

  PltSec = findNotEmptySectionByAddress(Obj, FileName, *DtMipsPltGot);
  if (!PltSec)
    return llvm::object::createError("there is no non-empty PLTGOT section at 0x" +
                       llvm::Twine::utohexstr(*DtMipsPltGot));

  PltRelSec = findNotEmptySectionByAddress(Obj, FileName, *DtJmpRel);
  if (!PltRelSec)
    return llvm::object::createError("there is no non-empty RELPLT section at 0x" +
                       llvm::Twine::utohexstr(*DtJmpRel));

  if (llvm::Expected<llvm::ArrayRef<uint8_t>> PltContentOrErr =
          Obj.getSectionContents(PltSec))
    PltEntries =
        Entries(reinterpret_cast<const Entry *>(PltContentOrErr->data()),
                PltContentOrErr->size() / sizeof(Entry));
  else
    return llvm::object::createError("unable to read PLTGOT section content: " +
                       toString(PltContentOrErr.takeError()));

  if (llvm::Expected<const Elf_Shdr *> PltSymTableOrErr =
          Obj.getSection(PltRelSec->sh_link))
    PltSymTable = *PltSymTableOrErr;
  else
    return llvm::object::createError("unable to get a symbol table linked to the " +
                       describe(Obj, *PltRelSec) + ": " +
                       toString(PltSymTableOrErr.takeError()));

  if (llvm::Expected<llvm::StringRef> StrTabOrErr =
          Obj.getStringTableForSymtab(*PltSymTable))
    PltStrTable = *StrTabOrErr;
  else
    return llvm::object::createError("unable to get a string table for the " +
                       describe(Obj, *PltSymTable) + ": " +
                       toString(StrTabOrErr.takeError()));

  return llvm::Error::success();
}

#endif

uint64_t MipsGOTParser::getGp() const {
  assert(GotSec);
  return GotSec->sh_addr + 0x7ff0;
}

const typename MipsGOTParser::Entry *
MipsGOTParser::getGotLazyResolver() const {
  return LocalNum > 0 ? &GotEntries[0] : nullptr;
}

const typename MipsGOTParser::Entry *
MipsGOTParser::getGotModulePointer() const {
  if (LocalNum < 2)
    return nullptr;
  const Entry &E = GotEntries[1];
  if ((E >> (sizeof(Entry) * 8 - 1)) == 0)
    return nullptr;
  return &E;
}

typename MipsGOTParser::Entries
MipsGOTParser::getLocalEntries() const {
  size_t Skip = getGotModulePointer() ? 2 : 1;
  if (LocalNum - Skip <= 0)
    return Entries();
  return GotEntries.slice(Skip, LocalNum - Skip);
}

typename MipsGOTParser::Entries
MipsGOTParser::getGlobalEntries() const {
  if (GlobalNum == 0)
    return Entries();

  //llvm::WithColor::note() << llvm::formatv("[MipsGOTParser::getGlobalEntries] GotEntries.size()={0} LocalNum={1} GlobalNum={2}\n", GotEntries.size(), LocalNum, GlobalNum);

  return GotEntries.slice(LocalNum, GlobalNum);
}

typename MipsGOTParser::Entries
MipsGOTParser::getOtherEntries() const {
  size_t OtherNum = GotEntries.size() - LocalNum - GlobalNum;
  if (OtherNum == 0)
    return Entries();
  return GotEntries.slice(LocalNum + GlobalNum, OtherNum);
}

uint64_t MipsGOTParser::getGotAddress(const Entry *E) const {
  int64_t Offset = std::distance(GotEntries.data(), E) * sizeof(Entry);
  if (GotSec) {
    return GotSec->sh_addr + Offset;
  } else {
    assert(GotSecAddr);
    return GotSecAddr + Offset;
  }
}

int64_t MipsGOTParser::getGotOffset(const Entry *E) const {
  int64_t Offset = std::distance(GotEntries.data(), E) * sizeof(Entry);
  return Offset - 0x7ff0;
}

const Elf_Sym *
MipsGOTParser::getGotSym(const Entry *E) const {
  int64_t Offset = std::distance(GotEntries.data(), E);
  return &GotDynSyms[Offset - LocalNum];
}

const typename MipsGOTParser::Entry *
MipsGOTParser::getPltLazyResolver() const {
  return PltEntries.empty() ? nullptr : &PltEntries[0];
}

const typename MipsGOTParser::Entry *
MipsGOTParser::getPltModulePointer() const {
  return PltEntries.size() < 2 ? nullptr : &PltEntries[1];
}

typename MipsGOTParser::Entries
MipsGOTParser::getPltEntries() const {
  if (PltEntries.size() <= 2)
    return Entries();
  return PltEntries.slice(2, PltEntries.size() - 2);
}

uint64_t MipsGOTParser::getPltAddress(const Entry *E) const {
  int64_t Offset = std::distance(PltEntries.data(), E) * sizeof(Entry);
  return PltSec->sh_addr + Offset;
}

const Elf_Sym *MipsGOTParser::getPltSym(const Entry *E) const {
  int64_t Offset = std::distance(getPltEntries().data(), E);
  if (PltRelSec->sh_type == llvm::ELF::SHT_REL) {
    Elf_Rel_Range Rels = unwrapOrError(Obj.rels(PltRelSec));
    return unwrapOrError(Obj.getRelocationSymbol(&Rels[Offset], PltSymTable));
  } else {
    Elf_Rela_Range Rels = unwrapOrError(Obj.relas(PltRelSec));
    return unwrapOrError(Obj.getRelocationSymbol(&Rels[Offset], PltSymTable));
  }
}

#endif

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
  llvm::Optional<int64_t> Addend;
};

struct RelSymbol {
  RelSymbol(const typename ELFT::Sym *S, llvm::StringRef N)
      : Sym(S), Name(N.str()) {}
  const Elf_Sym *Sym;
  std::string Name;
};

static RelSymbol getSymbolForReloc(ELFO &ObjF,
                                   Elf_Sym_Range dynamic_symbols,
                                   llvm::StringRef DynamicStringTable,
                                   const Relocation &Reloc) {
  auto WarnAndReturn = [&](const Elf_Sym *Sym,
                           const llvm::Twine &Reason) -> RelSymbol {
    llvm::WithColor::warning() << llvm::formatv(
        "unable to get name of the dynamic symbol with index {0}: {1}\n",
        llvm::Twine(Reloc.Symbol), Reason);
    return {Sym, "<corrupt>"};
  };

  llvm::ArrayRef<Elf_Sym> Symbols = dynamic_symbols;
  const Elf_Sym *FirstSym = Symbols.begin();
  if (!FirstSym)
    return WarnAndReturn(nullptr, "no dynamic symbol table found");

  // We might have an object without a section header. In this case the size of
  // Symbols is zero, because there is no way to know the size of the dynamic
  // table. We should allow this case and not print a warning.
  if (!Symbols.empty() && Reloc.Symbol >= Symbols.size())
    return WarnAndReturn(
        nullptr,
        "index is greater than or equal to the number of dynamic symbols (" +
            llvm::Twine(Symbols.size()) + ")");

  const ELFF *Obj = ObjF.getELFFile();
  const uint64_t FileSize = Obj->getBufSize();
  const uint64_t SymOffset = ((const uint8_t *)FirstSym - Obj->base()) +
                             (uint64_t)Reloc.Symbol * sizeof(Elf_Sym);
  if (SymOffset + sizeof(Elf_Sym) > FileSize)
    return WarnAndReturn(nullptr, "symbol at 0x" +
                                      llvm::Twine::utohexstr(SymOffset) +
                                      " goes past the end of the file (0x" +
                                      llvm::Twine::utohexstr(FileSize) + ")");

  const Elf_Sym *Sym = FirstSym + Reloc.Symbol;
  llvm::Expected<llvm::StringRef> ErrOrName = Sym->getName(DynamicStringTable);
  if (!ErrOrName)
    return WarnAndReturn(Sym, llvm::toString(ErrOrName.takeError()));

  return {Sym == FirstSym ? nullptr : Sym, (*ErrOrName).str()};
}

void for_each_dynamic_relocation(const ELFF &E,
                                 DynRegionInfo &DynRelRegion,
                                 DynRegionInfo &DynRelaRegion,
                                 DynRegionInfo &DynRelrRegion,
                                 DynRegionInfo &DynPLTRelRegion,
                                 std::function<void(const Relocation &R)> proc) {
  const bool IsMips64EL = E.isMips64EL();

  //
  // from ELFDumper::printDynamicRelocationsHelper()
  //
  if (DynRelaRegion.Size > 0) {
    auto DynRelaRelocs = DynRelaRegion.getAsArrayRef<Elf_Rela>();

    std::for_each(DynRelaRelocs.begin(),
                  DynRelaRelocs.end(),
                  [&](const Elf_Rela &Rela) {
                    proc(Relocation(Rela, IsMips64EL));
                  });
  }

  if (DynRelRegion.Size > 0) {
    auto DynRelRelocs = DynRelRegion.getAsArrayRef<Elf_Rel>();

    std::for_each(DynRelRelocs.begin(),
                  DynRelRelocs.end(),
                  [&](const Elf_Rel &Rel) {
                    proc(Relocation(Rel, IsMips64EL));
                  });
  }

  if (DynRelrRegion.Size > 0) {
    Elf_Relr_Range Relrs = DynRelrRegion.getAsArrayRef<Elf_Relr>();
    llvm::Expected<std::vector<Elf_Rela>> ExpectedRelrRelas = E.decode_relrs(Relrs);
    if (ExpectedRelrRelas) {
      auto &RelrRelasRelocs = *ExpectedRelrRelas;

      std::for_each(RelrRelasRelocs.begin(),
                    RelrRelasRelocs.end(),
                    [&](const Elf_Rela &Rela) {
                      proc(Relocation(Rela, IsMips64EL));
                    });
    }
  }

  if (DynPLTRelRegion.Size > 0) {
    if (DynPLTRelRegion.EntSize == sizeof(Elf_Rela)) {
      auto DynPLTRelRelocs = DynPLTRelRegion.getAsArrayRef<Elf_Rela>();

      std::for_each(DynPLTRelRelocs.begin(),
                    DynPLTRelRelocs.end(),
                    [&](const Elf_Rela &Rela) {
                      proc(Relocation(Rela, IsMips64EL));
                    });
    } else {
      auto DynPLTRelRelocs = DynPLTRelRegion.getAsArrayRef<Elf_Rel>();

      std::for_each(DynPLTRelRelocs.begin(),
                    DynPLTRelRelocs.end(),
                    [&](const Elf_Rel &Rel) {
                      proc(Relocation(Rel, IsMips64EL));
                    });
    }
  }
}

/// Represents a contiguous uniform range in the file. We cannot just create a
/// range directly because when creating one of these from the .dynamic table
/// the size, entity size and virtual address are different entries in arbitrary
/// order (DT_REL, DT_RELSZ, DT_RELENT for example).
struct DynRegionInfo {
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
  WithColor::error() << Buf << '\n';
  abort();
}

#if defined(TARGET_X86_64) || defined(TARGET_AARCH64) || defined(TARGET_MIPS64)
typedef typename obj::ELF64LE ELFT;
#elif defined(TARGET_I386) || (defined(TARGET_MIPS32) && !defined(HOST_WORDS_BIGENDIAN))
typedef typename obj::ELF32LE ELFT;
#elif defined(TARGET_MIPS32) && defined(HOST_WORDS_BIGENDIAN)
typedef typename obj::ELF32BE ELFT;
#else
#error
#endif

typedef typename obj::ELFObjectFile<ELFT> ELFO;
typedef typename obj::ELFFile<ELFT> ELFF;

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
    WithColor::error() << llvm::formatv("{0}: check failed. bug?\n", __func__);
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
      WithColor::warning() << llvm::formatv(
          "no valid dynamic table was found for {0}\n", ObjF->getFileName());
    }
    return res;
  }

  // At this point we have tables found from the section header and from the
  // dynamic segment. Usually they match, but we have to do sanity checks to
  // verify that.

  if (FromPhdr.Addr != FromSec.Addr) {
    WithColor::warning() << llvm::formatv("SHT_DYNAMIC section header and PT_DYNAMIC "
                                          "program header disagree about "
                                          "the location of the dynamic table for {0}\n",
                                          ObjF->getFileName());
  }

  if (!IsPhdrTableValid && !IsSecTableValid) {
    WithColor::warning() << llvm::formatv("no valid dynamic table was found for {0}\n",
                                          ObjF->getFileName());
    return res;
  }

  // Information in the PT_DYNAMIC program header has priority over the information
  // in a section header.
  if (IsPhdrTableValid) {
    if (!IsSecTableValid) {
#ifdef WARN
      WithColor::warning()
          << llvm::formatv("SHT_DYNAMIC dynamic table is invalid: PT_DYNAMIC "
                           "will be used for {0}\n",
                           ObjF->getFileName());
#endif
    }

    DynamicTable = FromPhdr;
  } else {
#ifdef WARN
    WithColor::warning() <<
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
    WithColor::warning() <<
      llvm::formatv("{0}: PT_DYNAMIC segment offset + size exceeds the size of the file\n", __func__);

    // Don't use the broken dynamic header.
    DynamicPhdr = nullptr;
  }

  if (DynamicPhdr && DynamicSec) {
    llvm::StringRef Name = unwrapOrError(Obj->getSectionName(DynamicSec));
    if (DynamicSec->sh_addr + DynamicSec->sh_size >
            DynamicPhdr->p_vaddr + DynamicPhdr->p_memsz ||
        DynamicSec->sh_addr < DynamicPhdr->p_vaddr)
      WithColor::warning() <<
        llvm::formatv("The SHT_DYNAMIC section '{0}' is not contained within the PT_DYNAMIC segment\n", Name);

    if (DynamicSec->sh_addr != DynamicPhdr->p_vaddr)
      WithColor::warning() <<
        llvm::formatv("The SHT_DYNAMIC section '{0}' is not at the start of PT_DYNAMIC segment\n", Name);
  }

  return std::make_pair(DynamicPhdr, DynamicSec);
}

static const typename ELFT::Shdr *
findSectionByName(const ELFF &Obj, llvm::StringRef Name) {
  for (const Elf_Shdr &Shdr : llvm::cantFail(Obj.sections())) {
    if (llvm::Expected<llvm::StringRef> NameOrErr = Obj.getSectionName(&Shdr)) {
      if (*NameOrErr == Name)
        return &Shdr;
    } else {
      WithColor::warning() << llvm::formatv(
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

  GotSec = findNotEmptySectionByAddress(Obj, FileName, *DtPltGot);
  if (!GotSec)
    return llvm::object::createError("there is no non-empty GOT section at 0x" +
                       llvm::Twine::utohexstr(*DtPltGot));

  LocalNum = *DtLocalGotNum;
  GlobalNum = DynSymTotal - *DtGotSym;

  llvm::ArrayRef<uint8_t> Content =
      unwrapOrError(Obj.getSectionContents(GotSec));
  GotEntries = Entries(reinterpret_cast<const Entry *>(Content.data()),
                       Content.size() / sizeof(Entry));
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
  return GotSec->sh_addr + Offset;
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

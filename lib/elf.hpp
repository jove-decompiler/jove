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
#if 0
      // TODO: Add a section index to this warning.
      reportWarning(createError("invalid section size (" + Twine(Size) +
                                ") or entity size (" + Twine(EntSize) + ")"),
                    FileName);
#else
#ifdef WARN
      WARN();
#endif
#endif

      return {Start, Start};
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
  exit(1);
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
typedef typename ELFF::Elf_Word Elf_Word;
typedef typename ELFF::Elf_Verdef Elf_Verdef;
typedef typename ELFF::Elf_Vernaux Elf_Vernaux;
typedef typename ELFF::Elf_Verneed Elf_Verneed;
typedef typename ELFF::Elf_Versym Elf_Versym;
typedef typename ELFF::Elf_Word Elf_Word;
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

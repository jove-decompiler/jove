#include "elf_recompiler.h"
#include <vector>
#include <llvm/IR/Module.h>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <boost/format.hpp>
#include <boost/filesystem.hpp>

using namespace std;
using namespace llvm;
using namespace object;
namespace fs = boost::filesystem;

namespace jove {

typedef boost::format fmt;

template <class T>
static T errorOrDefault(llvm::ErrorOr<T> Val, T Default = T()) {
  return Val ? *Val : Default;
}

template <typename ELFT>
static bool compareAddr(uint64_t VAddr, const Elf_Phdr_Impl<ELFT> *Phdr) {
  return VAddr < Phdr->p_vaddr;
}

template <typename ELFT> class elf_recompiler : public recompiler {
  typedef llvm::object::ELFFile<ELFT> ELFO;
  typedef typename ELFO::Elf_Phdr Elf_Phdr;
  typedef typename ELFO::Elf_Dyn_Range Elf_Dyn_Range;
#if 0
  typedef typename ELFO::Elf_Shdr Elf_Shdr;
  typedef typename ELFO::Elf_Sym Elf_Sym;
  typedef typename ELFO::Elf_Dyn Elf_Dyn;
  typedef typename ELFO::Elf_Rel Elf_Rel;
  typedef typename ELFO::Elf_Rela Elf_Rela;
  typedef typename ELFO::Elf_Rela_Range Elf_Rela_Range;
  typedef typename ELFO::Elf_Half Elf_Half;
  typedef typename ELFO::Elf_Hash Elf_Hash;
  typedef typename ELFO::Elf_GnuHash Elf_GnuHash;
  typedef typename ELFO::Elf_Ehdr Elf_Ehdr;
  typedef typename ELFO::Elf_Word Elf_Word;
  typedef typename ELFO::uintX_t uintX_t;
  typedef typename ELFO::Elf_Versym Elf_Versym;
  typedef typename ELFO::Elf_Verneed Elf_Verneed;
  typedef typename ELFO::Elf_Vernaux Elf_Vernaux;
  typedef typename ELFO::Elf_Verdef Elf_Verdef;
  typedef typename ELFO::Elf_Verdaux Elf_Verdaux;
#endif

  const ELFO& Obj;

public:
  elf_recompiler(const llvm::object::ELFObjectFile<ELFT> &EO, llvm::Module &M)
      : recompiler(EO, M), Obj(*EO.getELFFile()) {}

  void compile(const boost::filesystem::path &out) const {
    fs::path tmpbcfp(fs::unique_path());
    {
      error_code ec;
      raw_fd_ostream of(tmpbcfp.string(), ec, sys::fs::F_RW);
      WriteBitcodeToFile(&M, of);
    }

    string cmd = (fmt("llc -o %s -filetype=obj -relocation-model=pic %s") %
                  out % tmpbcfp)
                     .str();
    system(cmd.c_str());

    fs::remove(tmpbcfp);
  }

  void link(const boost::filesystem::path &obj,
            const boost::filesystem::path &out) const {
    string cmd = (fmt("ld -o %s -shared %s") % out % obj).str();
    system(cmd.c_str());
  }

private:
  void needed_shared_libraries_of_elf(vector<fs::path> &libs) {
    const Elf_Phdr *DynamicProgHeader = nullptr;
    SmallVector<const Elf_Phdr *, 4> LoadSegments;

    for (const Elf_Phdr &Phdr : Obj.program_headers()) {
      switch (Phdr.p_type) {
      case ELF::PT_DYNAMIC:
        DynamicProgHeader = &Phdr;
        break;
      case ELF::PT_LOAD:
        if (Phdr.p_filesz == 0)
          break;
        LoadSegments.push_back(&Phdr);
        break;
      }
    }

    if (!DynamicProgHeader)
      return;

    ErrorOr<Elf_Dyn_Range> dyntbl_ = Obj.dynamic_table(DynamicProgHeader);
    if (dyntbl_.getError())
      return;

    Elf_Dyn_Range dyntbl = *dyntbl_;

    const char *StringTableBegin = nullptr;
    uint64_t StringTableSize = 0;

    auto toMappedAddr = [&](uint64_t VAddr) -> const uint8_t * {
      const Elf_Phdr **I = upper_bound(LoadSegments.begin(), LoadSegments.end(),
                                       VAddr, compareAddr<ELFT>);
      if (I == LoadSegments.begin())
        return nullptr;
      --I;
      const Elf_Phdr &Phdr = **I;
      uint64_t Delta = VAddr - Phdr.p_vaddr;
      if (Delta >= Phdr.p_filesz)
        return nullptr;
      return Obj.base() + Phdr.p_offset + Delta;
    };

    for (const auto &Entry : dyntbl) {
      switch (Entry.d_tag) {
      case ELF::DT_STRTAB:
        StringTableBegin = StringTableBegin
                               ? StringTableBegin
                               : (const char *)toMappedAddr(Entry.getPtr());
        break;
      case ELF::DT_STRSZ:
        StringTableSize = Entry.getVal();
        break;
      }
    }

    if (!StringTableBegin)
      return;

    StringRef DynamicStringTable = StringRef(StringTableBegin, StringTableSize);

    for (const auto &Entry : dyntbl) {
      if (Entry.d_tag != ELF::DT_NEEDED)
        continue;

      if (Entry.d_un.d_val >= DynamicStringTable.size())
        continue;

      libs.push_back(
          StringRef(DynamicStringTable.data() + Entry.d_un.d_val).str());
    }
  }
};

template <class ELFT>
static unique_ptr<recompiler> *create_elf_recompiler(ELFObjectFile<ELFT> &O, Module &M) {
  unique_ptr<recompiler> R;
  R.reset(new elf_recompiler<ELFT>(O, M));
}

unique_ptr<recompiler> create_elf_recompiler(const ObjectFile &O, Module &M) {
  // Little-endian 32-bit
  if (const ELF32LEObjectFile *ELFObj = dyn_cast<ELF32LEObjectFile>(&O))
    return create_elf_recompiler(*ELFObj, M);

  // Big-endian 32-bit
  if (const ELF32BEObjectFile *ELFObj = dyn_cast<ELF32BEObjectFile>(&O))
    return create_elf_recompiler(*ELFObj, M);

  // Little-endian 64-bit
  if (const ELF64LEObjectFile *ELFObj = dyn_cast<ELF64LEObjectFile>(&O))
    return create_elf_recompiler(*ELFObj, M);

  // Big-endian 64-bit
  if (const ELF64BEObjectFile *ELFObj = dyn_cast<ELF64BEObjectFile>(&O))
    return create_elf_recompiler(*ELFObj, M);

  return nullptr;
}
}

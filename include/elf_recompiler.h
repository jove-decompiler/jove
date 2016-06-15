#pragma once
#include "recompiler.h"
#include "llvm/Object/ELFObjectFile.h"

namespace jove {

template <typename ELFT>
class elf_recompiler : public recompiler {
  typedef llvm::object::ELFFile<ELFT> ELFO;
#if 0
  typedef typename ELFO::Elf_Shdr Elf_Shdr;
  typedef typename ELFO::Elf_Sym Elf_Sym;
  typedef typename ELFO::Elf_Dyn Elf_Dyn;
  typedef typename ELFO::Elf_Dyn_Range Elf_Dyn_Range;
  typedef typename ELFO::Elf_Rel Elf_Rel;
  typedef typename ELFO::Elf_Rela Elf_Rela;
  typedef typename ELFO::Elf_Rela_Range Elf_Rela_Range;
  typedef typename ELFO::Elf_Phdr Elf_Phdr;
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

  void recompile() const {}
};

}

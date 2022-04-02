static llvm::Type *type_of_expression_for_relocation(const Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_MIPS_64:
  case llvm::ELF::R_MIPS_JUMP_SLOT:
  case llvm::ELF::R_MIPS_GLOB_DAT:
  case llvm::ELF::R_MIPS_TLS_TPREL64:
    return WordType();

  case llvm::ELF::R_MIPS_COPY:
  case llvm::ELF::R_MIPS_NONE:
    return VoidType();

  default:
    throw unhandled_relocation_exception();
  }
}

static llvm::Constant *expression_for_relocation(const Relocation &R,
                                                 const RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_MIPS_64:
    if (const Elf_Sym *Sym = RelSym.Sym) {
      if (Sym->isUndefined() || Sym->st_shndx == llvm::ELF::SHN_UNDEF) {
        return SymbolAddress(RelSym);
      } else {
	if (Sym->getType() == llvm::ELF::STT_FUNC)
	  return SectionPointer(Sym->st_value); /* breaks symbol interposition */
	else
          return SymbolAddress(RelSym);
      }
    } else {
      return SectionPointer(ExtractWordAtAddress(R.Offset));
    }

  case llvm::ELF::R_MIPS_JUMP_SLOT:
  case llvm::ELF::R_MIPS_GLOB_DAT:
    return SymbolAddress(RelSym);

  case llvm::ELF::R_MIPS_TLS_TPREL64:
    return BigWord();

  default:
    throw unhandled_relocation_exception();
  }
}

static bool is_manual_relocation(const Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_MIPS_TLS_TPREL64:
    return true;

  default:
    return false;
  }
}

static void compute_manual_relocation(llvm::IRBuilderTy &IRB,
                                      const Relocation &R,
                                      const RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_MIPS_TLS_TPREL64:
    return compute_tpoff_relocation(IRB, RelSym, ExtractWordAtAddress(R.Offset));

  default:
    throw unhandled_relocation_exception();
  }
}

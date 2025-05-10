template <bool MT, bool MinSize>
llvm::Type *llvm_t<MT, MinSize>::elf_type_of_expression_for_relocation(
    const elf::Relocation &R) {
  switch (R.Type) {
  case (llvm::ELF::R_MIPS_64 << 8) | llvm::ELF::R_MIPS_REL32:
//case (llvm::ELF::R_MIPS_64 << 8) | llvm::ELF::R_MIPS_GLOB_DAT:
  case llvm::ELF::R_MIPS_TLS_TPREL64:
  case llvm::ELF::R_MIPS_TLS_DTPMOD64:
  case llvm::ELF::R_MIPS_JUMP_SLOT:
    return WordType();

  case llvm::ELF::R_MIPS_64: /* we ignore such _64 dummy relocations */
  case llvm::ELF::R_MIPS_COPY:
  case llvm::ELF::R_MIPS_NONE:
    return VoidType();

  default:
    throw unhandled_relocation_exception();
  }
}

template <bool MT, bool MinSize>
llvm::Constant *llvm_t<MT, MinSize>::elf_expression_for_relocation(
    const elf::Relocation &R,
    const elf::RelSymbol &RelSym) {
  switch (R.Type) {
  case (llvm::ELF::R_MIPS_64 << 8) | llvm::ELF::R_MIPS_REL32:
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

//case (llvm::ELF::R_MIPS_64 << 8) | llvm::ELF::R_MIPS_GLOB_DAT:
  case llvm::ELF::R_MIPS_JUMP_SLOT:
    return SymbolAddress(RelSym);

  case llvm::ELF::R_MIPS_TLS_DTPMOD64:
  case llvm::ELF::R_MIPS_TLS_TPREL64:
    return BigWord();

  default:
    throw unhandled_relocation_exception();
  }
}

template <bool MT, bool MinSize>
bool llvm_t<MT, MinSize>::elf_is_manual_relocation(const elf::Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_MIPS_TLS_TPREL64:
//case llvm::ELF::R_MIPS_TLS_DTPMOD64:
    return true;

  default:
    return false;
  }
}

template <bool MT, bool MinSize>
void llvm_t<MT, MinSize>::elf_compute_manual_relocation(
    IRBuilderTy &IRB,
    const elf::Relocation &R,
    const elf::RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_MIPS_TLS_TPREL64:
    return elf_compute_tpoff_relocation(IRB, RelSym, ExtractWordAtAddress(R.Offset));

  default:
    throw unhandled_relocation_exception();
  }
}

template <bool MT, bool MinSize>
bool llvm_t<MT, MinSize>::elf_is_constant_relocation(const elf::Relocation &R) {
  switch (R.Type) {
  case (llvm::ELF::R_MIPS_64 << 8) | llvm::ELF::R_MIPS_REL32:
  case llvm::ELF::R_MIPS_JUMP_SLOT:
//case (llvm::ELF::R_MIPS_64 << 8) | llvm::ELF::R_MIPS_GLOB_DAT:
    return true;

  default:
    return false;
  }
}

template <bool MT, bool MinSize>
llvm::Type *
llvm_t<MT, MinSize>::coff_type_of_expression_for_relocation(uint8_t RelocType) {
  return WordType();
}

template <bool MT, bool MinSize>
llvm::Constant *
llvm_t<MT, MinSize>::coff_expression_for_relocation(uint8_t RelocType,
                                                    uint64_t Offset) {
  switch (RelocType) {
  default:
    throw unhandled_relocation_exception();
  }
}

template <bool MT, bool MinSize>
bool llvm_t<MT, MinSize>::coff_is_constant_relocation(uint8_t RelocType) {
  return true;
}

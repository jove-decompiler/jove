llvm::Type *LLVMTool::elf_type_of_expression_for_relocation(const elf::Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_386_RELATIVE:
  case llvm::ELF::R_386_GLOB_DAT:
  case llvm::ELF::R_386_JUMP_SLOT:
  case llvm::ELF::R_386_32:
  case llvm::ELF::R_386_IRELATIVE:
  case llvm::ELF::R_386_TLS_TPOFF:
  case llvm::ELF::R_386_TLS_DTPMOD32:
    return WordType();

  case llvm::ELF::R_386_COPY:
  case llvm::ELF::R_386_NONE:
    return VoidType();

  default:
    throw unhandled_relocation_exception();
  }
}

llvm::Constant *LLVMTool::elf_expression_for_relocation(const elf::Relocation &R,
                                                    const elf::RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_386_RELATIVE:
    if (R.Addend)
      return SectionPointer(*R.Addend);
    else
      return SectionPointer(ExtractWordAtAddress(R.Offset));

  case llvm::ELF::R_386_32: {
    llvm::Constant *GlobalAddr = SymbolAddress(RelSym);
    if (!GlobalAddr)
      return nullptr;

    if (R.Addend) {
      return llvm::ConstantExpr::getAdd(
          GlobalAddr,
          llvm::ConstantInt::get(WordType(), *R.Addend));
    } else {
      return llvm::ConstantExpr::getAdd(
          GlobalAddr,
          llvm::ConstantInt::get(WordType(), ExtractWordAtAddress(R.Offset)));
    }
  }

  case llvm::ELF::R_386_GLOB_DAT: {
  case llvm::ELF::R_386_JUMP_SLOT:
    llvm::Constant *GlobalAddr = SymbolAddress(RelSym);
    if (!GlobalAddr)
      return nullptr;

    if (R.Addend) {
      return llvm::ConstantExpr::getAdd(
          GlobalAddr,
          llvm::ConstantInt::get(WordType(), *R.Addend));
    } else {
      return GlobalAddr;
    }
  }

  case llvm::ELF::R_386_IRELATIVE:
  case llvm::ELF::R_386_TLS_TPOFF:
  case llvm::ELF::R_386_TLS_DTPMOD32:
    return BigWord();

  default:
    throw unhandled_relocation_exception();
  }
}

bool LLVMTool::elf_is_manual_relocation(const elf::Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_386_IRELATIVE:
  case llvm::ELF::R_386_TLS_TPOFF:
//case llvm::ELF::R_386_TLS_DTPMOD32:
    return true;

  default:
    return false;
  }
}

void LLVMTool::elf_compute_manual_relocation(llvm::IRBuilderTy &IRB,
                                         const elf::Relocation &R,
                                         const elf::RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_386_IRELATIVE:
    return elf_compute_irelative_relocation(IRB, R.Addend ? *R.Addend : ExtractWordAtAddress(R.Offset));

  case llvm::ELF::R_386_TLS_TPOFF:
    return elf_compute_tpoff_relocation(IRB, RelSym, ExtractWordAtAddress(R.Offset));

//case llvm::ELF::R_386_TLS_DTPMOD32:

  default:
    throw unhandled_relocation_exception();
  }
}

bool LLVMTool::elf_is_constant_relocation(const elf::Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_386_RELATIVE:
  case llvm::ELF::R_386_GLOB_DAT:
  case llvm::ELF::R_386_JUMP_SLOT:
  case llvm::ELF::R_386_32:
    return true;

  default:
    return false;
  }
}

llvm::Type *LLVMTool::coff_type_of_expression_for_relocation(uint8_t RelocType) {
  return WordType();
}

llvm::Constant *LLVMTool::coff_expression_for_relocation(uint8_t RelocType, uint64_t Offset) {
  switch (RelocType) {
  case llvm::COFF::IMAGE_REL_BASED_ABSOLUTE:
    return llvm::Constant::getNullValue(WordType());

  case llvm::COFF::IMAGE_REL_BASED_HIGHLOW: {
    taddr_t Addr = ExtractWordAtAddress(Offset);
    return SectionPointer(Addr);
  }

  default:
    throw unhandled_relocation_exception();
  }
}

bool LLVMTool::coff_is_constant_relocation(uint8_t RelocType) {
  return true;
}

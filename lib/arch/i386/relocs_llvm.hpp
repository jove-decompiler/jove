llvm::Type *LLVMTool::type_of_expression_for_relocation(const elf::Relocation &R) {
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

llvm::Constant *LLVMTool::expression_for_relocation(const elf::Relocation &R,
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

bool LLVMTool::is_manual_relocation(const elf::Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_386_IRELATIVE:
  case llvm::ELF::R_386_TLS_TPOFF:
//case llvm::ELF::R_386_TLS_DTPMOD32:
    return true;

  default:
    return false;
  }
}

void LLVMTool::compute_manual_relocation(llvm::IRBuilderTy &IRB,
                                         const elf::Relocation &R,
                                         const elf::RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_386_IRELATIVE:
    return compute_irelative_relocation(IRB, R.Addend ? *R.Addend : ExtractWordAtAddress(R.Offset));

  case llvm::ELF::R_386_TLS_TPOFF:
    return compute_tpoff_relocation(IRB, RelSym, ExtractWordAtAddress(R.Offset));

//case llvm::ELF::R_386_TLS_DTPMOD32:

  default:
    throw unhandled_relocation_exception();
  }
}

bool LLVMTool::is_constant_relocation(const elf::Relocation &R) {
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

static llvm::Type *type_of_expression_for_relocation(const Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_386_RELATIVE:
  case llvm::ELF::R_386_GLOB_DAT:
  case llvm::ELF::R_386_JUMP_SLOT:
  case llvm::ELF::R_386_32:
  case llvm::ELF::R_386_IRELATIVE:
  case llvm::ELF::R_386_TLS_TPOFF:
    return WordType();

  case llvm::ELF::R_386_COPY:
  case llvm::ELF::R_386_NONE:
    return VoidType();

  default:
    throw unhandled_relocation_exception();
  }
}

static llvm::Constant *expression_for_relocation(const Relocation &R,
                                                 const RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_386_RELATIVE:
    return SectionPointer(ExtractWordAtAddress(R.Offset));

  case llvm::ELF::R_386_32: {
    llvm::Constant *GlobalAddr = SymbolAddress(RelSym);
    if (!GlobalAddr)
      return nullptr;

    return llvm::ConstantExpr::getAdd(
        GlobalAddr,
	llvm::ConstantInt::get(WordType(), ExtractWordAtAddress(R.Offset)));
  }

  case llvm::ELF::R_386_GLOB_DAT:
  case llvm::ELF::R_386_JUMP_SLOT:
    return SymbolAddress(RelSym);

  case llvm::ELF::R_386_IRELATIVE:
  case llvm::ELF::R_386_TLS_TPOFF:
    return BigWord();

  default:
    throw unhandled_relocation_exception();
  }
}

static bool is_manual_relocation(const Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_386_IRELATIVE:
  case llvm::ELF::R_386_TLS_TPOFF:
    return true;

  default:
    return false;
  }
}

static void compute_manual_relocation(llvm::IRBuilderTy &IRB,
                                      const Relocation &R,
                                      const RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_386_IRELATIVE:
    return compute_irelative_relocation(IRB, ExtractWordAtAddress(R.Offset));

  case llvm::ELF::R_386_TLS_TPOFF:
    return compute_tpoff_relocation(IRB, RelSym, ExtractWordAtAddress(R.Offset));

  default:
    throw unhandled_relocation_exception();
  }
}

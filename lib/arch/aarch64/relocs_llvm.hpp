llvm::Type *LLVMTool::type_of_expression_for_relocation(const Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_AARCH64_RELATIVE:
  case llvm::ELF::R_AARCH64_GLOB_DAT:
  case llvm::ELF::R_AARCH64_JUMP_SLOT:
  case llvm::ELF::R_AARCH64_ABS64:
  case llvm::ELF::R_AARCH64_IRELATIVE:
  case llvm::ELF::R_AARCH64_TLS_TPREL64:
  case llvm::ELF::R_AARCH64_TLSDESC:
    return WordType();

  case llvm::ELF::R_AARCH64_COPY:
  case llvm::ELF::R_AARCH64_NONE:
    return VoidType();

  default:
    throw unhandled_relocation_exception();
  }
}

llvm::Constant *LLVMTool::expression_for_relocation(const Relocation &R,
                                                    const RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_AARCH64_RELATIVE:
    assert(R.Addend);
    return SectionPointer(*R.Addend);

  case llvm::ELF::R_AARCH64_GLOB_DAT:
  case llvm::ELF::R_AARCH64_JUMP_SLOT:
  case llvm::ELF::R_AARCH64_ABS64: {
    assert(R.Addend);

    llvm::Constant *GlobalAddr = SymbolAddress(RelSym);
    if (!GlobalAddr)
      return nullptr;

    return llvm::ConstantExpr::getAdd(
        GlobalAddr, llvm::ConstantInt::get(WordType(), *R.Addend));
  }

  case llvm::ELF::R_AARCH64_IRELATIVE:
  case llvm::ELF::R_AARCH64_TLS_TPREL64:
  case llvm::ELF::R_AARCH64_TLSDESC:
    return BigWord();

  default:
    throw unhandled_relocation_exception();
  }
}

bool LLVMTool::is_manual_relocation(const Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_AARCH64_IRELATIVE:
  case llvm::ELF::R_AARCH64_TLS_TPREL64:
//case llvm::ELF::R_AARCH64_TLSDESC:
    return true;

  default:
    return false;
  }
}

void LLVMTool::compute_manual_relocation(llvm::IRBuilderTy &IRB,
                                         const Relocation &R,
                                         const RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_AARCH64_IRELATIVE:
    assert(R.Addend);
    return compute_irelative_relocation(IRB, *R.Addend);

  case llvm::ELF::R_AARCH64_TLS_TPREL64:
    assert(R.Addend);
    return compute_tpoff_relocation(IRB, RelSym, *R.Addend);

  default:
    throw unhandled_relocation_exception();
  }
}

bool LLVMTool::is_constant_relocation(const Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_AARCH64_RELATIVE:
  case llvm::ELF::R_AARCH64_GLOB_DAT:
  case llvm::ELF::R_AARCH64_JUMP_SLOT:
  case llvm::ELF::R_AARCH64_ABS64:
    return true;

  default:
    return false;
  }
}

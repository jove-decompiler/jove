llvm::Type *LLVMTool::type_of_expression_for_relocation(const Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_X86_64_RELATIVE:
  case llvm::ELF::R_X86_64_GLOB_DAT:
  case llvm::ELF::R_X86_64_JUMP_SLOT:
  case llvm::ELF::R_X86_64_64:
  case llvm::ELF::R_X86_64_IRELATIVE:
  case llvm::ELF::R_X86_64_TPOFF64:
  case llvm::ELF::R_X86_64_DTPMOD64:
    return WordType();

  case llvm::ELF::R_X86_64_COPY:
  case llvm::ELF::R_X86_64_NONE:
    return VoidType();

  default:
    throw unhandled_relocation_exception();
  }
}

llvm::Constant *LLVMTool::expression_for_relocation(const Relocation &R,
                                                    const RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_X86_64_RELATIVE: {
    //WARN_ON(!R.Addend);

    tcg_uintptr_t Addr = R.Addend ? *R.Addend : 0;
    if (!Addr) /* XXX could happen if DT_RELR */
      Addr = ExtractWordAtAddress(R.Offset);

    return SectionPointer(Addr);
  }

  case llvm::ELF::R_X86_64_64:
  case llvm::ELF::R_X86_64_GLOB_DAT:
  case llvm::ELF::R_X86_64_JUMP_SLOT: {
    //WARN_ON(!R.Addend);

    llvm::Constant *GlobalAddr = SymbolAddress(RelSym);
    if (!GlobalAddr)
      return nullptr;

    if (!R.Addend)
      return GlobalAddr;

    return llvm::ConstantExpr::getAdd(
        GlobalAddr, llvm::ConstantInt::get(WordType(), *R.Addend));
  }

  case llvm::ELF::R_X86_64_IRELATIVE:
  case llvm::ELF::R_X86_64_TPOFF64:
  case llvm::ELF::R_X86_64_DTPMOD64:
    return BigWord();

  default:
    throw unhandled_relocation_exception();
  }
}

bool LLVMTool::is_manual_relocation(const Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_X86_64_IRELATIVE:
  case llvm::ELF::R_X86_64_TPOFF64:
//case llvm::ELF::R_X86_64_DTPMOD64:

    return true;

  default:
    return false;
  }
}

void LLVMTool::compute_manual_relocation(llvm::IRBuilderTy &IRB,
                                         const Relocation &R,
                                         const RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_X86_64_IRELATIVE:
    assert(R.Addend);
    return compute_irelative_relocation(IRB, *R.Addend);

  case llvm::ELF::R_X86_64_TPOFF64:
    assert(R.Addend);
    return compute_tpoff_relocation(IRB, RelSym, *R.Addend);

//case llvm::ELF::R_X86_64_DTPMOD64:

  default:
    throw unhandled_relocation_exception();
  }
}

bool LLVMTool::is_constant_relocation(const Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_X86_64_RELATIVE:
  case llvm::ELF::R_X86_64_GLOB_DAT:
  case llvm::ELF::R_X86_64_JUMP_SLOT:
  case llvm::ELF::R_X86_64_64:
    return true;

  default:
    return false;
  }
}

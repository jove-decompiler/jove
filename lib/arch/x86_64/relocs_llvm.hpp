llvm::Type *LLVMTool::elf_type_of_expression_for_relocation(const elf::Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_X86_64_RELATIVE:
  case llvm::ELF::R_X86_64_GLOB_DAT:
  case llvm::ELF::R_X86_64_JUMP_SLOT:
  case llvm::ELF::R_X86_64_64:
  case llvm::ELF::R_X86_64_IRELATIVE:
  case llvm::ELF::R_X86_64_TPOFF64:
  case llvm::ELF::R_X86_64_DTPMOD64:
  case llvm::ELF::R_X86_64_DTPOFF64:
    return WordType();

  case llvm::ELF::R_X86_64_TLSDESC:
    return TLSDescType();

  case llvm::ELF::R_X86_64_COPY:
  case llvm::ELF::R_X86_64_NONE:
    return VoidType();

  default:
    throw unhandled_relocation_exception();
  }
}

llvm::Constant *LLVMTool::elf_expression_for_relocation(const elf::Relocation &R,
                                                        const elf::RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_X86_64_RELATIVE: {
    //WARN_ON(!R.Addend);

    taddr_t Addr = R.Addend ? *R.Addend : 0;
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
  case llvm::ELF::R_X86_64_DTPOFF64:
    return BigWord();

  case llvm::ELF::R_X86_64_TLSDESC: {
    std::vector<llvm::Constant *> constantTable(
        2, llvm::Constant::getAllOnesValue(WordType()));
    return llvm::ConstantArray::get(TLSDescType(), constantTable);
  }

  default:
    throw unhandled_relocation_exception();
  }
}

bool LLVMTool::elf_is_manual_relocation(const elf::Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_X86_64_IRELATIVE:
  case llvm::ELF::R_X86_64_TPOFF64:
  case llvm::ELF::R_X86_64_DTPOFF64:
//case llvm::ELF::R_X86_64_DTPMOD64:
  case llvm::ELF::R_X86_64_TLSDESC:
    return true;

  default:
    return false;
  }
}

void LLVMTool::elf_compute_manual_relocation(llvm::IRBuilderTy &IRB,
                                             const elf::Relocation &R,
                                             const elf::RelSymbol &RelSym) {
  switch (R.Type) {
  case llvm::ELF::R_X86_64_IRELATIVE:
    assert(R.Addend);
    return elf_compute_irelative_relocation(IRB, *R.Addend);

  case llvm::ELF::R_X86_64_TPOFF64:
    assert(R.Addend);
    return elf_compute_tpoff_relocation(IRB, RelSym, *R.Addend);

  case llvm::ELF::R_X86_64_DTPOFF64: {
    assert(R.Addend);
    llvm::Constant *GlobalAddr = SymbolAddress(RelSym);
    assert(GlobalAddr);
    if (!R.Addend || *R.Addend == 0) {
      IRB.CreateRet(GlobalAddr);
      return;
    }

    IRB.CreateRet(llvm::ConstantExpr::getAdd(
        GlobalAddr, llvm::ConstantInt::get(WordType(), *R.Addend)));
    return;
  }

  case llvm::ELF::R_X86_64_TLSDESC: {
    llvm::AllocaInst *td = IRB.CreateAlloca(TLSDescType());

    llvm::Value *entry = IRB.CreateLoad(
        WordType(), IRB.CreateConstInBoundsGEP2_64(TLSDescType(),
                                                   TLSDescGV(), 0, 0));

    IRB.CreateStore(entry,
                    IRB.CreateConstInBoundsGEP2_64(TLSDescType(), td, 0, 0));

    IRB.CreateStore(IRB.getIntN(WordBytes() * 8, !R.Addend ? 0 : *R.Addend),
                    IRB.CreateConstInBoundsGEP2_64(TLSDescType(), td, 0, 1));

    IRB.CreateRet(IRB.CreateLoad(TLSDescType(), td));
    return;
  }

//case llvm::ELF::R_X86_64_DTPMOD64:

  default:
    throw unhandled_relocation_exception();
  }
}

bool LLVMTool::elf_is_constant_relocation(const elf::Relocation &R) {
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

llvm::Type *LLVMTool::coff_type_of_expression_for_relocation(uint8_t RelocType) {
  return WordType();
}

llvm::Constant *LLVMTool::coff_expression_for_relocation(uint8_t RelocType, uint64_t Offset) {
  switch (RelocType) {
  case llvm::COFF::IMAGE_REL_BASED_DIR64: {
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

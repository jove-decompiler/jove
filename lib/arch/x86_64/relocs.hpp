static bool elf_is_copy_relocation(const elf::Relocation &R) {
  return R.Type == llvm::ELF::R_X86_64_COPY;
}

static bool elf_is_irelative_relocation(const elf::Relocation &R) {
  return R.Type == llvm::ELF::R_X86_64_IRELATIVE;
}

static bool elf_is_relative_relocation(const elf::Relocation &R) {
  return R.Type == llvm::ELF::R_X86_64_RELATIVE;
}

static bool elf_is_addressof_relocation(const elf::Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_X86_64_64:
  case llvm::ELF::R_X86_64_GLOB_DAT:
  case llvm::ELF::R_X86_64_JUMP_SLOT:
    return true;
  default:
    return false;
  }
}

static bool coff_is_dir_relocation(uint8_t RelocType) {
  return RelocType == llvm::COFF::IMAGE_REL_BASED_DIR64;
}

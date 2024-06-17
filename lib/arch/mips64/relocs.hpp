static bool is_copy_relocation(const elf::Relocation &R) {
  return R.Type == llvm::ELF::R_MIPS_COPY;
}

static bool is_irelative_relocation(const elf::Relocation &R) {
  return false;
}

static bool is_relative_relocation(const elf::Relocation &R) {
  return R.Type == ((llvm::ELF::R_MIPS_64 << 8) | llvm::ELF::R_MIPS_REL32);
}

static bool is_addressof_relocation(const elf::Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_MIPS_64:
  case llvm::ELF::R_MIPS_GLOB_DAT:
  case llvm::ELF::R_MIPS_JUMP_SLOT:
    return true;
  default:
    return false;
  }
}

static bool is_copy_relocation(const Relocation &R) {
  return R.Type == llvm::ELF::R_386_COPY;
}

static bool is_irelative_relocation(const Relocation &R) {
  return R.Type == llvm::ELF::R_386_IRELATIVE;
}

static bool is_relative_relocation(const Relocation &R) {
  return R.Type == llvm::ELF::R_386_RELATIVE;
}

static bool is_addressof_relocation(const Relocation &R) {
  switch (R.Type) {
  case llvm::ELF::R_386_32:
  case llvm::ELF::R_386_GLOB_DAT:
  case llvm::ELF::R_386_JUMP_SLOT:
    return true;
  default:
    return false;
  }
}

//
// a relocation is a computation to perform on the contents; it is defined by a
// type, symbol, offset into the contents, and addend. Most relocations refer to
// a symbol and to an offset within the contents. A commonly used relocation is
// "set this location in the contents to the value of this symbol plus this
// addend". A relocation may refer to an undefined symbol.
//
struct relocation_t {
  enum class TYPE {
    //
    // This relocation is unimplemented or has irrelevant semantics
    //
    NONE,

    //
    // set the location specified to be the address plus the addend
    //
    RELATIVE,

    //
    // similar to RELATIVE except that the value used in this relocation is the
    // program address returned by the so-called resolver function
    //
    IRELATIVE,

    //
    // set the location specified to be the absolute address of the addend
    //
    ABSOLUTE,

    //
    // Copies the data from resolved symbol to address
    //
    COPY,

    //
    // address of a function or variable.
    //
    ADDRESSOF,

    TPOFF,
    TPMOD
  } Type;

  target_ulong Addr;
  unsigned SymbolIndex;
  target_ulong Addend;

  llvm::Type *T; /* XXX */
  llvm::Constant *C; /* XXX */

  llvm::SmallString<32> RelocationTypeName;
};

static constexpr relocation_t::TYPE relocation_type_of_elf_rela_type(uint64_t elf_rela_ty) {
  switch (elf_rela_ty) {
#include "relocs.hpp"
  default:
    return relocation_t::TYPE::NONE;
  }
};

static constexpr const char *string_of_reloc_type(relocation_t::TYPE ty) {
  switch (ty) {
  case relocation_t::TYPE::NONE:
    return "NONE";
  case relocation_t::TYPE::RELATIVE:
    return "RELATIVE";
  case relocation_t::TYPE::IRELATIVE:
    return "IRELATIVE";
  case relocation_t::TYPE::ABSOLUTE:
    return "ABSOLUTE";
  case relocation_t::TYPE::COPY:
    return "COPY";
  case relocation_t::TYPE::ADDRESSOF:
    return "ADDRESSOF";
  case relocation_t::TYPE::TPOFF:
    return "TPOFF";
  case relocation_t::TYPE::TPMOD:
    return "TPMOD";
  }

  __builtin_trap();
  __builtin_unreachable();
};

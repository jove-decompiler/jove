#pragma once
#include "types.h"
#include <llvm/Object/ObjectFile.h>
#include <llvm/ADT/ArrayRef.h>

namespace jove {

//
// to the dynamic linker, there are a small number of basic data types:
//
// (1) symbols
// (2) relocations
// (3) contents
//

//
// the content is what memory should look like during the execution of the
// program, and it is partitioned into sections- each having a type and array of
// bytes. They contain the values of initialized variables (e.g. data), static
// unnamed data like string constants and switch tables (e.g. rodata),
// uninitialized variables- in which case the array of bytes is generally
// omitted and assumed to contain only zeros (e.g. .bss).
//
struct section_t {
  std::string name;

  address_t addr;
  unsigned size;

  llvm::ArrayRef<uint8_t> contents;

  unsigned align;

  struct {
    unsigned read : 1;
    unsigned write : 1;
    unsigned exec : 1;
    unsigned tls : 1;
  } flags;
};

//
// a symbol is basically a name and a value. in a program compiled from C, the
// value of a symbol is roughly the address of a global. Each defined symbol has
// an address, and the dynamic linker will resolve each undefined symbol by
// finding a defined symbol with the same name.
//
struct symbol_t {
  std::string name;
  address_t addr;

  enum TYPE {
    NOTYPE,
    DATA,
    FUNCTION,
    TLSDATA,
  } ty;

  unsigned size;

  enum BINDING {
    NOBINDING,
    LOCAL,
    WEAK,
    GLOBAL
  } bind;

  // an undefined symbol is an imported function or global variable
  bool is_undefined() const { return addr == 0; }
  bool is_defined() const { return !is_undefined(); }
};

//
// a relocation is a computation to perform on the contents; it is defined by a
// type, symbol, offset into the contents, and addend. Most relocations refer to
// a symbol and to an offset within the contents. A commonly used relocation is
// "set this location in the contents to the value of this symbol plus this
// addend". A relocation may refer to an undefined symbol.
//
struct relocation_t {
  enum TYPE {
    //
    // This relocation is unimplemented or has irrelevant semantics
    //
    NONE,

    //
    // set the location specified to be the address plus the addend
    //
    RELATIVE,

    //
    // set the location specified to be the address of the symbol specified
    //
    ABSOLUTE,

    //
    // Copies the data from resolved symbol to address
    //
    COPY,

    //
    // address of a function.
    //
    // on linux x86_64, when C code is compiled to call an imported function, it
    // appears as
    //
    // callq  400450 <puts@plt>
    //
    // a call into the program linkage table. from here,
    //
    // jmpq   [_GLOBAL_OFFSET_TABLE_+0x18]
    //
    // transfers control to the imported function. a relocation is contained in
    // the object file of the type R_X86_64_JUMP_SLOT which sets
    // [_GLOBAL_OFFSET_TABLE_+0x18] equal to the address of the imported
    // function.
    //
    // on windows x86_64, when C code is compiled to call an imported function,
    // it appears as
    //
    // callq [_imp_MessageBoxA (00007ff7`607330c0)]
    //
    // which transfers control to the imported function. an entry in the import
    // address table (which will appear as a relocation as defined here)
    // contained in the object file sets [_imp_MessageBoxA (00007ff7`607330c0)]
    // equal to the address of the imported function.
    //
    FUNCTION,

    //
    // address of a variable.
    //
    DATA
  } ty;

  address_t addr;
  unsigned symidx;
  address_t addend;
};

typedef std::vector<section_t> section_table_t;
typedef std::vector<symbol_t> symbol_table_t;
typedef std::vector<relocation_t> relocation_table_t;

bool parse_elf_binary(const llvm::object::ObjectFile &, section_table_t &,
                      symbol_table_t &, relocation_table_t &);

bool parse_coff_binary(const llvm::object::ObjectFile &, section_table_t &,
                       symbol_table_t &, relocation_table_t &);

inline bool parse_binary(const llvm::object::ObjectFile &O,
                         section_table_t &secttbl, symbol_table_t &symtbl,
                         relocation_table_t &reloctbl) {
  if (O.isELF())
    return parse_elf_binary(O, secttbl, symtbl, reloctbl);
  else if (O.isCOFF())
    return parse_coff_binary(O, secttbl, symtbl, reloctbl);

  return false;
}

}

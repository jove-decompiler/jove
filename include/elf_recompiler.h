#pragma once
#include "recompiler.h"

namespace jove {

std::unique_ptr<recompiler>
create_elf_recompiler(const llvm::object::ObjectFile &, llvm::Module &);

}

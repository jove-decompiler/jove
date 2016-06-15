#pragma once
#include "recompiler.h"

namespace jove {

std::unique_ptr<recompiler>
create_coff_recompiler(const llvm::object::ObjectFile &, llvm::Module &);

}

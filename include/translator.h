#pragma once
#include "types.h"
#include <boost/icl/interval_map.hpp>
#include <config-target.h>
#include <inttypes.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Object/ObjectFile.h>
#include <vector>

namespace jove {

typedef uint64_t address_t;

class translator {
  llvm::object::ObjectFile &O;

  llvm::LLVMContext &C;
  llvm::Module &M;
  const llvm::DataLayout &DL;

  boost::icl::interval_map<address_t, section_number_t> addrspace;

public:
  translator(llvm::object::ObjectFile &, llvm::LLVMContext &, llvm::Module &);
  ~translator();

  void translate(address_t);
};
}

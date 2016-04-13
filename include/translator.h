#pragma once
#include <config-target.h>
#include <inttypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/Object/ObjectFile.h>
#include <boost/icl/interval_map.hpp>
#include <vector>

namespace jove {

typedef uint64_t address_t;

class translator {
  llvm::object::ObjectFile &O;

  llvm::LLVMContext& C;
  llvm::Module &M;
  const llvm::DataLayout &DL;

  std::vector<llvm::ArrayRef<uint8_t>> sectdata;
  boost::icl::interval_map<address_t, unsigned> sectaddrmap;

  void build_address_space_section_map();

public:
  translator(llvm::object::ObjectFile &, llvm::LLVMContext &, llvm::Module &);
  ~translator();

  void translate(address_t);
};
}

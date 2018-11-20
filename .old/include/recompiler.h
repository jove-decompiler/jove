#pragma once
#include <llvm/Object/ObjectFile.h>
#include <llvm/IR/Module.h>
#include <llvm/Linker/Linker.h>
#include <boost/filesystem/path.hpp>

namespace jove {

struct recompiler {
  void setup_thunks();
  void setup_helpers();

protected:
  const llvm::object::ObjectFile& O;
  llvm::Module& M;
  llvm::Linker L;

public:
  recompiler(const llvm::object::ObjectFile&, llvm::Module&);

  //
  // compiles bitcode to object file, writing to given path
  //
  virtual void compile(const boost::filesystem::path &out) const = 0;

  //
  // links object file to executable or shared library, writing to the given
  // path.
  //
  virtual void link(const boost::filesystem::path &obj,
                    const boost::filesystem::path &out) const = 0;
};

std::unique_ptr<recompiler> create_recompiler(const llvm::object::ObjectFile &,
                                              llvm::Module &);
}

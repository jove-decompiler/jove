#include "recompiler.h"

namespace jove {

struct coff_recompiler : public recompiler {
public:
  coff_recompiler(const llvm::object::ObjectFile &O, llvm::Module &M)
      : recompiler(O, M) {}

  void recompile() const {}
};

}

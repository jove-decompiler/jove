#include "coff_recompiler.h"

using namespace std;
using namespace llvm;
using namespace object;
namespace fs = boost::filesystem;

namespace jove {

struct coff_recompiler : public recompiler {
public:
  coff_recompiler(const llvm::object::ObjectFile &O, llvm::Module &M)
      : recompiler(O, M) {}

  void compile(const boost::filesystem::path &out) const {}
  void link(const boost::filesystem::path &obj,
            const boost::filesystem::path &out) const {}
};

std::unique_ptr<recompiler>
create_coff_recompiler(const llvm::object::ObjectFile &O, llvm::Module &M) {
  unique_ptr<recompiler> R;
  R.reset(new coff_recompiler(O, M));
  return R;
}
}

#include "recompiler.h"
#include <llvm/Linker/Linker.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <iostream>

using namespace std;
using namespace llvm;
using namespace object;

namespace jove {

static const uint8_t helpers_bitcode_data[] = {
#include "helpers.cpp"
};

static const uint8_t thunk_bitcode_data[] = {
#include "thunk.cpp"
};

recompiler::recompiler(const ObjectFile &O, Module &M)
    : O(O), M(M) {
  LLVMContext &C(M.getContext());
  unique_ptr<Module> HelperM;
  {
    unique_ptr<MemoryBuffer> MB(MemoryBuffer::getMemBuffer(
        StringRef(reinterpret_cast<const char *>(&helpers_bitcode_data[0]),
                  sizeof(helpers_bitcode_data)),
        "", false));

    HelperM = move(*parseBitcodeFile(MB->getMemBufferRef(), C));
  }

  unique_ptr<Module> ThunkM;
  {
    unique_ptr<MemoryBuffer> MB(MemoryBuffer::getMemBuffer(
        StringRef(reinterpret_cast<const char *>(&thunk_bitcode_data[0]),
                  sizeof(thunk_bitcode_data)),
        "", false));

    ThunkM = move(*parseBitcodeFile(MB->getMemBufferRef(), C));
  }

  Linker lnk(M);

  if (lnk.linkInModule(move(HelperM), Linker::LinkOnlyNeeded) ||
      lnk.linkInModule(move(ThunkM))) {
    cerr << "error linking bitcode" << endl;
    exit(1);
  }
}
}

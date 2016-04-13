#include "translator.h"
#include "binary.h"
#include "mc.h"
#include "qemutcg.h"
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ELFObjectFile.h>

using namespace llvm;
using namespace object;
using namespace std;

namespace jove {

translator::translator(ObjectFile &O, LLVMContext &C, Module &M)
    : O(O), C(C), M(M), DL(M.getDataLayout()) {
  //
  // init TCG translator
  //
  libqemutcg_init();

  //
  // init LLVM-MC for machine code analysis
  //
  libmc_init(&O);

  //
  // build address space mapping to sections
  //
  address_to_section_map_of_binary(O, addrspace);
}

translator::~translator() {}

void translator::translate(address_t a) {
  //
  // find section containing address
  //
  auto sectit = addrspace.find(a);
  if (sectit == addrspace.end())
    exit(45);

  ArrayRef<uint8_t> contents = section_contents_of_binary(O, (*sectit).second);

  libqemutcg_set_code(contents.data(), contents.size(),
                      (*sectit).first.lower());
  //
  // translate to TCG code
  //
  libqemutcg_translate(a);
}
}

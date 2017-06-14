#include "recompiler.h"
#include "elf_recompiler.h"
#include "coff_recompiler.h"
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <iostream>

using namespace std;
using namespace llvm;
using namespace object;

namespace jove {

recompiler::recompiler(const ObjectFile &O, Module &M)
    : O(O), M(M), L(M) {
  //
  // prepare bitcode
  //
  setup_thunks();
  setup_helpers();
}

static const uint8_t thunk_bitcode_data[] = {
#include "thunk.cpp"
};

void recompiler::setup_thunks() {
  //
  // before linking any new bitcode, save the list of exported functions
  //
  vector<string> fns;
  for (Function& F : M)
    if (F.getLinkage() == GlobalValue::ExternalLinkage && !F.isDeclaration())
      fns.push_back(F.getName().str());

  LLVMContext &C(M.getContext());
  unique_ptr<Module> ThunkM;
  {
    unique_ptr<MemoryBuffer> MB(MemoryBuffer::getMemBuffer(
        StringRef(reinterpret_cast<const char *>(&thunk_bitcode_data[0]),
                  sizeof(thunk_bitcode_data)),
        "", false));

    ThunkM = move(*parseBitcodeFile(MB->getMemBufferRef(), C));
  }

  if (L.linkInModule(move(ThunkM))) {
    cerr << "error linking thunk bitcode" << endl;
    exit(1);
  }

  //
  // for every function that was exported from the binary, make cloned copies
  // of thunks for each one appropriately
  //
  Function &exported_template_fn =
      *M.getFunction("__jove_exported_template_fn");
  Function &exported_template_fn_impl =
      *M.getFunction("__jove_exported_template_fn_impl");

  for (const string& sym : fns) {
    Function& F = *M.getFunction(sym);

    ValueToValueMapTy VMap;
    Function& G = *CloneFunction(&exported_template_fn, VMap);
    M.getFunctionList().push_back(&G);

    G.takeName(&F);
    F.setName(sym + "__jove_impl_");
    F.setLinkage(GlobalValue::InternalLinkage);
    F.setCallingConv(CallingConv::C);

    auto user_of_impl = [&](void) -> Instruction * {
      for (User *U : exported_template_fn_impl.users()) {
        Instruction* Inst = dyn_cast<Instruction>(U);
        if (!Inst)
          continue;

        if (Inst->getParent()->getParent() == &G)
          return Inst;
      }

      return nullptr;
    };

    Instruction* Inst = user_of_impl();
    assert(Inst);

    auto operand_index_of_impl_user = [&](void) -> unsigned {
      for (unsigned i = 0; i < Inst->getNumOperands(); ++i) {
        if (Inst->getOperand(i) == &exported_template_fn_impl)
          return i;
      }

      return numeric_limits<unsigned>::max();
    };

    unsigned opidx = operand_index_of_impl_user();
    assert(opidx < Inst->getNumOperands());

    Inst->setOperand(opidx, &F);
  }

  assert(exported_template_fn.getNumUses() == 0);
  M.getFunctionList().remove(&exported_template_fn);
#if 0
  assert(exported_template_fn_impl.getNumUses() == 0);
  M.getFunctionList().remove(&exported_template_fn_impl);
#endif

  //
  // insert thunks for remaining calls to __jove_* functions
  //
  Function &JFn0 =
      *M.getFunction("__jove_thunk_out");
  Function &JFn1 =
      *M.getFunction("__jove_indirect_jump");
  Function &JFn2 =
      *M.getFunction("__jove_indirect_call");
  Function &JFn3 =
      *M.getFunction("__jove_call");

  JFn1.replaceAllUsesWith(&JFn0);
  JFn2.replaceAllUsesWith(&JFn0);
  JFn3.replaceAllUsesWith(&JFn0);

  JFn0.setLinkage(GlobalValue::InternalLinkage);
}

static const uint8_t helpers_bitcode_data[] = {
#include "helpers.cpp"
};

void recompiler::setup_helpers() {
  LLVMContext &C(M.getContext());
  unique_ptr<Module> HelperM;
  {
    unique_ptr<MemoryBuffer> MB(MemoryBuffer::getMemBuffer(
        StringRef(reinterpret_cast<const char *>(&helpers_bitcode_data[0]),
                  sizeof(helpers_bitcode_data)),
        "", false));

    HelperM = move(*parseBitcodeFile(MB->getMemBufferRef(), C));
  }

  if (L.linkInModule(move(HelperM), Linker::LinkOnlyNeeded)) {
    cerr << "error linking QEMU helpers" << endl;
    exit(1);
  }
}

unique_ptr<recompiler> create_recompiler(const llvm::object::ObjectFile &O,
                                         llvm::Module &M) {
  if (O.isELF())
    return create_elf_recompiler(O, M);
  else if (O.isCOFF())
    return create_coff_recompiler(O, M);

  return nullptr;
}
}

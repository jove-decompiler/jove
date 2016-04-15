#include "translator.h"
#include "binary.h"
#include "mc.h"
#include "qemutcg.h"
#include <config-target.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ELFObjectFile.h>

using namespace llvm;
using namespace object;
using namespace std;

extern "C" {
void translator_tcg_helper(jove::translator *, uint64_t addr, const char *name);
void translator_enumerate_tcg_helpers(jove::translator *);
}

void translator_tcg_helper(jove::translator *T, uintptr_t addr,
                           const char *name) {
  T->tcg_helper(addr, name);
}

namespace jove {

static const uint8_t runtime_helpers_bitcode_data[] = {
#if defined(TARGET_AARCH64)
#include "runtime-helpers-aarch64.h"
#elif defined(TARGET_ARM)
#include "runtime-helpers-arm.h"
#elif defined(TARGET_X86_64)
#include "runtime-helpers-x86_64.h"
#elif defined(TARGET_I386)
#include "runtime-helpers-i386.h"
#elif defined(TARGET_MIPS)
#include "runtime-helpers-mipsel.h"
#endif
};

translator::translator(ObjectFile &O, LLVMContext &C, Module &M)
    : O(O), C(C), M(M), DL(M.getDataLayout()),
      _HelperM(move(*getLazyBitcodeModule(
          MemoryBuffer::getMemBuffer(
              StringRef(reinterpret_cast<const char *>(
                            &runtime_helpers_bitcode_data[0]),
                        sizeof(runtime_helpers_bitcode_data)),
              "", false),
          C))),
      HelperM(*_HelperM) {
  //
  // init TCG translator
  //
  libqemutcg_init();

  //
  // initialize helpers
  //
  init_helpers();

  //
  // init LLVM-MC for machine code analysis
  //
  libmc_init(&O);

  //
  // build address space mapping to sections
  //
  address_to_section_map_of_binary(O, addrspace);

  //
  // initialize needed Module types
  //
  FnAttr =
      AttributeSet::get(C, AttributeSet::FunctionIndex, Attribute::NoInline);

  FnThunkTy = FunctionType::get(Type::getVoidTy(C), false);
  FnThunkAttr =
      AttributeSet::get(C, AttributeSet::FunctionIndex, Attribute::Naked);

  IndirectJumpFn = Function::Create(
      FunctionType::get(Type::getVoidTy(C), false),
      GlobalValue::ExternalLinkage, "___jove_indirect_jump", &M);

  IndirectCallFn = Function::Create(
      FunctionType::get(Type::getVoidTy(C), false),
      GlobalValue::ExternalLinkage, "___jove_indirect_call", &M);
}

void translator::tcg_helper(uintptr_t addr, const char *name) {
  for (tcg::helper_t &h : tcg_helpers) {
    h.addr = addr;
    h.nm = name;
    h.llf = HelperM.getFunction(name);
    assert(h.llf);

    // parse metadata for given helper to get inputs & outputs
  }
}

void translator::init_helpers() { translator_enumerate_tcg_helpers(this); }

tuple<Function *, Function *> translator::translate(address_t a) {
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
  address_t succ_a = a + libqemutcg_translate(a);

  Function *FnThunk = nullptr;
  Function *Fn = nullptr;

  return make_tuple(FnThunk, Fn);
}
}

#include "translator.h"
#include "binary.h"
#include "mc.h"
#include "qemutcg.h"
#include <config-target.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <glib.h>

using namespace llvm;
using namespace object;
using namespace std;

extern "C" {
GHashTable* translator_tcg_helpers();

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
#include "runtime_helpers-aarch64.cpp"
#elif defined(TARGET_ARM)
#include "runtime_helpers-arm.cpp"
#elif defined(TARGET_X86_64)
#include "runtime_helpers-x86_64.cpp"
#elif defined(TARGET_I386)
#include "runtime_helpers-i386.cpp"
#elif defined(TARGET_MIPS)
#include "runtime_helpers-mipsel.cpp"
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
      HelperM(*_HelperM),
      tcg_globals{{
#if defined(TARGET_AARCH64)
#include "tcg_globals-aarch64.cpp"
#elif defined(TARGET_ARM)
#include "tcg_globals-arm.cpp"
#elif defined(TARGET_X86_64)
#include "tcg_globals-x86_64.cpp"
#elif defined(TARGET_I386)
#include "tcg_globals-i386.cpp"
#elif defined(TARGET_MIPS)
#include "tcg_globals-mipsel.cpp"
#endif
      }}
{
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

#if 0
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
#endif

void translator::init_helpers() {
  /* XXX */
  typedef struct TCGHelperInfo {
    void *func;
    const char *name;
    unsigned flags;
    unsigned sizemask;
  } TCGHelperInfo;
  /* XXX */

  GHashTable* helpers = translator_tcg_helpers();
  GHashTableIter iter;
  gpointer key, value;

  g_hash_table_iter_init(&iter, helpers);
  unsigned i = 0;
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    TCGHelperInfo* h = static_cast<TCGHelperInfo*>(value);

    tcg_helpers[i].addr = reinterpret_cast<uintptr_t>(h->func);
    tcg_helpers[i].nm = h->name;
    tcg_helpers[i].llf = HelperM.getFunction(h->name);
    assert(tcg_helpers[i].llf);

    ++i;
  }
}

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

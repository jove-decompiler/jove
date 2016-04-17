#include "translator.h"
#include "binary.h"
#include "mc.h"
#include "qemutcg.h"
#include <config-target.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/IR/Constants.h>
#include <boost/format.hpp>
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

namespace tcg {
/* XXX QEMUVERSIONDEPENDENT */
enum Opcode {
#define DEF(name, oargs, iargs, cargs, flags) INDEX_op_##name,
#include "tcg-opc.h"
#undef DEF
  NB_OPS,
};

struct Op {
  Opcode opc : 8;

  /* The number of out and in parameter for a call.  */
  unsigned callo : 2;
  unsigned calli : 6;

  /* Index of the arguments for this op, or -1 for zero-operand ops.  */
  signed args : 16;

  /* Index of the prex/next op, or -1 for the end of the list.  */
  signed prev : 16;
  signed next : 16;
};

struct ArgConstraint;

struct OpDef {
  const char *name;
  uint8_t nb_oargs, nb_iargs, nb_cargs, nb_args;
  uint8_t flags;
  ArgConstraint *args_ct;
  int *sorted_args;
#if defined(CONFIG_DEBUG_TCG)
  int used;
#endif
};

constexpr Arg TCG_CALL_DUMMY_ARG = -1;
constexpr Arg TCG_FIRST_GLOBAL_IDX = 1;
constexpr Arg TCG_CPU_STATE_ARG = 0;
static bool is_arg_global(Arg a) {
  return a != TCG_CPU_STATE_ARG && a != TCG_CALL_DUMMY_ARG &&
         a < tcg::num_globals;
}
}
extern "C" {
extern tcg::OpDef tcg_op_defs[];
}
/* XXX QEMUVERSIONDEPENDENT */

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

enum HELPER_METADATA_TYPE {
  HMT_INPUT,
  HMT_OUTPUT,
};

void translator::init_helpers() {
  /* XXX QEMUVERSIONDEPENDENT */
  typedef struct TCGHelperInfo {
    void *func;
    const char *name;
    unsigned flags;
    unsigned sizemask;
  } TCGHelperInfo;
  /* XXX QEMUVERSIONDEPENDENT */

  GHashTable *helpers = translator_tcg_helpers();

  GHashTableIter iter;
  gpointer key, value;
  g_hash_table_iter_init(&iter, helpers);

  int i = -1;
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    ++i;

    TCGHelperInfo *h = static_cast<TCGHelperInfo *>(value);

    tcg_helpers[i].addr = reinterpret_cast<uintptr_t>(h->func);
    tcg_helper_addr_map[tcg_helpers[i].addr] = &tcg_helpers[i];
    tcg_helpers[i].nm = h->name;
    tcg_helpers[i].llf =
        HelperM.getFunction((boost::format("helper_%s") % h->name).str());
    printf("%s\n", h->name);
    assert(tcg_helpers[i].llf);

    //
    // parse LLVM metadata for helper
    //
    NamedMDNode *nmdn = HelperM.getNamedMetadata(h->name);
    if (!nmdn)
      continue;

    for (unsigned i = 0; i < nmdn->getNumOperands(); ++i) {
      MDNode *mdn = nmdn->getOperand(i);
      assert(mdn->getNumOperands() == 2);

      HELPER_METADATA_TYPE hm_ty;
      {
        Metadata *M = mdn->getOperand(0);
        assert(isa<ConstantAsMetadata>(M));
        ConstantAsMetadata *CAsM = cast<ConstantAsMetadata>(M);
        Constant *C = CAsM->getValue();
        assert(isa<ConstantInt>(C));
        ConstantInt *CI = cast<ConstantInt>(C);
        hm_ty = static_cast<HELPER_METADATA_TYPE>(CI->getZExtValue());
      }

      unsigned tcggbl_idx;
      {
        Metadata *M = mdn->getOperand(1);
        assert(isa<ConstantAsMetadata>(M));
        ConstantAsMetadata *CAsM = cast<ConstantAsMetadata>(M);
        Constant *C = CAsM->getValue();
        assert(isa<ConstantInt>(C));
        ConstantInt *CI = cast<ConstantInt>(C);
        tcggbl_idx = CI->getZExtValue();
      }

      switch (hm_ty) {
      case HMT_INPUT:
        tcg_helpers[i].inglb.set(tcggbl_idx);
        break;
      case HMT_OUTPUT:
        tcg_helpers[i].outglb.set(tcggbl_idx);
        break;
      }
    }
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
  Function *FnThunk = nullptr;
  Function *Fn = nullptr;

  functions_to_translate = queue<address_t>();

  function_t f;
  f[boost::graph_bundle].entry_point = a;

  translate_function(f);

  return make_tuple(FnThunk, Fn);
}

void translator::translate_function(function_t& f) {
  //
  // recursive descent
  //
  translate_basic_block(f, f[boost::graph_bundle].entry_point);
}

static tuple<address_t, unsigned, unique_ptr<tcg::Op[]>, unique_ptr<tcg::Arg[]>>
translate_to_tcg(address_t a) {
  address_t succ_a = a + libqemutcg_translate(a);

  unique_ptr<tcg::Op[]> ops(new tcg::Op[libqemutcg_max_ops()]);
  unique_ptr<tcg::Arg[]> params(new tcg::Arg[libqemutcg_max_params()]);

  unsigned first_tcg_op_idx = libqemutcg_first_op_index();

  libqemutcg_copy_ops(ops.get());
  libqemutcg_copy_params(params.get());

  return make_tuple(succ_a, first_tcg_op_idx, move(ops), move(params));
}

void translator::translate_basic_block(function_t& f, address_t a) {
  basic_block_t bb = boost::add_vertex(f);
  f[bb].addr = a;

  address_t succ_a;

  tie(a, f[bb].first_tcg_op_idx, f[bb].tcg_ops, f[bb].tcg_args) =
      translate_to_tcg(a);

  calculate_defs_and_uses(f[bb]);

  for (tcg::Arg a = tcg::TCG_FIRST_GLOBAL_IDX; a < tcg::num_globals; ++a) {
#if 0
    f[bb].defs
    f[bb].uses
#endif
  }
}

void translator::calculate_defs_and_uses(basic_block_properties_t &bbprop) {
  tcg::global_set_t &defs = bbprop.defs;
  tcg::global_set_t &uses = bbprop.uses;

  const tcg::Op *ops = bbprop.tcg_ops.get();
  const tcg::Arg *params = bbprop.tcg_args.get();
  const tcg::Op *op;
  for (int oi = bbprop.first_tcg_op_idx; oi >= 0; oi = op->next) {
    op = &ops[oi];
    const tcg::Opcode c = op->opc;
    const tcg::OpDef *def = &tcg_op_defs[c];
    const tcg::Arg *args = &params[op->args];

    int nb_iargs = 0;
    int nb_oargs = 0;

    tcg::global_set_t iglb, oglb;

    switch (c) {
    case tcg::INDEX_op_discard:
      continue;
    case tcg::INDEX_op_call:
      nb_iargs = op->calli;
      nb_oargs = op->callo;

      if (c == tcg::INDEX_op_call) {
        //
        // take into account extra inputs and/or outputs by our version of the
        // helpers
        //
        tcg::helper_t *h = tcg_helper_addr_map[args[nb_oargs + nb_iargs]];
        iglb = h->inglb;
        oglb = h->outglb;
      }
      break;
    default:
      nb_iargs = def->nb_iargs;
      nb_oargs = def->nb_oargs;
      break;
    }

    for (int i = 0; i < nb_iargs; i++) {
      tcg::Arg a = args[nb_oargs + i];
      if (!tcg::is_arg_global(a))
        continue;

      iglb.set(a);
    }

    for (int i = 0; i < nb_oargs; i++) {
      tcg::Arg a = args[i];
      if (!tcg::is_arg_global(a))
        continue;

      oglb.set(a);
    }

    uses |= (iglb & (~defs));
    defs |= oglb;
  }
}

}

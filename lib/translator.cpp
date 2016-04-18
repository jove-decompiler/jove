#include <config-host.h>
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
#include <boost/graph/dominator_tree.hpp>
#include <boost/graph/filtered_graph.hpp>
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

constexpr Arg CALL_DUMMY_ARG = -1;
constexpr Arg FIRST_GLOBAL_IDX = 1;
constexpr Arg CPU_STATE_ARG = 0;
static bool is_arg_global(Arg a) {
  return a != CPU_STATE_ARG && a != CALL_DUMMY_ARG &&
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
      FnAttr(AttributeSet::get(C, AttributeSet::FunctionIndex,
                               Attribute::NoInline)),
      FnThunkTy(FunctionType::get(Type::getVoidTy(C), false)),
      FnThunkAttr(
          AttributeSet::get(C, AttributeSet::FunctionIndex, Attribute::Naked)),

      IndirectJumpFn(Function::Create(
          FunctionType::get(Type::getVoidTy(C), false),
          GlobalValue::ExternalLinkage, "___jove_indirect_jump", &M)),
      IndirectCallFn(Function::Create(
          FunctionType::get(Type::getVoidTy(C), false),
          GlobalValue::ExternalLinkage, "___jove_indirect_call", &M)),

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
      }} {
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

  sectstart = (*sectit).first.lower();
  sectdata = section_contents_of_binary(O, (*sectit).second);
  libqemutcg_set_code(sectdata.data(), sectdata.size(), sectstart);

  //
  // translate to TCG code
  //
  Function *FnThunk = nullptr;
  Function *Fn = nullptr;

  translated_basic_blocks.clear();
  functions_to_translate = queue<address_t>();

  function_t f;
  f[boost::graph_bundle].entry_point = a;

  basic_block_t entry = translate_function(f);

  unordered_map<basic_block_t, basic_block_t> idoms;
  lengauer_tarjan_dominator_tree(
      f, entry, boost::associative_property_map<
                    unordered_map<basic_block_t, basic_block_t>>(idoms));

#if 0
  for (const auto& dompair : idoms) {
    printf("%#lx dominates %#lx\n", f[dompair.second].addr,
           f[dompair.first].addr);
  }
#endif

  for (const auto& dompair : idoms)
    f[boost::add_edge(dompair.second, dompair.first, f).first].dom = true;

  struct dom_edges {
    translator::function_t *f;

    dom_edges() {}
    dom_edges(translator::function_t *f) : f(f) {}

    bool operator()(const control_flow_t &e) const {
      translator::function_t &_f = *f;
      return _f[e].dom;
    }
  };

  dom_edges e_filter(&f);
  typedef boost::filtered_graph<function_t, dom_edges> domtree_t;
  domtree_t domtree(f, e_filter);

  struct dfs_visitor : public boost::default_dfs_visitor {
    domtree_t& f;
    basic_block_t entry;
    unordered_map<basic_block_t, basic_block_t> &idoms;

    dfs_visitor(domtree_t &f, basic_block_t entry,
                unordered_map<basic_block_t, basic_block_t> &idoms)
        : f(f), entry(entry), idoms(idoms) {}

    void discover_vertex(basic_block_t bb, const domtree_t &) const {
      domtree_t::in_edge_iterator ei, eie;
      tie(ei, eie) = in_edges(bb, f);
      if (ei == eie) // root vertex
        return;

      basic_block_t idom = boost::source(*ei, f);

      tcg::global_set_t &uses_a = f[idom].uses;
      tcg::global_set_t &defs_a = f[idom].defs;

      tcg::global_set_t &uses_b = f[bb].uses;
      tcg::global_set_t &defs_b = f[bb].defs;

      uses_b = uses_a | (uses_b & (~defs_a));
      defs_b |= defs_a;
    }

    void finish_vertex(basic_block_t bb, const domtree_t &) const {
      domtree_t::out_edge_iterator ei, eie;
      tie(ei, eie) = out_edges(bb, f);
      if (ei != eie)
        return;

      //
      // leaf vertex
      //
      tcg::global_set_t &uses = f[bb].uses;
      tcg::global_set_t &defs = f[bb].defs;

      f[entry].uses |= uses;
      f[entry].defs |= defs;
    }
  };

  dfs_visitor vis(domtree, entry, idoms);
  boost::depth_first_search(domtree, boost::visitor(vis).root_vertex(entry));

  for (tcg::Arg a = tcg::FIRST_GLOBAL_IDX; a < tcg::num_globals; ++a)
    if (domtree[entry].defs.test(a))
      printf("DEF: %s\n", tcg_globals[a].nm);

  for (tcg::Arg a = tcg::FIRST_GLOBAL_IDX; a < tcg::num_globals; ++a)
    if (domtree[entry].uses.test(a))
      printf("USE: %s\n", tcg_globals[a].nm);

  return make_tuple(FnThunk, Fn);
}

translator::basic_block_t translator::translate_function(function_t& f) {
  //
  // recursive descent
  //
  return translate_basic_block(f, f[boost::graph_bundle].entry_point);
}

static tuple<address_t, address_t, unsigned, unique_ptr<tcg::Op[]>,
             unique_ptr<tcg::Arg[]>>
translate_to_tcg(address_t addr) {
  address_t succ_addr = addr + libqemutcg_translate(addr);
#if 0
  libqemutcg_print_ops();
#endif

  unique_ptr<tcg::Op[]> ops(new tcg::Op[libqemutcg_max_ops()]);
  unique_ptr<tcg::Arg[]> params(new tcg::Arg[libqemutcg_max_params()]);

  unsigned first_tcg_op_idx = libqemutcg_first_op_index();
  uint64_t last_instr_addr = libqemutcg_last_tcg_op_addr();

  libqemutcg_copy_ops(ops.get());
  libqemutcg_copy_params(params.get());

  return make_tuple(last_instr_addr, succ_addr, first_tcg_op_idx, move(ops),
                    move(params));
}

translator::basic_block_t translator::translate_basic_block(function_t &f,
                                                            address_t addr) {
  auto bb_it = translated_basic_blocks.find(addr);
  if (bb_it != translated_basic_blocks.end())
    return (*bb_it).second;

  basic_block_t bb = boost::add_vertex(f);
  f[bb].addr = addr;
  translated_basic_blocks.insert(make_pair(addr, bb));

  address_t last_instr_addr, succ_addr;

  tie(last_instr_addr, succ_addr, f[bb].first_tcg_op_idx, f[bb].tcg_ops,
      f[bb].tcg_args) = translate_to_tcg(addr);

  calculate_defs_and_uses(f[bb]);

#if 0
  for (tcg::Arg a = tcg::FIRST_GLOBAL_IDX; a < tcg::num_globals; ++a) {
    if (f[bb].defs.test(a))
      printf("DEF: %s\n", tcg_globals[a].nm);

    if (f[bb].uses.test(a))
      printf("USE: %s\n", tcg_globals[a].nm);
  }
#endif

  MCInst Inst;
  uint64_t size = libmc_analyze_instr(
      Inst, sectdata.data() + (last_instr_addr - sectstart), last_instr_addr);

  const MCInstrDesc &Desc = libmc_instrinfo()->get(Inst.getOpcode());
  const MCInstrAnalysis *MIA = libmc_instranalyzer();
  assert(MIA); /* only available on ARM & X86 */

#if 0
  if (MIA->isConditionalBranch(Inst) || MIA->isUnconditionalBranch(Inst) ||
      MIA->isCall(Inst))
#endif

  uint64_t target;
  bool has_target = MIA->evaluateBranch(Inst, last_instr_addr, size, target);

#if 0
  printf("MCInstrAnalysis (%lu bytes)\n", size);
  if (MIA->isReturn(Inst))
    printf("Return\n");
  if (MIA->isBranch(Inst))
    printf("Branch\n");
  if (MIA->isConditionalBranch(Inst))
    printf("Conditional Branch\n");
  if (MIA->isUnconditionalBranch(Inst))
    printf("Unconditional Branch\n");
  if (MIA->isIndirectBranch(Inst))
    printf("Indirect Branch\n");
  if (MIA->isCall(Inst)) {
    printf("Call\n");
    if (!has_target)
      printf("IndirectCall\n");
  }
  if (has_target)
    printf("Target: 0x%lx\n", target);

  printf("MCInstrDesc\n");
  if (Desc.isReturn())
    printf("Return\n");
  if (Desc.isBranch())
    printf("Branch\n");
  if (Desc.isConditionalBranch())
    printf("Conditional Branch\n");
  if (Desc.isUnconditionalBranch())
    printf("Unconditional Branch\n");
  if (Desc.isIndirectBranch())
    printf("Indirect Branch\n");
  if (Desc.isCall())
    printf("Call\n");
#endif

  if (MIA->isReturn(Inst)) {
  } else if (MIA->isConditionalBranch(Inst)) {
    boost::add_edge(bb, translate_basic_block(f, target), f);
    boost::add_edge(bb, translate_basic_block(f, succ_addr), f);
  } else if (MIA->isUnconditionalBranch(Inst)) {
    boost::add_edge(bb, translate_basic_block(f, target), f);
  } else if (MIA->isIndirectBranch(Inst)) {
  } else if (MIA->isCall(Inst)) {
    boost::add_edge(bb, translate_basic_block(f, succ_addr), f);
  }

  return bb;
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
      if (tcg::is_arg_global(args[0]))
        defs.reset(args[0]);

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

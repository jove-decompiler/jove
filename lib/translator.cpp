#include "translator.h"
#include "binary.h"
#include "mc.h"
#include "qemutcg.h"
#include <boost/format.hpp>
#include <boost/graph/dominator_tree.hpp>
#include <boost/graph/filtered_graph.hpp>
#include <boost/graph/graphviz.hpp>
#include <config-host.h>
#include <config-target.h>
#include <fstream>
#include <glib.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <boost/range/adaptor/reversed.hpp>

using namespace llvm;
using namespace object;
using namespace std;

extern "C" {
GHashTable *translator_tcg_helpers();

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

/* XXX wrong, but doesn't matter */
typedef uint8_t insn_unit;

struct Relocation {
  struct Relocation *next;
  int type;
  insn_unit *ptr;
  intptr_t addend;
};

struct Label {
  unsigned has_value : 1;
  unsigned id : 31;
  union {
    uintptr_t value;
    insn_unit *value_ptr;
    Relocation *first_reloc;
  } u;
};

constexpr Arg CALL_DUMMY_ARG = -1;
constexpr Arg FIRST_GLOBAL_IDX = 1;
constexpr Arg CPU_STATE_ARG = 0;

static bool is_arg_global(Arg a) {
  return a != CPU_STATE_ARG && a != CALL_DUMMY_ARG && a < tcg::num_globals;
}

enum MemOp {
  MO_8 = 0,
  MO_16 = 1,
  MO_32 = 2,
  MO_64 = 3,
  MO_SIZE = 3, /* Mask for the above.  */

  MO_SIGN = 4, /* Sign-extended, otherwise zero-extended.  */

  MO_BSWAP = 8, /* Host reverse endian.  */
#ifdef HOST_WORDS_BIGENDIAN
  MO_LE = MO_BSWAP,
  MO_BE = 0,
#else
  MO_LE = 0,
  MO_BE = MO_BSWAP,
#endif
#ifdef TARGET_WORDS_BIGENDIAN
  MO_TE = MO_BE,
#else
  MO_TE = MO_LE,
#endif

  /* MO_UNALN accesses are never checked for alignment.
     MO_ALIGN accesses will result in a call to the CPU's
     do_unaligned_access hook if the guest address is not aligned.
     The default depends on whether the target CPU defines ALIGNED_ONLY.  */
  MO_AMASK = 16,
#ifdef ALIGNED_ONLY
  MO_ALIGN = 0,
  MO_UNALN = MO_AMASK,
#else
  MO_ALIGN = MO_AMASK,
  MO_UNALN = 0,
#endif

  /* Combinations of the above, for ease of use.  */
  MO_UB = MO_8,
  MO_UW = MO_16,
  MO_UL = MO_32,
  MO_SB = MO_SIGN | MO_8,
  MO_SW = MO_SIGN | MO_16,
  MO_SL = MO_SIGN | MO_32,
  MO_Q = MO_64,

  MO_LEUW = MO_LE | MO_UW,
  MO_LEUL = MO_LE | MO_UL,
  MO_LESW = MO_LE | MO_SW,
  MO_LESL = MO_LE | MO_SL,
  MO_LEQ = MO_LE | MO_Q,

  MO_BEUW = MO_BE | MO_UW,
  MO_BEUL = MO_BE | MO_UL,
  MO_BESW = MO_BE | MO_SW,
  MO_BESL = MO_BE | MO_SL,
  MO_BEQ = MO_BE | MO_Q,

  MO_TEUW = MO_TE | MO_UW,
  MO_TEUL = MO_TE | MO_UL,
  MO_TESW = MO_TE | MO_SW,
  MO_TESL = MO_TE | MO_SL,
  MO_TEQ = MO_TE | MO_Q,

  MO_SSIZE = MO_SIZE | MO_SIGN,
};
static Label *arg_label(Arg i) { return (Label *)(uintptr_t)i; }
typedef uint32_t MemOpIdx;
static MemOp get_memop(MemOpIdx oi) { return (MemOp)(oi >> 4); }
static unsigned get_mmuidx(MemOpIdx oi) { return oi & 15; }
extern "C" {
extern tcg::OpDef tcg_op_defs[];
struct TCGContext;
extern TCGContext tcg_ctx;
const char *tcg_find_helper(TCGContext *s, uintptr_t val);
extern const char *const cond_name[];
extern const char *const ldst_name[];
}
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

tuple<Function *, Function *>
translator::translate(const std::vector<address_t> &addrs) {
  vector<address_t> functions_translated;

  functions_to_translate = queue<address_t>();
  for (address_t addr : addrs)
    functions_to_translate.push(addr);

  while (!functions_to_translate.empty()) {
    address_t addr = functions_to_translate.front();
    functions_to_translate.pop();

    translate_function(addr);

    functions_translated.push_back(addr);
  }

  //
  // compute return values for functions encountered
  //
  for (address_t addr : functions_translated) {
    function_t& f = *function_table[addr];
    compute_returned(f);

#if 1
    cout << hex << addr << endl;

    cout << '<';
    tcg::global_set_t all = f[boost::graph_bundle].params |
                            f[boost::graph_bundle].returned |
                            f[boost::graph_bundle].outputs;

    vector<tcg::Arg> params;
    glbv.reserve(tcg::num_globals);
    explode_tcg_global_set(glbv, f[boost::graph_bundle].params);

    for (auto g : params)
        cout << ' ' << tcg_globals[g].nm;

    for (tcg::Arg a = tcg::FIRST_GLOBAL_IDX; a < tcg::num_globals; ++a) {
      if (!all.test(a))
        continue;

      if (f[boost::graph_bundle].params.test(a))
        cout << ' ' << tcg_globals[a].nm;
      else
        cout << ' ' << string(strlen(tcg_globals[a].nm), ' ');
    }
    cout << endl;

    cout << '>';
    for (tcg::Arg a = tcg::FIRST_GLOBAL_IDX; a < tcg::num_globals; ++a) {
      if (!all.test(a))
        continue;

      if (f[boost::graph_bundle].returned.test(a))
        cout << ' ' << tcg_globals[a].nm;
      else
        cout << ' ' << string(strlen(tcg_globals[a].nm), ' ');
    }
    cout << endl;

    cout << '≥';
    for (tcg::Arg a = tcg::FIRST_GLOBAL_IDX; a < tcg::num_globals; ++a) {
      if (!all.test(a))
        continue;

      if (f[boost::graph_bundle].outputs.test(a))
        cout << ' ' << tcg_globals[a].nm;
      else
        cout << ' ' << string(strlen(tcg_globals[a].nm), ' ');
    }
    cout << endl;
#endif
  }

  //
  // write graphviz files for control-flow graphs
  //
#if 1
  for (address_t addr : functions_translated) {
    function_t& f = *function_table[addr];
    write_function_graphviz(f);
  }
#endif

  //
  // translate functions to llvm
  //
  for (address_t addr : boost::adaptors::reverse(functions_translated)) {
    function_t& f = *function_table[addr];
    translate_function_llvm(f);
  }

  return make_tuple(nullptr, nullptr);
}

translator::function_t& translator::translate_function(address_t addr) {
  //
  // check to see if function was already translated
  //
  {
    auto f_it = function_table.find(addr);
    if (f_it != function_table.end())
      return *(*f_it).second;
    else
      function_table[addr].reset(new function_t);
  }

  //
  // initialize function
  //
  function_t& f = *function_table[addr];
  f[boost::graph_bundle].entry_point = addr;

  //
  // initialize data structures used during translation of a function
  //
  parentMap.clear();
  verticesByDFNum.clear();
  translated_basic_blocks.clear();

  //
  // identify section containing function for access to instruction bytes
  //
  {
    auto sectit = addrspace.find(addr);
    assert(sectit != addrspace.end());

    sectstart = (*sectit).first.lower();
    sectdata = section_contents_of_binary(O, (*sectit).second);
  }
  libqemutcg_set_code(sectdata.data(), sectdata.size(), sectstart);

  //
  // conduct a recursive descent of the function, and translate each basic block
  // into QEMU TCG intermediate code
  //
  if (translate_basic_block(f, addr) ==
      boost::graph_traits<function_t>::null_vertex()) {
    cout << '<';
    cout << endl;

    cout << '>';
    cout << endl;
    return f;
  }

  //
  // determine parameters for function
  //
  compute_params(f);

  return f;
}

void translator::compute_params(function_t& f) {
  //
  // compute defs and uses for each basic block in preparation for liveness
  // analysis
  //
  for (basic_block_t bb : verticesByDFNum)
    compute_basic_block_defs_and_uses(f[bb]);

  //
  // conduct data-flow analysis via iterative worklist algorithm. we iterate in
  // reverse-preorder since this is a backwards data-flow analysis
  //
  bool change;
  do {
    change = false;

    for (basic_block_t bb : boost::adaptors::reverse(verticesByDFNum)) {
      auto eit_pair = boost::out_edges(bb, f);
      tcg::global_set_t live_in_before = f[bb].live_in;

      f[bb].live_out =
          accumulate(eit_pair.first, eit_pair.second, tcg::global_set_t(),
                     [&](tcg::global_set_t glbl, control_flow_t cf) {
                       return glbl | f[boost::target(cf, f)].live_in;
                     });
      f[bb].live_in =
          f[bb].uses | (f[bb].live_out & ~(f[bb].defs | f[bb].dead));

      change = change || live_in_before != f[bb].live_in;
    }
  } while (change);

  f[boost::graph_bundle].params = f[*boost::vertices(f).first].live_in;
}

void translator::compute_returned(function_t& f) {
  //
  // compute outputs by constructing the dominator tree for the function's
  // control-flow graph and follow the data-flow for generated outputs, which
  // are killed by globals marked as 'dead' by basic blocks
  //
  basic_block_t entry = *boost::vertices(f).first;

  vector<basic_block_t> idoms(boost::num_vertices(f),
                              boost::graph_traits<function_t>::null_vertex());
  boost::lengauer_tarjan_dominator_tree_without_dfs(
      f, entry, boost::get(boost::vertex_index, f),
      boost::get(boost::vertex_index, f),
      boost::make_iterator_property_map(parentMap.begin(),
                                        boost::get(boost::vertex_index, f)),
      verticesByDFNum, boost::make_iterator_property_map(
                           idoms.begin(), boost::get(boost::vertex_index, f)));

  for (auto i : boost::irange<unsigned>(0, idoms.size())) {
    if (idoms[i] == boost::graph_traits<function_t>::null_vertex())
      continue;

    f[boost::add_edge(idoms[i], i, f).first].dom = true;
  }

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

#if 0
  {
    ofstream of(
        (boost::format("%lx.domtree.dot") % f[boost::graph_bundle].entry_point)
            .str());
    boost::write_graphviz(of, domtree,
                          graphviz_label_writer<domtree_t>(*this, domtree),
                          graphviz_edge_prop_writer(), graphviz_prop_writer());
  }
#endif

  struct dfs_visitor : public boost::default_dfs_visitor {
    domtree_t &f;

    dfs_visitor(domtree_t &f) : f(f) {}

    void discover_vertex(basic_block_t bb, const domtree_t &) const {
      domtree_t::in_edge_iterator ei, eie;
      tie(ei, eie) = in_edges(bb, f);
      if (ei == eie) { // root vertex
        f[bb].outputs = f[bb].defs;
        return;
      }

      // immediate dominator is unique
      basic_block_t idom = boost::source(*ei, f);
      tcg::global_set_t &outs_a = f[idom].outputs;

      tcg::global_set_t &defs_b = f[bb].defs;
      tcg::global_set_t &dead_b = f[bb].dead;
      tcg::global_set_t &outs_b = f[bb].outputs;

      outs_b = defs_b | outs_a & ~dead_b;
    }

    void finish_vertex(basic_block_t bb, const domtree_t &) const {
      domtree_t::out_edge_iterator ei, eie;
      tie(ei, eie) = out_edges(bb, f);
      if (ei != eie) // non-leaf vertex
        return;

      f[boost::graph_bundle].outputs |= f[bb].outputs;
    }
  };

  //
  // compute outputs
  //
  dfs_visitor vis(domtree);
  boost::depth_first_search(domtree, boost::visitor(vis).root_vertex(entry));

  //
  // compute returned set of globals for f. it is equal to
  //
  // (              ∪ (OUT[B]                 ) ∩ OUTPUTS(f)
  // ∀ caller basic blocks B
  //
  const auto &calls = callers[f[boost::graph_bundle].entry_point];
  tcg::global_set_t X =
      accumulate(calls.begin(), calls.end(), tcg::global_set_t(),
                 [&](tcg::global_set_t res, const caller_t &caller) {
                   function_t &caller_f = *caller.first;
                   return res | caller_f[caller.second].live_out;
                 });

  f[boost::graph_bundle].returned = X.any()
                                        ? (X & f[boost::graph_bundle].outputs)
                                        : f[boost::graph_bundle].outputs;
}

translator::basic_block_t translator::translate_basic_block(function_t &f,
                                                            address_t addr) {
  MCInst Inst;
  uint64_t size;

  //
  // if the first instruction has an invalid encoding, then we assume it is
  // unreachable and do not create a basic block for this address
  //
  if (!libmc_analyze_instr(Inst, size,
                           sectdata.data() + (addr - sectstart),
                           addr))
    return boost::graph_traits<function_t>::null_vertex();

  //
  // perform the translation from machine code to TCG intermediate code for one
  // basic block
  //
  address_t succ_addr = addr + libqemutcg_translate(addr);
  address_t last_instr_addr = libqemutcg_last_tcg_op_addr();

  //
  // if the last instruction in the basic block has an invalid encoding, then
  // we assume it is unreachable and do not create a basic block for this
  // address
  //
  if (!libmc_analyze_instr(Inst, size,
                           sectdata.data() + (last_instr_addr - sectstart),
                           last_instr_addr))
    return boost::graph_traits<function_t>::null_vertex();

  //
  // prepare data structures for new basic block
  //
  basic_block_t bb = boost::add_vertex(f);
  translated_basic_blocks[addr] = bb;
  parentMap.resize(boost::num_vertices(f));
  verticesByDFNum.push_back(bb);

  //
  // fill basic block properties
  //
  f[bb].addr = addr;
  f[bb].first_tcg_op_idx = libqemutcg_first_op_index();
  f[bb].tcg_ops.reset(new tcg::Op[libqemutcg_max_ops()]);
  f[bb].tcg_args.reset(new tcg::Arg[libqemutcg_max_params()]);
  libqemutcg_copy_ops(f[bb].tcg_ops.get());
  libqemutcg_copy_params(f[bb].tcg_args.get());

  //
  // conduct analysis of last instruction (the terminator of the block) and
  // (recursively) descend into branch targets, translating basic blocks
  //
  auto control_flow_to = [&](address_t dst_addr) -> void {
    auto bb_it = translated_basic_blocks.find(dst_addr);
    if (bb_it != translated_basic_blocks.end()) {
      f[boost::add_edge(bb, (*bb_it).second, f).first].back_edge = true;
      return;
    }

    basic_block_t succ_bb = translate_basic_block(f, dst_addr);
    if (succ_bb != boost::graph_traits<function_t>::null_vertex()) {
      boost::add_edge(bb, succ_bb, f);
      parentMap[boost::get(boost::vertex_index, f)[succ_bb]] = bb;
    }
  };

#if defined(TARGET_AARCH64)
  auto aarch64_evaluateUnconditionalBranch = [&](uint64_t& target) -> void {
    assert(Inst.getNumOperands() == 1);
    assert(Inst.getOperand(0).isImm());

    target = static_cast<uint64_t>(4*Inst.getOperand(0).getImm() +
                                   static_cast<int64_t>(last_instr_addr));
  };

  auto aarch64_evaluateConditionalBranch = [&](uint64_t& target) -> void {
    assert(Inst.getNumOperands() == 2);
    assert(Inst.getOperand(1).isImm());

    target = static_cast<uint64_t>(4*Inst.getOperand(1).getImm() +
                                   static_cast<int64_t>(last_instr_addr));
  };

  auto aarch64_evaluateCall = [&](uint64_t& target) -> bool {
    if (Inst.getNumOperands() != 1 || !Inst.getOperand(0).isImm())
      return false;

    target = static_cast<uint64_t>(4*Inst.getOperand(0).getImm() +
                                   static_cast<int64_t>(last_instr_addr));
    return true;
  };
#endif

  const MCInstrAnalysis *MIA = libmc_instranalyzer();
  unique_ptr<MCInstrAnalysis> _MIA;
  if (!MIA) {
    _MIA.reset(new MCInstrAnalysis(libmc_instrinfo()));
    MIA = _MIA.get();
  }

  if (MIA->isReturn(Inst)) {
  } else if (MIA->isConditionalBranch(Inst)) {
    uint64_t target;
#if defined(TARGET_X86_64)
    assert(MIA->evaluateBranch(Inst, last_instr_addr, size, target));
#elif defined(TARGET_AARCH64)
    aarch64_evaluateConditionalBranch(target);
#endif

    control_flow_to(target);
    control_flow_to(succ_addr);
  } else if (MIA->isUnconditionalBranch(Inst)) {
    uint64_t target;
#if defined(TARGET_X86_64)
    assert(MIA->evaluateBranch(Inst, last_instr_addr, size, target));
#elif defined(TARGET_AARCH64)
    aarch64_evaluateUnconditionalBranch(target);
#endif

    control_flow_to(target);
  } else if (MIA->isIndirectBranch(Inst)) {
  } else if (MIA->isCall(Inst)) {
    bool is_indirect;
    uint64_t target;
#if defined(TARGET_X86_64)
    is_indirect = !MIA->evaluateBranch(Inst, last_instr_addr, size, target);
#elif defined(TARGET_AARCH64)
    is_indirect = !aarch64_evaluateCall(target);
#endif
    if (!is_indirect) {
      functions_to_translate.push(target);
      callers[target].push_back({&f, bb});
    }

    control_flow_to(succ_addr);
  }

  return bb;
}

void translator::compute_basic_block_defs_and_uses(
    basic_block_properties_t &bbprop) {
  tcg::global_set_t &defs = bbprop.defs;
  tcg::global_set_t &uses = bbprop.uses;
  tcg::global_set_t &dead = bbprop.dead;

  const tcg::Op *ops = bbprop.tcg_ops.get();
  const tcg::Arg *params = bbprop.tcg_args.get();
  const tcg::Op *op;
  for (int oi = bbprop.first_tcg_op_idx; oi >= 0; oi = op->next) {
    op = &ops[oi];
    const tcg::Opcode c = op->opc;
    const tcg::OpDef *def = &tcg::tcg_op_defs[c];
    const tcg::Arg *args = &params[op->args];

    int nb_iargs = 0;
    int nb_oargs = 0;

    tcg::global_set_t iglb, oglb;

    switch (c) {
    case tcg::INDEX_op_discard:
      if (tcg::is_arg_global(args[0])) {
        defs.reset(args[0]);
        dead.set(args[0]);
      }

      continue;
    case tcg::INDEX_op_call:
      nb_iargs = op->calli;
      nb_oargs = op->callo;

      if (c == tcg::INDEX_op_call) {
        //
        // take into account extra inputs and/or outputs by our version of the
        // helpers
        //
        auto h_addr = args[nb_oargs + nb_iargs];
        auto h_it = tcg_helper_addr_map.find(h_addr);
        if (h_it == tcg_helper_addr_map.end()) {
          cerr << "warning: bad call to tcg helper" << endl;
          continue;
        }

        tcg::helper_t *h = (*h_it).second;
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

    uses |= (iglb & ~defs & ~dead);
    defs |= oglb;
    dead &= ~oglb;
  }
}

void translator::print_tcg_ops(ostream &out,
                               const basic_block_properties_t &bbprop) const {
  auto string_of_tcg_arg = [&](tcg::Arg a) -> string {
    if (a < tcg::num_globals)
      return tcg_globals[a].nm;
    else
      return (boost::format("tmp_%d") % static_cast<int>(a)).str();
  };

  char buf[128];
  char asmbuf[128];

  const tcg::Op *ops = bbprop.tcg_ops.get();
  const tcg::Arg *params = bbprop.tcg_args.get();
  const tcg::Op *op;
  for (int oi = bbprop.first_tcg_op_idx; oi >= 0; oi = op->next) {
    int i, k, nb_oargs, nb_iargs, nb_cargs;

    op = &ops[oi];
    const tcg::Opcode c = op->opc;
    const tcg::OpDef *def = &tcg::tcg_op_defs[c];
    const tcg::Arg *args = &params[op->args];

    if (c == tcg::INDEX_op_insn_start) {
      i = 0;
      target_ulong a;
#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
      a = ((target_ulong)args[i * 2 + 1] << 32) | args[i * 2];
#else
      a = args[i];
#endif
#if 0
      printf(" " TARGET_FMT_lx, a);

      printf("|%d", (int)(s->gen_first_op_idx - code_pc));
      printf("|%s", libmc_instr_asm((s->gen_first_op_idx - code_pc) + code,
                                    s->gen_first_op_idx - code_pc, asmbuf));
#endif

      out << endl
          << "0x" << hex << a << "    "
          << libmc_instr_asm(sectdata.data() + (a - sectstart), a, asmbuf)
          << endl
          << endl;

      continue;
    } else {
      if (c == tcg::INDEX_op_call) {
        /* variable number of arguments */
        nb_oargs = op->callo;
        nb_iargs = op->calli;
        nb_cargs = def->nb_cargs;

        /* function name, flags, out args */
        out << (boost::format("%s %s,$0x%" TCG_PRIlx ",$%d") % def->name %
                tcg_find_helper(&tcg::tcg_ctx, args[nb_oargs + nb_iargs]) %
                args[nb_oargs + nb_iargs + 1] % nb_oargs);

        for (i = 0; i < nb_oargs; i++)
          out << (boost::format(",%s") % string_of_tcg_arg(args[i]));

        for (i = 0; i < nb_iargs; i++) {
          tcg::Arg arg = args[nb_oargs + i];
          string t("<dummy>");

          if (arg != tcg::CALL_DUMMY_ARG)
            t = string_of_tcg_arg(arg);

          out << (boost::format(",%s") % t);
        }
      } else {
        out << (boost::format("%s ") % def->name);

        nb_oargs = def->nb_oargs;
        nb_iargs = def->nb_iargs;
        nb_cargs = def->nb_cargs;

        k = 0;
        for (i = 0; i < nb_oargs; i++) {
          if (k != 0) {
            out << ',';
          }
          out << string_of_tcg_arg(args[k++]);
        }
        for (i = 0; i < nb_iargs; i++) {
          if (k != 0) {
            out << ",";
          }
          out << string_of_tcg_arg(args[k++]);
        }
        switch (c) {
        case tcg::INDEX_op_brcond_i32:
        case tcg::INDEX_op_setcond_i32:
        case tcg::INDEX_op_movcond_i32:
        case tcg::INDEX_op_brcond2_i32:
        case tcg::INDEX_op_setcond2_i32:
        case tcg::INDEX_op_brcond_i64:
        case tcg::INDEX_op_setcond_i64:
        case tcg::INDEX_op_movcond_i64:
          out << (boost::format(",%s") % tcg::cond_name[args[k++]]);
          i = 1;
          break;
        case tcg::INDEX_op_qemu_ld_i32:
        case tcg::INDEX_op_qemu_st_i32:
        case tcg::INDEX_op_qemu_ld_i64:
        case tcg::INDEX_op_qemu_st_i64: {
          tcg::MemOpIdx oi = args[k++];
          tcg::MemOp op = tcg::get_memop(oi);
          unsigned ix = tcg::get_mmuidx(oi);

          if (op & ~(tcg::MO_AMASK | tcg::MO_BSWAP | tcg::MO_SSIZE)) {
            out << (boost::format(",$0x%x,%u") % op % ix);
          } else {
            const char *s_al = "", *s_op;
            if (op & tcg::MO_AMASK) {
              if ((op & tcg::MO_AMASK) == tcg::MO_ALIGN) {
                s_al = "al+";
              } else {
                s_al = "un+";
              }
            }
            s_op = tcg::ldst_name[op & (tcg::MO_BSWAP | tcg::MO_SSIZE)];
            out << (boost::format(",%s%s,%u") % s_al % s_op % ix);
          }
          i = 1;
        } break;
        default:
          i = 0;
          break;
        }
        switch (c) {
        case tcg::INDEX_op_set_label:
        case tcg::INDEX_op_br:
        case tcg::INDEX_op_brcond_i32:
        case tcg::INDEX_op_brcond_i64:
        case tcg::INDEX_op_brcond2_i32:
          out << (boost::format("%s$L%d") % (k ? "," : "") %
                  ((int)tcg::arg_label(args[k])->id));
          i++, k++;
          break;
        default:
          break;
        }
        for (; i < nb_cargs; i++, k++) {
          out << (boost::format("%s$%s0x%" TCG_PRIlx) % (k ? "," : "") %
                  (((tcg_target_long)args[k]) < 0 ? "-" : "") %
                  (((tcg_target_long)args[k]) < 0 ? -((tcg_target_long)args[k])
                                                  : args[k]));
        }
      }
    }
    out << endl;
  }
}

template <typename Graph> struct graphviz_label_writer {
  translator& t;
  const Graph &g;
  graphviz_label_writer(translator& t, const Graph &g) : t(t), g(g) {}

  template <class VertexOrEdge>
  void operator()(std::ostream &out, const VertexOrEdge &v) const {
    std::string s;

    {
      ostringstream oss;
      t.print_tcg_ops(oss, g[v]);
      s = oss.str();
    }

    s.reserve(2 * s.size());

    boost::replace_all(s, "\\", "\\\\");
    boost::replace_all(s, "\r\n", "\\l");
    boost::replace_all(s, "\n", "\\l");
    boost::replace_all(s, "\"", "\\\"");
    boost::replace_all(s, "{", "\\{");
    boost::replace_all(s, "}", "\\}");
    boost::replace_all(s, "|", "\\|");
    boost::replace_all(s, "|", "\\|");
    boost::replace_all(s, "<", "\\<");
    boost::replace_all(s, ">", "\\>");
    boost::replace_all(s, "(", "\\(");
    boost::replace_all(s, ")", "\\)");
    boost::replace_all(s, ",", "\\,");
    boost::replace_all(s, ";", "\\;");
    boost::replace_all(s, ":", "\\:");
    boost::replace_all(s, " ", "\\ ");

    out << "[label=\"";
    out << s;
    out << "\"]";
  }
};

struct graphviz_edge_prop_writer {
  template <class Edge>
  void operator()(ostream &out, const Edge &e) const {
    static const char *edge_type_styles[] = {
        "solid", "dashed", /*"invis"*/ "dotted"
    };

    out << "[style=\"" << edge_type_styles[0] << "\"]";
  }
};

struct graphviz_prop_writer {
  void operator()(ostream &out) const {
    out << "fontname = \"Courier\"\n"
           "fontsize = 10\n"
           "\n"
           "node [\n"
           "fontname = \"Courier\"\n"
           "fontsize = 10\n"
           "shape = \"record\"\n"
           "]\n"
           "\n"
           "edge [\n"
           "fontname = \"Courier\"\n"
           "fontsize = 10\n"
           "]\n"
           "\n";
  }
};


void translator::write_function_graphviz(function_t &f) {
  ofstream of(
      (boost::format("%lx.dot") % f[boost::graph_bundle].entry_point).str());
  boost::write_graphviz(of, f, graphviz_label_writer<function_t>(*this, f),
                        graphviz_edge_prop_writer(), graphviz_prop_writer());
}

void translator::explode_tcg_global_set(vector<tcg::Arg> &out,
                                        tcg::global_set_t glbs) {
  static_assert(sizeof(unsigned long long) == sizeof(uint64_t),
                "unsigned long long must be 64-bits");

  constexpr unsigned long long mask_no_bit_table[64] = {
      ~(1ULL >> 0),  ~(1ULL >> 1),  ~(1ULL >> 2),  ~(1ULL >> 3),
      ~(1ULL >> 4),  ~(1ULL >> 5),  ~(1ULL >> 6),  ~(1ULL >> 7),
      ~(1ULL >> 8),  ~(1ULL >> 9),  ~(1ULL >> 10), ~(1ULL >> 11),
      ~(1ULL >> 12), ~(1ULL >> 13), ~(1ULL >> 14), ~(1ULL >> 15),
      ~(1ULL >> 16), ~(1ULL >> 17), ~(1ULL >> 18), ~(1ULL >> 19),
      ~(1ULL >> 20), ~(1ULL >> 21), ~(1ULL >> 22), ~(1ULL >> 23),
      ~(1ULL >> 24), ~(1ULL >> 25), ~(1ULL >> 26), ~(1ULL >> 27),
      ~(1ULL >> 28), ~(1ULL >> 29), ~(1ULL >> 30), ~(1ULL >> 31),
      ~(1ULL >> 32), ~(1ULL >> 33), ~(1ULL >> 34), ~(1ULL >> 35),
      ~(1ULL >> 36), ~(1ULL >> 37), ~(1ULL >> 38), ~(1ULL >> 39),
      ~(1ULL >> 40), ~(1ULL >> 41), ~(1ULL >> 42), ~(1ULL >> 43),
      ~(1ULL >> 44), ~(1ULL >> 45), ~(1ULL >> 46), ~(1ULL >> 47),
      ~(1ULL >> 48), ~(1ULL >> 49), ~(1ULL >> 50), ~(1ULL >> 51),
      ~(1ULL >> 52), ~(1ULL >> 53), ~(1ULL >> 54), ~(1ULL >> 55),
      ~(1ULL >> 56), ~(1ULL >> 57), ~(1ULL >> 58), ~(1ULL >> 59),
      ~(1ULL >> 60), ~(1ULL >> 61), ~(1ULL >> 62), ~(1ULL >> 63)};

  if (glbs.none())
    return;

  unsigned long long x = glbs.to_ullong();
  int idx = 0;
  do {
    int pos = ffsll(x) + 1;
    x <<= pos;
    idx += pos;
    out.push_back(idx-1);
  } while (x);
}

void translator::translate_function_llvm(function_t& f) {
  //
  // build function type
  //
  auto types_of_tcg_global_set = [&](vector<Type *> tys,
                                     tcg::global_set_t glbs) -> void {
    if (glbs.none())
      return;

    vector<tcg::Arg> glbv;
    glbv.reserve(tcg::num_globals);
    explode_tcg_global_set(glbv, glbs);

    tys.resize(glbv.size());
    transform(glbv.begin(), glbv.end(), tys.begin(), [&](tcg::Arg g) {
      return IntegerType::get(C,
                              tcg_globals[g].ty == tcg::GLOBAL_I32 ? 32 : 64);
    });
  };

  vector<Type*> param_tys;
  vector<Type*> return_tys;

  types_of_tcg_global_set(param_tys, f[boost::graph_bundle].params);
  types_of_tcg_global_set(return_tys, f[boost::graph_bundle].returned);

  FunctionType *ty =
      FunctionType::get(StructType::get(C, ArrayRef<Type *>(return_tys)),
                        ArrayRef<Type *>(param_tys), false);

  //
  // create function
  //
  Function *llf = Function::Create(
      ty, GlobalValue::ExternalLinkage,
      (boost::format("%x") % f[boost::graph_bundle].entry_point).str(), &M);
}

}

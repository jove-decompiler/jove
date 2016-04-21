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
char *tcg_get_arg_str_idx(TCGContext *s, char *buf, int buf_size, int idx);
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

tuple<Function *, Function *> translator::translate(address_t addr) {
  functions_to_translate = queue<address_t>();

  function_t& f = translate_function(addr);

  while (!functions_to_translate.empty()) {
    translate_function(functions_to_translate.front());
    functions_to_translate.pop();
  }

  return make_tuple(f[boost::graph_bundle].llf,
                    f[boost::graph_bundle].thunk_llf);
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
  // into QEMU TCG intermediate
  //
  translate_basic_block(f, addr);

#if 1
  write_function_graphviz(f);
#endif

  //
  // determine parameters for function
  //
  compute_params(f);

  //
  // determine return values for function (and other outputs to cpu state)
  //
  compute_returned(f);

#if 1
  cout << '<';
  for (tcg::Arg a = tcg::FIRST_GLOBAL_IDX; a < tcg::num_globals; ++a)
    if (f[boost::graph_bundle].params.test(a))
      cout << ' ' << tcg_globals[a].nm;
  cout << endl;

  cout << '>';
  for (tcg::Arg a = tcg::FIRST_GLOBAL_IDX; a < tcg::num_globals; ++a)
    if (f[boost::graph_bundle].outputs.test(a))
      cout << ' ' << tcg_globals[a].nm;
  cout << endl;
#endif

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
  // determine outputs
  //
  dfs_visitor vis(domtree);
  boost::depth_first_search(domtree, boost::visitor(vis).root_vertex(entry));
}

translator::basic_block_t translator::translate_basic_block(function_t &f,
                                                            address_t addr) {
  basic_block_t bb = boost::add_vertex(f);
  f[bb].addr = addr;

  translated_basic_blocks.insert(make_pair(addr, bb));
  parentMap.resize(boost::num_vertices(f));
  verticesByDFNum.push_back(bb);

  address_t succ_addr = addr + libqemutcg_translate(addr);
  f[bb].first_tcg_op_idx = libqemutcg_first_op_index();

  f[bb].tcg_ops.reset(new tcg::Op[libqemutcg_max_ops()]);
  f[bb].tcg_args.reset(new tcg::Arg[libqemutcg_max_params()]);

  libqemutcg_copy_ops(f[bb].tcg_ops.get());
  libqemutcg_copy_params(f[bb].tcg_args.get());

  address_t last_instr_addr = libqemutcg_last_tcg_op_addr();
  MCInst Inst;
  uint64_t size = libmc_analyze_instr(
      Inst, sectdata.data() + (last_instr_addr - sectstart), last_instr_addr);

  const MCInstrAnalysis *MIA = libmc_instranalyzer();
  assert(MIA); /* only available on ARM & X86 */

  uint64_t target;
  MIA->evaluateBranch(Inst, last_instr_addr, size, target);

  auto control_flow_to = [&](address_t dst_addr) -> void {
    auto bb_it = translated_basic_blocks.find(dst_addr);
    if (bb_it != translated_basic_blocks.end()) {
      f[boost::add_edge(bb, (*bb_it).second, f).first].back_edge = true;
      return;
    }

    basic_block_t succ_bb = translate_basic_block(f, dst_addr);
    boost::add_edge(bb, succ_bb, f);

    parentMap[boost::get(boost::vertex_index, f)[succ_bb]] = bb;
  };

  if (MIA->isReturn(Inst)) {
  } else if (MIA->isConditionalBranch(Inst)) {
    control_flow_to(target);
    control_flow_to(succ_addr);
  } else if (MIA->isUnconditionalBranch(Inst)) {
    control_flow_to(target);
  } else if (MIA->isIndirectBranch(Inst)) {
  } else if (MIA->isCall(Inst)) {
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

    uses |= (iglb & ~defs & ~dead);
    defs |= oglb;
    dead &= ~oglb;
  }
}

void translator::print_tcg_ops(ostream &out,
                               const basic_block_properties_t &bbprop) const {
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

      out << endl << "0x" << hex << a << endl;
      out << libmc_instr_asm(sectdata.data() + (a - sectstart), a, asmbuf)
          << endl << endl;

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
          out << (boost::format(",%s") %
                  tcg_get_arg_str_idx(&tcg::tcg_ctx, buf, sizeof(buf), args[i]));

        for (i = 0; i < nb_iargs; i++) {
          tcg::Arg arg = args[nb_oargs + i];
          const char *t = "<dummy>";

          if (arg != tcg::CALL_DUMMY_ARG)
            t = tcg_get_arg_str_idx(&tcg::tcg_ctx, buf, sizeof(buf), arg);

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
          out << tcg_get_arg_str_idx(&tcg::tcg_ctx, buf, sizeof(buf), args[k++]);
        }
        for (i = 0; i < nb_iargs; i++) {
          if (k != 0) {
            out << ",";
          }
          out << tcg_get_arg_str_idx(&tcg::tcg_ctx, buf, sizeof(buf), args[k++]);
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

}

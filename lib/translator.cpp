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
#include <llvm/IR/Verifier.h>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/icl/split_interval_set.hpp>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/Analysis/ValueTracking.h>

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
constexpr Arg CPU_STATE_ARG = 0;

static bool is_arg_global(Arg a) {
  return a != CPU_STATE_ARG && a != CALL_DUMMY_ARG && a < tcg::num_globals;
}

static bool is_arg_temp(Arg a) {
  return a >= tcg::num_globals && a != CALL_DUMMY_ARG;
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
typedef enum {
    /* non-signed */
    TCG_COND_NEVER  = 0 | 0 | 0 | 0,
    TCG_COND_ALWAYS = 0 | 0 | 0 | 1,
    TCG_COND_EQ     = 8 | 0 | 0 | 0,
    TCG_COND_NE     = 8 | 0 | 0 | 1,
    /* signed */
    TCG_COND_LT     = 0 | 0 | 2 | 0,
    TCG_COND_GE     = 0 | 0 | 2 | 1,
    TCG_COND_LE     = 8 | 0 | 2 | 0,
    TCG_COND_GT     = 8 | 0 | 2 | 1,
    /* unsigned */
    TCG_COND_LTU    = 0 | 4 | 0 | 0,
    TCG_COND_GEU    = 0 | 4 | 0 | 1,
    TCG_COND_LEU    = 8 | 4 | 0 | 0,
    TCG_COND_GTU    = 8 | 4 | 0 | 1,
} TCGCond;
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

translator::translator(ObjectFile &O, const string &MNm)
    : O(O), M(MNm, C), DL(M.getDataLayout()),
      _HelperM(move(*getLazyBitcodeModule(
          MemoryBuffer::getMemBuffer(
              StringRef(reinterpret_cast<const char *>(
                            &runtime_helpers_bitcode_data[0]),
                        sizeof(runtime_helpers_bitcode_data)),
              "", false),
          C))),
      HelperM(*_HelperM), b(C), word_ty(
#if defined(TARGET_AARCH64) || defined(TARGET_X86_64)
                                    IntegerType::get(C, 64)
#else
                                    IntegerType::get(C, 32)
#endif
                                        ),
      FnAttr(AttributeSet::get(C, AttributeSet::FunctionIndex,
                               Attribute::NoInline)),
      FnThunkTy(FunctionType::get(Type::getVoidTy(C), false)),
      FnThunkAttr(
          AttributeSet::get(C, AttributeSet::FunctionIndex, Attribute::Naked)),
      ExternalFnTy(FunctionType::get(Type::getVoidTy(C), false)),
      ExternalFnPtrTy(PointerType::get(ExternalFnTy, 0)),
      IndirectJumpFn(Function::Create(
          FunctionType::get(Type::getVoidTy(C),
                            ArrayRef<Type *>(ExternalFnPtrTy), false),
          GlobalValue::ExternalLinkage, "___jove_indirect_jump", &M)),
      IndirectCallFn(Function::Create(
          FunctionType::get(Type::getVoidTy(C), ArrayRef<Type *>(word_ty),
                            false),
          GlobalValue::ExternalLinkage, "___jove_indirect_call", &M)),

      callconv{{{
#if defined(TARGET_AARCH64)
#include "abi_callingconv_arg_regs-aarch64.cpp"
#elif defined(TARGET_ARM)
#include "abi_callingconv_arg_regs-arm.cpp"
#elif defined(TARGET_X86_64)
#include "abi_callingconv_arg_regs-x86_64.cpp"
#elif defined(TARGET_I386)
#include "abi_callingconv_arg_regs-i386.cpp"
#elif defined(TARGET_MIPS)
#include "abi_callingconv_arg_regs-mipsel.cpp"
#endif
               }},
               {{
#if defined(TARGET_AARCH64)
#include "abi_callingconv_ret_regs-aarch64.cpp"
#elif defined(TARGET_ARM)
#include "abi_callingconv_ret_regs-arm.cpp"
#elif defined(TARGET_X86_64)
#include "abi_callingconv_ret_regs-x86_64.cpp"
#elif defined(TARGET_I386)
#include "abi_callingconv_ret_regs-i386.cpp"
#elif defined(TARGET_MIPS)
#include "abi_callingconv_ret_regs-mipsel.cpp"
#endif
               }}},
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
  // initialize LLVM-MC for machine code analysis
  //
  libmc_init(&O);

  //
  // initialize helpers
  //
  init_helpers();

  //
  // initialize data structures and modify the bitcode to prepare for
  // translating to LLVM
  //
  prepare_for_translation();
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
    string sym = (boost::format("helper_%s") % h->name).str();
    tcg_helpers[i].llf = HelperM.getFunction(sym);
    assert(tcg_helpers[i].llf);

    //
    // parse LLVM metadata for helper
    //
    NamedMDNode *nmdn = HelperM.getNamedMetadata(sym);

    if (!nmdn)
      continue;

    tcg_helpers[i].inglbv.reserve(nmdn->getNumOperands());
    tcg_helpers[i].outglbv.reserve(nmdn->getNumOperands());
    for (unsigned j = 0; j < nmdn->getNumOperands(); ++j) {
      MDNode *mdn = nmdn->getOperand(j);
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
        tcg_helpers[i].inglbv.push_back(tcggbl_idx);
        break;
      case HMT_OUTPUT:
        tcg_helpers[i].outglb.set(tcggbl_idx);
        tcg_helpers[i].outglbv.push_back(tcggbl_idx);
        break;
      }
    }
  }
}

template <typename InputIterator, typename Pred, typename Func>
Func for_each_if(InputIterator first, InputIterator last, Pred p, Func f) {
  while (first != last) {
    if (p(*first))
      f(*first);
    ++first;
  }
  return f;
}

void translator::create_section_global_variables() {
  //
  // create address to section number mapping
  //
  for (unsigned i = 0; i < secttbl.size(); ++i) {
    section_t& sect = secttbl[i];
    boost::icl::discrete_interval<address_t> intervl =
        boost::icl::discrete_interval<address_t>::right_open(
            sect.addr, sect.addr + sect.size);
    addrspace.add(make_pair(intervl, i + 1));
  }

  //
  // initialize section intervals
  //
  typedef boost::icl::split_interval_set<unsigned> section_interval_map_t;
  typedef section_interval_map_t::interval_type section_interval_t;
  vector<section_interval_map_t> sectstuffs(secttbl.size());
  for (unsigned i = 0; i < secttbl.size(); ++i)
    sectstuffs[i].insert(section_interval_t::right_open(0, secttbl[i].size));


  //
  // allocate local data structures
  //
  std::vector<StructType*> sectgvtys;

  sectgvs.reserve(secttbl.size());
  sectgvtys.resize(secttbl.size());
  sectrelocs.resize(secttbl.size());
  sectreloctys.resize(secttbl.size());

  //
  // compute section field types, and split section intervals
  //

  auto type_for_relocation = [&](const relocation_t &reloc, Type* ty) -> void {
    assert(ty);

    unsigned sectidx = (*addrspace.find(reloc.addr)).second - 1;
    unsigned off = reloc.addr - secttbl[sectidx].addr;

    sectreloctys[sectidx][off] = ty;
    sectstuffs[sectidx].insert(
        section_interval_t::right_open(off, off + sizeof(address_t)));
  };

  auto process_function_relocation_type =
      [&](const relocation_t &reloc) -> void {
    symbol_t& sym = symtbl[reloc.symidx];
    Type *ty = sym.is_undefined() ?
        PointerType::get(FunctionType::get(Type::getVoidTy(C), false), 0) :
        M.getFunction(sym.name)->getType();

    type_for_relocation(reloc, ty);
  };

  auto process_data_relocation_type = [&](const relocation_t &reloc) -> void {
    symbol_t& sym = symtbl[reloc.symidx];
    Type *ty = PointerType::get(
        sym.size ? IntegerType::get(C, 8 * sym.size) : word_type(), 0);

    type_for_relocation(reloc, ty);
  };

  auto process_relative_relocation_type =
      [&](const relocation_t &reloc) -> void {
    type_for_relocation(reloc, PointerType::get(word_type(), 0));
  };

  static const char *reloc_ty_str[] = {"NONE", "RELATIVE", "ABSOLUTE",
                                       "COPY", "FUNCTION", "DATA"};

  for (const relocation_t &reloc : reloctbl) {
    cout << (boost::format("(%s) %x %s") % reloc_ty_str[reloc.ty] % reloc.addr %
             (addrspace.find(reloc.addr) == addrspace.end() ? "~" : "-"));
    if (reloc.symidx < symtbl.size()) {
      symbol_t &sym = symtbl[reloc.symidx];
      cout << (boost::format(" : %s [%s]") % sym.name %
               (sym.is_defined()
                    ? (boost::format("DEFINED @ %x {%d}") % sym.addr % sym.size)
                          .str()
                    : "UNDEFINED"));
    }
    cout << endl;
  }

  for_each_if(reloctbl.begin(), reloctbl.end(),
              [&](const relocation_t &reloc) -> bool {
                return reloc.ty == relocation_t::FUNCTION &&
                       addrspace.find(reloc.addr) != addrspace.end();
              },
              process_function_relocation_type);
  for_each_if(reloctbl.begin(), reloctbl.end(),
              [&](const relocation_t &reloc) -> bool {
                return reloc.ty == relocation_t::DATA &&
                       addrspace.find(reloc.addr) != addrspace.end();
              },
              process_data_relocation_type);
  for_each_if(reloctbl.begin(), reloctbl.end(),
              [&](const relocation_t &reloc) -> bool {
                return reloc.ty == relocation_t::RELATIVE &&
                       addrspace.find(reloc.addr) != addrspace.end();
              },
              process_relative_relocation_type);

  //
  // create section global variables
  //
  for (unsigned i = 0; i < secttbl.size(); ++i) {
    section_t &sect = secttbl[i];

    section_interval_map_t &sectstuff = sectstuffs[i];

    vector<Type *> structfieldtys;

    for (auto it = sectstuff.begin(); it != sectstuff.end(); ++it) {
      const section_interval_t &intvl = *it;
      auto relocit = sectreloctys[i].find(intvl.lower());
      Type *ty = relocit != sectreloctys[i].end()
                     ? (*relocit).second
                     : ArrayType::get(IntegerType::get(C, 8),
                                      intvl.upper() - intvl.lower());

      structfieldtys.push_back(ty);
    }

    string sectnm_ = sect.name;
    boost::replace_all(sectnm_, ".", "_");

    sectgvtys[i] =
        StructType::create(C, structfieldtys, "struct.__jove_" + sectnm_, true);
    GlobalVariable *sectgv =
        new GlobalVariable(M, sectgvtys[i], true, GlobalValue::ExternalLinkage,
                           nullptr, "__jove_" + sectnm_);
    sectgv->setAlignment(sect.align);

    sectgvs.push_back(sectgv);
    sectgvmap.insert({sectgv, i});
  }

  //
  // initialize section global variables
  //
  auto constant_for_relocation = [&](const relocation_t &reloc,
                                     Constant *Cnst) -> void {
    assert(Cnst);

    unsigned sectidx = (*addrspace.find(reloc.addr)).second - 1;
    unsigned off = reloc.addr - secttbl[sectidx].addr;
    sectrelocs[sectidx][off] = Cnst;
  };

  auto process_function_relocation = [&](const relocation_t &reloc) -> void {
    symbol_t &sym = symtbl[reloc.symidx];

    Constant *Cnst;
    if (sym.is_undefined()) {
      GlobalVariable *g = M.getGlobalVariable(sym.name);
      Cnst =
          g ? g : M.getOrInsertFunction(
                      sym.name, FunctionType::get(Type::getVoidTy(C), false));
    } else {
      Cnst =
          M.getOrInsertFunction((boost::format("%s_thunk") % sym.name).str(),
                                FunctionType::get(Type::getVoidTy(C), false));
    }

    constant_for_relocation(reloc, Cnst);
  };

  auto process_data_relocation = [&](const relocation_t &reloc) -> void {
    symbol_t &sym = symtbl[reloc.symidx];

    Constant *Cnst;
    if (sym.is_undefined()) {
      Function *f = M.getFunction(sym.name);
      Cnst = f ? f : M.getOrInsertGlobal(sym.name, word_type());
    } else {
      Function *f = M.getFunction(sym.name);
      if (f) {
        Cnst = f;
      } else {
        GlobalVariable *g = M.getGlobalVariable(sym.name);
        if (g) {
          Cnst = g;
        } else {
          unsigned sectidx = (*addrspace.find(sym.addr)).second - 1;
          section_t &sect = secttbl[sectidx];
          unsigned off = sym.addr - sect.addr;

          uint64_t cnstvl;
          switch (sym.size) {
          case 1:
            cnstvl = sect.contents.begin()[off];
            break;
          case 2:
            cnstvl = *reinterpret_cast<const uint16_t *>(
                &sect.contents.begin()[off]);
            break;
          case 4:
            cnstvl = *reinterpret_cast<const uint32_t *>(
                &sect.contents.begin()[off]);
            break;
          case 8:
            cnstvl = *reinterpret_cast<const uint64_t *>(
                &sect.contents.begin()[off]);
            break;
          default:
            cerr << "warning: defined symbol with unknown size " << dec
                 << sym.size << endl;
            return;
          }

          Type *ty = IntegerType::get(C, sym.size ? 8 * sym.size
                                                  : 8 * sizeof(address_t));
          Cnst =
              new GlobalVariable(M, ty, false, GlobalVariable::ExternalLinkage,
                                 ConstantInt::get(ty, cnstvl), sym.name);
        }
      }
    }

    constant_for_relocation(reloc, Cnst);
  };

  auto process_relative_relocation = [&](const relocation_t &reloc) -> void {
    constant_for_relocation(reloc, section_ptr(reloc.addend));
  };

  for_each_if(reloctbl.begin(), reloctbl.end(),
              [&](const relocation_t &reloc) -> bool {
                return reloc.ty == relocation_t::FUNCTION &&
                       addrspace.find(reloc.addr) != addrspace.end();
              },
              process_function_relocation);
  for_each_if(reloctbl.begin(), reloctbl.end(),
              [&](const relocation_t &reloc) -> bool {
                return reloc.ty == relocation_t::DATA &&
                       addrspace.find(reloc.addr) != addrspace.end();
              },
              process_data_relocation);
  for_each_if(reloctbl.begin(), reloctbl.end(),
              [&](const relocation_t &reloc) -> bool {
                return reloc.ty == relocation_t::RELATIVE &&
                       addrspace.find(reloc.addr) != addrspace.end();
              },
              process_relative_relocation);

  //
  // create initializers
  //
  for (unsigned i = 0; i < secttbl.size(); ++i) {
    vector<llvm::Constant *> structfieldconsts;
    StructType *sectgvty = sectgvtys[i];

    section_interval_map_t &sectstuff = sectstuffs[i];
    StructType::element_iterator sectgvty_elem_it = sectgvty->element_begin();
    for (auto it = sectstuff.begin(); it != sectstuff.end(); ++it) {
      const section_interval_t &intvl = *it;
      Type* sectgvty_elem = *sectgvty_elem_it++;

      Constant *cnst = nullptr;

      auto relocit = sectrelocs[i].find(intvl.lower());
      if (relocit != sectrelocs[i].end()) { // a relocation
        cnst = ConstantExpr::getPointerCast((*relocit).second, sectgvty_elem);
      } else { // section data
        section_t &sect = secttbl[i];
        cnst = ConstantDataArray::get(
            C, ArrayRef<uint8_t>(sect.contents.begin() + (*it).lower(),
                                 sect.contents.begin() + (*it).upper()));
      }

      structfieldconsts.push_back(cnst);
    }

    sectgvs[i]->setInitializer(
        ConstantStruct::get(sectgvtys[i], structfieldconsts));
  }
}

void translator::prepare_for_translation() {
  //
  // create the thread-local CPUState
  //
  GlobalVariable *rthlp_cpu_state = HelperM.getNamedGlobal("cpu_state");
  assert(rthlp_cpu_state);

  Type *cpu_state_ty =
      cast<PointerType>(rthlp_cpu_state->getType())->getElementType();
  cpu_state_glb_llv = new GlobalVariable(
      M, cpu_state_ty, false, GlobalValue::InternalLinkage,
      ConstantAggregateZero::get(cpu_state_ty), rthlp_cpu_state->getName(),
      nullptr, GlobalValue::GeneralDynamicTLSModel);

  //
  // parse the binary
  //
  parse_binary(O, secttbl, symtbl, reloctbl);

  //
  // binary section data
  //
  create_section_global_variables();
}

llvm::Function *translator::function_of_addr(address_t addr) {
  auto it = function_table.find(addr);
  if (it == function_table.end())
    return nullptr;

  function_t& f = *(*it).second;
  return f[boost::graph_bundle].llf;
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

    if (translate_function(addr))
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

    vector<unsigned> params, returned, outputs;

    explode_tcg_global_set(params, f[boost::graph_bundle].params);
    explode_tcg_global_set(returned, f[boost::graph_bundle].returned);
    explode_tcg_global_set(outputs, f[boost::graph_bundle].outputs);

    cout << '<';
    for (auto g : params)
      cout << ' ' << tcg_globals[g].nm;
    cout << endl;

    cout << '>';
    for (auto g : returned)
      cout << ' ' << tcg_globals[g].nm;
    cout << endl;

    cout << '=';
    for (auto g : outputs)
      cout << ' ' << tcg_globals[g].nm;
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
  // in preparation for LLVM translation, create LLVM prototypes for each
  // function
  //
  for (address_t addr : functions_translated) {
    function_t &f = *function_table[addr];

    //
    // build function type
    //
    auto types_of_tcg_global_set = [&](vector<Type *>& tys,
                                       tcg::global_set_t glbs) -> void {
      if (glbs.none())
        return;

      vector<unsigned> glbv;
      explode_tcg_global_set(glbv, glbs);

      tys.resize(glbv.size());
      transform(glbv.begin(), glbv.end(), tys.begin(), [&](unsigned gidx) {
        return IntegerType::get(
            C, tcg_globals[gidx].ty == tcg::GLOBAL_I32 ? 32 : 64);
      });
    };

    vector<Type *> param_tys;
    vector<Type *> return_tys;

    types_of_tcg_global_set(param_tys, f[boost::graph_bundle].params);
    types_of_tcg_global_set(return_tys, f[boost::graph_bundle].returned);

    FunctionType *ty = FunctionType::get(
        return_tys.empty() ? Type::getVoidTy(C)
                           : StructType::get(C, ArrayRef<Type *>(return_tys)),
        ArrayRef<Type *>(param_tys), false);

    //
    // create function
    //
    f[boost::graph_bundle].llf = Function::Create(
        ty, GlobalValue::ExternalLinkage,
        (boost::format("%x") % f[boost::graph_bundle].entry_point).str(), &M);
    f[boost::graph_bundle].llf->setAttributes(FnAttr);
  }

  //
  // translate TCG -> LLVM for each function
  //
  for (address_t addr : functions_translated) {
    function_t &f = *function_table[addr];
    translate_function_llvm(f);
  }

  return make_tuple(nullptr, nullptr);
}

bool translator::translate_function(address_t addr) {
  //
  // check to see if function was already translated
  //
  {
    auto f_it = function_table.find(addr);
    if (f_it != function_table.end())
      return false;
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
    sectdata = secttbl[(*sectit).second - 1].contents;
  }
  libqemutcg_set_code(sectdata.data(), sectdata.size(), sectstart);

  //
  // conduct a recursive descent of the function, and translate each basic block
  // into QEMU TCG intermediate code
  //
  if (translate_basic_block(f, addr) ==
      boost::graph_traits<function_t>::null_vertex())
    return false;

  //
  // determine parameters for function
  //
  compute_params(f);

  return true;
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
  if (addr > sectstart + sectdata.size())
    return boost::graph_traits<function_t>::null_vertex();

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

  address_t next_addr = last_instr_addr + size;

  //
  // prepare data structures for new basic block
  //
  basic_block_t bb = boost::add_vertex(f);
  basic_block_properties_t& bbprop = f[bb];
  bbprop.addr = addr;
  translated_basic_blocks[addr] = bb;
  parentMap.resize(boost::num_vertices(f));
  verticesByDFNum.push_back(bb);

  //
  // copy TCG translation data structures to basic block properties
  //
  bbprop.first_tcg_op_idx = libqemutcg_first_op_index();
  bbprop.num_tmps = libqemutcg_num_tmps();
  bbprop.lbls.reserve(2*libqemutcg_num_labels());
  bbprop.lbls.resize(libqemutcg_num_labels());
  bbprop.tcg_ops.reset(new tcg::Op[libqemutcg_max_ops()]);
  bbprop.tcg_args.reset(new tcg::Arg[libqemutcg_max_params()]);
  bbprop.tcg_tmps.reset(new tcg::Tmp[libqemutcg_num_tmps()]);
  libqemutcg_copy_ops(bbprop.tcg_ops.get());
  libqemutcg_copy_params(bbprop.tcg_args.get());
  libqemutcg_copy_tmps(bbprop.tcg_tmps.get());
  prepare_tcg_ops(bbprop);

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

  const MCRegisterInfo &MRI = *libmc_reginfo();
  const MCInstrDesc &Desc = libmc_instrinfo()->get(Inst.getOpcode());

  if (MIA->isReturn(Inst)) {
    bbprop.term = basic_block_properties_t::TERM_RETURN;
  } else if (MIA->isConditionalBranch(Inst)) {
    bbprop.term = basic_block_properties_t::TERM_CONDITIONAL_JUMP;

    uint64_t target;
#if defined(TARGET_X86_64)
    assert(MIA->evaluateBranch(Inst, last_instr_addr, size, target));
#elif defined(TARGET_AARCH64)
    aarch64_evaluateConditionalBranch(target);
#endif

    control_flow_to(target);
    control_flow_to(succ_addr);
  } else if (MIA->isUnconditionalBranch(Inst)) {
    bbprop.term = basic_block_properties_t::TERM_UNCONDITIONAL_JUMP;

    uint64_t target;
#if defined(TARGET_X86_64)
    assert(MIA->evaluateBranch(Inst, last_instr_addr, size, target));
#elif defined(TARGET_AARCH64)
    aarch64_evaluateUnconditionalBranch(target);
#endif

    control_flow_to(target);
  } else if (MIA->isIndirectBranch(Inst)) {
    bbprop.term = basic_block_properties_t::TERM_INDIRECT_JUMP;
    // XXX is indirect jump to a PLT entry?
  } else if (MIA->isCall(Inst)) {
    bool is_indirect;
    uint64_t target;
#if defined(TARGET_X86_64)
    is_indirect = !MIA->evaluateBranch(Inst, last_instr_addr, size, target);
#elif defined(TARGET_AARCH64)
    is_indirect = !aarch64_evaluateCall(target);
#endif

    bbprop.term = is_indirect ? basic_block_properties_t::TERM_INDIRECT_CALL
                              : basic_block_properties_t::TERM_CALL;

    if (!is_indirect) {
      functions_to_translate.push(target);
      callers[target].push_back({&f, bb});
      bbprop.callee = target;
    }

    control_flow_to(succ_addr);
  } else {
    MCInst second_to_lst_inst;
    address_t second_to_lst_addr = libqemutcg_second_to_last_tcg_op_addr();
    MCInst succ_inst;
    if ((libmc_analyze_instr(succ_inst, size,
                             sectdata.data() + (next_addr - sectstart),
                             next_addr) &&
         MIA->isReturn(succ_inst)) ||
        (second_to_lst_addr &&
         libmc_analyze_instr(second_to_lst_inst, size,
                             sectdata.data() + (second_to_lst_addr - sectstart),
                             second_to_lst_addr) &&
         MIA->isReturn(second_to_lst_inst))) {
      bbprop.term = basic_block_properties_t::TERM_RETURN;
    } else {
      /* unknown control flow */
      char asmbuf[0x100];
      cerr << "warning: mysterious basic block terminator " << endl
           << "0x" << hex << last_instr_addr << "    "
           << libmc_instr_asm(sectdata.data() + (last_instr_addr - sectstart),
                              last_instr_addr, asmbuf)
           << endl;

      bbprop.term = basic_block_properties_t::TERM_UNKNOWN;
      control_flow_to(succ_addr);
    }
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
    case tcg::INDEX_op_call: {
      nb_iargs = op->calli;
      nb_oargs = op->callo;

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
    } break;
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

void translator::prepare_tcg_ops(basic_block_properties_t &bbprop) {
  const tcg::Op *ops = bbprop.tcg_ops.get();
  tcg::Arg *params = bbprop.tcg_args.get();
  const tcg::Op *op;
  for (int oi = bbprop.first_tcg_op_idx; oi >= 0; oi = op->next) {
    int i, k, nb_oargs, nb_iargs, nb_cargs;

    op = &ops[oi];
    const tcg::Opcode c = op->opc;
    const tcg::OpDef *def = &tcg::tcg_op_defs[c];
    tcg::Arg *args = &params[op->args];

    if (c == tcg::INDEX_op_insn_start) {
    } else if (c == tcg::INDEX_op_call) {
      /* variable number of arguments */
      nb_oargs = op->callo;
      nb_iargs = op->calli;
      nb_cargs = def->nb_cargs;
    } else {
      nb_oargs = def->nb_oargs;
      nb_iargs = def->nb_iargs;
      nb_cargs = def->nb_cargs;

      k = 0;
      k += nb_oargs;
      k += nb_iargs;
      switch (c) {
      case tcg::INDEX_op_brcond_i32:
      case tcg::INDEX_op_setcond_i32:
      case tcg::INDEX_op_movcond_i32:
      case tcg::INDEX_op_brcond2_i32:
      case tcg::INDEX_op_setcond2_i32:
      case tcg::INDEX_op_brcond_i64:
      case tcg::INDEX_op_setcond_i64:
      case tcg::INDEX_op_movcond_i64:
        ++k;
        i = 1;
        break;
      case tcg::INDEX_op_qemu_ld_i32:
      case tcg::INDEX_op_qemu_st_i32:
      case tcg::INDEX_op_qemu_ld_i64:
      case tcg::INDEX_op_qemu_st_i64:
        i = 1;
        break;
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
        args[k] = tcg::arg_label(args[k])->id;
        i++, k++;
        break;
      default:
        break;
      }
      k += nb_cargs;
    }
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
          out << (boost::format("%s$L%d") % (k ? "," : "") % ((int)args[k]));
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
  struct normal_edges {
    translator::function_t *f;

    normal_edges() {}
    normal_edges(translator::function_t *f) : f(f) {}

    bool operator()(const control_flow_t &e) const {
      translator::function_t &_f = *f;
      return !_f[e].dom;
    }
  };

  normal_edges e_filter(&f);
  boost::filtered_graph<function_t, normal_edges> graph(f, e_filter);

  ofstream of(
      (boost::format("%lx.dot") % f[boost::graph_bundle].entry_point).str());
  boost::write_graphviz(of, graph, graphviz_label_writer<function_t>(*this, f),
                        graphviz_edge_prop_writer(), graphviz_prop_writer());
}

void translator::explode_tcg_global_set(vector<unsigned> &out,
                                        tcg::global_set_t glbs) {
  if (glbs.none())
    return;

#if 0
  cout << "explode_tcg_global_set: " << glbs << endl;
#endif

  out.reserve(tcg::num_globals);

  unsigned long long x = glbs.to_ullong();
  int idx = 0;
  do {
    int pos = ffsll(x);
    x >>= pos;
    idx += pos;
#if 0
    cout << "explode_tcg_global_set " << dec << idx-1 << endl;
#endif
    out.push_back(idx-1);
  } while (x);
}

void translator::explode_tcg_temp_set(vector<unsigned> &out,
                                      tcg::temp_set_t tmps) {
  if (tmps.none())
    return;

  out.reserve(tcg::num_globals*2);

  unsigned long long x = tmps.to_ullong();
  int idx = 0;
  do {
    int pos = ffsll(x);
    x >>= pos;
    idx += pos;
    out.push_back(idx - 1 + tcg::num_globals);
  } while (x);
}

Type *translator::word_type() {
  return word_ty;
}

Value* translator::cpu_state_global_gep(unsigned gidx) {
  SmallVector<Value *, 4> Indices;
  getNaturalGEPWithOffset(tcg_glb_llv_m[tcg::CPU_STATE_ARG], 
      APInt(64, tcg_globals[gidx].cpustoff),
      IntegerType::get(C, tcg_globals[gidx].ty == tcg::GLOBAL_I32 ? 32 : 64),
      Indices);
  assert(!Indices.empty() && Indices.size() != 1);

  Value *ptr = b.CreateInBoundsGEP(
      nullptr, tcg_glb_llv_m[tcg::CPU_STATE_ARG], Indices,
      (boost::format("%s_ptr") % tcg_globals[gidx].nm).str());
  return ptr;
}

Value *translator::load_global_from_cpu_state(unsigned gidx) {
  return b.CreateLoad(
      cpu_state_global_gep(gidx),
      (boost::format("%s_loaded") % tcg_globals[gidx].nm).str());
}

void translator::store_global_to_cpu_state(Value* gvl, unsigned gidx) {
  b.CreateStore(gvl, cpu_state_global_gep(gidx));
}

void translator::translate_function_llvm(function_t& f) {
  Function *const llf = f[boost::graph_bundle].llf;
  boost::graph_traits<function_t>::vertex_iterator vi, vi_end;

  //
  // the first step in translating TCG to LLVM is creating an LLVM basic block
  // for each TCG basic block
  //
  for (tie(vi, vi_end) = boost::vertices(f); vi != vi_end; ++vi) {
    f[*vi].llbb =
        BasicBlock::Create(C, (boost::format("%x") % f[*vi].addr).str(), llf);
    f[*vi].exitllbb =
        BasicBlock::Create(C, (boost::format("E%x") % f[*vi].addr).str(), llf);

    for (unsigned i = 0; i < f[*vi].lbls.size(); ++i)
      f[*vi].lbls[i] =
          BasicBlock::Create(C, (boost::format("L%u") % i).str(), llf);
  }

  //
  // next we computing the set of TCG globals that are used so that we may
  // create alloca's for each of them at the head of the function
  //
#ifndef NJOVEDBG
  tie(vi, vi_end) = boost::vertices(f);
  unsigned max_num_temps =
      accumulate(vi, vi_end, 0u, [&](unsigned res, basic_block_t bb) {
        return max(res, f[bb].num_tmps);
      });

  if (tcg::longest_word_bits < max_num_temps - tcg::num_globals) {
    cerr << "can't do fast method for computing set of TCG temps used" << endl;
    exit(1);
  }
#endif

  tie(vi, vi_end) = boost::vertices(f);
  tcg::global_set_t glb_used_s = f[boost::graph_bundle].used = accumulate(
      vi, vi_end, tcg::global_set_t(),
      [&](tcg::global_set_t res, basic_block_t bb) -> tcg::global_set_t {
        return res | compute_tcg_globals_used(f[bb]);
      });

  vector<unsigned> glb_used_v;
  explode_tcg_global_set(glb_used_v, glb_used_s);
 
#if 0
  for (unsigned glbused : glb_used_v)
    cout << "glbused: " << dec << glbused << endl;
#endif

  basic_block_t entry = *boost::vertices(f).first;
  b.SetInsertPoint(f[entry].llbb);

  //
  // create the Alloca's for globals
  //
  for (auto gidx : glb_used_v)
    tcg_glb_llv_m[gidx] = b.CreateAlloca(
        IntegerType::get(C, tcg_globals[gidx].ty == tcg::GLOBAL_I32 ? 32 : 64),
        nullptr, (boost::format("%s_ptr") % tcg_globals[gidx].nm).str());

  //
  // add the CPUState extern global as the LLVM value for env
  //
  tcg_glb_llv_m[tcg::CPU_STATE_ARG] = cpu_state_glb_llv;

  //
  // initialize tcg global parameter Alloca's
  //
  vector<unsigned> glb_params_v;
  explode_tcg_global_set(glb_params_v, f[boost::graph_bundle].params);

  for_each(boost::make_zip_iterator(
               boost::make_tuple(glb_params_v.begin(), llf->arg_begin())),
           boost::make_zip_iterator(
               boost::make_tuple(glb_params_v.end(), llf->arg_end())),
           [&](const boost::tuple<unsigned, Argument &> &t) {
             t.get<1>().setName(tcg_globals[t.get<0>()].nm);
             b.CreateStore(&t.get<1>(), tcg_glb_llv_m[t.get<0>()]);
           });

  //
  // translate each basic block to LLVM, in roughly topological order
  //
  tie(vi, vi_end) = boost::vertices(f);
  for (;;) {
#if 0
    cout << hex << f[*vi].addr << ": f[*vi].lbls.size() = " << dec
         << f[*vi].lbls.size() << endl;
#endif

    translate_tcg_to_llvm(f, *vi);
    ++vi;

    if (vi == vi_end)
      break;

    b.SetInsertPoint(f[*vi].llbb);
  }

#if 0
  f[boost::graph_bundle].llf->dump();
#endif
  if (verifyFunction(*f[boost::graph_bundle].llf, &errs())) {
    errs().flush();
    abort();
  }
}

tcg::global_set_t
translator::compute_tcg_globals_used(basic_block_properties_t &bbprop) {
  tcg::global_set_t res;

  auto arg = [&](tcg::Arg a) -> void {
    if (tcg::is_arg_global(a))
      res.set(a);
  };

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

    switch (c) {
    case tcg::INDEX_op_discard:
      arg(args[0]);
      continue;
    case tcg::INDEX_op_call: {
      nb_iargs = op->calli;
      nb_oargs = op->callo;

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
      res |= h->inglb;
      res |= h->outglb;
    } break;
    default:
      nb_iargs = def->nb_iargs;
      nb_oargs = def->nb_oargs;
      break;
    }

    for (int i = 0; i < nb_iargs; i++)
      arg(args[nb_oargs + i]);

    for (int i = 0; i < nb_oargs; i++)
      arg(args[i]);
  }

  return res;
}

tcg::temp_set_t
translator::compute_tcg_temps_used(basic_block_properties_t &bbprop) {
  tcg::temp_set_t res;

  auto arg = [&](tcg::Arg a) -> void {
    if (tcg::is_arg_temp(a))
      res.set(a - tcg::num_globals);
  };

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

    switch (c) {
    case tcg::INDEX_op_discard:
      arg(args[0]);
      continue;
    case tcg::INDEX_op_call:
      nb_iargs = op->calli;
      nb_oargs = op->callo;
      break;
    default:
      nb_iargs = def->nb_iargs;
      nb_oargs = def->nb_oargs;
      break;
    }

    for (int i = 0; i < nb_iargs; i++)
      arg(args[nb_oargs + i]);

    for (int i = 0; i < nb_oargs; i++)
      arg(args[i]);
  }

  return res;
}

void translator::translate_tcg_to_llvm(function_t &f, basic_block_t bb) {
  basic_block_properties_t& bbprop = f[bb];
  //
  // initialize tcg tmp Alloca's
  //
  tcg::temp_set_t temps_used_s = compute_tcg_temps_used(bbprop);
  vector<unsigned> temps_used_v;
  explode_tcg_temp_set(temps_used_v, temps_used_s);
  for (auto tmp : temps_used_v) {
    tcg_tmp_llv_m[tmp] = b.CreateAlloca(
        IntegerType::get(C,
                         bbprop.tcg_tmps[tmp].type == tcg::TYPE_I32 ? 32 : 64),
        nullptr, (boost::format("tmp%u") % static_cast<unsigned>(tmp)).str());
  }

  //
  // create an alloca for the program counter if this basic block has a
  // conditional branch
  //
  if (bbprop.lbls.size())
    pc_llv = b.CreateAlloca(word_type(), nullptr, "pc_ptr");

  //
  // translate the TCG operations to LLVM instructions
  //
  const tcg::Op *ops = bbprop.tcg_ops.get();
  const tcg::Arg *params = bbprop.tcg_args.get();
  const tcg::Op *op;
  for (int oi = bbprop.first_tcg_op_idx; oi >= 0; oi = op->next) {
    op = &ops[oi];
    translate_tcg_operation_to_llvm(bbprop, op, &params[op->args]);
  }

  //
  // if there are any basic blocks without a terminator, create a branch from
  // them to the exit basic block
  //
  if (!bbprop.llbb->getTerminator()) {
    b.SetInsertPoint(bbprop.llbb);
    b.CreateBr(bbprop.exitllbb);
  }

  //
  // if the basic block has at least one successor, then we know its terminator
  // is a conditional or unconditional jump.
  //
  b.SetInsertPoint(bbprop.exitllbb);

  auto on_unconditional_jump = [&](basic_block_t dst) -> void {
    b.CreateBr(f[dst].llbb);
  };

  auto on_conditional_jump = [&](basic_block_t dst1,
                                 basic_block_t dst2) -> void {
    Value *pc = b.CreateLoad(pc_llv);
    Value *addr1 = section_int_ptr(f[dst1].addr);
    b.CreateCondBr(b.CreateICmpEQ(pc, addr1), f[dst1].llbb, f[dst2].llbb);
  };

  auto on_call = [&](basic_block_t succ) -> void {
    //
    // for outputs which are not passed as arguments to function, store them to
    // the CPU state
    //

    function_t& callee = *function_table[bbprop.callee];
    vector<unsigned> glb_params_v;
    explode_tcg_global_set(glb_params_v, callee[boost::graph_bundle].params);

    vector<Value *> passed(glb_params_v.size());
    transform(glb_params_v.begin(), glb_params_v.end(), passed.begin(),
              [&](unsigned gidx) -> Value * {
                if (f[boost::graph_bundle].used.test(gidx))
                  return b.CreateLoad(tcg_glb_llv_m[gidx],
                                      tcg_globals[gidx].nm + string("_passed"));
                else
                  return load_global_from_cpu_state(gidx);
              });

    Value *res = b.CreateCall(callee[boost::graph_bundle].llf,
                              ArrayRef<Value *>(passed));

    //
    // store the return values from the call to this functions' local copies of
    // globals-- or, if this function doesn't work with any of those globals--
    // store them to the CPU state.
    //
    vector<unsigned> ret_v;
    explode_tcg_global_set(ret_v, callee[boost::graph_bundle].returned);

    for (unsigned i = 0; i < ret_v.size(); ++i) {
      unsigned gidx = ret_v[i];
      Value* gvl = b.CreateExtractValue(res, ArrayRef<unsigned>(i));
      gvl->setName(tcg_globals[gidx].nm + string("_returned"));
      if (f[boost::graph_bundle].used.test(gidx))
        b.CreateStore(gvl, tcg_glb_llv_m[gidx]);
      else
        store_global_to_cpu_state(gvl, gidx);
    }

    b.CreateBr(f[succ].llbb);
  };

  auto on_indirect_call = [&](basic_block_t succ) -> void {
    b.CreateCall(IndirectCallFn, ArrayRef<Value*>(pc_llv));
    b.CreateBr(f[succ].llbb);
  };

  auto on_return = [&](void) -> void {
    //
    // store to CPU state the outputs which are not returned
    //
    tcg::global_set_t tostore =
        f[boost::graph_bundle].outputs & ~f[boost::graph_bundle].returned;
    vector<unsigned> tostore_v;
    explode_tcg_global_set(tostore_v, tostore);
    for (unsigned gidx : tostore_v)
      store_global_to_cpu_state(b.CreateLoad(tcg_glb_llv_m[gidx]), gidx);

    //
    // examine returned outputs
    //
    FunctionType *llf_ty = f[boost::graph_bundle].llf->getFunctionType();
    Type *ret_ty = llf_ty->getReturnType();

    //
    // if return type is void, then nothing to do
    //
    if (ret_ty == Type::getVoidTy(C)) {
      b.CreateRetVoid();
      return;
    }

    //
    // must be returning a struct. pile the values together to make the return
    // value
    //
    assert(isa<StructType>(ret_ty));
    vector<unsigned> ret_v;
    explode_tcg_global_set(ret_v, f[boost::graph_bundle].returned);

    assert(ret_v.size() == cast<StructType>(ret_ty)->getNumElements());

    Value *res =
        accumulate(
            ret_v.begin(), ret_v.end(), pair<unsigned, Value *>(0u, nullptr),
            [&](pair<unsigned, Value *> respair, unsigned gidx) {
              unsigned idx = respair.first;
              Value *res = respair.second;
              return make_pair(idx + 1, b.CreateInsertValue(
                                            res ? res : UndefValue::get(ret_ty),
                                            b.CreateLoad(tcg_glb_llv_m[gidx]),
                                            ArrayRef<unsigned>(idx)));
            })
            .second;
    b.CreateRet(res);
  };

  auto on_indirect_jump = [&](void) -> void {
#if 0
    // check for relocation

#if 0
    pc_llv->dump();
    pc_llv->getType()->dump();
    if (isa<ConstantExpr>(pc_llv))
      cout << "PC_LLV IS CONSTEXPR" << endl;
    if (isa<ConstantInt>(pc_llv))
      cout << "PC_LLV IS CONSTINT" << endl;
#endif

    if (isa<LoadInst>(pc_llv)) {
      Value *ptr = cast<LoadInst>(pc_llv)->getPointerOperand();

      int64_t off;
      Value *base = GetPointerBaseWithConstantOffset(ptr, off, DL);
      auto it = sectgvmap.find(base);
      if (it != sectgvmap.end()) {
        // XXX TODO
      }
    }
    Constant* pcconst = try_fold_to_constant();
#if 0
    if (pcconst) {
      cout << "FOLDED PC_LLV TO CONST" << endl;
      pcconst->dump();
    }
#endif
    if (pcconst && isa<Function>(pcconst)) {
      // this is a tail call to a relocated function
      b.CreateCall(cast<Function>(pcconst));
      on_return();
    } else {
#endif
      Value* passed_pc = b.CreateIntToPtr(pc_llv, ExternalFnPtrTy);
      b.CreateCall(IndirectJumpFn, ArrayRef<Value*>(passed_pc));
      // TODO imported functions
      on_return();
#if 0
    }
#endif
  };

  auto on_unknown = [&](basic_block_t succ) -> void {
    if (bbprop.lbls.size()) {
      cout << "unknown basic block terminator: multiple basic blocks!" << endl;
      // for unknown instructions we create a branch checking if the program
      // counter is either the current basic block's address (in which case we
      // branch back) or the successor's address (in which case we branch
      // there). when neither of those cases are true, we create an unreachable
      if (succ == boost::graph_traits<function_t>::null_vertex()) {
        BasicBlock *elsellbb =
            BasicBlock::Create(C, "unknown", f[boost::graph_bundle].llf);

        b.CreateCondBr(
            b.CreateICmpEQ(b.CreateLoad(pc_llv),
                           section_int_ptr(bbprop.addr)),
            bbprop.llbb, elsellbb);

        b.SetInsertPoint(elsellbb);
        b.CreateUnreachable();
        return;
      }

      BasicBlock *else1llbb =
          BasicBlock::Create(C, "unknown1", f[boost::graph_bundle].llf);
      BasicBlock *else2llbb =
          BasicBlock::Create(C, "unknown2", f[boost::graph_bundle].llf);

      Value *pc = b.CreateLoad(pc_llv);
      b.CreateCondBr(
          b.CreateICmpEQ(pc, section_int_ptr(f[succ].addr)),
          f[succ].llbb, else1llbb);

      b.SetInsertPoint(else1llbb);
      b.CreateCondBr(
          b.CreateICmpEQ(pc, section_int_ptr(bbprop.addr)),
          bbprop.llbb, else2llbb);

      b.SetInsertPoint(else2llbb);
      b.CreateUnreachable();
    } else {
      ConstantInt* pcint = try_fold_to_constant_int(pc_llv);
      cout << "unknown basic block terminator: ";
      if (pcint) {
        address_t pc = pcint->getZExtValue();
        cout << "folded to constant address: " << hex << pc << endl;
        if (pc == bbprop.addr) {
          b.CreateBr(bbprop.llbb);
          return;
        } else if (succ != boost::graph_traits<function_t>::null_vertex() &&
                 pc == f[succ].addr) {
          b.CreateBr(f[succ].llbb);
          return;
        }
      } else {
        cout << "could not fold to constant address" << endl;
      }

      b.CreateUnreachable();
    }
  };

  struct normal_edges {
    translator::function_t *f;

    normal_edges() {}
    normal_edges(translator::function_t *f) : f(f) {}

    bool operator()(const control_flow_t &e) const {
      translator::function_t &_f = *f;
      return !_f[e].dom;
    }
  };

  normal_edges e_filter(&f);
  typedef boost::filtered_graph<function_t, normal_edges> control_flow_graph_t;
  control_flow_graph_t cfg(f, e_filter);

  boost::graph_traits<control_flow_graph_t>::out_edge_iterator ei, ei_end;
  tie(ei, ei_end) = boost::out_edges(bb, cfg);
  switch (bbprop.term) {
  case basic_block_properties_t::TERM_UNCONDITIONAL_JUMP:
    on_unconditional_jump(boost::target(*ei++, cfg));
    break;
  case basic_block_properties_t::TERM_CONDITIONAL_JUMP: {
    basic_block_t dst1 = boost::target(*ei++, cfg);
    basic_block_t dst2 = boost::target(*ei++, cfg);
    on_conditional_jump(dst1, dst2);
  } break;
  case basic_block_properties_t::TERM_CALL:
    on_call(boost::target(*ei++, cfg));
    break;
  case basic_block_properties_t::TERM_INDIRECT_CALL:
    on_indirect_call(boost::target(*ei++, cfg));
    break;
  case basic_block_properties_t::TERM_INDIRECT_JUMP:
    on_indirect_jump();
    break;
  case basic_block_properties_t::TERM_RETURN:
    on_return();
    break;
  case basic_block_properties_t::TERM_UNKNOWN:
    on_unknown(ei == ei_end ? boost::graph_traits<function_t>::null_vertex()
                            : boost::target(*ei++, cfg));
    break;
  }

  assert(bbprop.exitllbb->getTerminator());
  assert(ei == ei_end);
}

void translator::translate_tcg_operation_to_llvm(
    basic_block_properties_t &bbprop, const tcg::Op *op, const tcg::Arg *args) {
  const tcg::Opcode opc = op->opc;
  const tcg::OpDef &def = tcg::tcg_op_defs[opc];

  auto name = [&](tcg::Arg a) -> string {
    if (a == tcg::CALL_DUMMY_ARG)
      return "dummy";

    if (a == tcg::CPU_STATE_ARG)
      return "env";

    if (a < tcg::num_globals)
      return tcg_globals[a].nm;
    else
      return (boost::format("tmp%u") % static_cast<unsigned>(a)).str();
  };

  auto set = [&](Value *v, tcg::Arg a) -> void {
    assert(a != tcg::CALL_DUMMY_ARG && a != tcg::CPU_STATE_ARG);

    if (a < tcg::num_globals) {
      b.CreateStore(v, tcg_glb_llv_m[a]);
    } else {
      if (bbprop.tcg_tmps[a].temp_local)
        b.CreateStore(v, tcg_tmp_llv_m[a]);
      else
        tcg_tmp_llv_m[a] = v;
    }
  };

  auto get = [&](tcg::Arg a) -> Value * {
    assert(a != tcg::CALL_DUMMY_ARG);

    if (a == tcg::CPU_STATE_ARG)
      return b.CreatePtrToInt(tcg_glb_llv_m[tcg::CPU_STATE_ARG], word_type());

    Value* ptr = nullptr;

    if (a < tcg::num_globals) {
      ptr = tcg_glb_llv_m[a];
    } else {
      if (bbprop.tcg_tmps[a].temp_local)
        ptr = tcg_tmp_llv_m[a];
      else
        return tcg_tmp_llv_m[a];
    }

    return b.CreateLoad(ptr);
  };

  auto immediate_constant = [&](unsigned bits, tcg::Arg a) -> Value * {
    if (bits == sizeof(address_t) * 8) {
      Value *intptr = section_int_ptr(a);
      if (intptr) {
#if 1
        cout << "immediate_constant: arg is address " << hex << a << endl;
#endif
        return intptr;
      }
    }

    return ConstantInt::get(IntegerType::get(C, bits), a);
  };

  auto type = [&](tcg::Arg a) -> Type * {
    assert(a != tcg::CALL_DUMMY_ARG && a != tcg::CPU_STATE_ARG);
    return a < tcg::num_globals
               ? IntegerType::get(C, tcg_globals[a].ty == tcg::GLOBAL_I32 ? 32
                                                                          : 64)
               : IntegerType::get(
                     C, bbprop.tcg_tmps[a].type == tcg::TYPE_I32 ? 32 : 64);
  };

  auto adjust_type_size = [&](unsigned target, Value *v) -> Value* {
    if (target == 32 && v->getType() == IntegerType::get(C, 64))
        v = b.CreateTrunc(v, IntegerType::get(C, target));

    return v;
  };

  auto cpu_state_gep = [&](unsigned memBits, unsigned offset) -> Value * {
    SmallVector<Value *, 4> Indices;
    getNaturalGEPWithOffset(cpu_state_glb_llv,
                            APInt(64, offset), IntegerType::get(C, memBits),
                            Indices);
    assert(!Indices.empty() && Indices.size() != 1);

    Value *ptr = ConstantExpr::getInBoundsGetElementPtr(
        nullptr, cpu_state_glb_llv, Indices);

    ptr = b.CreatePointerCast(
        ptr, PointerType::get(IntegerType::get(C, memBits), 0));
    return ptr;
  };

  auto cpu_state_load = [&](unsigned memBits, unsigned offset) -> Value * {
#if defined(TARGET_I386)
    if (offset >= tcg::cpu_state_segs_offset &&
        offset < tcg::cpu_state_segs_offset + tcg::cpu_state_segs_size)
      return ConstantInt::get(IntegerType::get(C, memBits), 0);
#endif

    return b.CreateLoad(cpu_state_gep(memBits, offset));
  };

  auto guest_load_from_constant_address = [&](unsigned bits,
                                              address_t addr) -> Value * {
    auto it = addrspace.find(addr);
    if (it == addrspace.end())
      return nullptr;

#if 1
    cout << "guest_load_from_constant_address: addr = " << hex << addr << endl;
#endif

    unsigned sectidx = (*it).second - 1;
    unordered_map<unsigned, Constant *> &relocs = sectrelocs[sectidx];

    unsigned off = addr - (*it).first.lower();

    auto relit = relocs.find(off);
    if (relit != relocs.end())
      return b.CreatePtrToInt((*relit).second, IntegerType::get(C, bits));

    SmallVector<Value *, 4> Indices;
    getNaturalGEPWithOffset(sectgvs[sectidx], APInt(64, off),
                            IntegerType::get(C, bits), Indices);
    assert(!Indices.empty() && Indices.size() != 1);
    Value *ptr = b.CreateInBoundsGEP(tcg_glb_llv_m[tcg::CPU_STATE_ARG], Indices,
                                     (boost::format("%x") % addr).str());
    ptr = b.CreatePointerCast(ptr,
                              PointerType::get(IntegerType::get(C, bits), 0));

    return b.CreateLoad(ptr);
  };

  auto guest_load = [&](unsigned bits) -> Value * {
    Value *addr = get(args[1]);

    ConstantInt *addr_int = try_fold_to_constant_int(addr);

    if (addr_int) {
      Value *v =
          guest_load_from_constant_address(bits, addr_int->getZExtValue());
      if (v)
        return v;
    }

    addr = b.CreateZExt(addr, word_type());
    addr =
        b.CreateIntToPtr(addr, PointerType::get(IntegerType::get(C, bits), 0));
    return b.CreateLoad(addr);
  };

  auto set_program_counter = [&](Value* v) -> void {
    if (!bbprop.lbls.size())
      pc_llv = v;
    else
      b.CreateStore(v, pc_llv);
  };

  switch (opc) {
  case tcg::INDEX_op_insn_start:
    break;

  case tcg::INDEX_op_discard:
    set(UndefValue::get(type(args[0])), args[0]);
    break;

  case tcg::INDEX_op_call: {
    //
    // take into account extra inputs and/or outputs by our version of the
    // helpers
    //
    unsigned nb_iargs = op->calli;
    unsigned nb_oargs = op->callo;

    auto h_addr = args[nb_oargs + nb_iargs];
    auto h_it = tcg_helper_addr_map.find(h_addr);
    if (h_it == tcg_helper_addr_map.end())
      exit(138);

    tcg::helper_t *h = (*h_it).second;

    Function *hlp_llf = cast<Function>(M.getOrInsertFunction(
        h->llf->getName(), h->llf->getFunctionType(), h->llf->getAttributes()));
    FunctionType *hlp_llf_ty = hlp_llf->getFunctionType();

    vector<Value *> passed;
    passed.reserve(nb_iargs + h->inglbv.size());

    if (hlp_llf_ty->getNumParams() != 0) {
      for (unsigned i = 0; i < nb_iargs; i++) {
        tcg::Arg arg = args[nb_oargs + i];

        if (arg == tcg::CALL_DUMMY_ARG ||
            arg == tcg::CPU_STATE_ARG) /* helper functions were transformed to
                                          not take CPU state */
          continue;

#if 0
        cout << "hlpfll arg: " << dec << arg << endl;
#endif
        passed.push_back(get(arg));
      }

      for (auto gidx : h->inglbv)
        passed.push_back(get(gidx));
    }

#if 0
    cout << "nb_iargs = " << dec << nb_iargs << endl;
    cout << "h->inglbv.size() = " << dec << h->inglbv.size() << endl;
    hlp_llf->dump();
#endif
    assert(passed.size() == hlp_llf_ty->getNumParams());
    for (unsigned i = 0; i < passed.size(); ++i) {
      Type *param_ty = hlp_llf_ty->getParamType(i);
      if (isa<PointerType>(param_ty))
        passed[i] = b.CreateIntToPtr(passed[i], param_ty);
    }

    Value *res = b.CreateCall(hlp_llf, ArrayRef<Value *>(passed));
#if 0
    res->dump();
#endif

    if (h->outglbv.size()) {
#if 0
      cout << "h->outglbv.size() = " << h->outglbv.size() << endl;
      for (unsigned i = 0; i < h->outglbv.size(); ++i)
        cout << "outglb: " << tcg_globals[h->outglbv[i]].nm << endl;
#endif

      // return type is a struct
      assert(isa<StructType>(res->getType()));
      for (unsigned i = 0; i < nb_oargs; ++i) {
        unsigned idx = i;
        set(b.CreateExtractValue(res, ArrayRef<unsigned>(idx)), args[i]);
      }
      for (unsigned i = 0; i < h->outglbv.size(); ++i) {
        unsigned idx = nb_oargs + i;
        set(b.CreateExtractValue(res, ArrayRef<unsigned>(idx)), h->outglbv[i]);
      }
    } else if (nb_oargs) {
      // return type is a single?
      if (nb_oargs == 1) {
        set(res, args[0]);
      } else {
        for (unsigned i = 0; i < nb_oargs; ++i) {
          unsigned idx = i;
          set(b.CreateExtractValue(res, ArrayRef<unsigned>(idx)), args[i]);
        }
      }
    }
  } break;

  case tcg::INDEX_op_br:
    b.CreateBr(bbprop.lbls[args[0]]);
    break;

#define __OP_BRCOND_C(tcg_cond, cond)                                          \
  case tcg_cond:                                                               \
    v = b.CreateICmp##cond(get(args[0]), get(args[1]));                        \
    break;

#define __OP_BRCOND(opc_name, bits)                                            \
  case opc_name: {                                                             \
    Value *v;                                                                  \
    switch (args[2]) {                                                         \
      __OP_BRCOND_C(tcg::TCG_COND_EQ, EQ)                                      \
      __OP_BRCOND_C(tcg::TCG_COND_NE, NE)                                      \
      __OP_BRCOND_C(tcg::TCG_COND_LT, SLT)                                     \
      __OP_BRCOND_C(tcg::TCG_COND_GE, SGE)                                     \
      __OP_BRCOND_C(tcg::TCG_COND_LE, SLE)                                     \
      __OP_BRCOND_C(tcg::TCG_COND_GT, SGT)                                     \
      __OP_BRCOND_C(tcg::TCG_COND_LTU, ULT)                                    \
      __OP_BRCOND_C(tcg::TCG_COND_GEU, UGE)                                    \
      __OP_BRCOND_C(tcg::TCG_COND_LEU, ULE)                                    \
      __OP_BRCOND_C(tcg::TCG_COND_GTU, UGT)                                    \
    default:                                                                   \
      assert(false);                                                           \
    }                                                                          \
    BasicBlock *bb = BasicBlock::Create(                                       \
        C, (boost::format("l%u") % bbprop.lbls.size()).str(),                  \
        bbprop.llbb->getParent());                                             \
    bbprop.lbls.push_back(bb);                                                 \
    b.CreateCondBr(v, bbprop.lbls[args[3]], bb);                               \
    b.SetInsertPoint(bb);                                                      \
  } break;

    __OP_BRCOND(tcg::INDEX_op_brcond_i32, 32)
    __OP_BRCOND(tcg::INDEX_op_brcond_i64, 64)

#undef __OP_BRCOND_C
#undef __OP_BRCOND

  case tcg::INDEX_op_set_label:
    b.SetInsertPoint(bbprop.lbls[args[0]]);
    break;

  case tcg::INDEX_op_movi_i32:
    set(immediate_constant(32, args[1]), args[0]);
    break;

  case tcg::INDEX_op_mov_i32:
    // Move operation may perform truncation of the value
    set(b.CreateTrunc(get(args[1]), IntegerType::get(C, 32)), args[0]);
    break;

  case tcg::INDEX_op_movi_i64:
    set(immediate_constant(64, args[1]), args[0]);
    break;

  case tcg::INDEX_op_mov_i64:
    set(get(args[1]), args[0]);
    break;

/* size extensions */
#define __EXT_OP(opc_name, truncBits, opBits, signE)                           \
  case opc_name:                                                               \
    set(b.Create##signE##Ext(                                                  \
            b.CreateTrunc(get(args[1]), IntegerType::get(C, truncBits)),       \
            IntegerType::get(C, opBits)),                                      \
        args[0]);                                                              \
    break;

    __EXT_OP(tcg::INDEX_op_ext8s_i32, 8, 32, S)
    __EXT_OP(tcg::INDEX_op_ext8u_i32, 8, 32, Z)
    __EXT_OP(tcg::INDEX_op_ext16s_i32, 16, 32, S)
    __EXT_OP(tcg::INDEX_op_ext16u_i32, 16, 32, Z)

    __EXT_OP(tcg::INDEX_op_ext8s_i64, 8, 64, S)
    __EXT_OP(tcg::INDEX_op_ext8u_i64, 8, 64, Z)
    __EXT_OP(tcg::INDEX_op_ext16s_i64, 16, 64, S)
    __EXT_OP(tcg::INDEX_op_ext16u_i64, 16, 64, Z)
    __EXT_OP(tcg::INDEX_op_ext32s_i64, 32, 64, S)
    __EXT_OP(tcg::INDEX_op_ext32u_i64, 32, 64, Z)

#undef __EXT_OP

//
// load from host memory
//
#define __LD_OP(opc_name, memBits, regBits, signE)                             \
  case opc_name: {                                                             \
    Value *v;                                                                  \
    if (args[1] == tcg::CPU_STATE_ARG) {                                       \
      v = cpu_state_load(memBits, args[2]);                                    \
    } else {                                                                   \
      v = b.CreateAdd(get(args[1]), ConstantInt::get(word_type(), args[2]));   \
      v = b.CreateIntToPtr(v,                                                  \
                           PointerType::get(IntegerType::get(C, memBits), 0)); \
      v = b.CreateLoad(v);                                                     \
    }                                                                          \
    set(b.Create##signE##Ext(v, IntegerType::get(C, regBits)), args[0]);       \
  } break;

//
// store to host memory
// special case: when we see a st_i64/32 tmp, env, offset where offset points to
// to the program counter field, then we store it in our local variable
//
#define __ST_OP(opc_name, memBits, regBits)                                    \
  case opc_name: {                                                             \
    Value *valueToStore = get(args[0]);                                        \
    Value *addr;                                                               \
    if (args[1] == tcg::CPU_STATE_ARG) {                                       \
      if (args[2] == tcg::cpu_state_program_counter_offset)                    \
        return set_program_counter(valueToStore);                              \
      else                                                                     \
        addr = cpu_state_gep(memBits, args[2]);                                \
    } else {                                                                   \
      addr =                                                                   \
          b.CreateAdd(get(args[1]), ConstantInt::get(word_type(), args[2]));   \
      addr = b.CreateIntToPtr(                                                 \
          addr, PointerType::get(IntegerType::get(C, memBits), 0));            \
    }                                                                          \
    b.CreateStore(b.CreateTrunc(valueToStore, IntegerType::get(C, memBits)),   \
                  addr);                                                       \
  } break;

    __LD_OP(tcg::INDEX_op_ld8u_i32, 8, 32, Z)
    __LD_OP(tcg::INDEX_op_ld8s_i32, 8, 32, S)
    __LD_OP(tcg::INDEX_op_ld16u_i32, 16, 32, Z)
    __LD_OP(tcg::INDEX_op_ld16s_i32, 16, 32, S)
    __LD_OP(tcg::INDEX_op_ld_i32, 32, 32, Z)

    __ST_OP(tcg::INDEX_op_st8_i32, 8, 32)
    __ST_OP(tcg::INDEX_op_st16_i32, 16, 32)
    __ST_OP(tcg::INDEX_op_st_i32, 32, 32)

    __LD_OP(tcg::INDEX_op_ld8u_i64, 8, 64, Z)
    __LD_OP(tcg::INDEX_op_ld8s_i64, 8, 64, S)
    __LD_OP(tcg::INDEX_op_ld16u_i64, 16, 64, Z)
    __LD_OP(tcg::INDEX_op_ld16s_i64, 16, 64, S)
    __LD_OP(tcg::INDEX_op_ld32u_i64, 32, 64, Z)
    __LD_OP(tcg::INDEX_op_ld32s_i64, 32, 64, S)
    __LD_OP(tcg::INDEX_op_ld_i64, 64, 64, Z)

    __ST_OP(tcg::INDEX_op_st8_i64, 8, 64)
    __ST_OP(tcg::INDEX_op_st16_i64, 16, 64)
    __ST_OP(tcg::INDEX_op_st32_i64, 32, 64)
    __ST_OP(tcg::INDEX_op_st_i64, 64, 64)

#undef __LD_OP
#undef __ST_OP

#define __ARITH_OP(opc_name, op, bits)                                         \
  case opc_name: {                                                             \
    Value *v1 = adjust_type_size(bits, get(args[1]));                          \
    Value *v2 = adjust_type_size(bits, get(args[2]));                          \
    assert(v1->getType() == v2->getType());                                    \
    set(b.Create##op(v1, v2), args[0]);                                        \
  } break;

#define __ARITH_OP2(opc_name, op, bits)                                        \
  case opc_name: {                                                             \
    Value *t1_low = get(args[2]);                                              \
    Value *t1_high = get(args[3]);                                             \
    Value *t2_low = get(args[4]);                                              \
    Value *t2_high = get(args[5]);                                             \
                                                                               \
    assert(t1_low->getType() == IntegerType::get(C, bits));                    \
    assert(t1_high->getType() == IntegerType::get(C, bits));                   \
    assert(t2_low->getType() == IntegerType::get(C, bits));                    \
    assert(t2_high->getType() == IntegerType::get(C, bits));                   \
                                                                               \
    Value *t1 = b.CreateOr(                                                    \
        b.CreateShl(b.CreateZExt(t1_high, IntegerType::get(C, bits * 2)),      \
                    ConstantInt::get(IntegerType::get(C, bits * 2), bits)),    \
        b.CreateZExt(t1_low, IntegerType::get(C, bits * 2)));                  \
                                                                               \
    Value *t2 = b.CreateOr(                                                    \
        b.CreateShl(b.CreateZExt(t2_high, IntegerType::get(C, bits * 2)),      \
                    ConstantInt::get(IntegerType::get(C, bits * 2), bits)),    \
        b.CreateZExt(t2_low, IntegerType::get(C, bits * 2)));                  \
                                                                               \
    Value *t0 = b.Create##op(t1, t2);                                          \
                                                                               \
    Value *t0_low = b.CreateTrunc(t0, IntegerType::get(C, bits));              \
    Value *t0_high = b.CreateTrunc(                                            \
        b.CreateLShr(t0,                                                       \
                     ConstantInt::get(IntegerType::get(C, bits * 2), bits)),   \
        IntegerType::get(C, bits));                                            \
                                                                               \
    set(t0_low, args[0]);                                                      \
    set(t0_high, args[1]);                                                     \
  } break;

#define __ARITH_OP_MUL2(opc_name, signE, bits)                                 \
  case opc_name: {                                                             \
    Value *t1 = get(args[2]);                                                  \
    Value *t2 = get(args[3]);                                                  \
                                                                               \
    assert(t1->getType() == IntegerType::get(C, bits));                        \
    assert(t2->getType() == IntegerType::get(C, bits));                        \
                                                                               \
    Value *t0 =                                                                \
        b.CreateMul(b.Create##signE##Ext(t1, IntegerType::get(C, bits * 2)),   \
                    b.Create##signE##Ext(t2, IntegerType::get(C, bits * 2)));  \
                                                                               \
    Value *t0_low = b.CreateTrunc(t0, IntegerType::get(C, bits));              \
    Value *t0_high = b.CreateTrunc(                                            \
        b.CreateLShr(t0,                                                       \
                     ConstantInt::get(IntegerType::get(C, bits * 2), bits)),   \
        IntegerType::get(C, bits));                                            \
                                                                               \
    set(t0_low, args[0]);                                                      \
    set(t0_high, args[1]);                                                     \
  } break;

#define __ARITH_OP_DIV2(opc_name, signE, bits)                                 \
  case opc_name: {                                                             \
    Value *v2 = get(args[2]);                                                  \
    Value *v3 = get(args[3]);                                                  \
    Value *v4 = get(args[4]);                                                  \
                                                                               \
    assert(v2->getType() == IntegerType::get(C, bits));                        \
    assert(v3->getType() == IntegerType::get(C, bits));                        \
    assert(v4->getType() == IntegerType::get(C, bits));                        \
                                                                               \
    Value *v = b.CreateShl(                                                    \
        b.CreateZExt(v3, IntegerType::get(C, bits * 2)),                       \
        b.CreateZExt(ConstantInt::get(IntegerType::get(C, bits), bits),        \
                     IntegerType::get(C, bits * 2)));                          \
                                                                               \
    v = b.CreateOr(v, b.CreateZExt(v2, IntegerType::get(C, bits * 2)));        \
                                                                               \
    set(b.CreateTrunc(b.Create##signE##Div(                                    \
                          v, b.CreateZExt(v4, IntegerType::get(C, bits * 2))), \
                      IntegerType::get(C, bits)),                              \
        args[0]);                                                              \
                                                                               \
    set(b.CreateTrunc(b.Create##signE##Rem(                                    \
                          v, b.CreateZExt(v4, IntegerType::get(C, bits * 2))), \
                      IntegerType::get(C, bits)),                              \
        args[1]);                                                              \
                                                                               \
  } break;

#define __ARITH_OP_ROT(opc_name, op1, op2, bits)                               \
  case opc_name: {                                                             \
    Value *v1 = get(args[1]);                                                  \
    Value *v2 = get(args[2]);                                                  \
    assert(v1->getType() == IntegerType::get(C, bits));                        \
    assert(v2->getType() == IntegerType::get(C, bits));                        \
    Value *v =                                                                 \
        b.CreateSub(ConstantInt::get(IntegerType::get(C, bits), bits), v2);    \
    set(b.CreateOr(b.Create##op1(v1, v2), b.Create##op2(v1, v)), args[0]);     \
  } break;

#define __ARITH_OP_I(opc_name, op, i, bits)                                    \
  case opc_name: {                                                             \
    Value *v1 = get(args[1]);                                                  \
    assert(v1->getType() == IntegerType::get(C, bits));                        \
    set(b.Create##op(ConstantInt::get(IntegerType::get(C, bits), i), v1),      \
        args[0]);                                                              \
  } break;

#define __ARITH_OP_BSWAP(opc_name, sBits, bits)                                \
  case opc_name: {                                                             \
    Value *v1 = get(args[1]);                                                  \
    assert(v1->getType() == IntegerType::get(C, bits));                        \
    Type *Tys[] = {IntegerType::get(C, sBits)};                                \
    Function *bswap = Intrinsic::getDeclaration(                               \
        &M, Intrinsic::bswap, ArrayRef<llvm::Type *>(Tys, 1));                 \
    Value *v = b.CreateTrunc(v1, IntegerType::get(C, sBits));                  \
    set(b.CreateZExt(b.CreateCall(bswap, v), IntegerType::get(C, bits)),       \
        args[0]);                                                              \
  } break;

    __ARITH_OP(tcg::INDEX_op_add_i32, Add, 32)
    __ARITH_OP(tcg::INDEX_op_sub_i32, Sub, 32)
    __ARITH_OP(tcg::INDEX_op_mul_i32, Mul, 32)

    __ARITH_OP(tcg::INDEX_op_div_i32, SDiv, 32)
    __ARITH_OP(tcg::INDEX_op_divu_i32, UDiv, 32)
    __ARITH_OP(tcg::INDEX_op_rem_i32, SRem, 32)
    __ARITH_OP(tcg::INDEX_op_remu_i32, URem, 32)
    __ARITH_OP_DIV2(tcg::INDEX_op_div2_i32, S, 32)
    __ARITH_OP_DIV2(tcg::INDEX_op_divu2_i32, U, 32)

    __ARITH_OP(tcg::INDEX_op_and_i32, And, 32)
    __ARITH_OP(tcg::INDEX_op_or_i32, Or, 32)
    __ARITH_OP(tcg::INDEX_op_xor_i32, Xor, 32)

    __ARITH_OP(tcg::INDEX_op_shl_i32, Shl, 32)
    __ARITH_OP(tcg::INDEX_op_shr_i32, LShr, 32)
    __ARITH_OP(tcg::INDEX_op_sar_i32, AShr, 32)

    __ARITH_OP_ROT(tcg::INDEX_op_rotl_i32, Shl, LShr, 32)
    __ARITH_OP_ROT(tcg::INDEX_op_rotr_i32, LShr, Shl, 32)

    __ARITH_OP_I(tcg::INDEX_op_not_i32, Xor, (uint64_t)-1, 32)
    __ARITH_OP_I(tcg::INDEX_op_neg_i32, Sub, 0, 32)

    __ARITH_OP_BSWAP(tcg::INDEX_op_bswap16_i32, 16, 32)
    __ARITH_OP_BSWAP(tcg::INDEX_op_bswap32_i32, 32, 32)

    __ARITH_OP(tcg::INDEX_op_add_i64, Add, 64)
    __ARITH_OP(tcg::INDEX_op_sub_i64, Sub, 64)
    __ARITH_OP(tcg::INDEX_op_mul_i64, Mul, 64)

    __ARITH_OP(tcg::INDEX_op_div_i64, SDiv, 64)
    __ARITH_OP(tcg::INDEX_op_divu_i64, UDiv, 64)
    __ARITH_OP(tcg::INDEX_op_rem_i64, SRem, 64)
    __ARITH_OP(tcg::INDEX_op_remu_i64, URem, 64)
    __ARITH_OP_DIV2(tcg::INDEX_op_div2_i64, S, 64)
    __ARITH_OP_DIV2(tcg::INDEX_op_divu2_i64, U, 64)

    __ARITH_OP(tcg::INDEX_op_and_i64, And, 64)
    __ARITH_OP(tcg::INDEX_op_or_i64, Or, 64)
    __ARITH_OP(tcg::INDEX_op_xor_i64, Xor, 64)

    __ARITH_OP(tcg::INDEX_op_shl_i64, Shl, 64)
    __ARITH_OP(tcg::INDEX_op_shr_i64, LShr, 64)
    __ARITH_OP(tcg::INDEX_op_sar_i64, AShr, 64)

    __ARITH_OP_ROT(tcg::INDEX_op_rotl_i64, Shl, LShr, 64)
    __ARITH_OP_ROT(tcg::INDEX_op_rotr_i64, LShr, Shl, 64)

    __ARITH_OP_I(tcg::INDEX_op_not_i64, Xor, (uint64_t)-1, 64)
    __ARITH_OP_I(tcg::INDEX_op_neg_i64, Sub, 0, 64)

    __ARITH_OP_BSWAP(tcg::INDEX_op_bswap16_i64, 16, 64)
    __ARITH_OP_BSWAP(tcg::INDEX_op_bswap32_i64, 32, 64)
    __ARITH_OP_BSWAP(tcg::INDEX_op_bswap64_i64, 64, 64)

    __ARITH_OP2(tcg::INDEX_op_add2_i64, Add, 64)
    __ARITH_OP2(tcg::INDEX_op_sub2_i64, Sub, 64)

    __ARITH_OP_MUL2(tcg::INDEX_op_mulu2_i64, Z, 64)
    __ARITH_OP_MUL2(tcg::INDEX_op_muls2_i64, S, 64)

#undef __ARITH_OP_BSWAP
#undef __ARITH_OP_I
#undef __ARITH_OP_ROT
#undef __ARITH_OP_DIV2
#undef __ARITH_OP

//
// store to guest memory
//
#define __OP_QEMU_ST(opc_name, bits)                                           \
  case opc_name: {                                                             \
    Value *addr = get(args[1]);                                                \
    addr = b.CreateZExt(addr, word_type());                                    \
    addr = b.CreateIntToPtr(addr,                                              \
                            PointerType::get(IntegerType::get(C, bits), 0));   \
    Value *valueToStore =                                                      \
        b.CreateIntCast(get(args[0]), IntegerType::get(C, bits), false);       \
    b.CreateStore(valueToStore, addr);                                         \
  } break;

//
// load from guest memory
//
#define __OP_QEMU_LD(opc_name, bits)                                           \
  case opc_name:                                                               \
    set(guest_load(bits), args[0]);                                            \
    break;

    __OP_QEMU_ST(tcg::INDEX_op_qemu_st_i32, 32)
    __OP_QEMU_ST(tcg::INDEX_op_qemu_st_i64, 64)

    __OP_QEMU_LD(tcg::INDEX_op_qemu_ld_i32, 32)
    __OP_QEMU_LD(tcg::INDEX_op_qemu_ld_i64, 64)

#undef __OP_QEMU_LD
#undef __OP_QEMU_ST

  case tcg::INDEX_op_exit_tb:
    b.CreateBr(bbprop.exitllbb);
    break;

  case tcg::INDEX_op_goto_tb:
    break;

  case tcg::INDEX_op_deposit_i32: {
    Value *arg1 = get(args[1]);
    Value *arg2 = get(args[2]);

    arg2 = b.CreateTrunc(arg2, IntegerType::get(C, 32));

    uint32_t ofs = args[3];
    uint32_t len = args[4];

    if (ofs == 0 && len == 32) {
      set(arg2, args[0]);
      break;
    }

    uint32_t mask = (1u << len) - 1;
    Value *t1, *ret;
    if (ofs + len < 32) {
      t1 = b.CreateAnd(arg2, APInt(32, mask));
      t1 = b.CreateShl(t1, APInt(32, ofs));
    } else {
      t1 = b.CreateShl(arg2, APInt(32, ofs));
    }

    ret = b.CreateAnd(arg1, APInt(32, ~(mask << ofs)));
    ret = b.CreateOr(ret, t1);
    set(ret, args[0]);
  } break;

  case tcg::INDEX_op_deposit_i64: {
    Value *arg1 = get(args[1]);
    Value *arg2 = get(args[2]);
    arg2 = b.CreateTrunc(arg2, IntegerType::get(C, 64));

    uint32_t ofs = args[3];
    uint32_t len = args[4];

    if (0 == ofs && 64 == len) {
      set(arg2, args[0]);
      break;
    }

    uint64_t mask = (1u << len) - 1;
    Value *t1, *ret;

    if (ofs + len < 64) {
      t1 = b.CreateAnd(arg2, APInt(64, mask));
      t1 = b.CreateShl(t1, APInt(64, ofs));
    } else {
      t1 = b.CreateShl(arg2, APInt(64, ofs));
    }

    ret = b.CreateAnd(arg1, APInt(64, ~(mask << ofs)));
    ret = b.CreateOr(ret, t1);
    set(ret, args[0]);
  } break;

  default:
    cerr << "error: Unhandled TCG operation '" << def.name << "'" << endl;
    abort();
    break;
  }
}

/// \brief Get a natural GEP off of the BasePtr walking through Ty toward
/// TargetTy without changing the offset of the pointer.
///
/// This routine assumes we've already established a properly offset GEP with
/// Indices, and arrived at the Ty type. The goal is to continue to GEP with
/// zero-indices down through type layers until we find one the same as
/// TargetTy. If we can't find one with the same type, we at least try to use
/// one with the same size. If none of that works, we just produce the GEP as
/// indicated by Indices to have the correct offset.
void translator::getNaturalGEPWithType(Value *BasePtr, Type *Ty, Type *TargetTy,
                                       SmallVectorImpl<Value *> &Indices) {
  if (Ty == TargetTy)
    return;

  // Pointer size to use for the indices.
  unsigned PtrSize = DL.getPointerTypeSizeInBits(BasePtr->getType());

  // See if we can descend into a struct and locate a field with the correct
  // type.
  unsigned NumLayers = 0;
  Type *ElementTy = Ty;
  do {
    if (ElementTy->isPointerTy())
      break;

    if (ArrayType *ArrayTy = dyn_cast<ArrayType>(ElementTy)) {
      ElementTy = ArrayTy->getElementType();
      Indices.push_back(b.getIntN(PtrSize, 0));
    } else if (VectorType *VectorTy = dyn_cast<VectorType>(ElementTy)) {
      ElementTy = VectorTy->getElementType();
      Indices.push_back(b.getInt32(0));
    } else if (StructType *STy = dyn_cast<StructType>(ElementTy)) {
      if (STy->element_begin() == STy->element_end())
        break; // Nothing left to descend into.
      ElementTy = *STy->element_begin();
      Indices.push_back(b.getInt32(0));
    } else {
      break;
    }
    ++NumLayers;
  } while (ElementTy != TargetTy);
  if (ElementTy != TargetTy)
    Indices.erase(Indices.end() - NumLayers, Indices.end());
}

/// \brief Recursively compute indices for a natural GEP.
///
/// This is the recursive step for getNaturalGEPWithOffset that walks down the
/// element types adding appropriate indices for the GEP.
void translator::getNaturalGEPRecursively(Value *Ptr, Type *Ty, APInt &Offset,
                                          Type *TargetTy,
                                          SmallVectorImpl<Value *> &Indices) {
  if (Offset == 0) {
    getNaturalGEPWithType(Ptr, Ty, TargetTy, Indices);
    return;
  }

  // We can't recurse through pointer types.
  if (Ty->isPointerTy())
    return;

  // We try to analyze GEPs over vectors here, but note that these GEPs are
  // extremely poorly defined currently. The long-term goal is to remove GEPing
  // over a vector from the IR completely.
  if (VectorType *VecTy = dyn_cast<VectorType>(Ty)) {
    unsigned ElementSizeInBits = DL.getTypeSizeInBits(VecTy->getScalarType());
    if (ElementSizeInBits % 8 != 0) {
      // GEPs over non-multiple of 8 size vector elements are invalid.
      return;
    }
    APInt ElementSize(Offset.getBitWidth(), ElementSizeInBits / 8);
    APInt NumSkippedElements = Offset.sdiv(ElementSize);
    if (NumSkippedElements.ugt(VecTy->getNumElements()))
      return;
    Offset -= NumSkippedElements * ElementSize;
    Indices.push_back(b.getInt(NumSkippedElements));
    getNaturalGEPRecursively(Ptr, VecTy->getElementType(), Offset, TargetTy,
                             Indices);
    return;
  }

  if (ArrayType *ArrTy = dyn_cast<ArrayType>(Ty)) {
    Type *ElementTy = ArrTy->getElementType();
    APInt ElementSize(Offset.getBitWidth(), DL.getTypeAllocSize(ElementTy));
    APInt NumSkippedElements = Offset.sdiv(ElementSize);
    if (NumSkippedElements.ugt(ArrTy->getNumElements()))
      return;

    Offset -= NumSkippedElements * ElementSize;
    Indices.push_back(b.getInt(NumSkippedElements));
    getNaturalGEPRecursively(Ptr, ElementTy, Offset, TargetTy, Indices);
    return;
  }

  StructType *STy = dyn_cast<StructType>(Ty);
  if (!STy)
    return;

  const StructLayout *SL = DL.getStructLayout(STy);
  uint64_t StructOffset = Offset.getZExtValue();
  if (StructOffset >= SL->getSizeInBytes())
    return;
  unsigned Index = SL->getElementContainingOffset(StructOffset);
  Offset -= APInt(Offset.getBitWidth(), SL->getElementOffset(Index));
  Type *ElementTy = STy->getElementType(Index);
  if (Offset.uge(DL.getTypeAllocSize(ElementTy)))
    return; // The offset points into alignment padding.

  Indices.push_back(b.getInt32(Index));
  getNaturalGEPRecursively(Ptr, ElementTy, Offset, TargetTy, Indices);
}

/// \brief Get a natural GEP from a base pointer to a particular offset and
/// resulting in a particular type.
///
/// The goal is to produce a "natural" looking GEP that works with the existing
/// composite types to arrive at the appropriate offset and element type for
/// a pointer. TargetTy is the element type the returned GEP should point-to if
/// possible. We recurse by decreasing Offset, adding the appropriate index to
/// Indices, and setting Ty to the result subtype.
///
/// If no natural GEP can be constructed, this function returns null.
void translator::getNaturalGEPWithOffset(Value *Ptr, APInt Offset,
                                         Type *TargetTy,
                                         SmallVectorImpl<Value *> &Indices) {
  PointerType *Ty = cast<PointerType>(Ptr->getType());

  // Don't consider any GEPs through an i8* as natural unless the TargetTy is
  // an i8.
  if (Ty == b.getInt8PtrTy(Ty->getAddressSpace()) && TargetTy->isIntegerTy(8))
    return;

  Type *ElementTy = Ty->getElementType();
  if (!ElementTy->isSized())
    return; // We can't GEP through an unsized element.
  APInt ElementSize(Offset.getBitWidth(), DL.getTypeAllocSize(ElementTy));
  if (ElementSize == 0)
    return; // Zero-length arrays can't help us build a natural GEP.
  APInt NumSkippedElements = Offset.sdiv(ElementSize);

  Offset -= NumSkippedElements * ElementSize;
  Indices.push_back(b.getInt(NumSkippedElements));
  getNaturalGEPRecursively(Ptr, ElementTy, Offset, TargetTy, Indices);
}

ConstantInt *translator::try_fold_to_constant_int(Value *v) {
  ConstantInt *vint = nullptr;
  if (isa<ConstantInt>(v)) {
    vint = cast<ConstantInt>(v);
  } else if (isa<Instruction>(v)) {
    Constant *foldedaddr = ConstantFoldInstruction(cast<Instruction>(v), DL);

    if (foldedaddr && isa<ConstantInt>(foldedaddr))
      vint = cast<ConstantInt>(foldedaddr);
  }

  return vint;
}

#if 0
  // Unwrap ptrtoint casts
  // TODO XXX check that it is lossless
  if (PtrToIntInst *PTII = dyn_cast<PtrToIntInst>(v))
    v = PTII->getPointerOperand();
#endif

Constant* translator::try_fold_to_constant(Value* v) {
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(v)) {
    // unwrap ptrtoint casts
    if (CE->getOpcode() == Instruction::PtrToInt)
      return try_fold_to_constant(CE->getOperand(0));

    return ConstantFoldConstantExpression(CE, DL);
  }

  if (isa<Constant>(v))
    return cast<Constant>(v);

  if (isa<Instruction>(v))
    return ConstantFoldInstruction(cast<Instruction>(v), DL);

  return nullptr;
}

Constant* translator::section_ptr(address_t addr) {
  auto it = addrspace.find(addr);
  if (it == addrspace.end())
    return nullptr;

  unsigned sectidx = (*it).second - 1;
  unsigned off = addr - (*it).first.lower();

  SmallVector<Value *, 4> Indices;
  getNaturalGEPWithOffset(sectgvs[sectidx], APInt(64, off),
                          IntegerType::get(C, sizeof(address_t) * 8), Indices);

  return ConstantExpr::getInBoundsGetElementPtr(nullptr, sectgvs[sectidx],
                                                Indices);
}

Value* translator::section_int_ptr(address_t addr) {
  Value* ptr = section_ptr(addr);
  return ptr ? b.CreatePtrToInt(ptr, word_type()) : nullptr;
}

}

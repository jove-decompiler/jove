#pragma once
#include "binary.h"
#include <array>
#include <boost/graph/adjacency_list.hpp>
#include <boost/icl/interval_map.hpp>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Object/ObjectFile.h>
#include <tuple>
#include <unordered_map>
#include <vector>
#include <queue>

#if defined(TARGET_AARCH64)
#include "tcgdefs-aarch64.hpp"
#elif defined(TARGET_ARM)
#include "tcgdefs-arm.hpp"
#elif defined(TARGET_X86_64)
#include "tcgdefs-x86_64.hpp"
#elif defined(TARGET_I386)
#include "tcgdefs-i386.hpp"
#elif defined(TARGET_MIPS)
#include "tcgdefs-mipsel.hpp"
#endif

/* XXX QEMUVERSIONDEPENDENT */
#if defined(TARGET_AARCH64) || defined(TARGET_X86_64) || defined(TARGET_MIPS64)
#define TARGET_LONG_BITS 64
#else
#define TARGET_LONG_BITS 32
#endif
#if UINTPTR_MAX == UINT32_MAX
#define TCG_TARGET_REG_BITS 32
typedef int32_t tcg_target_long;
typedef uint32_t tcg_target_ulong;
#define TCG_PRIlx PRIx32
#define TCG_PRIld PRId32
#elif UINTPTR_MAX == UINT64_MAX
#define TCG_TARGET_REG_BITS 64
typedef int64_t tcg_target_long;
typedef uint64_t tcg_target_ulong;
#define TCG_PRIlx PRIx64
#define TCG_PRIld PRId64
#endif
#define TARGET_LONG_SIZE (TARGET_LONG_BITS / 8)
/* target_ulong is the type of a virtual address */
#if TARGET_LONG_SIZE == 4
typedef int32_t target_long;
typedef uint32_t target_ulong;
#define TARGET_FMT_lx "%08x"
#define TARGET_FMT_ld "%d"
#define TARGET_FMT_lu "%u"
#elif TARGET_LONG_SIZE == 8
typedef int64_t target_long;
typedef uint64_t target_ulong;
#define TARGET_FMT_lx "%016" PRIx64
#define TARGET_FMT_ld "%" PRId64
#define TARGET_FMT_lu "%" PRIu64
#else
#error TARGET_LONG_SIZE undefined
#endif
/* XXX QEMUVERSIONDEPENDENT */


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
typedef tcg_target_ulong Arg;

enum Type {
    TYPE_I32,
    TYPE_I64,
    TYPE_COUNT, /* number of different types */

    /* An alias for the size of the host register.  */
#if TCG_TARGET_REG_BITS == 32
    TYPE_REG = TYPE_I32,
#else
    TYPE_REG = TYPE_I64,
#endif

    /* An alias for the size of the native pointer.  */
#if UINTPTR_MAX == UINT32_MAX
    TYPE_PTR = TYPE_I32,
#else
    TYPE_PTR = TYPE_I64,
#endif

    /* An alias for the size of the target "long", aka register.  */
#if TARGET_LONG_BITS == 64
    TYPE_TL = TYPE_I64,
#else
    TYPE_TL = TYPE_I32,
#endif
};

enum TempVal {
    TEMP_VAL_DEAD,
    TEMP_VAL_REG,
    TEMP_VAL_MEM,
    TEMP_VAL_CONST,
};

struct Tmp {
    unsigned int reg:8;
    unsigned int mem_reg:8;
    TempVal val_type:8;
    Type base_type:8;
    Type type:8;
    unsigned int fixed_reg:1;
    unsigned int mem_coherent:1;
    unsigned int mem_allocated:1;
    unsigned int temp_local:1; /* If true, the temp is saved across
                                  basic blocks. Otherwise, it is not
                                  preserved across basic blocks. */
    unsigned int temp_allocated:1; /* never used for code gen */

    tcg_target_long val;
    intptr_t mem_offset;
    const char *name;
};
/* XXX QEMUVERSIONDEPENDENT */

enum GLOBAL_TYPE { GLOBAL_I32, GLOBAL_I64, UNDEFINED };

struct global_t {
  GLOBAL_TYPE ty;
  unsigned cpustoff;
  const char *nm;
};

typedef std::bitset<num_globals> global_set_t;

constexpr unsigned longest_word_bits = sizeof(unsigned long long)*8;
typedef std::bitset<longest_word_bits> temp_set_t;

struct helper_t {
  uintptr_t addr;
  const char *nm;
  llvm::Function *llf;
  global_set_t inglb, outglb;
  std::vector<unsigned> inglbv, outglbv;
};
}

class translator {
public:
  struct basic_block_properties_t {
    address_t addr;

    unsigned first_tcg_op_idx;
    std::unique_ptr<tcg::Op[]> tcg_ops;
    std::unique_ptr<tcg::Arg[]> tcg_args;
    std::unique_ptr<tcg::Tmp[]> tcg_tmps;
    unsigned num_tmps;
    unsigned num_labels;

    enum TERMINATOR {
      TERM_UNCONDITIONAL_JUMP,
      TERM_CONDITIONAL_JUMP,
      TERM_CALL,
      TERM_INDIRECT_CALL,
      TERM_INDIRECT_JUMP,
      TERM_RETURN,
      TERM_UNKNOWN /* e.g. HLT, non-control flow instruction */
    } term;

    address_t callee;

    // for computing inputs & outputs
    tcg::global_set_t uses;
    tcg::global_set_t defs;
    tcg::global_set_t dead;

    tcg::global_set_t live_in;
    tcg::global_set_t live_out;

    tcg::global_set_t outputs;

    llvm::BasicBlock* llbb;
    std::vector<llvm::BasicBlock*> lbls;
    llvm::BasicBlock* exitllbb;
  };

  struct function_properties_t {
    address_t entry_point;

    //
    // the set of TCG globals which are provided as parameters
    //
    tcg::global_set_t params;

    //
    // the set of TCG globals which are written to
    //
    tcg::global_set_t outputs;

    //
    // the set of TCG globals which are returned. this is affected by the
    // liveness analysis of callers of this function
    //
    tcg::global_set_t returned;

    tcg::global_set_t used;

    llvm::Function* thunk_llf;
    llvm::Function* llf;
  };

  struct control_flow_properties_t {
    bool dom, back_edge;

    control_flow_properties_t() : dom(false), back_edge(false) {}
  };

  typedef boost::adjacency_list<boost::vecS,               /* OutEdgeList */
                                boost::vecS,               /* VertexList */
                                boost::bidirectionalS,     /* Directed */
                                basic_block_properties_t,  /* VertexProperties */
                                control_flow_properties_t, /* EdgeProperties */
                                function_properties_t,     /* GraphProperties */
                                boost::vecS                /* EdgeList */
                                >
      function_t;
  typedef function_t::vertex_descriptor basic_block_t;
  typedef function_t::edge_descriptor control_flow_t;
private:
  llvm::object::ObjectFile &O;

  llvm::LLVMContext C;
  llvm::Module M;
  const llvm::DataLayout &DL;

  std::unique_ptr<llvm::Module> _HelperM;
  llvm::Module &HelperM;

  llvm::IRBuilder<> b;

  section_table_t secttbl;
  symbol_table_t symtbl;
  relocation_table_t reloctbl;

  boost::icl::interval_map<address_t, unsigned> addrspace;

  llvm::Type* word_ty;

  llvm::AttributeSet FnAttr;

  llvm::FunctionType *FnThunkTy;
  llvm::AttributeSet FnThunkAttr;

  llvm::Function *IndirectJumpFn;
  llvm::Function *IndirectCallFn;

  const std::array<tcg::global_t, tcg::num_globals> tcg_globals;
  std::array<tcg::helper_t, tcg::num_helpers> tcg_helpers;

  std::unordered_map<uintptr_t, tcg::helper_t *> tcg_helper_addr_map;

  std::unordered_map<address_t, basic_block_t> translated_basic_blocks;
  std::queue<address_t> functions_to_translate;

  // contains basic blocks in depth first search order. if we access this
  // vector sequentially, it's equivalent to access vertices by depth first
  // search order.
  // on discover vertex
  std::vector<basic_block_t> verticesByDFNum;

  // the predecessor map records the parent of the depth first search tree
  // on tree edge
  std::vector<basic_block_t> parentMap;

  // section for which we are translating for
  // XXX TODO change this to always look for correct section
  llvm::ArrayRef<uint8_t> sectdata;
  address_t sectstart;

  std::unordered_map<address_t, std::unique_ptr<function_t>> function_table;

  typedef std::pair<function_t *, basic_block_t> caller_t;
  typedef std::unordered_map<address_t, std::vector<caller_t>> callers_t;
  callers_t callers;

  std::array<llvm::Value*, tcg::max_temps> tcg_tmp_llv_m;
  std::array<llvm::Value*, tcg::num_globals> tcg_glb_llv_m;
  llvm::Value* pc_llv;
  llvm::Value* cpu_state_glb_llv;

  std::unordered_map<std::string, llvm::Function*> function_sym_table;
  std::unordered_map<address_t, llvm::Function*> reloc_function_table;

  llvm::Type *word_type();
  void init_helpers();
  void prepare_for_translation();
  bool translate_function(address_t);
  basic_block_t translate_basic_block(function_t&, address_t);
  void write_function_graphviz(function_t &);
  void prepare_tcg_ops(basic_block_properties_t &bbprop);

  void compute_basic_block_defs_and_uses(basic_block_properties_t &);
  void compute_params(function_t&);
 
  void compute_returned(function_t&);

  void explode_tcg_global_set(std::vector<unsigned> &, tcg::global_set_t);
  void explode_tcg_temp_set(std::vector<unsigned> &, tcg::temp_set_t);
  void translate_function_llvm(function_t &f);
  tcg::global_set_t compute_tcg_globals_used(basic_block_properties_t &);
  tcg::temp_set_t compute_tcg_temps_used(basic_block_properties_t &);
  void translate_tcg_to_llvm(function_t &f, basic_block_t bb);
  void translate_tcg_operation_to_llvm(basic_block_properties_t &,
                                       const tcg::Op *, const tcg::Arg *);
  llvm::Value *buildGEP(llvm::Value *BasePtr, llvm::SmallVectorImpl<llvm::Value *> &Indices,
                        llvm::Twine NamePrefix);
  llvm::Value *getNaturalGEPWithType(
      llvm::Value *BasePtr, llvm::Type *Ty, llvm::Type *TargetTy,
      llvm::SmallVectorImpl<llvm::Value *> &Indices, llvm::Twine NamePrefix);
  llvm::Value *
  getNaturalGEPRecursively(llvm::Value *Ptr, llvm::Type *Ty,
                           llvm::APInt &Offset, llvm::Type *TargetTy,
                           llvm::SmallVectorImpl<llvm::Value *> &Indices,
                           llvm::Twine NamePrefix);
  llvm::Value *getNaturalGEPWithOffset(llvm::Value *Ptr, llvm::APInt Offset,
                                       llvm::Type *TargetTy,
                                       llvm::SmallVectorImpl<llvm::Value *> &Indices,
                                       llvm::Twine NamePrefix);
  llvm::Value *load_global_from_cpu_state(unsigned gidx);
  void store_global_to_cpu_state(llvm::Value *gvl, unsigned gidx);

public:
  translator(llvm::object::ObjectFile &, const std::string& Nm);
  ~translator() {}

  llvm::Module& module() {
    return M;
  }

  const section_table_t& section_table() {
    return secttbl;
  }

  const symbol_table_t& symbol_table() {
    return symtbl;
  }

  const relocation_table_t& relocation_table() {
    return reloctbl;
  }

  void tcg_helper(uintptr_t addr, const char *name);

  // given an entry point, translates to an LLVM function and its counterpart
  // thunk (for untranslated-code to use)
  std::tuple<llvm::Function *, llvm::Function *>
  translate(const std::vector<address_t> &);

  llvm::Function* function_of_addr(address_t);

  void print_tcg_ops(std::ostream &out,
                     const basic_block_properties_t &bbprop) const;
};
}

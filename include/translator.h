#pragma once
#include "types.h"
#include <array>
#include <boost/graph/adjacency_list.hpp>
#include <boost/icl/interval_map.hpp>
#include <config-target.h>
#include <inttypes.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
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
/* XXX QEMUVERSIONDEPENDENT */

enum GLOBAL_TYPE { GLOBAL_I32, GLOBAL_I64, UNDEFINED };

struct global_t {
  GLOBAL_TYPE ty;
  unsigned cpustoff;
  const char *nm;
};

typedef std::bitset<num_globals> global_set_t;

struct helper_t {
  uintptr_t addr;
  const char *nm;
  llvm::Function *llf;
  global_set_t inglb, outglb;
};
}

class translator {
public:
  struct basic_block_properties_t {
    int index;

    address_t addr;

    unsigned first_tcg_op_idx;
    std::unique_ptr<tcg::Op[]> tcg_ops;
    std::unique_ptr<tcg::Arg[]> tcg_args;

    // for computing inputs & outputs
    tcg::global_set_t uses;
    tcg::global_set_t defs;
    tcg::global_set_t dead;

    tcg::global_set_t live_in;
    tcg::global_set_t live_out;

    tcg::global_set_t outputs;
  };

  struct function_properties_t {
    address_t entry_point;

    //
    // the set of TCG globals which are provided as parameters
    //
    tcg::global_set_t params;

    //
    // the set of TCG globals which are written to the CPUState, and not
    // returned.
    //
    tcg::global_set_t outputs;

    //
    // the set of TCG globals which are returned. this is affected by the
    // liveness analysis of callers of this function
    //
    tcg::global_set_t returned;

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

  llvm::LLVMContext &C;
  llvm::Module &M;
  const llvm::DataLayout &DL;

  std::unique_ptr<llvm::Module> _HelperM;
  llvm::Module &HelperM;

  boost::icl::interval_map<address_t, section_number_t> addrspace;

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

  llvm::ArrayRef<uint8_t> sectdata;
  address_t sectstart;

  std::unordered_map<address_t, std::unique_ptr<function_t>> function_table;

  typedef std::pair<function_t *, basic_block_t> caller_t;
  typedef std::unordered_map<address_t, std::vector<caller_t>> callers_t;
  callers_t callers;

  void init_helpers();
  function_t& translate_function(address_t);
  basic_block_t translate_basic_block(function_t&, address_t);
  void write_function_graphviz(function_t &);

  void compute_basic_block_defs_and_uses(basic_block_properties_t &);
  void compute_params(function_t&);
  
  void compute_returned(function_t&);

  void explode_tcg_global_set(std::vector<const tcg::global_t *> &,
                              tcg::global_set_t);
  void translate_function_llvm(function_t &f);

public:
  translator(llvm::object::ObjectFile &, llvm::LLVMContext &, llvm::Module &);
  ~translator() {}

  void tcg_helper(uintptr_t addr, const char *name);

  // given an entry point, translates to an LLVM function and its counterpart
  // thunk (for untranslated-code to use)
  std::tuple<llvm::Function *, llvm::Function *>
  translate(const std::vector<address_t> &);

  void print_tcg_ops(std::ostream &out,
                     const basic_block_properties_t &bbprop) const;
};
}

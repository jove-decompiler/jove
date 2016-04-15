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

#ifndef TCG_TARGET_REG_BITS
#if UINTPTR_MAX == UINT32_MAX
#define TCG_TARGET_REG_BITS 32
#elif UINTPTR_MAX == UINT64_MAX
#define TCG_TARGET_REG_BITS 64
#endif
#endif

#if TCG_TARGET_REG_BITS == 32
typedef int32_t tcg_target_long;
typedef uint32_t tcg_target_ulong;
#elif TCG_TARGET_REG_BITS == 64
typedef int64_t tcg_target_long;
typedef uint64_t tcg_target_ulong;
#endif

/* Bits for TCGOpDef->flags, 8 bits available.  */
enum {
    /* Instruction defines the end of a basic block.  */
    TCG_OPF_BB_END       = 0x01,
    /* Instruction clobbers call registers and potentially update globals.  */
    TCG_OPF_CALL_CLOBBER = 0x02,
    /* Instruction has side effects: it cannot be removed if its outputs
       are not used, and might trigger exceptions.  */
    TCG_OPF_SIDE_EFFECTS = 0x04,
    /* Instruction operands are 64-bits (otherwise 32-bits).  */
    TCG_OPF_64BIT        = 0x08,
    /* Instruction is optional and not implemented by the host, or insn
       is generic and should not be implemened by the host.  */
    TCG_OPF_NOT_PRESENT  = 0x10,
};

/* XXX QEMUVERSIONDEPENDENT */

typedef enum TCGOpcode {
#define DEF(name, oargs, iargs, cargs, flags) INDEX_op_ ## name,
#include "tcg-opc.h"
#undef DEF
    NB_OPS,
} TCGOpcode;

namespace jove {
namespace tcg {

/* XXX QEMUVERSIONDEPENDENT */
typedef struct Op {
    TCGOpcode opc   : 8;

    /* The number of out and in parameter for a call.  */
    unsigned callo  : 2;
    unsigned calli  : 6;

    /* Index of the arguments for this op, or -1 for zero-operand ops.  */
    signed args     : 16;

    /* Index of the prex/next op, or -1 for the end of the list.  */
    signed prev     : 16;
    signed next     : 16;
} TCGOp;
/* XXX QEMUVERSIONDEPENDENT */

typedef tcg_target_ulong Arg;

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

  struct basic_block_properties_t {
    address_t addr;

    std::unique_ptr<tcg::Op[]> tcg_ops;
    std::unique_ptr<tcg::Arg[]> tcg_args;
  };

  struct function_properties_t {
    address_t entry_point;
  };

  typedef boost::adjacency_list<boost::vecS,              /* OutEdgeList */
                                boost::vecS,              /* VertexList */
                                boost::bidirectionalS,    /* Directed */
                                basic_block_properties_t, /* VertexProperties */
                                boost::no_property,       /* EdgeProperties */
                                function_properties_t,    /* GraphProperties */
                                boost::vecS               /* EdgeList */
                                >
      function_t;

  std::queue<address_t> functions_to_translate;

  void init_helpers();
  void translate_function(function_t&);
  void translate_basic_block(function_t&, address_t);

public:
  translator(llvm::object::ObjectFile &, llvm::LLVMContext &, llvm::Module &);
  ~translator() {}

  void tcg_helper(uintptr_t addr, const char *name);

  // given an entry point, translates to an LLVM function and its counterpart
  // thunk (for untranslated-code to use)
  std::tuple<llvm::Function *, llvm::Function *> translate(address_t);
};
}

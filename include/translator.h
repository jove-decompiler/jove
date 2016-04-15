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

namespace jove {
namespace tcg {

struct Op;
typedef unsigned long Arg;

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

  struct basic_block_t {
    address_t addr;

    const tcg::Op *tcg_ops;
    const tcg::Arg *tcg_args;
  };

  struct basicblock_or_tcgglobal_t {
    bool isbb;

    union {
      basic_block_t bb;
      unsigned tcg_gbl_idx;
    };
  };

  typedef boost::adjacency_list<
      boost::vecS,               /* OutEdgeList */
      boost::vecS,               /* VertexList */
      boost::bidirectionalS,     /* Directed */
      basicblock_or_tcgglobal_t, /* VertexProperties */
      boost::no_property,        /* EdgeProperties */
      boost::no_property,        /* GraphProperties */
      boost::vecS                /* EdgeList */
      >
      function_t;

  void init_helpers();

public:
  translator(llvm::object::ObjectFile &, llvm::LLVMContext &, llvm::Module &);
  ~translator() {}

  void tcg_helper(uintptr_t addr, const char *name);

  // given an entry point, translates to an LLVM function and its counterpart
  // thunk (for untranslated-code to use)
  std::tuple<llvm::Function *, llvm::Function *> translate(address_t);
};
}

#include "translator.h"

#if 0
#include <tuple>
#include <array>
#include <libgen.h>
#include <iostream>
#include <sstream>
#include <list>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <bitset>
#include <chrono>
#include <sstream>
#include <iterator>
#include <memory>
#include <iomanip>
#include <sys/mman.h>

#include <llvm/ADT/Triple.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/DiagnosticPrinter.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/Utils/Cloning.h>

using std::array;
using std::tuple;
using std::tie;
using std::make_pair;
using std::cout;
using std::cerr;
using std::vector;
using std::list;
using std::unordered_map;
using std::unordered_set;
using std::unique_ptr;
using std::string;
using std::dec;
using std::bitset;
using std::hex;
using std::endl;
using std::ostringstream;
using std::error_code;
using std::fill;
#endif

using namespace llvm;
using namespace llvm::object;
#if 0
using namespace llvm::legacy;
#endif

//
// Macros
//
#if 0
#define PONYA_OFFSETOF(type, member) ((size_t) &(((type*)0)->member))
#endif

namespace jove {

//
// Types & data structures
//
#if 0
typedef uint32_t tcg_global_size_t;
typedef uint32_t tcg_global_offset_t;

enum tcg_global_size_t {
  PONYA_TGS_32, /* = TCG_TYPE_I32 = 0 */
  PONYA_TGS_64, /* = TCG_TYPE_I64 = 1 */
  PONYA_TGS_16,
  PONYA_TGS_8
};

struct tcg_global_t {
  tcg_global_size_t   size;
  tcg_global_offset_t offs;

  tcg_global_t() {}
  tcg_global_t(tcg_global_size_t size,
    tcg_global_offset_t offs) : size(size), offs(offs)
  {}
};

static const char *string_of_tcg_global_size[] = {"u32", "u64", "u16", "u8"};

static const unsigned bits_of_ponya_tcg_global_size[] = {32, 64, 16, 8};

static const uint64_t g[] = {
    0xdeadbeef,   // 0
    PONYA_TGS_8,  // 1
    PONYA_TGS_16, // 2
    0xdeadbeef,   // 3
    PONYA_TGS_32, // 4
    0xdeadbeef,   // 5
    0xdeadbeef,   // 6
    0xdeadbeef,   // 7
    PONYA_TGS_64  // 8
};

static tcg_global_size_t tcg_global_size_of_tcg_type(TCGType ty) {
  return static_cast<tcg_global_size_t>(ty);
}

static bool isGlobalSizeGreater(tcg_global_size_t lhs,
  tcg_global_size_t rhs) {
  return lhs > rhs;
}

template <typename T>
class tcg_global_map {
  array<T, ponyaCPUStateSize> mapping;

public:
  typedef typename std::array<T, ponyaCPUStateSize>::size_type size_type;
  typedef typename array<T, ponyaCPUStateSize>::iterator iterator;

  iterator begin() {
  }

  iterator end() {
    return mapping.end();
  }

  T& operator[](tcg_global_t gl) {
    return mapping[gl.offs];
  }

  const T& operator[](tcg_global_t gl) const {
    return mapping[gl.offs];
  }
};

class tcg_global_unordered_set {
  array<bool, ponyaCPUStateSize> mem;
  list<tcg_global_t> lst;
  tcg_global_map<list<tcg_global_t>::iterator> lst_its;

public:
  typedef list<tcg_global_t>::iterator iterator;
  typedef list<tcg_global_t>::const_iterator const_iterator;

  tcg_global_unordered_set() {
    fill(mem.begin(), mem.end(), false);
  }

  tcg_global_unordered_set(const tcg_global_unordered_set& s) {
    fill(mem.begin(), mem.end(), false);
    operator=(s);
  }

  void operator=(const tcg_global_unordered_set& rhs) {
    clear();

    for (auto it = rhs.begin(); it != rhs.end(); ++it) {
      const tcg_global_t& gl = *it;

      lst.push_back(gl);
      auto gl_it = lst.end();
      --gl_it;
      lst_its[gl] = gl_it;
      mem[gl.offs] = true;
    }
  }

  iterator begin() {
    return lst.begin();
  }

  iterator end() {
    return lst.end();
  }

  const_iterator begin() const {
    return lst.begin();
  }

  const_iterator end() const {
    return lst.end();
  }

  void clear() {
    for (auto it = begin(); it != end(); ++it)
      mem[(*it).offs] = false;

    lst.clear();
  }

  bool exists(tcg_global_t gl) const {
    return mem[gl.offs];
  }

  void add(tcg_global_t gl) {
    if (!exists(gl)) {
      lst.push_back(gl);
      auto it = lst.end();
      --it;
      lst_its[gl] = it;
      mem[gl.offs] = true;
    } else if (isGlobalSizeGreater(gl.size, (*lst_its[gl]).size)) {
      /* if the size of the given local is greater than the existing global's
       * size, replace the existing global's size */
      (*lst_its[gl]).size = gl.size;
    }
  }
};

static tcg_global_unordered_set ponya_tcg_global_unordered_set_union(
    const tcg_global_unordered_set& x,
    const tcg_global_unordered_set& y) {
  tcg_global_unordered_set res(x);

  for (auto it = y.begin(); it != y.end(); ++it)
    res.add(*it);

  return res;
}

class tcg_local_unordered_set {
  bitset<TCG_MAX_TEMPS> mem;
  vector<uint32_t> lst;

public:
  typedef vector<uint32_t>::iterator iterator;
  typedef vector<uint32_t>::const_iterator const_iterator;

  iterator begin() {
    return lst.begin();
  }

  iterator end() {
    return lst.end();
  }

  const_iterator begin() const {
    return lst.begin();
  }

  const_iterator end() const {
    return lst.end();
  }

  void clear() {
    for (auto it = begin(); it != end(); ++it)
      mem[*it] = false;

    lst.clear();
  }

  bool exists(uint32_t lcl) const {
    return mem[lcl];
  }

  void add(uint32_t lcl) {
    if (!exists(lcl)) {
      lst.push_back(lcl);
      mem[lcl] = true;
    }
  }
};

enum HELPER_TYPE {
  QEMU_HELPER,         // calls QEMU helper directly
  PONYA_HELPER_SIMPLE, // simple, unchanged, does not access CPU state
  PONYA_HELPER,        // uses CPU state parameter and passes fields by value
};

struct Helper {
  Function* f;

  Helper() {}
  Helper(Function* f) : f(f) {}

  virtual bool doesAccessCPUState() = 0;

  virtual HELPER_TYPE getType() = 0;
};

struct QEMUHelper : public Helper {
  QEMUHelper() {}
  QEMUHelper(Function* f) : Helper(f) {}

  bool doesAccessCPUState() {
    return true;
  }

  HELPER_TYPE getType()
  { return QEMU_HELPER; }
};

struct PonyaHelperSimple : public Helper {
  PonyaHelperSimple() {}
  PonyaHelperSimple(Function* f) : Helper(f) {}

  bool doesAccessCPUState() {
    return false;
  }

  HELPER_TYPE getType()
  { return PONYA_HELPER_SIMPLE; }
};

// passes arguments through CPU state pointer argument, and
// passes some arguments by value
struct PonyaHelper : public Helper {
  bool passesCPUStateArg;
  bool isCPUStateArgNew;
  tcg_global_unordered_set ref;
  tcg_global_unordered_set mod;
  tcg_global_unordered_set promotedInputs;
  tcg_global_unordered_set promotedOutputs;

  PonyaHelper() : passesCPUStateArg(false), isCPUStateArgNew(false) {}
  PonyaHelper(Function *)
      : Helper(f), passesCPUStateArg(false), isCPUStateArgNew(false) {}

  bool doesAccessCPUState() { return passesCPUStateArg; }

  HELPER_TYPE getType() { return PONYA_HELPER; }
};

//
// translator methods
//

class TCGLLVMContextPrivate {
  /* our data layout */
  const DataLayout* dl;

  /* translated llvm function type */
  FunctionType* fty;

  /* TCG globals GEP indices */
  tcg_global_map<vector<Value*> > tcg_glb_gep_idxs;

  /* TCG global symbols */
  tcg_global_map<const char*> tcg_glb_syms;

  /* table with load mmu functions:
   * __ldb_mmu, __ldw_mmu, __ldl_mmu, __ldq_mmu, __ldq_mmu */
  Function* ponya_qemu_ld_helpers[5];
  Function* ponya_panda_ld_helpers[5];

  /* table with store mmu functions:
   * __stb_mmu, __stw_mmu, __stl_mmu, __stq_mmu, __stq_mmu */
  Function* ponya_qemu_st_helpers[5];
  Function* ponya_panda_st_helpers[5];

  /* helpful stub functions */
  Function* llf_ponyaCallStub1;
  Function* llf_ponyaCallStub2;
  Function* llf_ponyaRetStub;
  Function* llf_ponyaDoLongjmp;
#ifndef CONFIG_PONYA
  Function* llf_ponyaException;
#endif
#ifdef CONFIG_PONYA
  Function* llf_ponyaIndirectJump;
#endif

  /* helpful types */
  StructType* cpu_state_ty;
  PointerType* cpu_state_ptr_ty;
  Type* ponyaCallStubCPUStatePtrTy;
  Type* ponyaCallStubDecompiledBBFuncTy;
  Type* void_ty;
  Type* i8_ty;
  PointerType* i8p_ty;
  Type* i16_ty;
  Type* i32_ty;
  Type* i64_ty;
  FunctionType* func___gxx_personality_v0_ty;
  FunctionType* func___cxa_begin_catch_ty;
  FunctionType* func___cxa_end_catch_ty;
  Type* landing_pad_field_tys[2];
  Type* landing_pad_ty;

  /* alias metadata node for guest/host distinction */
  MDNode* alias_scope_list;

  /* helper functions */
  unordered_map<string, Helper*> helpers;

  //
  // fields which are constructed and torn down repeatedly each translation
  //

  /* helpful class to make LLVM code */
  IRBuilder<> b;

  /* current TCG context */
  TCGContext* tcgctx;

  /* current function */
  Function* llf;

  /* TCG globals which are tcg_inputs (i.e. ref) */
  tcg_global_unordered_set tcg_inputs;

  /* TCG globals which are tcg_outputs (i.e. mod) */
  tcg_global_unordered_set tcg_outputs;

  /* union of TCG inputs and TCG outputs */
  tcg_global_unordered_set tcg_globals;

  /* TCG locals */
  tcg_local_unordered_set tcg_locals;

  /* llvm locals of TCG globals */
  tcg_global_map<AllocaInst*> tcg_glb_vals;

  /* llvm locals of TCG locals */
  array<AllocaInst*, TCG_MAX_TEMPS> tcg_lcl_vals;

  /* exit block of current function */
  BasicBlock* exitbb;

  /* TCG labels to blocks */
  array<BasicBlock*, TCG_MAX_LABELS> tcg_label_to_llbb;

  /* last label seen */
  uint64_t max_tcg_label;

  /* llvm locals corresponding to TCG global outputs which specify whether
   * their local versions have been modified */
  tcg_global_map<AllocaInst*> tcg_glb_vals_mod;

  /* TCG global GEP's */
  tcg_global_map<Value*> tcg_glb_cpu_st_ptrs;

#ifndef CONFIG_PONYA
  /* function return value (next TB) */
  AllocaInst* retlocal;

  /* last TCG op */
  AllocaInst* last_tcg_op_local;

  /* catch blocks for exceptions */
  vector<BasicBlock*> catch_blocks;

  /* catch block that can be reused if catch dirty bit is zero */
  BasicBlock* catch_block;
  bool catch_dirty;

  /* memoized function declarations */
  Constant* func___gxx_personality_v0;
  Function* func___cxa_begin_catch;
  Function* func___cxa_end_catch;
#endif

  /* function calls to at end of translation */
#ifdef CONFIG_PONYA
  vector<CallInst*> calls_to_inline;
#endif

public:
  TCGLLVMContextPrivate();
  ~TCGLLVMContextPrivate();

  bool verify();
  bool verifyFunc();
  bool verifyOther();

  void logLLVM(TranslationBlock*);

  /* shortcuts */
  Type* intType(int w) { return IntegerType::get(llctx, w); }
  Type* intPtrType(int w) { return PointerType::get(intType(w), 0); }
  Type* wordType() { return intType(TCG_TARGET_REG_BITS); }
  Type* wordType(int bits) { return intType(bits); }
  Type* wordPtrType() { return intPtrType(TCG_TARGET_REG_BITS); }

  void adjustTypeSize(unsigned target, Value **v1) {
      Value *va = *v1;
      if (target == 32) {
          if (va->getType() == intType(64)) {
              *v1 = b.CreateTrunc(va, intType(target));
          } else if (va->getType() != intType(32)) {
              assert(false);
          }
      }
  }

  void adjustTypeSize(unsigned target, Value **v1, Value **v2) {
    adjustTypeSize(target, v1);
    adjustTypeSize(target, v2);
  }

  Type* tcgType(int type) {
    return type == TCG_TYPE_I64 ? intType(64) : intType(32);
  }

  Type* tcgPtrType(int type) {
    return type == TCG_TYPE_I64 ? intPtrType(64) : intPtrType(32);
  }

  void startNewBasicBlock(BasicBlock *bb = nullptr) {
    if(!bb)
        bb = BasicBlock::Create(llctx);
    else
        assert(bb->getParent() == 0);

    if(!b.GetInsertBlock()->getTerminator()){
        b.CreateBr(bb);
    }

    llf->getBasicBlockList().push_back(bb);
    b.SetInsertPoint(bb);
  }

  unsigned getValueBits(uint64_t idx) {
    switch (tcgctx->temps[idx].type) {
      case TCG_TYPE_I32: return 32;
      case TCG_TYPE_I64: return 64;
      default: assert(false && "Unknown size");
    }
    return 0;
  }

  BasicBlock* getLabel(uint64_t idx) {
    if (!tcg_label_to_llbb[idx]) {
      max_tcg_label = std::max<uint64_t>(max_tcg_label, idx);
      tcg_label_to_llbb[idx] = BasicBlock::Create(llctx/*, bbName.str()*/);
    }
    return tcg_label_to_llbb[idx];
  }

  Instruction* ponyaGuestMemOp(Instruction* ins) {
    ins->setMetadata(LLVMContext::MD_noalias, alias_scope_list);
    return ins;
  }

  Instruction* ponyaHostMemOp(Instruction* ins) {
    ins->setMetadata(LLVMContext::MD_alias_scope, alias_scope_list);
    return ins;
  }

  /* store all of our TCG global output local versions to the CPU state */
  void storeValues() {
#if 0
    errs() << *llf << "\n";
    errs().flush();
#endif
    for (auto it = tcg_outputs.begin(); it != tcg_outputs.end(); ++it) {
      Value* mod = ponyaHostMemOp(b.CreateLoad(tcg_glb_vals_mod[*it]));
      Value* ptr = tcg_glb_cpu_st_ptrs[*it];
      Value* v2 = ponyaHostMemOp(b.CreateLoad(ptr));
      Value* v1 = ponyaHostMemOp(b.CreateLoad(tcg_glb_vals[*it]));

#if 0
      if (v1->getType() != v2->getType()) {
        errs() << "huh? types differ: " <<
          *v2->getType() << ' ' <<
          *v1->getType() << '\n';

        mod->print(errs()); errs() << '\n';
        v1->print(errs()); errs() << '\n';
        v2->print(errs()); errs() << '\n';

        errs().flush();
        exit(1);
      }
#endif

      Value* sel = b.CreateSelect(mod, v1, v2);
      ponyaHostMemOp(b.CreateStore(sel, ptr));

      b.CreateStore(ConstantInt::get(intType(1), 0), tcg_glb_vals_mod[*it]);
    }
  }

  /* load all our TCG global input local versions from the CPU state */
  void loadValues() {
    for (auto it = tcg_inputs.begin(); it != tcg_inputs.end(); ++it) {
      b.CreateStore(b.CreateLoad(tcg_glb_cpu_st_ptrs[*it]), tcg_glb_vals[*it]);
      if (tcg_outputs.exists(*it))
        b.CreateStore(ConstantInt::get(intType(1), 0), tcg_glb_vals_mod[*it]);
    }
  }

  /* store TCG global output local versions to the CPU state which may be read
   * by the given helper */
  void storeNeccessaryValues(PonyaHelper* ph) {
    for (auto it = tcg_outputs.begin(); it != tcg_outputs.end(); ++it) {
      if (!ph->ref.exists(*it))
        continue;

      Value* mod = ponyaHostMemOp(b.CreateLoad(tcg_glb_vals_mod[*it]));
      Value* ptr = tcg_glb_cpu_st_ptrs[*it];
      Value* v2 = ponyaHostMemOp(b.CreateLoad(ptr));
      Value* v1 = ponyaHostMemOp(b.CreateLoad(tcg_glb_vals[*it]));

      Value* sel = b.CreateSelect(mod, v1, v2);
      ponyaHostMemOp(b.CreateStore(sel, ptr));

      b.CreateStore(ConstantInt::get(intType(1), 0), tcg_glb_vals_mod[*it]);
    }
  }

  /* load TCG global input local versions from the CPU state which may have
   * been written by the given helper */
  void loadNeccessaryValues(PonyaHelper* ph) {
    for (auto it = tcg_inputs.begin(); it != tcg_inputs.end(); ++it) {
      if (!ph->mod.exists(*it))
        continue;

      b.CreateStore(b.CreateLoad(tcg_glb_cpu_st_ptrs[*it]), tcg_glb_vals[*it]);
      if (tcg_outputs.exists(*it))
        b.CreateStore(ConstantInt::get(intType(1), 0), tcg_glb_vals_mod[*it]);
    }
  }

  Value* ponyaCPUStGEPForTCGGlobal(tcg_global_t gl) {
    vector<Value*>& indices = tcg_glb_gep_idxs[gl];

    if (indices.empty())
      return nullptr;

#if !defined(NDEBUG) || defined(CONFIG_PONYA)
    string sym;
    const char* sym_ = tcg_glb_syms[gl];
    if (sym_) {
      sym += sym_;
    } else {
      if (gl.offs < ponyaCPUStateNBRegs*(sizeof(target_ulong)) &&
          gl.size == PONYA_TGS_64) {
        int reg_idx = gl.offs / sizeof(target_ulong);
        sym += reg_idx_name[reg_idx];
      } else {
        sym += std::to_string(gl.offs);
      }
    }
    sym += "_pointer";
#else
    string sym("_" + std::to_string(gl.offs));
#endif

#ifdef CONFIG_PONYA
    Function::arg_iterator param_it = llf->arg_begin();
    ++param_it; // st parameter
    return b.CreateInBoundsGEP(param_it, indices, sym);
#else
    return b.CreateInBoundsGEP(llf->arg_begin(), indices, sym);
#endif
  }

  /* given a global, returns a llvm local corresponding to it */
  Value* getValueOfGlobal(tcg_global_t gl) {
    Value* ptr = b.CreatePointerCast(tcg_glb_vals[gl],
      intPtrType(bits_of_ponya_tcg_global_size[gl.size]));
    Value* res = b.CreateLoad(ptr);

#if !defined(NDEBUG) || defined(CONFIG_PONYA)
    string sym;
    const char* sym_ = tcg_glb_syms[gl];
    if (sym_) {
      sym += sym_;
    } else {
      if (gl.offs < ponyaCPUStateNBRegs*(sizeof(target_ulong)) &&
          gl.size == PONYA_TGS_64) {
        int reg_idx = gl.offs / sizeof(target_ulong);
        sym += reg_idx_name[reg_idx];
      } else {
        sym += std::to_string(gl.offs);
      }
    }
#else
    string sym(std::to_string(gl.offs));
#endif

    res->setName(sym);

    return res;
  }

  /* given a TCGArg, returns a llvm local for the corresponding TCG global or
   * TCG local */
  Value* getValueOfTCGArg(TCGArg idx) {
    if (idx == _ponya_tcg_cpu_env) {
      // tcg env
#ifdef CONFIG_PONYA
      Function::arg_iterator param_it = llf->arg_begin();
      ++param_it; // st parameter
      return b.CreatePtrToInt(param_it, wordType());
#else
      return b.CreatePtrToInt(llf->arg_begin(), wordType());
#endif
    } else if (likely(idx < (uint64_t)tcg_ctx.nb_globals)) {
      // tcg global
      TCGTemp *ts = &tcg_ctx.temps[idx];
      assert(!ts->fixed_reg);

      tcg_global_t gl;
      gl.size = tcg_global_size_of_tcg_type(ts->type);
      gl.offs = ts->mem_offset;

      return getValueOfGlobal(gl);
    } else if (idx < TCG_MAX_TEMPS) {
      // tcg local
      return b.CreateLoad(tcg_lcl_vals[idx]);
    }

    assert(false && "given TCGArg is garbage");
    return nullptr;
  }

  /* given a TCGArg, stores a value to the llvm local for the corresponding
   * TCG global or TCG local */
  void setValueOfTCGArg(TCGArg idx, Value* v) {
    if (idx == _ponya_tcg_cpu_env) {
      assert(false && "cannot store to CPU state pointer");
    } else if (likely(idx < (uint64_t)tcg_ctx.nb_globals)) {
      // tcg global
      TCGTemp *ts = &tcg_ctx.temps[idx];
      assert(!ts->fixed_reg);

      tcg_global_t gl;
      gl.size = tcg_global_size_of_tcg_type(ts->type);
      gl.offs = ts->mem_offset;

      setValueOfGlobal(gl, v);
    } else if (idx < TCG_MAX_TEMPS) {
      // tcg local
      b.CreateStore(v, tcg_lcl_vals[idx]);
    }
  }

  /* given a global, stores a value to the llvm local corresponding to it */
  void setValueOfGlobal(tcg_global_t gl, Value* v) {
    assert(tcg_outputs.exists(gl));

    b.CreateStore(ConstantInt::get(intType(1), 1), tcg_glb_vals_mod[gl]);
#ifndef CONFIG_PONYA
    catch_dirty = true;
#endif

    b.CreateStore(v,
      b.CreatePointerCast(
        tcg_glb_vals[gl],
        intPtrType(bits_of_ponya_tcg_global_size[gl.size])));
  }

  Value* getCPUStatePtrOfGlobal(tcg_global_t gl) {
    Value* ptr = ponyaCPUStGEPForTCGGlobal(gl);
    if (ptr) {
      Type* base_ty = cast<SequentialType>(ptr->getType())->getElementType();
      if (!base_ty->isIntegerTy() ||
          cast<IntegerType>(base_ty)->getBitWidth() !=
          bits_of_ponya_tcg_global_size[gl.size])
        return b.CreatePointerCast(ptr,
          intPtrType(bits_of_ponya_tcg_global_size[gl.size]));
      else
        return ptr;
    } else {
      Value* v;
      v = b.CreateAdd(getValueOfTCGArg(_ponya_tcg_cpu_env),
        ConstantInt::get(wordType(), gl.offs));
      v = b.CreateIntToPtr(v,
        intPtrType(bits_of_ponya_tcg_global_size[gl.size]));
      return v;
    }
  }

  Function* ofFunctionInHelperMod(Function* f) {
#ifdef CONFIG_PONYA
    return f;
#else
    Function* fInMod = cast<Function>(llm->getOrInsertFunction(
          f->getName(), f->getFunctionType()));
    fInMod->copyAttributesFrom(f);
    return fInMod;
#endif
  }

  /* Code generation */
  Value* generateQemuMemOp(bool ld, Value *value, Value *addr, int mem_index, int bits);
  int generateOperation(int opc, const TCGArg *args);
  void generateCode(void* cpu_st, TCGContext *s, TranslationBlock *tb);
  void generateUnreachableCode(TranslationBlock *tb);

  /* ponya */
  void ponyaInitTranslationFunction(const TCGContext *s, TranslationBlock *tb, const string& f_sym);
  void ponyaComputeOverApproxTCGInputsAndOutputs(TCGContext *s,
    TranslationBlock *tb);

  void ponyaOnExitTB(uint64_t next_tb = 0) {
#ifndef CONFIG_PONYA
    ponyaHostMemOp(b.CreateStore(ConstantInt::get(wordType(), next_tb), retlocal));
#endif
    b.CreateBr(exitbb);
  }

  void fillTCGExtTempOffToGEPIndicesMap();
  void fillTCGExtTempOffToGEPIndicesMapSub(Type* ty,
    vector<Value*> indices,
    std::list<vector<Value*> > out[4]);

  uint64_t byteOffsetOfGEPIndicesSub(Type* ty,
    vector<Value*>& indices,
    vector<Value*>::iterator index,
    uint64_t byte_offset) const;

  tcg_global_offset_t byteOffsetOfGEPIndices(Type* base_ty,
      vector<Value*>& indices) const;

  void setCPUStateSize(size_t s);
  void cpuStateField(uint64_t off, const char* sym);

#ifdef CONFIG_PONYA
  void ponyaInlineLater(CallInst* CI) {
    calls_to_inline.push_back(CI);
  }
#endif

  CallInst *buildCallStub1(uint64_t pc, Value *res_arg = nullptr,
                           Value *st_arg = nullptr);
  CallInst *buildCallStub2(uint64_t pc1, uint64_t pc2);

  // Returns the TargetMachine instance or zero if no triple is provided.
  TargetMachine* GetTargetMachine(Triple TheTriple) {
    std::string Error;
    const Target *TheTarget = TargetRegistry::lookupTarget("x86-64" /* XXX */,
        TheTriple, Error);

    // Some modules don't specify a triple, and this is okay.
    if (!TheTarget) {                                                                                       
      return nullptr;
    }                                                                                                       

    // XXX TODO?
#if 0
    // Package up features to be passed to target/subtarget                                                 
    std::string FeaturesStr;
    if (MAttrs.size()) {                                                                                    
      SubtargetFeatures Features;
      for (unsigned i = 0; i != MAttrs.size(); ++i)
        Features.AddFeature(MAttrs[i]);                                                                     
      FeaturesStr = Features.getString();
    }
#endif

    return TheTarget->createTargetMachine(TheTriple.getTriple(),
                                          "x86-64" /* XXX */,
                                          string(),
                                          getJITTargetOptions(),
                                          Reloc::Default,
                                          CodeModel::Default,
                                          CodeGenOpt::Aggressive);
  }

#if 0
  legacy::FunctionPassManager* makeFPM(Module* M) {
    legacy::FunctionPassManager* fpmgr = new legacy::FunctionPassManager(M);

    fpmgr->add(new DataLayoutPass());
    unique_ptr<TargetMachine> tm(GetTargetMachine(Triple(_llm->getTargetTriple())));
    tm->addAnalysisPasses(*fpmgr);

    PassManagerBuilder Builder;
    Builder.OptLevel = 3;
    Builder.SizeLevel = 0;
    Builder.SLPVectorize = false; // XXX maybe change this

    Builder.populateFunctionPassManager(*fpmgr);

    return fpmgr;
  }

  legacy::PassManager* makeMPM(Module* M) {
    legacy::PassManager* pmgr = new legacy::PassManager;

    pmgr->add(new TargetLibraryInfo(Triple(_llm->getTargetTriple())));
    pmgr->add(new DataLayoutPass());
    unique_ptr<TargetMachine> tm(GetTargetMachine(Triple(_llm->getTargetTriple())));
    tm->addAnalysisPasses(*pmgr);

    {
      PassManagerBuilder Builder;
      Builder.VerifyInput = false;
      Builder.StripDebug = false;

      Builder.populateLTOPassManager(*pmgr);
    }

    {
      PassManagerBuilder Builder;
      Builder.OptLevel = 3;
      Builder.SizeLevel = 0;
      Builder.SLPVectorize = false; // XXX maybe change this

      Builder.populateModulePassManager(*pmgr);
    }

    return pmgr;
  }

#else
  legacy::FunctionPassManager* makeFPM(Module* M) {
    legacy::FunctionPassManager* fpmgr = new legacy::FunctionPassManager(M);

#define __PASS(CLASS) do {\
  fpmgr->add(new CLASS());\
} while (0)

#define ___PASS(CLASS) do {\
  fpmgr->add(create ## CLASS());\
} while (0)

#if 0
    // works
    __PASS(DataLayoutPass);
    tm->addAnalysisPasses(*fpmgr);
    ___PASS(ScopedNoAliasAAPass);
    __PASS(AssumptionCacheTracker);
    ___PASS(BasicAliasAnalysisPass);
    __PASS(DominatorTreeWrapperPass);
    ___PASS(PromoteMemoryToRegisterPass);
    ___PASS(InstructionCombiningPass);
    ___PASS(ReassociatePass);
    ___PASS(EarlyCSEPass);
    ___PASS(LazyValueInfoPass);
    __PASS(MemoryDependenceAnalysis);
    ___PASS(GVNPass);
    ___PASS(PostDomTree);
    ___PASS(PostDomFrontier);
    ___PASS(DeadStoreEliminationPass);
#endif
#if 0
    ___PASS(PromoteMemoryToRegisterPass);

    __PASS(DataLayoutPass);
    tm->addAnalysisPasses(*fpmgr);
    ___PASS(ScopedNoAliasAAPass);
    __PASS(AssumptionCacheTracker);
    ___PASS(BasicAliasAnalysisPass);

    ___PASS(EarlyCSEPass);

    fpmgr->add(createCFGSimplificationPass(255));
    ___PASS(ReassociatePass);

    __PASS(DominatorTreeWrapperPass);
    ___PASS(InstructionCombiningPass);
    ___PASS(LazyValueInfoPass);
    __PASS(MemoryDependenceAnalysis);
    ___PASS(GVNPass);
    __PASS(MemoryDependenceAnalysis);

    ___PASS(PostDomTree);
    ___PASS(PostDomFrontier);
    ___PASS(DeadStoreEliminationPass);
#endif
#if 0
    ___PASS(PromoteMemoryToRegisterPass);

    __PASS(DataLayoutPass);
    tm->addAnalysisPasses(*fpmgr);
    ___PASS(ScopedNoAliasAAPass);
    __PASS(AssumptionCacheTracker);
    ___PASS(BasicAliasAnalysisPass);

    ___PASS(EarlyCSEPass);

    fpmgr->add(createCFGSimplificationPass(255));
    ___PASS(ReassociatePass);
    ___PASS(DeadStoreEliminationPass);
#endif
    ___PASS(PromoteMemoryToRegisterPass);
    ___PASS(InstructionCombiningPass);
    fpmgr->add(createCFGSimplificationPass(1));
    //tm->addAnalysisPasses(*fpmgr);
    //___PASS(DeadStoreEliminationPass);

#undef __PASS
#undef ___PASS

    return fpmgr;
  }
#endif

  void registerHelperFunction(Function& f);
  void logLLVMBeforeOpt();

  TargetOptions getJITTargetOptions() {
    TargetOptions res;
#if 0
    res.EnableFastISel = true;
#ifndef NDEBUG
    res.NoFramePointerElim = true;
    res.DisableTailCalls = true;
    res.JITEmitDebugInfo = true;
#endif
#endif
    return res;
  }

#ifndef CONFIG_PONYA
  BasicBlock* ponyaCatchBlock() {
#if 0
    if (!func___cxa_begin_catch)
      func___cxa_begin_catch = Function::Create(
        func___cxa_begin_catch_ty,
        GlobalValue::ExternalLinkage,
        "__cxa_begin_catch",
        llm);
    if (!func___cxa_end_catch)
      func___cxa_end_catch = Function::Create(
        func___cxa_end_catch_ty,
        GlobalValue::ExternalLinkage,
        "__cxa_end_catch",
        llm);
#endif

    if (catch_block && !catch_dirty)
      return catch_block;

    catch_block = BasicBlock::Create(llctx);
    catch_dirty = false;
    catch_blocks.push_back(catch_block);

    LandingPadInst* lpInst = LandingPadInst::Create(landing_pad_ty, 0, "",
      catch_block);
    lpInst->setCleanup(false);
    lpInst->addClause(ConstantPointerNull::get(i8p_ty));

    unsigned exnSlotIdx = 0;
    ExtractValueInst* exnSlot = ExtractValueInst::Create(lpInst,
      exnSlotIdx, "", catch_block);
    Value* ponyaExArgs[3] = {
      llf->arg_begin(),
      b.CreateLoad(last_tcg_op_local),
      exnSlot
    };
    CallInst* ponyaExCall = CallInst::Create(ofFunctionInHelperMod(llf_ponyaException),
      ArrayRef<Value*>(&ponyaExArgs[0], &ponyaExArgs[3]), "", catch_block);
    ponyaExCall->setTailCall(true);
    new UnreachableInst(llctx, catch_block);

    // save insert point
    BasicBlock* savedBB = b.GetInsertBlock();
    BasicBlock::iterator savedIt = b.GetInsertPoint();

    // make instructions to store values to CPU state
    b.SetInsertPoint(ponyaExCall);
    storeValues();

    // restore insert point
    b.SetInsertPoint(savedBB, savedIt);

    return catch_block;
  }
#endif
};

#ifndef CONFIG_PONYA
static string get_program_dir() {
  char buff[1024];
  ssize_t len = readlink("/proc/self/exe", buff, sizeof(buff));

  assert(len != -1);
  buff[len] = '\0';

  return dirname(buff);
}
#endif

static void diagnosticHandler(const DiagnosticInfo &DI, void *Context) {
  string ErrStorage;
  {
    raw_string_ostream OS(ErrStorage);
    DiagnosticPrinterRawOStream DP(OS);
    DI.print(DP);
  }                                                                                                      
  qemu_log("%s\n", ErrStorage.c_str());
  abort();
}

#endif

translator::translator(ObjectFile &O, LLVMContext &C, Module &M)
    : O(O), C(C), M(M), DL(M.getDataLayout()) {}

translator::~translator() {}

#if 0

TCGLLVMContextPrivate::TCGLLVMContextPrivate()
  : llctx(getGlobalContext()),
    void_ty(Type::getVoidTy(llctx)),
    i8_ty(IntegerType::get(llctx, 8)),
    i8p_ty(PointerType::get(i8_ty, 0)),
    i16_ty(IntegerType::get(llctx, 16)),
    i32_ty(IntegerType::get(llctx, 32)),
    i64_ty(IntegerType::get(llctx, 64)),
    func___gxx_personality_v0_ty(FunctionType::get(i32_ty, true)),
    func___cxa_begin_catch_ty(FunctionType::get(i8p_ty, i8p_ty, false)),
    func___cxa_end_catch_ty(FunctionType::get(void_ty, false)),

    landing_pad_field_tys{i8p_ty, i32_ty},
    landing_pad_ty(StructType::get(llctx,
      ArrayRef<Type*>(&landing_pad_field_tys[0],
                      &landing_pad_field_tys[2]), false)),
  
    b(llctx),
    max_tcg_label(0)

#ifndef CONFIG_PONYA
    , catch_block(nullptr),
    catch_dirty(false),
    func___gxx_personality_v0(nullptr),
    func___cxa_begin_catch(nullptr),
    func___cxa_end_catch(nullptr)
#endif
{
  static bool initOnce = false;
  if (!initOnce)
    initOnce = true;
  else
    abort();

  // initialize member fields for translation
  fill(tcg_label_to_llbb.begin(), tcg_label_to_llbb.end(), nullptr);
  fill(tcg_glb_syms.begin(), tcg_glb_syms.end(), nullptr);
  fill(tcg_glb_vals.begin(), tcg_glb_vals.end(), nullptr);
  fill(tcg_glb_vals_mod.begin(), tcg_glb_vals_mod.end(), nullptr);
  fill(tcg_glb_cpu_st_ptrs.begin(), tcg_glb_cpu_st_ptrs.end(), nullptr);

  InitializeNativeTarget();                                                      
  InitializeNativeTargetAsmPrinter();                                            
  InitializeNativeTargetAsmParser();                                             
  InitializeNativeTargetDisassembler();

  EnablePrettyStackTrace();
  llctx.setDiagnosticHandler(diagnosticHandler);

  // XXX do we need this?
  StringMap<cl::Option*>& optMap(cl::getRegisteredOptions());

  {
    auto optIt = optMap.find("enable-noalias-unique-cloning");
    if (optIt != optMap.end())
      ((cl::opt<bool>*)(*optIt).second)->setValue(false);
    else
      qemu_log("warning: could not set enable-noalias-unique-cloning\n");
  }

  {
    auto optIt = optMap.find("enable-noalias-to-md-conversion");
    if (optIt != optMap.end())
      ((cl::opt<bool>*)(*optIt).second)->setValue(false);
    else
      qemu_log("warning: could not set enable-noalias-to-md-conversion\n");
  }

#if 0
  {
    auto optIt = optMap.find("enable-dse-ssu");
    if (optIt != optMap.end())
      ((cl::opt<bool>*)(*optIt).second)->setValue(true);
    else
      qemu_log("warning: could not set enable-dse-ssu\n");
  }
#endif

  // get file path of helper bitcode
  const string helper_fp =
#ifdef CONFIG_PONYA
    _helper_fp
#else
    get_program_dir() + "/llvm-helpers-panda.bc"
#endif
  ;

  ponyalogload("helper bitcode", [&]{
    // read helper bitcode
    ErrorOr<unique_ptr<MemoryBuffer>> hlpFOrErr =
      MemoryBuffer::getFileOrSTDIN(helper_fp);
    if (error_code ec = hlpFOrErr.getError()) {
      qemu_log("error: could not parse helper bitcode file ('%s')\n", ec.message().c_str());
      abort();
    }

    ErrorOr<unique_ptr<Module>> llmErrOr = parseBitcodeFile(
      hlpFOrErr.get()->getMemBufferRef(), llctx);
    if (error_code ec = llmErrOr.getError()) {
      qemu_log("error: could not parse helper bitcode file ('%s')\n", ec.message().c_str());
      abort();
    }

    assert(llmErrOr.get().get());

    initial_llm = move(llmErrOr.get());
  });

  llm = initial_llm.get();

  // get datalayout
  dl = &;

  // get alias scopes
  NamedMDNode* scope_list_nmdn = llm->getNamedMetadata("ponya_alias_scope_list");
  assert(scope_list_nmdn && scope_list_nmdn->getNumOperands() == 1);

  alias_scope_list = scope_list_nmdn->getOperand(0);
  assert(alias_scope_list);

  // in ponya mode, set linkonce_odr linkage by default policy
#ifdef CONFIG_PONYA
  for (Module::iterator f_it = llm->begin(); f_it != llm->end(); ++f_it) {
    Function& f = *f_it;
    if (!f.isDeclaration())
      f.setLinkage(GlobalValue::LinkOnceODRLinkage);
  }

  // except! for these essential helper functions:
  // XXX TODO conditionally make these external, as we do not want multiple
  // copies of these lying around
#if 1
  //llm->getFunction("_ponya__start_llvm")->setLinkage(GlobalValue::ExternalLinkage);
  //llm->getFunction("_ponya_start_llvm")->setLinkage(GlobalValue::ExternalLinkage);
  //llm->getFunction("_ponya_syscall_open_linux_x86_64_llvm")->setLinkage(GlobalValue::ExternalLinkage);
  //llm->getFunction("_ponya_syscall_read_linux_x86_64_llvm")->setLinkage(GlobalValue::ExternalLinkage);
#endif
#endif

  // gather helper function stubs
  for (Module::iterator f_it = llm->begin(); f_it != llm->end(); ++f_it) {
    // skip declarations
    Function& f = *f_it;
    if (f.isDeclaration())
      continue;

    // does symbol imply it is a helper function stub?
    string sym = f.getName().str();
    const string prefix("helper_");
    const string suffix("_llvm");

    bool has_prefix = sym.size() >= prefix.size() &&
      sym.compare(0, prefix.size(), prefix) == 0;

    if (!has_prefix)
      continue;

    bool has_suffix = sym.size() >= suffix.size() &&
      sym.compare(sym.size() - suffix.size(), suffix.size(), suffix) == 0;

    if (!has_suffix)
      continue;

    registerHelperFunction(f);
  }

#ifndef CONFIG_PONYA
  func___gxx_personality_v0 = llm->getOrInsertFunction("__gxx_personality_v0",
    func___gxx_personality_v0_ty);
  ponyalogassert(func___gxx_personality_v0);
#endif

  const Attribute::AttrKind excAK = Attribute::UWTable;
  const AttributeSet mmuFnAS = AttributeSet::get(llctx,
    AttributeSet::FunctionIndex, excAK);
  Type* ldMMUFnPrms[2] = {wordType(), intType(sizeof(int)*8)};

  //
  // initialize table for MMU load functions
  //
  ponya_qemu_ld_helpers[0] = cast<Function>(
    llm->getOrInsertFunction("__ldb_mmu",
    FunctionType::get(i8_ty, ldMMUFnPrms, false), mmuFnAS));

  ponya_qemu_ld_helpers[1] = cast<Function>(
    llm->getOrInsertFunction("__ldw_mmu",
    FunctionType::get(i16_ty, ldMMUFnPrms, false), mmuFnAS));

  ponya_qemu_ld_helpers[2] = cast<Function>(
    llm->getOrInsertFunction("__ldl_mmu",
    FunctionType::get(i32_ty, ldMMUFnPrms, false), mmuFnAS));

  ponya_qemu_ld_helpers[3] = cast<Function>(
    llm->getOrInsertFunction("__ldq_mmu",
    FunctionType::get(i64_ty, ldMMUFnPrms, false), mmuFnAS));

  ponya_qemu_ld_helpers[4] = cast<Function>(
    llm->getOrInsertFunction("__ldq_mmu",
    FunctionType::get(i64_ty, ldMMUFnPrms, false), mmuFnAS));

  // panda ones
  ponya_panda_ld_helpers[0] = cast<Function>(
    llm->getOrInsertFunction("__ldb_mmu_panda",
    FunctionType::get(i8_ty, ldMMUFnPrms, false), mmuFnAS));

  ponya_panda_ld_helpers[1] = cast<Function>(
    llm->getOrInsertFunction("__ldw_mmu_panda",
    FunctionType::get(i16_ty, ldMMUFnPrms, false), mmuFnAS));

  ponya_panda_ld_helpers[2] = cast<Function>(
    llm->getOrInsertFunction("__ldl_mmu_panda",
    FunctionType::get(i32_ty, ldMMUFnPrms, false), mmuFnAS));

  ponya_panda_ld_helpers[3] = cast<Function>(
    llm->getOrInsertFunction("__ldq_mmu_panda",
    FunctionType::get(i64_ty, ldMMUFnPrms, false), mmuFnAS));

  ponya_panda_ld_helpers[4] = cast<Function>(
    llm->getOrInsertFunction("__ldq_mmu_panda",
    FunctionType::get(i64_ty, ldMMUFnPrms, false), mmuFnAS));

  //
  // initialize table for MMU store functions
  //
  Type* stbMMUFnPrms[3] = {wordType(), i8_ty, intType(sizeof(int)*8)};
  Type* stwMMUFnPrms[3] = {wordType(), i16_ty, intType(sizeof(int)*8)};
  Type* stlMMUFnPrms[3] = {wordType(), i32_ty, intType(sizeof(int)*8)};
  Type* stqMMUFnPrms[3] = {wordType(), i64_ty, intType(sizeof(int)*8)};

  ponya_qemu_st_helpers[0] = cast<Function>(
    llm->getOrInsertFunction("__stb_mmu",
    FunctionType::get(void_ty, stbMMUFnPrms, false), mmuFnAS));

  ponya_qemu_st_helpers[1] = cast<Function>(
    llm->getOrInsertFunction("__stw_mmu",
    FunctionType::get(void_ty, stwMMUFnPrms, false), mmuFnAS));

  ponya_qemu_st_helpers[2] = cast<Function>(
    llm->getOrInsertFunction("__stl_mmu",
    FunctionType::get(void_ty, stlMMUFnPrms, false), mmuFnAS));

  ponya_qemu_st_helpers[3] = cast<Function>(
    llm->getOrInsertFunction("__stq_mmu",
    FunctionType::get(void_ty, stqMMUFnPrms, false), mmuFnAS));

  ponya_qemu_st_helpers[4] = cast<Function>(
    llm->getOrInsertFunction("__stq_mmu",
    FunctionType::get(void_ty, stqMMUFnPrms, false), mmuFnAS));

  // panda ones
  ponya_panda_st_helpers[0] = cast<Function>(
    llm->getOrInsertFunction("__stb_mmu_panda",
    FunctionType::get(void_ty, stbMMUFnPrms, false), mmuFnAS));

  ponya_panda_st_helpers[1] = cast<Function>(
    llm->getOrInsertFunction("__stw_mmu_panda",
    FunctionType::get(void_ty, stwMMUFnPrms, false), mmuFnAS));

  ponya_panda_st_helpers[2] = cast<Function>(
    llm->getOrInsertFunction("__stl_mmu_panda",
    FunctionType::get(void_ty, stlMMUFnPrms, false), mmuFnAS));

  ponya_panda_st_helpers[3] = cast<Function>(
    llm->getOrInsertFunction("__stq_mmu_panda",
    FunctionType::get(void_ty, stqMMUFnPrms, false), mmuFnAS));

  ponya_panda_st_helpers[4] = cast<Function>(
    llm->getOrInsertFunction("__stq_mmu_panda",
    FunctionType::get(void_ty, stqMMUFnPrms, false), mmuFnAS));

  // if not ponya mode, create JIT engine
#ifndef CONFIG_PONYA
  ponyaloginitialize("JIT engine", [&]{
    orcdynlljit.reset(new ponya::OrcDynamicJIT(llm));
  });
#endif

#if 0
  for (Module::iterator f_it = llm->begin(); f_it != llm->end(); ++f_it) {
    Function& f = *f_it;
    if (f.isDeclaration() || !f.hasDefaultVisibility())
      continue;

    auto llf_jit_sym = orc_lljit->findSymbolIn(orc_lljit_handle, f.getName());
    uint64_t jitted_addr = (uint64_t)
      OrcDynamicJIT::fromTargetAddress<tcg_tc_ptr_t>(llf_jit_sym.getAddress());

    qemu_log("%s at %#lx\n", f.getName().str().c_str(), jitted_addr);
  }
#endif

  // get various stubs
  llf_ponyaCallStub1 = llm->getFunction("_ponyaCallStub1_llvm");
  llf_ponyaCallStub2 = llm->getFunction("_ponyaCallStub2_llvm");
  llf_ponyaRetStub   = llm->getFunction("_ponyaRetStub_llvm");
  llf_ponyaDoLongjmp = llm->getFunction("_ponyaDoLongjmp_llvm");
#ifndef CONFIG_PONYA
  llf_ponyaException = llm->getFunction("_ponyaException_llvm");
#endif
#ifdef CONFIG_PONYA
  // declare stub for indirect jumps
  llf_ponyaIndirectJump = Function::Create(
    FunctionType::get(void_ty, wordType(), false),
    GlobalValue::ExternalLinkage,
    "_ponyaIndirectJump",
    llm);
#endif

  ponyalogassert(llf_ponyaCallStub1);
  ponyalogassert(llf_ponyaCallStub2);
  ponyalogassert(llf_ponyaRetStub);
  ponyalogassert(llf_ponyaDoLongjmp);
#ifndef CONFIG_PONYA
  ponyalogassert(llf_ponyaException);
#endif
#ifdef CONFIG_PONYA
  ponyalogassert(llf_ponyaIndirectJump);
#endif

  // these can be internal
  llf_ponyaCallStub1->setLinkage(GlobalValue::InternalLinkage);
  llf_ponyaCallStub2->setLinkage(GlobalValue::InternalLinkage);
  llf_ponyaRetStub->setLinkage(GlobalValue::InternalLinkage);

  // get various types
  ponyaCallStubCPUStatePtrTy = llf_ponyaCallStub1->arg_begin()->getType();
  auto callStubArgIt = llf_ponyaCallStub1->arg_begin();
  ++callStubArgIt;
  ++callStubArgIt;
  ponyaCallStubDecompiledBBFuncTy = callStubArgIt->getType();

  // get cpu state type we are using
  cpu_state_ptr_ty = cast<PointerType>(ponyaCallStubCPUStatePtrTy);
  cpu_state_ty = cast<StructType>(cpu_state_ptr_ty->getElementType());

  // compute our llvm function prototype
#ifdef CONFIG_PONYA
  Type* argtys[2] = {cpu_state_ptr_ty, cpu_state_ptr_ty};
  fty = FunctionType::get(void_ty, argtys, false);
#else
  fty = FunctionType::get(wordType(), cpu_state_ptr_ty, false);
#endif

  // get target machine
  tm = GetTargetMachine(Triple(llm->getTargetTriple()));

  // initialize tcg global GEP indices table
  fillTCGExtTempOffToGEPIndicesMap();

  // XXX DBG
#if 0
  for (auto& hf : helpers) {
    outs() << hf.second->f->getName() << " " << *hf.second->f->getFunctionType() << "\n";
    outs().flush();
  }
#endif

  ponyalogassert(!verify());

  // if ponya mode, set up the global optimizer pipeline.
#ifdef CONFIG_PONYA
  fpm = makeFPM(llm);
  fpm->doInitialization();
#endif
}

TCGLLVMContextPrivate::~TCGLLVMContextPrivate()
{
}

enum HELPER_METADATA_TYPE {
  HMT_INPUTS,
  HMT_OUTPUTS,
  HMT_ALIAS_ANALYSIS,
  HMT_HAS_CPU_STATE_PARAMETER,
  HMT_HAS_EXTRA_CPU_STATE_PARAMETER
};

void TCGLLVMContextPrivate::registerHelperFunction(Function& f)
{
#ifndef CONFIG_PONYA
  ponyalogassert(f.getLinkage() == GlobalValue::ExternalLinkage);
#endif

  /* XXX DBG */
#if 0
  cerr << f.getName().str() << endl;
#endif

  // get the metadata associated with f, and parse it to determine what type of
  // helper function are we registering
  HELPER_TYPE h_ty = PONYA_HELPER;
  unique_ptr<PonyaHelperSimple> phs(new PonyaHelperSimple);
  unique_ptr<PonyaHelper> ph(new PonyaHelper);

  NamedMDNode* f_nmdn = llm->getNamedMetadata(f.getName());
  if (!f_nmdn) {
    // no metadata associated with f. => f does not have a CPU state parameter,
    // and no tcg_inputs or tcg_outputs were promoted. it's a simple helper function.
    h_ty = PONYA_HELPER_SIMPLE;
  } else {
    if (f_nmdn->getNumOperands() > 0)
      h_ty = PONYA_HELPER;

    for (unsigned i = 0; i < f_nmdn->getNumOperands(); ++i) {
      MDNode* mdn = f_nmdn->getOperand(i);
      assert(mdn->getNumOperands() >= 2);
      Metadata* M = mdn->getOperand(0);
      assert(isa<ConstantAsMetadata>(M));
      ConstantAsMetadata* CAsM = cast<ConstantAsMetadata>(M);
      Constant* C = CAsM->getValue();
      assert(isa<ConstantInt>(C));
      ConstantInt* CI = cast<ConstantInt>(C);

      HELPER_METADATA_TYPE hm_ty =
        static_cast<HELPER_METADATA_TYPE>(CI->getZExtValue());
      switch (hm_ty) {
        case HMT_INPUTS: {
          Metadata* IM = mdn->getOperand(1);
          assert(isa<MDNode>(IM));
          MDNode* MDN = cast<MDNode>(IM);

          /* XXX DBG */
#if 0
          cerr << "  tcg_inputs:" << endl;
#endif
          for (unsigned j = 0; j + 1 < MDN->getNumOperands(); j += 2) {
            Metadata* offM  = MDN->getOperand(j);
            Metadata* sizeM = MDN->getOperand(j + 1);

            assert(isa<ConstantAsMetadata>(offM));
            assert(isa<ConstantAsMetadata>(sizeM));

            Constant* offC  = cast<ConstantAsMetadata>(offM)->getValue();
            Constant* sizeC = cast<ConstantAsMetadata>(sizeM)->getValue();

            assert(isa<ConstantInt>(offC));
            assert(isa<ConstantInt>(sizeC));

            ConstantInt* offCI  = cast<ConstantInt>(offC);
            ConstantInt* sizeCI = cast<ConstantInt>(sizeC);

            /* XXX DBG */
#if 0
            cerr << "    " << dec << sizeCI->getZExtValue() << ' ' << offCI->getZExtValue() << endl;
#endif
            ph->promotedInputs.add(tcg_global_t(
              g[sizeCI->getZExtValue()],
              offCI->getZExtValue()));
          }
          break; }
        case HMT_OUTPUTS: {
          Metadata* OM = mdn->getOperand(1);
          assert(isa<MDNode>(OM));
          MDNode* MDN = cast<MDNode>(OM);

          /* XXX DBG */
#if 0
          cerr << "  tcg_outputs:" << endl;
#endif
          for (unsigned j = 0; j + 1 < MDN->getNumOperands(); j += 2) {
            Metadata* offM  = MDN->getOperand(j);
            Metadata* sizeM = MDN->getOperand(j + 1);

            assert(isa<ConstantAsMetadata>(offM));
            assert(isa<ConstantAsMetadata>(sizeM));

            Constant* offC  = cast<ConstantAsMetadata>(offM)->getValue();
            Constant* sizeC = cast<ConstantAsMetadata>(sizeM)->getValue();

            assert(isa<ConstantInt>(offC));
            assert(isa<ConstantInt>(sizeC));

            ConstantInt* offCI  = cast<ConstantInt>(offC);
            ConstantInt* sizeCI = cast<ConstantInt>(sizeC);

            /* XXX DBG */
#if 0
            cerr << "    " << dec << sizeCI->getZExtValue() << ' ' << offCI->getZExtValue() << endl;
#endif
            ph->promotedOutputs.add(tcg_global_t(
              g[sizeCI->getZExtValue()],
              offCI->getZExtValue()));
          }
          break; }
        case HMT_ALIAS_ANALYSIS: {
          // XXX DBG
#if 0
          errs() << f.getName() << "\n";
          errs() << *mdn << "\n";
          for (unsigned j = 0; j < mdn->getNumOperands(); ++j)
            errs() << *mdn->getOperand(j) << "\n";
#endif

          Metadata* refM = mdn->getOperand(1);
          assert(isa<MDNode>(refM));
          MDNode* refMDN = cast<MDNode>(refM);

          /* XXX DBG */
#if 0
          cerr << "  ref alias analysis:" << endl;
#endif
          for (unsigned j = 0; j + 1 < refMDN->getNumOperands(); j += 2) {
            Metadata* begM = refMDN->getOperand(j);
            Metadata* endM = refMDN->getOperand(j + 1);

            assert(isa<ConstantAsMetadata>(begM));
            assert(isa<ConstantAsMetadata>(endM));

            Constant* begC = cast<ConstantAsMetadata>(begM)->getValue();
            Constant* endC = cast<ConstantAsMetadata>(endM)->getValue();

            assert(isa<ConstantInt>(begC));
            assert(isa<ConstantInt>(endC));

            ConstantInt* begCI = cast<ConstantInt>(begC);
            ConstantInt* endCI = cast<ConstantInt>(endC);

            unsigned beg = begCI->getZExtValue();
            unsigned end = endCI->getZExtValue();

            /* XXX DBG */
#if 0
            cerr << "    MAX:" << dec << ponyaCPUStateSize << endl;
            cerr << "    [" << dec << beg << ", " << end << ")" << endl;
#endif

            for (unsigned off = beg; off < end; ++off)
              ph->ref.add(tcg_global_t(PONYA_TGS_8, off));
          }

          Metadata* modM = mdn->getOperand(2);
          assert(isa<MDNode>(modM));
          MDNode* modMDN = cast<MDNode>(modM);

          /* XXX DBG */
#if 0
          cerr << "  llm alias analysis:" << endl;
#endif
          for (unsigned j = 0; j + 1 < modMDN->getNumOperands(); j += 2) {
            Metadata* begM = modMDN->getOperand(j);
            Metadata* endM = modMDN->getOperand(j + 1);

            assert(isa<ConstantAsMetadata>(begM));
            assert(isa<ConstantAsMetadata>(endM));

            Constant* begC = cast<ConstantAsMetadata>(begM)->getValue();
            Constant* endC = cast<ConstantAsMetadata>(endM)->getValue();

            assert(isa<ConstantInt>(begC));
            assert(isa<ConstantInt>(endC));

            ConstantInt* begCI = cast<ConstantInt>(begC);
            ConstantInt* endCI = cast<ConstantInt>(endC);

            unsigned beg = begCI->getZExtValue();
            unsigned end = endCI->getZExtValue();

            for (unsigned off = beg; off < end; ++off)
              ph->mod.add(tcg_global_t(PONYA_TGS_8, off));

            /* XXX DBG */
#if 0
            cerr << "    [" << dec << beg << ", " << end << ")" << endl;
#endif
          }
          break; }
        case HMT_HAS_CPU_STATE_PARAMETER:
          ph->passesCPUStateArg = true;
          break;
        case HMT_HAS_EXTRA_CPU_STATE_PARAMETER:
          ph->isCPUStateArgNew = true;
          break;
      }
    }
  }

  // remove prefix
  string tcg_sym(f.getName());
  {
    const string prefix("helper_");
    if (tcg_sym.size() >= prefix.size() &&
        tcg_sym.compare(0, prefix.size(), prefix) == 0)
      tcg_sym = tcg_sym.erase(0, prefix.size());
    else
      ponyalogassert(false);
  }

  // remove suffix
  {
    const string suffix("_llvm");
    if (tcg_sym.size() >= suffix.size() &&
        tcg_sym.compare(tcg_sym.size() - suffix.size(), suffix.size(),
          suffix) == 0)
      tcg_sym = tcg_sym.substr(0, tcg_sym.size() - suffix.size());
    else
      ponyalogassert(false);
  }

  // add helper to table
  switch (h_ty) {
    case PONYA_HELPER_SIMPLE:
      /* XXX DBG */
#if 0
      cerr << "  (0)" << endl;
#endif
      phs->f = &f;
      helpers[tcg_sym] = phs.release();
      break;
    case PONYA_HELPER:
      /* XXX DBG */
#if 0
      cerr << "  (1)" << endl;
#endif
      ph->f = &f;
      helpers[tcg_sym] = ph.release();
      break;
    default:
      assert(false);
  }
}

void TCGLLVMContextPrivate::setCPUStateSize(size_t s)
{
  assert(ponyaCPUStateSize == s);
}

void TCGLLVMContextPrivate::cpuStateField(uint64_t off, const char* sym)
{
  tcg_glb_syms[tcg_global_t(PONYA_TGS_8, off)] = sym;
}

void TCGLLVMContextPrivate::fillTCGExtTempOffToGEPIndicesMapSub(Type* ty,
    vector<Value*> indices,
    std::list<vector<Value*> > out[4])
{
  if (ty->isAggregateType()) {
    if (ty->getTypeID() == Type::StructTyID) {
      StructType* stct_ty = cast<StructType>(ty);

      for (unsigned int i = 0; i < stct_ty->getNumElements(); ++i) {
        vector<Value*> indices2(indices);
        indices2.push_back(ConstantInt::get(intType(32), i));

        fillTCGExtTempOffToGEPIndicesMapSub(stct_ty->getElementType(i),
            indices2, out);
      }
    } else if (ty->getTypeID() == Type::ArrayTyID) {
      ArrayType* arr_ty = cast<ArrayType>(ty);
      for (unsigned int i = 0; i < arr_ty->getNumElements(); ++i) {
        vector<Value*> indices2(indices);
        indices2.push_back(ConstantInt::get(intType(32), i));

        fillTCGExtTempOffToGEPIndicesMapSub(arr_ty->getElementType(),
            indices2, out);
      }
    } else {
      assert(false);
    }
  } else if (ty->isSingleValueType()) {
    int byte_count = dl->getTypeAllocSize(ty);
    if (byte_count == 1 ||
        byte_count == 2 ||
        byte_count == 4 ||
        byte_count == 8) {
      tcg_global_size_t size = g[byte_count];
      out[size].push_back(indices);
    } else {
      assert(false);
    }
  } else {
    assert(false);
  }
}

uint64_t TCGLLVMContextPrivate::byteOffsetOfGEPIndicesSub(Type* ty,
    vector<Value*>& indices,
    vector<Value*>::iterator index,
    uint64_t byte_offset) const {
  if (index == indices.end())
    return byte_offset;

  Value* idx_ = *index++;
  assert(isa<ConstantInt>(idx_));
  unsigned idx = static_cast<unsigned>(cast<ConstantInt>(idx_)->getZExtValue());

  if (ty->isAggregateType()) {
    if (ty->getTypeID() == Type::StructTyID) {
      StructType* stct_ty = cast<StructType>(ty);
      Type* elt_ty = stct_ty->getElementType(idx);

      const StructLayout *SL = dl->getStructLayout(stct_ty);
      return byteOffsetOfGEPIndicesSub(elt_ty, indices, index, byte_offset + SL->getElementOffset(idx));
    } else if (ty->getTypeID() == Type::ArrayTyID) {
      ArrayType* arr_ty = cast<ArrayType>(ty);
      Type* elt_ty = arr_ty->getElementType();

      return byteOffsetOfGEPIndicesSub(elt_ty, indices, index,
          byte_offset + idx*(dl->getTypeAllocSize(elt_ty)));
    } else {
      assert(false);
    }
  } else {
    assert(false);
  }
  return true;                 
}

tcg_global_offset_t TCGLLVMContextPrivate::byteOffsetOfGEPIndices(Type* base_ty,
   vector<Value*>& indices) const {
  assert(indices.begin() != indices.end() &&
         "Must provide nonempty indices");

  return byteOffsetOfGEPIndicesSub(base_ty, indices, indices.begin(), 0);
}

void TCGLLVMContextPrivate::fillTCGExtTempOffToGEPIndicesMap()
{
  std::list<vector<Value*> > elt_indices_by_size[4];

  for (unsigned int i = 0; i < cpu_state_ty->getNumElements(); ++i) {
    vector<Value*> starting_indices(1, ConstantInt::get(intType(32), i));
    fillTCGExtTempOffToGEPIndicesMapSub(cpu_state_ty->getElementType(i),
      starting_indices, elt_indices_by_size);
  }

  for (tcg_global_size_t size = 0; size < 4; ++size) {
    for (auto it = elt_indices_by_size[size].begin();
         it != elt_indices_by_size[size].end(); ++it) {
      vector<Value*>& indices = *it;

      tcg_global_offset_t off = byteOffsetOfGEPIndices(cpu_state_ty, indices);

      // these are really for cpu_state_ptr_ty
      indices.insert(indices.begin(), ConstantInt::get(wordType(), 0));
      tcg_glb_gep_idxs[tcg_global_t(size, off)] = indices;
    }
  }
}

Value* TCGLLVMContextPrivate::generateQemuMemOp(bool ld, Value *value, Value *addr, int mem_index, int bits)
{
  assert(addr->getType() == intType(TARGET_LONG_BITS));
  assert(ld || value->getType() == intType(bits));
  assert(TCG_TARGET_REG_BITS == 64); //XXX

#ifndef CONFIG_PONYA
  vector<Value*> argValues;
  argValues.reserve(3);
  argValues.push_back(addr);
  if (!ld)
    argValues.push_back(value);
  argValues.push_back(ConstantInt::get(intType(8*sizeof(int)), mem_index));

  vector<Type*> argTypes;
  argTypes.reserve(3);
  for(int i=0; i<(ld?2:3); ++i)
    argTypes.push_back(argValues[i]->getType());

  Function* hf;
  if (panda_use_memcb)
    hf = ld ? ponya_panda_ld_helpers[bits>>4] : ponya_panda_st_helpers[bits>>4];
  else
    hf = ld ? ponya_qemu_ld_helpers[bits>>4] : ponya_qemu_st_helpers[bits>>4];
  hf = ofFunctionInHelperMod(hf);

  Value* res = NULL;

  BasicBlock* normalSucc = BasicBlock::Create(llctx);
  if (ld) {
    Value* ldPrms[2] = {
      addr,
      ConstantInt::get(intType(8*sizeof(int)), mem_index)
    };

    res = b.CreateInvoke(hf, normalSucc, ponyaCatchBlock(), ldPrms, "");
  } else {
    Value* stPrms[3] = {
      addr,
      value,
      ConstantInt::get(intType(8*sizeof(int)), mem_index)
    };

    b.CreateInvoke(hf, normalSucc, ponyaCatchBlock(), stPrms, "");
  }
  llf->getBasicBlockList().push_back(normalSucc);
  b.SetInsertPoint(normalSucc);

  return res;
#else
  vector<Value*> argValues2;
  addr = b.CreateZExt(addr, wordType());
  addr = b.CreateIntToPtr(addr, intPtrType(bits));
  if (ld) {
    return ponyaGuestMemOp(b.CreateLoad(addr));
  } else {
    ponyaGuestMemOp(b.CreateStore(value, addr));
    return NULL;
  }
#endif
}

int TCGLLVMContextPrivate::generateOperation(int opc, const TCGArg *args)
{
  Value *v;
  TCGOpDef &def = tcg_op_defs[opc];
  int nb_args = def.nb_args;

  switch(opc) {
  case INDEX_op_debug_insn_start:
    break;

  /* predefined ops */
  case INDEX_op_nop:
  case INDEX_op_nop1:
  case INDEX_op_nop2:
  case INDEX_op_nop3:
    break;

  case INDEX_op_nopn:
    nb_args = args[0];
    break;

  case INDEX_op_discard:
    break;

  case INDEX_op_call: {
    // compute numbers of tcg_inputs and tcg_outputs
    int nb_oargs = args[0] >> 16;
    int nb_iargs = args[0] & 0xffff;
    nb_args = nb_oargs + nb_iargs + def.nb_cargs + 1;
    assert(nb_oargs == 0 || nb_oargs == 1);

    // compute helper function symbol
    tcg_target_ulong helperAddrC = args[-1]; // XXX
    const char* helperName = tcg_helper_get_name(tcgctx,
                                                 (void*)helperAddrC);
    assert(helperName);

    QEMUHelper temp_qh;

    // look up helper function. is there a ponya version?
    auto it = helpers.find(helperName);
    Helper* h;
    if (unlikely(it == helpers.end())) {
#ifndef CONFIG_PONYA
      qemu_log("warning: calling QEMU helper function '%s'\n", helperName);
#endif

      vector<Type*> argTypes;
      argTypes.reserve(nb_iargs-1);
      for(int i=0; i < nb_iargs-1; ++i) {
        TCGArg arg = args[nb_oargs + i + 1];
        if(arg != TCG_CALL_DUMMY_ARG) {
          Value *v = getValueOfTCGArg(arg);
          argTypes.push_back(v->getType());
        }
      }

      Type* retType = nb_oargs == 0 ?
          Type::getVoidTy(llctx) : wordType(getValueBits(args[1]));
      Function* helperFunc = cast<Function>(llm->getOrInsertFunction(
            string("helper_") + helperName,
            FunctionType::get(retType, argTypes, false)));

      temp_qh.f = helperFunc;
      h = &temp_qh;
    } else {
      h = (*it).second;
    }

    // compute argument list
    Function::arg_iterator param_it = h->f->arg_begin();
    vector<Value*> argValues;
    argValues.reserve(nb_iargs*2);
    for (int i = 0; i < nb_iargs-1; ++i) {
      TCGArg arg = args[nb_oargs + i + 1];
      if (arg == TCG_CALL_DUMMY_ARG)
        continue;

      Value* param = param_it++;
      Type* param_ty = param->getType();

      /* TCG CPU state field pointer argument? */
      if (unlikely(arg >= TCG_MAX_TEMPS)) {
        cerr << "warning: passing TCG CPU field for " << helperName << endl;

        /* CPU state field pointer */
        tcg_global_t gl;
        gl.size = PONYA_TGS_8; /* XXX doesn't matter */
        gl.offs = arg - TCG_MAX_TEMPS;

        /* if we have a global for the given offset, pass the global's local.
         * otherwise construct a pointer for the given offset */
        if (unlikely(tcg_globals.exists(gl))) {
          /* note: we assume that the accesses in the given helper are contained
           * within gl.size (unsound) */
          v = tcg_glb_vals[gl];
        } else {
          v = getCPUStatePtrOfGlobal(gl);
        }

        /* probably something like pointer to XMMReg */
        if (likely(v->getType() != param_ty))
          v = b.CreatePointerCast(v, param_ty);
      } else {
        /* regular TCGArg */
        v = getValueOfTCGArg(arg);

        if (unlikely(v->getType() != param_ty)) {
          if (likely(param_ty->isPointerTy())) {
            v = b.CreateIntToPtr(v, param_ty);
          } else {
            errs() << "unable to call helper (#1) " << helperName << '\n' <<
              "param type: " << *param_ty << '\n' <<
              "v: " << *v << '\n' <<
              "helper llvm function type: " << *h->f->getType() << '\n';
            errs().flush();
            exit(1);
          }
        }
      }

      argValues.push_back(v);
    }

    auto doCall = [&] () -> Instruction* {
      Function& f = *h->f;

      if (param_it != f.arg_end()) {
        cerr << "bad call instruction for " << f.getName().str() << endl;
        exit(1);
      }

      Function* _f = ofFunctionInHelperMod(&f);

#ifndef CONFIG_PONYA
      if (h->doesAccessCPUState() && !f.hasFnAttribute(Attribute::NoUnwind)) {
        // generate invoke and lazily create catch basic block
        BasicBlock* normalSucc = BasicBlock::Create(llctx);
        InvokeInst* res = b.CreateInvoke(_f, normalSucc, ponyaCatchBlock(),
          ArrayRef<Value*>(argValues), "");
        llf->getBasicBlockList().push_back(normalSucc);
        b.SetInsertPoint(normalSucc);
        return res;
      } else {
#endif
        // generate call
        CallInst* CI = b.CreateCall(_f, ArrayRef<Value*>(argValues));
        CI->setTailCall(true);
        return CI;
#ifndef CONFIG_PONYA
      }
#endif
    };

    switch (h->getType()) {
      case QEMU_HELPER: {
        storeValues();
        Instruction* result = doCall();
        loadValues();
        if (nb_oargs == 1)
          setValueOfTCGArg(args[1], result);
        break; }
      case PONYA_HELPER_SIMPLE: {
        Instruction* result = doCall();
        if (nb_oargs == 1)
          setValueOfTCGArg(args[1], result);
        break; }
      case PONYA_HELPER: {
        PonyaHelper* ph = static_cast<PonyaHelper*>(h);

        if (ph->isCPUStateArgNew) {
#ifdef CONFIG_PONYA
          Function::arg_iterator llfa = llf->arg_begin();
          ++llfa;
          argValues.push_back(llfa);
#else
          argValues.push_back(llf->arg_begin());
#endif
          ++param_it;
        }

        for (auto it = ph->promotedInputs.begin();
             it != ph->promotedInputs.end(); ++it) {
          Value* arg = getValueOfGlobal(*it);
          Type* param_ty = param_it->getType();

          if (likely(arg->getType() == param_ty)) {
            argValues.push_back(arg);
          } else if (param_ty->isPointerTy()) {
            argValues.push_back(b.CreateIntToPtr(arg, param_ty));
          } else {
            errs() << "unable to call helper (#2) " << helperName << '\n' <<
              "param type: " << *param_ty << '\n' <<
              "v: " << *arg << '\n' <<
              "helper llvm function type: " << *h->f->getType() << '\n';
            errs().flush();
            exit(1);
          }

          ++param_it;
        }

        storeNeccessaryValues(ph);
        Instruction* result = doCall();
        loadNeccessaryValues(ph);

        unsigned retIdx = 0;
        if (nb_oargs == 1) {
          if (ph->promotedOutputs.begin() == ph->promotedOutputs.end()) {
            setValueOfTCGArg(args[1], result);
          } else {
            setValueOfTCGArg(args[1], b.CreateExtractValue(result, retIdx));
            ++retIdx;
          }
        }
        for (auto it = ph->promotedOutputs.begin();
             it != ph->promotedOutputs.end(); ++it, ++retIdx)
          setValueOfGlobal(*it, b.CreateExtractValue(result, retIdx));
        break; }
    }
    break; }

  case INDEX_op_br:
    b.CreateBr(getLabel(args[0]));
    startNewBasicBlock();
    break;

#define __OP_BRCOND_C(tcg_cond, cond)\
  case tcg_cond:\
    v = b.CreateICmp ## cond(\
      getValueOfTCGArg(args[0]), getValueOfTCGArg(args[1])); \
  break;

#define __OP_BRCOND(opc_name, bits)\
  case opc_name: {\
    assert(getValueOfTCGArg(args[0])->getType() == intType(bits)); \
    assert(getValueOfTCGArg(args[1])->getType() == intType(bits)); \
    switch(args[2]) {\
      __OP_BRCOND_C(TCG_COND_EQ,   EQ)\
      __OP_BRCOND_C(TCG_COND_NE,   NE)\
      __OP_BRCOND_C(TCG_COND_LT,  SLT)\
      __OP_BRCOND_C(TCG_COND_GE,  SGE)\
      __OP_BRCOND_C(TCG_COND_LE,  SLE)\
      __OP_BRCOND_C(TCG_COND_GT,  SGT)\
      __OP_BRCOND_C(TCG_COND_LTU, ULT)\
      __OP_BRCOND_C(TCG_COND_GEU, UGE)\
      __OP_BRCOND_C(TCG_COND_LEU, ULE)\
      __OP_BRCOND_C(TCG_COND_GTU, UGT)\
      default:\
        tcg_abort();\
    }\
    BasicBlock* bb = BasicBlock::Create(llctx);\
    b.CreateCondBr(v, getLabel(args[3]), bb);\
    startNewBasicBlock(bb);\
  } break;

  __OP_BRCOND(INDEX_op_brcond_i32, 32)

#if TCG_TARGET_REG_BITS == 64
  __OP_BRCOND(INDEX_op_brcond_i64, 64)
#endif

#undef __OP_BRCOND_C
#undef __OP_BRCOND

#define __OP_SETCOND_C(tcg_cond, cond)\
          case tcg_cond:\
              v = b.CreateICmp ## cond(v1, v2); \
          break;

#define __OP_SETCOND(opc_name, bits)\
  case opc_name: {\
    Value* v1  = getValueOfTCGArg(args[1]);\
    Value* v2  = getValueOfTCGArg(args[2]);\
    assert(v1->getType() == intType(bits));\
    assert(v2->getType() == intType(bits));\
    switch(args[3]) {\
      __OP_SETCOND_C(TCG_COND_EQ,   EQ)\
      __OP_SETCOND_C(TCG_COND_NE,   NE)\
      __OP_SETCOND_C(TCG_COND_LT,  SLT)\
      __OP_SETCOND_C(TCG_COND_GE,  SGE)\
      __OP_SETCOND_C(TCG_COND_LE,  SLE)\
      __OP_SETCOND_C(TCG_COND_GT,  SGT)\
      __OP_SETCOND_C(TCG_COND_LTU, ULT)\
      __OP_SETCOND_C(TCG_COND_GEU, UGE)\
      __OP_SETCOND_C(TCG_COND_LEU, ULE)\
      __OP_SETCOND_C(TCG_COND_GTU, UGT)\
      default:\
        tcg_abort();\
    }\
    BasicBlock* bb = BasicBlock::Create(llctx, "setZero");\
    BasicBlock* finished = BasicBlock::Create(llctx, "done");\
    BasicBlock* bbSet = BasicBlock::Create(llctx, "setOne"); \
    b.CreateCondBr(v, bbSet, bb);\
    llf->getBasicBlockList().push_back(bbSet);\
    b.SetInsertPoint(bbSet);\
    setValueOfTCGArg(args[0], ConstantInt::get(intType(bits), 1));\
    /*delValue(args[0]);                                      */ \
    b.CreateBr(finished);\
    llf->getBasicBlockList().push_back(bb);\
    b.SetInsertPoint(bb);\
    setValueOfTCGArg(args[0], ConstantInt::get(intType(bits), 0));\
    /*delValue(args[0]);                                      */ \
    b.CreateBr(finished);\
    llf->getBasicBlockList().push_back(finished);\
    b.SetInsertPoint(finished);\
  } break;

  __OP_SETCOND(INDEX_op_setcond_i32, 32)

#if TCG_TARGET_REG_BITS == 64
  __OP_SETCOND(INDEX_op_setcond_i64, 64)
#endif

#undef __OP_SETCOND_C
#undef __OP_SETCOND

  case INDEX_op_set_label:
    assert(getLabel(args[0])->getParent() == 0);
    startNewBasicBlock(getLabel(args[0]));
    break;

  case INDEX_op_movi_i32:
    setValueOfTCGArg(args[0], ConstantInt::get(intType(32), args[1]));
    break;

  case INDEX_op_mov_i32:
    // Move operation may perform truncation of the value
    assert(getValueOfTCGArg(args[1])->getType() == intType(32) ||
            getValueOfTCGArg(args[1])->getType() == intType(64));
    setValueOfTCGArg(args[0],
            b.CreateTrunc(getValueOfTCGArg(args[1]), intType(32)));
    break;

#if TCG_TARGET_REG_BITS == 64
  case INDEX_op_movi_i64:
    setValueOfTCGArg(args[0], ConstantInt::get(intType(64), args[1]));
    break;

  case INDEX_op_mov_i64:
    assert(getValueOfTCGArg(args[1])->getType() == intType(64));
    setValueOfTCGArg(args[0], getValueOfTCGArg(args[1]));
    break;
#endif

  /* size extensions */
#define __EXT_OP(opc_name, truncBits, opBits, signE )\
  case opc_name:\
    setValueOfTCGArg(args[0], b.Create ## signE ## Ext(\
            b.CreateTrunc(\
                getValueOfTCGArg(args[1]), intType(truncBits)),\
            intType(opBits)));\
    break;

  __EXT_OP(INDEX_op_ext8s_i32,   8, 32, S)
  __EXT_OP(INDEX_op_ext8u_i32,   8, 32, Z)
  __EXT_OP(INDEX_op_ext16s_i32, 16, 32, S)
  __EXT_OP(INDEX_op_ext16u_i32, 16, 32, Z)

#if TCG_TARGET_REG_BITS == 64
  __EXT_OP(INDEX_op_ext8s_i64,   8, 64, S)
  __EXT_OP(INDEX_op_ext8u_i64,   8, 64, Z)
  __EXT_OP(INDEX_op_ext16s_i64, 16, 64, S)
  __EXT_OP(INDEX_op_ext16u_i64, 16, 64, Z)
  __EXT_OP(INDEX_op_ext32s_i64, 32, 64, S)
  __EXT_OP(INDEX_op_ext32u_i64, 32, 64, Z)
#endif

#undef __EXT_OP

  /* load/store */
#define __LD_OP(opc_name, memBits, regBits, signE)\
  case opc_name:\
    assert(getValueOfTCGArg(args[1])->getType() == wordType()); \
    v = b.CreateAdd(getValueOfTCGArg(args[1]),\
                ConstantInt::get(wordType(), args[2])); \
    v = b.CreateIntToPtr(v, intPtrType(memBits));\
    v = ponyaGuestMemOp(b.CreateLoad(v));\
    setValueOfTCGArg(args[0], b.Create ## signE ## Ext(\
                v, intType(regBits)));\
    break;

#define __ST_OP(opc_name, memBits, regBits)\
  case opc_name:  {\
    assert(getValueOfTCGArg(args[0])->getType() == intType(regBits)); \
    assert(getValueOfTCGArg(args[1])->getType() == wordType());\
    Value* valueToStore = getValueOfTCGArg(args[0]);\
    v = b.CreateAdd(getValueOfTCGArg(args[1]),\
                ConstantInt::get(wordType(), args[2]));\
    v = b.CreateIntToPtr(v, intPtrType(memBits));\
    ponyaGuestMemOp(b.CreateStore(b.CreateTrunc(\
            valueToStore, intType(memBits)), v));\
  } break;

  __LD_OP(INDEX_op_ld8u_i32,   8, 32, Z)
  __LD_OP(INDEX_op_ld8s_i32,   8, 32, S)
  __LD_OP(INDEX_op_ld16u_i32, 16, 32, Z)
  __LD_OP(INDEX_op_ld16s_i32, 16, 32, S)
  __LD_OP(INDEX_op_ld_i32,    32, 32, Z)

  __ST_OP(INDEX_op_st8_i32,   8, 32)
  __ST_OP(INDEX_op_st16_i32, 16, 32)
  __ST_OP(INDEX_op_st_i32,   32, 32)

#if TCG_TARGET_REG_BITS == 64
  __LD_OP(INDEX_op_ld8u_i64,   8, 64, Z)
  __LD_OP(INDEX_op_ld8s_i64,   8, 64, S)
  __LD_OP(INDEX_op_ld16u_i64, 16, 64, Z)
  __LD_OP(INDEX_op_ld16s_i64, 16, 64, S)
  __LD_OP(INDEX_op_ld32u_i64, 32, 64, Z)
  __LD_OP(INDEX_op_ld32s_i64, 32, 64, S)
  __LD_OP(INDEX_op_ld_i64,    64, 64, Z)

  __ST_OP(INDEX_op_st8_i64,   8, 64)
  __ST_OP(INDEX_op_st16_i64, 16, 64)
  __ST_OP(INDEX_op_st32_i64, 32, 64)
  __ST_OP(INDEX_op_st_i64,   64, 64)
#endif

#undef __LD_OP
#undef __ST_OP

  /* load/store (ponya) */
#define __LD_OP_EXT_PONYA(opc_name, memBits, regBits, signE)\
  case opc_name: {\
    tcg_global_t src = ponya_tcg_global_t(PONYA_TGS_ ## memBits, args[2]);\
    Value* v = getValueOfGlobal(src);\
    Value* new_v = b.Create ## signE ## Ext(v, intType(regBits));\
    setValueOfTCGArg(args[0], new_v);\
  } break;

#define __ST_OP_EXT_PONYA(opc_name, memBits, regBits)\
  case opc_name: {\
    tcg_global_t dst = ponya_tcg_global_t(PONYA_TGS_ ## memBits, args[2]);\
    setValueOfGlobal(dst, b.CreateTrunc(getValueOfTCGArg(args[0]), intType(memBits)));\
  } break;

  __LD_OP_EXT_PONYA(INDEX_op_ld8u_i32_ponya,   8, 32, Z)
  __LD_OP_EXT_PONYA(INDEX_op_ld8s_i32_ponya,   8, 32, S)
  __LD_OP_EXT_PONYA(INDEX_op_ld16u_i32_ponya, 16, 32, Z)
  __LD_OP_EXT_PONYA(INDEX_op_ld16s_i32_ponya, 16, 32, S)
  __LD_OP_EXT_PONYA(INDEX_op_ld_i32_ponya,    32, 32, Z)

  __ST_OP_EXT_PONYA(INDEX_op_st8_i32_ponya,   8, 32)
  __ST_OP_EXT_PONYA(INDEX_op_st16_i32_ponya, 16, 32)
  __ST_OP_EXT_PONYA(INDEX_op_st_i32_ponya,   32, 32)

#if TCG_TARGET_REG_BITS == 64
  __LD_OP_EXT_PONYA(INDEX_op_ld8u_i64_ponya,   8, 64, Z)
  __LD_OP_EXT_PONYA(INDEX_op_ld8s_i64_ponya,   8, 64, S)
  __LD_OP_EXT_PONYA(INDEX_op_ld16u_i64_ponya, 16, 64, Z)
  __LD_OP_EXT_PONYA(INDEX_op_ld16s_i64_ponya, 16, 64, S)
  __LD_OP_EXT_PONYA(INDEX_op_ld32u_i64_ponya, 32, 64, Z)
  __LD_OP_EXT_PONYA(INDEX_op_ld32s_i64_ponya, 32, 64, S)
  __LD_OP_EXT_PONYA(INDEX_op_ld_i64_ponya,    64, 64, Z)

  __ST_OP_EXT_PONYA(INDEX_op_st8_i64_ponya,   8, 64)
  __ST_OP_EXT_PONYA(INDEX_op_st16_i64_ponya, 16, 64)
  __ST_OP_EXT_PONYA(INDEX_op_st32_i64_ponya, 32, 64)
  __ST_OP_EXT_PONYA(INDEX_op_st_i64_ponya,   64, 64)
#endif

#undef __LD_OP_EXT_PONYA
#undef __ST_OP_EXT_PONYA

  /* arith */
#define __ARITH_OP(opc_name, op, bits)\
  case opc_name: {\
      Value *v1 = getValueOfTCGArg(args[1]);\
      Value *v2 = getValueOfTCGArg(args[2]);\
      adjustTypeSize(bits, &v1, &v2);\
      assert(v1->getType() == intType(bits));\
      assert(v2->getType() == intType(bits));\
      setValueOfTCGArg(args[0], b.Create ## op(v1, v2));\
  } break;

#define __ARITH_OP_DIV2(opc_name, signE, bits)\
  case opc_name:\
    assert(getValueOfTCGArg(args[2])->getType() == intType(bits));\
    assert(getValueOfTCGArg(args[3])->getType() == intType(bits));\
    assert(getValueOfTCGArg(args[4])->getType() == intType(bits));\
    v = b.CreateShl(\
            b.CreateZExt(\
                getValueOfTCGArg(args[3]), intType(bits*2)),\
            b.CreateZExt(\
                ConstantInt::get(intType(bits), bits),\
                intType(bits*2)));\
    v = b.CreateOr(v,\
            b.CreateZExt(\
                getValueOfTCGArg(args[2]), intType(bits*2)));\
    setValueOfTCGArg(args[0], b.Create ## signE ## Div(\
            v, getValueOfTCGArg(args[4])));\
    setValueOfTCGArg(args[1], b.Create ## signE ## Rem(\
            v, getValueOfTCGArg(args[4])));\
    break;

#define __ARITH_OP_ROT(opc_name, op1, op2, bits)\
  case opc_name:\
    assert(getValueOfTCGArg(args[1])->getType() == intType(bits));\
    assert(getValueOfTCGArg(args[2])->getType() == intType(bits));\
    v = b.CreateSub(\
            ConstantInt::get(intType(bits), bits),\
            getValueOfTCGArg(args[2]));\
    setValueOfTCGArg(args[0], b.CreateOr(\
            b.Create ## op1 (\
                getValueOfTCGArg(args[1]), getValueOfTCGArg(args[2])),\
            b.Create ## op2 (\
                getValueOfTCGArg(args[1]), v)));\
    break;

#define __ARITH_OP_I(opc_name, op, i, bits)\
  case opc_name:\
    assert(getValueOfTCGArg(args[1])->getType() == intType(bits));\
    setValueOfTCGArg(args[0], b.Create ## op(\
                ConstantInt::get(intType(bits), i),\
                getValueOfTCGArg(args[1])));\
    break;

#define __ARITH_OP_BSWAP(opc_name, sBits, bits)\
  case opc_name: {\
    assert(getValueOfTCGArg(args[1])->getType() == intType(bits));\
    Type* Tys[] = { intType(sBits) };\
    Function *bswap = Intrinsic::getDeclaration(llm,\
            Intrinsic::bswap, ArrayRef<Type*>(Tys,1));\
    v = b.CreateTrunc(getValueOfTCGArg(args[1]),intType(sBits));\
    setValueOfTCGArg(args[0], b.CreateZExt(\
            b.CreateCall(bswap, v), intType(bits)));\
    } break;


  __ARITH_OP(INDEX_op_add_i32, Add, 32)
  __ARITH_OP(INDEX_op_sub_i32, Sub, 32)
  __ARITH_OP(INDEX_op_mul_i32, Mul, 32)

#ifdef TCG_TARGET_HAS_div_i32
  __ARITH_OP(INDEX_op_div_i32,  SDiv, 32)
  __ARITH_OP(INDEX_op_divu_i32, UDiv, 32)
  __ARITH_OP(INDEX_op_rem_i32,  SRem, 32)
  __ARITH_OP(INDEX_op_remu_i32, URem, 32)
#else
  __ARITH_OP_DIV2(INDEX_op_div2_i32,  S, 32)
  __ARITH_OP_DIV2(INDEX_op_divu2_i32, U, 32)
#endif

  __ARITH_OP(INDEX_op_and_i32, And, 32)
  __ARITH_OP(INDEX_op_or_i32,   Or, 32)
  __ARITH_OP(INDEX_op_xor_i32, Xor, 32)

  __ARITH_OP(INDEX_op_shl_i32,  Shl, 32)
  __ARITH_OP(INDEX_op_shr_i32, LShr, 32)
  __ARITH_OP(INDEX_op_sar_i32, AShr, 32)

  __ARITH_OP_ROT(INDEX_op_rotl_i32, Shl, LShr, 32)
  __ARITH_OP_ROT(INDEX_op_rotr_i32, LShr, Shl, 32)

  __ARITH_OP_I(INDEX_op_not_i32, Xor, (uint64_t) -1, 32)
  __ARITH_OP_I(INDEX_op_neg_i32, Sub, 0, 32)

  __ARITH_OP_BSWAP(INDEX_op_bswap16_i32, 16, 32)
  __ARITH_OP_BSWAP(INDEX_op_bswap32_i32, 32, 32)

#if TCG_TARGET_REG_BITS == 64
  __ARITH_OP(INDEX_op_add_i64, Add, 64)
  __ARITH_OP(INDEX_op_sub_i64, Sub, 64)
  __ARITH_OP(INDEX_op_mul_i64, Mul, 64)

#ifdef TCG_TARGET_HAS_div_i64
  __ARITH_OP(INDEX_op_div_i64,  SDiv, 64)
  __ARITH_OP(INDEX_op_divu_i64, UDiv, 64)
  __ARITH_OP(INDEX_op_rem_i64,  SRem, 64)
  __ARITH_OP(INDEX_op_remu_i64, URem, 64)
#else
  __ARITH_OP_DIV2(INDEX_op_div2_i64,  S, 64)
  __ARITH_OP_DIV2(INDEX_op_divu2_i64, U, 64)
#endif

  __ARITH_OP(INDEX_op_and_i64, And, 64)
  __ARITH_OP(INDEX_op_or_i64,   Or, 64)
  __ARITH_OP(INDEX_op_xor_i64, Xor, 64)

  __ARITH_OP(INDEX_op_shl_i64,  Shl, 64)
  __ARITH_OP(INDEX_op_shr_i64, LShr, 64)
  __ARITH_OP(INDEX_op_sar_i64, AShr, 64)

  __ARITH_OP_ROT(INDEX_op_rotl_i64, Shl, LShr, 64)
  __ARITH_OP_ROT(INDEX_op_rotr_i64, LShr, Shl, 64)

  __ARITH_OP_I(INDEX_op_not_i64, Xor, (uint64_t) -1, 64)
  __ARITH_OP_I(INDEX_op_neg_i64, Sub, 0, 64)

  __ARITH_OP_BSWAP(INDEX_op_bswap16_i64, 16, 64)
  __ARITH_OP_BSWAP(INDEX_op_bswap32_i64, 32, 64)
  __ARITH_OP_BSWAP(INDEX_op_bswap64_i64, 64, 64)
#endif

#undef __ARITH_OP_BSWAP
#undef __ARITH_OP_I
#undef __ARITH_OP_ROT
#undef __ARITH_OP_DIV2
#undef __ARITH_OP

  /* QEMU specific */
#if TCG_TARGET_REG_BITS == 64

#if defined(CONFIG_SOFTMMU) && !defined(CONFIG_PONYA)
#define __OP_QEMU_ST(opc_name, bits)\
  case opc_name: {\
    generateQemuMemOp(false,\
        b.CreateIntCast(\
            getValueOfTCGArg(args[0]), intType(bits), false), \
        getValueOfTCGArg(args[1]), args[2], bits);\
    } break;


#define __OP_QEMU_LD(opc_name, bits, signE)\
  case opc_name: {\
    Value* V = generateQemuMemOp(true, NULL,\
        getValueOfTCGArg(args[1]), args[2], bits);\
    setValueOfTCGArg(args[0], b.Create ## signE ## Ext(\
        V, intType(std::max(TARGET_LONG_BITS, bits)))); \
    } break;

#define __OP_QEMU_LDD(opc_name, bits)\
  case opc_name: {\
    Value* V = generateQemuMemOp(true, NULL, \
        getValueOfTCGArg(args[1]), args[2], bits);\
    setValueOfTCGArg(args[0], V);\
    } break;
#else
#define __OP_QEMU_ST(opc_name, bits)\
  case opc_name:\
    generateQemuMemOp(false,\
        b.CreateIntCast(\
            getValueOfTCGArg(args[0]), intType(bits), false), \
        getValueOfTCGArg(args[1]), args[2], bits);\
    break;

#define __OP_QEMU_LD(opc_name, bits, signE)\
  case opc_name:\
    v = generateQemuMemOp(true, NULL,\
        getValueOfTCGArg(args[1]), args[2], bits);\
    setValueOfTCGArg(args[0], b.Create ## signE ## Ext(\
        v, intType(std::max(TARGET_LONG_BITS, bits)))); \
    break;

#define __OP_QEMU_LDD(opc_name, bits)\
  case opc_name:\
    v = generateQemuMemOp(true, NULL,\
        getValueOfTCGArg(args[1]), args[2], bits); \
    setValueOfTCGArg(args[0], v);\
    break;
#endif

  __OP_QEMU_ST(INDEX_op_qemu_st8,   8)
  __OP_QEMU_ST(INDEX_op_qemu_st16, 16)
  __OP_QEMU_ST(INDEX_op_qemu_st32, 32)
  __OP_QEMU_ST(INDEX_op_qemu_st64, 64)

  __OP_QEMU_LD(INDEX_op_qemu_ld8s,   8, S)
  __OP_QEMU_LD(INDEX_op_qemu_ld8u,   8, Z)
  __OP_QEMU_LD(INDEX_op_qemu_ld16s, 16, S)
  __OP_QEMU_LD(INDEX_op_qemu_ld16u, 16, Z)
  __OP_QEMU_LD(INDEX_op_qemu_ld32s, 32, S)
  __OP_QEMU_LD(INDEX_op_qemu_ld32u, 32, Z)
  __OP_QEMU_LD(INDEX_op_qemu_ld64,  64, Z)

  __OP_QEMU_LDD(INDEX_op_qemu_ld32, 32)

#undef __OP_QEMU_LD
#undef __OP_QEMU_ST
#undef __OP_QEMU_LDD

#endif

  case INDEX_op_exit_tb:
    ponyaOnExitTB(args[0]);
    break;

  case INDEX_op_goto_tb:
    /* XXX: tb linking is disabled */
    break;

  case INDEX_op_deposit_i32: {
    //llvm::errs() << *llf << "\n";
    Value *arg1 = getValueOfTCGArg(args[1]);
    //llvm::errs() << "arg1=" << *arg1 << "\n";
    //arg1 = b.CreateTrunc(arg1, intType(32));


    Value *arg2 = getValueOfTCGArg(args[2]);
    //llvm::errs() << "arg2=" << *arg2 << "\n";
    arg2 = b.CreateTrunc(arg2, intType(32));

    uint32_t ofs = args[3];
    uint32_t len = args[4];

    if (ofs == 0 && len == 32) {
        setValueOfTCGArg(args[0], arg2);
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
    setValueOfTCGArg(args[0], ret);
  }
  break;

  case INDEX_op_deposit_i64: {
    //llvm::errs() << *llf << "\n";
    Value *arg1 = getValueOfTCGArg(args[1]);
    //llvm::errs() << "arg1=" << *arg1 << "\n";
    //arg1 = b.CreateTrunc(arg1, intType(32));


    Value *arg2 = getValueOfTCGArg(args[2]);
    //llvm::errs() << "arg2=" << *arg2 << "\n";
    arg2 = b.CreateTrunc(arg2, intType(64));

    uint64_t ofs = args[3];
    uint64_t len = args[4];

    if (ofs == 0 && len == 64) {
        setValueOfTCGArg(args[0], arg2);
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
    setValueOfTCGArg(args[0], ret);
  }
  break;

  default:
    cerr << "ERROR: unknown TCG micro operation '"
              << def.name << "'" << endl;
    tcg_abort();
    break;
  }

  return nb_args;
}

// compute over approximation of TCG function tcg_inputs and tcg_outputs
void TCGLLVMContextPrivate::ponyaComputeOverApproxTCGInputsAndOutputs(TCGContext *s,
    TranslationBlock *tb)
{
  const TCGArg *args = gen_opparam_buf;
  for (int opc_index=0; ;++opc_index) {
    int c = (int)gen_opc_buf[opc_index];
    const TCGOpDef *def = &tcg_op_defs[c];

    switch (c) {
      case INDEX_op_end:
        return;

      case INDEX_op_discard:
        break;

#define PONYA_IARG(idx) do {\
    if (idx == _ponya_tcg_cpu_env) {\
      /* tcg env, do nothing */\
    } else if (likely(idx < (uint64_t)tcg_ctx.nb_globals)) {\
      /* tcg global */\
      TCGTemp *ts = &tcg_ctx.temps[idx];\
      assert(!ts->fixed_reg);\
      \
      tcg_global_t gl;\
      gl.size = tcg_global_size_of_tcg_type(ts->type);\
      gl.offs = ts->mem_offset;\
      \
      tcg_inputs.add(gl);\
    } else if (idx < TCG_MAX_TEMPS) {\
      /* tcg local */\
      tcg_locals.add((uint32_t)idx);\
    }\
  } while (0)

#define PONYA_OARG(idx) do {\
    if (idx == _ponya_tcg_cpu_env) {\
      /* tcg env */\
      assert(false && "cannot have output to TCG env");\
    } else if (likely(idx < (uint64_t)tcg_ctx.nb_globals)) {\
      /* tcg global */\
      TCGTemp *ts = &tcg_ctx.temps[idx];\
      assert(!ts->fixed_reg);\
      \
      tcg_global_t gl;\
      gl.size = tcg_global_size_of_tcg_type(ts->type);\
      gl.offs = ts->mem_offset;\
      \
      tcg_outputs.add(gl);\
    } else if (idx < TCG_MAX_TEMPS) {\
      /* tcg local */\
      tcg_locals.add((uint32_t)idx);\
    }\
  } while (0)

#define PONYA_ST(NEW_OP, SIZE) do {\
    if (args[1] == _ponya_tcg_cpu_env) {\
      tcg_outputs.add(tcg_global_t(PONYA_TGS_ ## SIZE, args[2]));\
      gen_opc_buf[opc_index] = (NEW_OP);\
    }\
  } while (0)

#define PONYA_LD(NEW_OP, SIZE) do {\
    PONYA_OARG(args[0]);\
    if (args[1] == _ponya_tcg_cpu_env) {\
      tcg_inputs.add(tcg_global_t(PONYA_TGS_ ## SIZE, args[2]));\
      gen_opc_buf[opc_index] = (NEW_OP);\
    }\
  } while (0)

#define PONYA_ST_64(OP) PONYA_ST(OP ## _ponya, 64)
#define PONYA_ST_32(OP) PONYA_ST(OP ## _ponya, 32)
#define PONYA_ST_16(OP) PONYA_ST(OP ## _ponya, 16)
#define PONYA_ST_8(OP) PONYA_ST(OP ## _ponya, 8)

#define PONYA_LD_64(OP) PONYA_LD(OP ## _ponya, 64)
#define PONYA_LD_32(OP) PONYA_LD(OP ## _ponya, 32)
#define PONYA_LD_16(OP) PONYA_LD(OP ## _ponya, 16)
#define PONYA_LD_8(OP) PONYA_LD(OP ## _ponya, 8)

#define PONYA_ON_ST_64(OP) case OP: { PONYA_ST_64(OP); } break;
#define PONYA_ON_ST_32(OP) case OP: { PONYA_ST_32(OP); } break;
#define PONYA_ON_ST_16(OP) case OP: { PONYA_ST_16(OP); } break;
#define PONYA_ON_ST_8(OP)  case OP: { PONYA_ST_8(OP);  } break;

#define PONYA_ON_LD_64(OP) case OP: { PONYA_LD_64(OP); } break;
#define PONYA_ON_LD_32(OP) case OP: { PONYA_LD_32(OP); } break;
#define PONYA_ON_LD_16(OP) case OP: { PONYA_LD_16(OP); } break;
#define PONYA_ON_LD_8(OP)  case OP: { PONYA_LD_8(OP);  } break;

      PONYA_ON_ST_32(INDEX_op_st_i32)
      PONYA_ON_ST_32(INDEX_op_st32_i64)
      PONYA_ON_ST_64(INDEX_op_st_i64)
      PONYA_ON_ST_8(INDEX_op_st8_i32)
      PONYA_ON_ST_8(INDEX_op_st8_i64)
      PONYA_ON_ST_16(INDEX_op_st16_i32)
      PONYA_ON_ST_16(INDEX_op_st16_i64)
      PONYA_ON_LD_32(INDEX_op_ld_i32)
      PONYA_ON_LD_64(INDEX_op_ld_i64)
      PONYA_ON_LD_8(INDEX_op_ld8s_i32)
      PONYA_ON_LD_8(INDEX_op_ld8s_i64)
      PONYA_ON_LD_8(INDEX_op_ld8u_i32)
      PONYA_ON_LD_8(INDEX_op_ld8u_i64)
      PONYA_ON_LD_16(INDEX_op_ld16s_i32)
      PONYA_ON_LD_16(INDEX_op_ld16s_i64)
      PONYA_ON_LD_16(INDEX_op_ld16u_i32)
      PONYA_ON_LD_16(INDEX_op_ld16u_i64)
      PONYA_ON_LD_32(INDEX_op_ld32s_i64)
      PONYA_ON_LD_32(INDEX_op_ld32u_i64)

#undef PONYA_ST
#undef PONYA_LD

#undef PONYA_ST_64
#undef PONYA_ST_32
#undef PONYA_ST_16
#undef PONYA_ST_8

#undef PONYA_LD_64
#undef PONYA_LD_32
#undef PONYA_LD_16
#undef PONYA_LD_8

#undef PONYA_ON_ST_64
#undef PONYA_ON_ST_32
#undef PONYA_ON_ST_16
#undef PONYA_ON_ST_8

#undef PONYA_ON_LD_64
#undef PONYA_ON_LD_32
#undef PONYA_ON_LD_16
#undef PONYA_ON_LD_8

      case INDEX_op_call:
        {
          tcg_target_ulong helperAddrC = args[-1]; // XXX
          const char *helperName = tcg_helper_get_name(tcgctx, (void*)helperAddrC);
          assert(helperName);

          auto it = helpers.find(helperName);
          if (likely(it != helpers.end())) {
            Helper* h = (*it).second;
            if (likely(h->getType() == PONYA_HELPER)) {
              PonyaHelper* ph = static_cast<PonyaHelper*>(h);
              for (auto it = ph->promotedInputs.begin();
                   it != ph->promotedInputs.end(); ++it)
                tcg_inputs.add(*it);

              for (auto it = ph->promotedOutputs.begin();
                   it != ph->promotedOutputs.end(); ++it)
                tcg_outputs.add(*it);
            }
          }

          int call_nb_oargs = args[0] >> 16;
          int call_nb_iargs = args[0] & 0xffff;

          for(int i=0; i < call_nb_iargs-1; ++i) {
            TCGArg iarg = args[call_nb_oargs + i + 1];
            PONYA_IARG(iarg);
          }

          assert(call_nb_oargs == 0 || call_nb_oargs == 1);
          if (call_nb_oargs == 1) {
            PONYA_OARG(args[1]);
          }
        }
        break;

#define PONYA_OP_QEMU_ST(opc_name, bits)\
  case opc_name: {\
  } break;

#define PONYA_OP_QEMU_LD(opc_name, bits, signE)\
  case opc_name: {\
    PONYA_OARG(args[0]);\
  } break;

#define PONYA_OP_QEMU_LDD(opc_name, bits)\
  case opc_name: {\
    PONYA_OARG(args[0]);\
  } break;

      PONYA_OP_QEMU_ST(INDEX_op_qemu_st8,   8)
      PONYA_OP_QEMU_ST(INDEX_op_qemu_st16, 16)
      PONYA_OP_QEMU_ST(INDEX_op_qemu_st32, 32)
      PONYA_OP_QEMU_ST(INDEX_op_qemu_st64, 64)

      PONYA_OP_QEMU_LD(INDEX_op_qemu_ld8s,   8, S)
      PONYA_OP_QEMU_LD(INDEX_op_qemu_ld8u,   8, Z)
      PONYA_OP_QEMU_LD(INDEX_op_qemu_ld16s, 16, S)
      PONYA_OP_QEMU_LD(INDEX_op_qemu_ld16u, 16, Z)
      PONYA_OP_QEMU_LD(INDEX_op_qemu_ld32s, 32, S)
      PONYA_OP_QEMU_LD(INDEX_op_qemu_ld32u, 32, Z)
      PONYA_OP_QEMU_LD(INDEX_op_qemu_ld64,  64, Z)

      PONYA_OP_QEMU_LDD(INDEX_op_qemu_ld32, 32)

#undef PONYA_OP_QEMU_ST
#undef PONYA_OP_QEMU_LD
#undef PONYA_OP_QEMU_LDD

      default:
        {
          int k = 0;
          for(int i = 0; i < def->nb_oargs; i++) {
            TCGArg oarg = args[k++];
            PONYA_OARG(oarg);
          }
          for(int i = 0; i < def->nb_iargs; i++) {
            TCGArg iarg = args[k++];
            PONYA_IARG(iarg);
          }
        }
        break;
#undef PONYA_IARG
#undef PONYA_OARG
    }

    // advance args.
    // adopted from tcg_dump_ops
    int nb_oargs, nb_iargs, nb_cargs;
    switch (c) {
      case INDEX_op_call: { /* variable number of arguments */
        TCGArg arg = *args;
        nb_oargs = arg >> 16;
        nb_oargs += 1;
        nb_iargs = arg & 0xffff;
        nb_cargs = def->nb_cargs;
        } break;
      case INDEX_op_nopn: /* variable number of arguments */
        nb_cargs = *args;
        nb_oargs = 0;
        nb_iargs = 0;
        break;
      default:
        nb_oargs = def->nb_oargs;
        nb_iargs = def->nb_iargs;
        nb_cargs = def->nb_cargs;
        break;
    }
    args += nb_iargs + nb_oargs + nb_cargs;
  }
}

static void ponyaAddAttributeToArgument(Argument* A, Attribute::AttrKind AK) {
  A->addAttr(AttributeSet::get(A->getContext(), A->getArgNo() + 1, AK));
}

CallInst *TCGLLVMContextPrivate::buildCallStub1(uint64_t pc, Value *res_arg,
                                                Value *st_arg) {
  ostringstream dstOSS;
  dstOSS << "0x" << hex << pc;
  string dstSym = dstOSS.str();

  Function* dst = llm->getFunction(dstSym);
  if (!dst) {
    dst = Function::Create(fty, Function::ExternalLinkage, dstSym, llm);

    // function attributes
    Function::arg_iterator param_it = dst->arg_begin();
    Argument *res_arg = param_it++;
    Argument *st_arg = param_it++;

    res_arg->setName("result");
    st_arg->setName("state");

    ponyaAddAttributeToArgument(res_arg, Attribute::NonNull);
    ponyaAddAttributeToArgument(st_arg, Attribute::NonNull);

    ponyaAddAttributeToArgument(res_arg, Attribute::NoAlias);
    ponyaAddAttributeToArgument(st_arg, Attribute::NoAlias);

    ponyaAddAttributeToArgument(st_arg, Attribute::ByVal);
  }

  Function::arg_iterator param_it = llf->arg_begin();
  Argument *llf_res_arg = param_it++;
  Argument *llf_st_arg = param_it++;
  Value *args[3] = {res_arg ? res_arg : llf_res_arg,
                    st_arg ? st_arg : llf_st_arg, dst};

  return b.CreateCall(llf_ponyaCallStub1, args);
}

CallInst* TCGLLVMContextPrivate::buildCallStub2(uint64_t pc1, uint64_t pc2)
{
  ostringstream dst1OSS;
  dst1OSS << "0x" << hex << pc1;
  string dst1Sym = dst1OSS.str();

  ostringstream dst2OSS;
  dst2OSS << "0x" << hex << pc2;
  string dst2Sym = dst2OSS.str();

  Function* dst1 = llm->getFunction(dst1Sym);
  if (!dst1) {
    dst1 = Function::Create(fty, Function::ExternalLinkage, dst1Sym, llm);

    // function attributes
    Function::arg_iterator param_it = dst1->arg_begin();
    Argument *res_arg = param_it++;
    Argument *st_arg = param_it++;

    res_arg->setName("result");
    st_arg->setName("state");

    ponyaAddAttributeToArgument(res_arg, Attribute::NonNull);
    ponyaAddAttributeToArgument(st_arg, Attribute::NonNull);

    ponyaAddAttributeToArgument(res_arg, Attribute::NoAlias);
    ponyaAddAttributeToArgument(st_arg, Attribute::NoAlias);

    ponyaAddAttributeToArgument(st_arg, Attribute::ByVal);
  }

  Function* dst2 = llm->getFunction(dst2Sym);
  if (!dst2) {
    dst2 = Function::Create(fty, Function::ExternalLinkage, dst2Sym, llm);

    // function attributes
    Function::arg_iterator param_it = dst2->arg_begin();
    Argument *res_arg = param_it++;
    Argument *st_arg = param_it++;

    res_arg->setName("result");
    st_arg->setName("state");

    ponyaAddAttributeToArgument(res_arg, Attribute::NonNull);
    ponyaAddAttributeToArgument(st_arg, Attribute::NonNull);

    ponyaAddAttributeToArgument(res_arg, Attribute::NoAlias);
    ponyaAddAttributeToArgument(st_arg, Attribute::NoAlias);

    ponyaAddAttributeToArgument(st_arg, Attribute::ByVal);
  }

  Function::arg_iterator param_it = llf->arg_begin();
  Argument *res_arg = param_it++;
  Argument *st_arg = param_it++;
  Value *args[6] = {res_arg,
                    st_arg,
                    ConstantInt::get(intType(64), pc1),
                    dst1,
                    ConstantInt::get(intType(64), pc2),
                    dst2};

  return b.CreateCall(llf_ponyaCallStub2, args);
}

void TCGLLVMContextPrivate::ponyaInitTranslationFunction(const TCGContext *s,
    TranslationBlock *tb, const string& f_sym)
{
  // create the llvm function to be executed. it may have been already
  // declared
  if ((llf = llm->getFunction(f_sym))) {
    ponyalogassert(llf->isDeclaration() && "translation llvm fn already "
        "defined");
    llf->setLinkage(Function::ExternalLinkage); /* just to be sure */
  } else {
    llf = Function::Create(fty, GlobalValue::ExternalLinkage, f_sym, llm);
  }

#ifndef CONFIG_PONYA
  llf->setPersonalityFn(ConstantExpr::getBitCast(ofFunctionInHelperMod(cast<Function>(func___gxx_personality_v0)), i8p_ty));
#endif

  tb->llvm_function = llf;

  // set function argument attributes
#ifdef CONFIG_PONYA
  {
    Function::arg_iterator param_it = llf->arg_begin();
    Argument *res_arg = param_it++;
    Argument *st_arg = param_it++;

    res_arg->setName("result");
    st_arg->setName("state");

    ponyaAddAttributeToArgument(res_arg, Attribute::NonNull);
    ponyaAddAttributeToArgument(st_arg, Attribute::NonNull);

    ponyaAddAttributeToArgument(res_arg, Attribute::NoAlias);
    ponyaAddAttributeToArgument(st_arg, Attribute::NoAlias);

    ponyaAddAttributeToArgument(st_arg, Attribute::ByVal);
  }
#else
  {
    Function::arg_iterator param_it = llf->arg_begin();
    Argument* cpu_st_arg = param_it++;
    ponyaAddAttributeToArgument(cpu_st_arg, Attribute::NoAlias);
    ponyaAddAttributeToArgument(cpu_st_arg, Attribute::NonNull);
  }
#endif

  // create entry block
  BasicBlock* entryBlock = BasicBlock::Create(llctx, "", llf);
  b.SetInsertPoint(entryBlock);

#ifndef CONFIG_PONYA
  // create local for return value
  retlocal = b.CreateAlloca(wordType());

  // create locals for last TCG op
  last_tcg_op_local = b.CreateAlloca(intType(32));
#endif

  // create llvm locals of TCG locals
  for (auto it = tcg_locals.begin(); it != tcg_locals.end(); ++it) {
    uint32_t idx = *it;
    tcg_lcl_vals[idx] = b.CreateAlloca(tcgType(s->temps[idx].type));
  }

  // compute globals
  tcg_globals = ponya_tcg_global_unordered_set_union(tcg_inputs, tcg_outputs);

  // create llvm locals for globals
  for (auto it = tcg_globals.begin(); it != tcg_globals.end(); ++it)
    tcg_glb_vals[*it] = b.CreateAlloca(intType(bits_of_ponya_tcg_global_size[(*it).size]));

  // initialize pointers to inputs and outputs
  for (auto it = tcg_globals.begin(); it != tcg_globals.end(); ++it)
    tcg_glb_cpu_st_ptrs[*it] = getCPUStatePtrOfGlobal(*it);

  // initialize values of inputs
  for (auto it = tcg_inputs.begin(); it != tcg_inputs.end(); ++it) {
    Value* v = ponyaHostMemOp(b.CreateLoad(tcg_glb_cpu_st_ptrs[*it]));

#if !defined(NDEBUG) || defined(CONFIG_PONYA)
    string sym;
    const char* sym_ = tcg_glb_syms[*it];
    if (sym_) {
      sym += sym_;
    } else {
      if ((*it).offs < ponyaCPUStateNBRegs*(sizeof(target_ulong)) &&
          (*it).size == PONYA_TGS_64) {
        int reg_idx = (*it).offs / sizeof(target_ulong);
        sym += reg_idx_name[reg_idx];
      } else {
        sym += std::to_string((*it).offs);
      }
    }
#else
    string sym(std::to_string((*it).offs));
#endif

    v->setName(sym);

    b.CreateStore(v, tcg_glb_vals[*it]);
  }

  // initialize mod map for outputs
  for (auto it = tcg_outputs.begin(); it != tcg_outputs.end(); ++it) {
    tcg_glb_vals_mod[*it] = b.CreateAlloca(intType(1));
    b.CreateStore(ConstantInt::get(intType(1), 0), tcg_glb_vals_mod[*it]);
  }

  // create exit block
  exitbb = BasicBlock::Create(llctx);

  // don't inline!
  llf->addAttribute(AttributeSet::FunctionIndex, Attribute::NoInline);
}
#endif

void translator::translate(address_t a)
{
}

#if 0
void TCGLLVMContextPrivate::generateCode(void* cpu_st, TCGContext *s, TranslationBlock *tb)
{
  // XXX DBG
#if 0
  ponyalogassert(!verify());
  ponyalogassert(func___gxx_personality_v0);
#endif

  // compute symbol for new function
  static unsigned m_tbCount = 1;

  string f_sym;
#ifndef CONFIG_PONYA
  string mod_sym;
#endif
  {
    ostringstream fName;
#ifdef CONFIG_PONYA
    fName << "0x" << hex << tb->pc;
#else
    fName << "tcg_llvm_tb_" << dec << m_tbCount++ << "_" << hex << tb->pc;
#endif

    f_sym = fName.str();

#ifndef CONFIG_PONYA
    fName << "_mod";
    mod_sym = fName.str();
#endif
  }

  // jnitialize various variables for translation
  max_tcg_label = 0;
  tcgctx = s;

#ifndef CONFIG_PONYA
  llm = new Module(mod_sym, llctx);
  llm->setDataLayout(initial_llm->getDataLayout());
  llm->setTargetTriple(initial_llm->getTargetTriple());

  fpm = makeFPM(llm);
  fpm->doInitialization();
#endif

  // preprocess TCG code, computing tcg_inputs & tcg_outputs
  ponyalogcall("ponyaComputeOverApproxTCGInputsAndOutputs", [=]{
    ponyaComputeOverApproxTCGInputsAndOutputs(s, tb);
  });

  // initialize the function we are producing
  ponyalogcall("ponyaInitTranslationFunction", [=]{
    ponyaInitTranslationFunction(s, tb, f_sym);
  });

  // for every TCG instruction, translate to corresponding (equivalent) LLVM
  const uint64_t* args = gen_opparam_buf;
  const uint16_t* ops  = gen_opc_buf;
  for (int opc = *ops++; opc != INDEX_op_end; opc = *ops++) {
#ifndef CONFIG_PONYA
    int opi = ops - gen_opc_buf;

    // check to store last TCG op index
    if (opc == INDEX_op_debug_insn_start)
      b.CreateStore(ConstantInt::get(intType(32), opi), last_tcg_op_local);
#endif

    // XXX DBG
#if 0
    const TCGOpDef *def = &tcg_op_defs[opc];
    errs() << def->name << "\n";
#if 0
    errs() << *llf << "\n";
    errs().flush();
#endif
    args += generateOperation(opc, args);
    errs() << *llf << "\n";
    errs().flush();
#endif

    // generate LLVM
#if 1
    args += generateOperation(opc, args);
#endif
  }

  // finish creating last basic block if necessary
  if (!llf->back().getTerminator())
    ponyaOnExitTB();

  // begin building the exit basic block code
  llf->getBasicBlockList().push_back(exitbb);
  b.SetInsertPoint(exitbb);

  // store local versions of tcg_outputs to env (and registers passed by val
  // to their local Alloca's, which'll be a no'op)
  storeValues();

  // if ponya mode, create calls to successor basic block functions
#ifdef CONFIG_PONYA
  switch (_mc2tcg_br_type) {
  case PONYA_CALL: {
    // XXX TODO handle res appropriately

    AllocaInst *returned_st = b.CreateAlloca(cpu_state_ty);
    ponyaInlineLater(buildCallStub1(_mc2tcg_call_dst, returned_st));
    ponyaInlineLater(
        buildCallStub1(_mc2tcg_call_ret_addr, nullptr, returned_st));
  } break;
  case PONYA_UNCOND_JMP:
    ponyaInlineLater(buildCallStub1(_mc2tcg_uncond_jmp_dst));
    break;
  case PONYA_COND_JMP:
    ponyaInlineLater(
        buildCallStub2(_mc2tcg_cond_jmp_dst0, _mc2tcg_cond_jmp_dst1));
    break;
  case PONYA_IND_CALL:
    ponyaInlineLater(buildCallStub1(_mc2tcg_call_ret_addr));
    break;
  case PONYA_INTERRUPT:
    ponyaInlineLater(buildCallStub1(_mc2tcg_int_ret_addr));
    break;
  case PONYA_REP:
    ponyaInlineLater(buildCallStub1(_mc2tcg_repz_ret_addr));
    break;
  case PONYA_IND_JMP:
    b.CreateCall(llf_ponyaIndirectJump,
                 getValueOfGlobal(tcg_global_t(
                     PONYA_TGS_64, PONYA_OFFSETOF(CPUX86State, eip))));
    break;
  case PONYA_RET: {
    Function::arg_iterator param_it = llf->arg_begin();
    Argument *res_arg = param_it++;
    Argument *st_arg = param_it++;
    Value *args[2] = {res_arg, st_arg};
    ponyaInlineLater(b.CreateCall(llf_ponyaRetStub, args));
  } break;
  case PONYA_EXCEPTION:
  case PONYA_HLT:
    break;
  case 0xdead:
    assert(0 && "unimplemented branch type in i386/translate.c");
  default:
    assert(0 && "bug in i386/translate.c");
  }

  // create ret!
  b.CreateRetVoid();
#else
  // create ret!
  b.CreateRet(ponyaHostMemOp(b.CreateLoad(retlocal)));

  for (auto it = catch_blocks.begin(); it != catch_blocks.end(); ++it)
    llf->getBasicBlockList().push_back(*it);
#endif

  // XXX DBG
#if 0
  if (verifyModule(*llm)) {
      fprintf(stderr, "verifying module failed");
      assert(false);
  }
#endif

  // inline function calls
#ifdef CONFIG_PONYA
  for (auto& CI : calls_to_inline) {
    InlineFunctionInfo IFI;
    InlineFunction(CI, IFI);
  }
#endif

  // if not ponya mode, logging
#ifndef CONFIG_PONYA
  logLLVMBeforeOpt();
#endif

#if 0
#ifndef NDEBUG
  ponyalogassert(!verifyFunc());
#endif
#endif

  // optimize function
  fpm->run(*llf);

#if 0
#ifndef NDEBUG
#ifdef CONFIG_PONYA
  ponyalogassert(!verifyFunc());
#else
  ponyalogassert(!verify());
#endif
#endif
#endif

  if (__ponyaDumpModAndAbort) {
    errs() << (panda_in_kernel((CPUState*)cpu_st) ? "[kernel mode]" : "[user mode]") << "\n";
    llf->print(errs());
    errs().flush();
    abort();
  }

  // if not ponya mode, logging
#ifndef CONFIG_PONYA
  logLLVM(tb);
#endif

  // if not ponya mode, do JIT compilation
#ifndef CONFIG_PONYA
  void* fn;
  size_t len;
  
  ponyalogcall("doJIT", [&]{
    tie(fn, len) = orcdynlljit->JITCompileFunction(llm, llf);
  });

  ponyalogassert(fn);

  tb->llvm_tc_ptr = (uint8_t*)fn;
  tb->llvm_tc_end = (uint8_t*)fn + len;
#endif

  // if ponya mode, make function static
#ifdef CONFIG_PONYA
  llf->setLinkage(GlobalValue::InternalLinkage);
#endif

  // clean up for next translation
  memset(tcg_label_to_llbb.data(), 0, sizeof(BasicBlock*)*(max_tcg_label+1));
  tcg_outputs.clear();
  tcg_inputs.clear();
  tcg_locals.clear();
#ifdef CONFIG_PONYA
  calls_to_inline.clear();
#else
  catch_blocks.clear();
  catch_block = nullptr;
  catch_dirty = false;
#endif
}
#endif
}

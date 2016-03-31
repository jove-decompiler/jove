#pragma once

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// ponya
enum PONYA_TRANSLATION_BLOCK_TYPE {
  PONYA_CALL,
  PONYA_RET,
  PONYA_UNCOND_JMP,
  PONYA_COND_JMP,
  PONYA_IND_JMP,
  PONYA_IND_CALL,
  PONYA_INTERRUPT,
  PONYA_EXCEPTION,
  PONYA_REP,
  PONYA_HLT,
  PONYA_UNREACHABLE
};

//#include "tcg.h"

/*****************************/
/* Functions for QEMU c code */

struct TranslationBlock;
struct TCGLLVMContext;

extern struct TCGLLVMContext* tcg_llvm_ctx;

struct TCGLLVMRuntime {
    // NOTE: The order of these are fixed !
    uint64_t helper_ret_addr;
    uint64_t helper_call_addr;
    uint64_t helper_regs[3];
    // END of fixed block

    TranslationBlock *last_tb;
    uint64_t last_opc_index;
    uint64_t last_pc;
};

extern struct TCGLLVMRuntime tcg_llvm_runtime;

struct TCGLLVMContext* tcg_llvm_initialize(void);

// ponya
void ponya_set_cpu_state_nb_regs(size_t nb);
void ponya_set_cpu_state_size(size_t s);
void ponya_set_tcg_cpu_env(uint64_t);
void ponya_cpu_state_field(uint64_t off, const char* sym);

void tcg_llvm_destroy(void);

void tcg_llvm_verify();
void tcg_llvm_verify_other();

void tcg_llvm_tb_alloc(struct TranslationBlock *tb);
void tcg_llvm_tb_free(struct TranslationBlock *tb);

void tcg_llvm_gen_code(struct TCGLLVMContext *l,
                       void* cpu_st,
                       struct TCGContext *s,
                       struct TranslationBlock *tb);
void tcg_llvm_gen_unreachable_code(struct TCGLLVMContext *l,
                                   struct TranslationBlock *tb);

const char* tcg_llvm_get_func_name(struct TranslationBlock *tb);

uintptr_t tcg_llvm_qemu_tb_exec(void *env, TranslationBlock *tb);

int tcg_llvm_search_last_pc(struct TranslationBlock *tb, uintptr_t searched_pc);

void tcg_llvm_write_module(struct TCGLLVMContext *l, const char *path);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

/***********************************/
/* External interface for C++ code */

namespace llvm {
    class Function;
    class LLVMContext;
    class Module;
    class ModuleProvider;
    class ExecutionEngine;
    namespace legacy {
      class FunctionPassManager;
    }
}

class TCGLLVMContextPrivate;
class TCGLLVMContext
{
private:
    TCGLLVMContextPrivate* m_private;

public:
    TCGLLVMContext();
    ~TCGLLVMContext();

    llvm::LLVMContext& getLLVMContext();

    llvm::Module* getModule();
    llvm::ModuleProvider* getModuleProvider();

    llvm::ExecutionEngine* getExecutionEngine();

    void deleteExecutionEngine();
    llvm::legacy::FunctionPassManager* getFunctionPassManager() const;

    void generateCode(struct TCGContext *s,
                      void* cpu_st,
                      struct TranslationBlock *tb);

    void generateUnreachableCode(struct TranslationBlock *tb);

    void writeModule(const char *path);
    bool verify();
    bool verifyOther();

    // ponya
    void finishedTranslation();
    void setCPUStateSize(size_t);
    void setCPUStateNBRegs(size_t);
    void cpuStateField(uint64_t off, const char* sym);
    bool hasTranslatedBasicBlock(uint64_t);
};

#endif

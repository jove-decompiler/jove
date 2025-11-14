#pragma once
#include "jove/jove.h"
#include "ptrace.h"
#include "disas.h"
#include "tool.h"
#include "B.h"

#include <boost/unordered/unordered_flat_map.hpp>

namespace llvm {
class MCInst;
}

namespace jove {

struct trapped_t;

typedef uintptr_t (*single_step_proc_t)(ptrace::tracee_state_t &, trapped_t &, pid_t
#if defined(__mips64) || defined(__mips__)
                                      , uintptr_t
#endif
);

struct unsupported_opcode_exception {};

struct ptrace_emulation {
  [[noinline]]
  static single_step_proc_t load_single_step_proc(trapped_t &,
                                                  llvm::MCInst &
#if defined(__mips64) || defined(__mips__)
                                                , llvm::MCInst &
#endif
                                                  );
};

template <bool MT, bool MinSize>
struct ptrace_emulator_t : public VerboseThing {
  jv_base_t<MT, MinSize> &jv;
  disas_t &disas;

#if defined(__mips64) || defined(__mips__)
  uintptr_t ExecutableRegionAddress = 0;
#endif

  ptrace_emulator_t(jv_base_t<MT, MinSize> &jv, disas_t &disas)
      : jv(jv), disas(disas) {}
};

struct __attribute__((packed)) trapped_t {
  single_step_proc_t single_step_proc;
  basic_block_index_t BBIdx;
  taddr_t TermAddr;

  //
  // the following variables are cached for performance reasons.
  //
  unsigned BIdx : 19;
  unsigned TT   : 3; /* terminator type */
  unsigned IC   : 1; /* is call? */
  unsigned LJ   : 1; /* longjmp? */
  unsigned OD   : 1; /* (nonzero) out degree? */
  unsigned DT   : 1; /* (has) dynamic target? */
  unsigned IL   : 4; /* instruction length */
#if defined(__x86_64__) || defined(__i386__)
  unsigned Scale : 2;
#else
  unsigned Unused : 2;
#endif

#if defined(__x86_64__) || defined(__i386__)
  int32_t Disp;
#elif defined(__mips64) || defined(__mips__)
  uint32_t DelaySlotInsn;
#endif

  template <bool MT, bool MinSize>
  explicit trapped_t(ptrace_emulator_t<MT, MinSize> &,
                     basic_block_index_t,
                     binary_index_t,
                     B::ref);
};

#if defined(__mips64) || defined(__mips__)
uint32_t code_cave_idx_of_reg(unsigned);
unsigned reg_of_idx(unsigned);
uint32_t encoding_of_jump_to_reg(unsigned);
#endif

}

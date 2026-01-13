#pragma once
#include "jove/jove.h"
#include "ptrace.h"
#include "disas.h"
#include "tool.h"
#include "B.h"

#include <boost/unordered/unordered_flat_map.hpp>

#if 1
#include <llvm/MC/MCInst.h>
#else
namespace llvm {
class MCInst;
}
#endif

namespace jove {

struct trapped_t;

typedef uintptr_t
#if !defined(__x86_64__) && defined(__i386__)
  __attribute__((regparm(3)))
#endif
  (*single_step_proc_t)(ptrace::tracee_state_t &, trapped_t &, pid_t, uintptr_t);

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

  //
  // code cave size
  //
  static constexpr unsigned N =
#if defined(__x86_64__) || defined(__i386__)
      16
#elif defined(__aarch64__)
      4
#elif defined(__mips64) || defined(__mips__)
      32 * 2 * sizeof(ptrace::word)
#else
#error
#endif
      ;

  uintptr_t ExecutableRegionAddress = 0;

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
  unsigned IL   : 6; /* instruction length */

#if defined(__x86_64__) || defined(__i386__)
  int64_t Disp;
  int64_t Scale;
#elif defined(__mips64) || defined(__mips__)
  uint32_t DelaySlotInsn;
#endif

#ifndef NDEBUG
  llvm::MCInst Inst;
#endif

  template <bool MT, bool MinSize>
  explicit trapped_t(ptrace_emulator_t<MT, MinSize> &,
                     basic_block_index_t,
                     binary_index_t,
                     pid_t child,
                     void *const ptr,
                     B::ref);
};

#if defined(__mips64) || defined(__mips__)
uint32_t code_cave_idx_of_reg(unsigned);
unsigned reg_of_idx(unsigned);
uint32_t encoding_of_jump_to_reg(unsigned);
#endif

}

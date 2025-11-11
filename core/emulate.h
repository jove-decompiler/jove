#pragma once
#include "jove/jove.h"
#include "ptrace.h"
#include "disas.h"
#include "tool.h"
#include "B.h"

#include <boost/unordered/unordered_flat_map.hpp>

#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>

namespace llvm {
class MCInst;
}

namespace jove {

struct trapped_t {
  const basic_block_index_t BBIdx;
  const taddr_t TermAddr;

  llvm::MCInst Inst;
#if defined(__mips64) || defined(__mips__)
  uint32_t     DelaySlotInsn;
  llvm::MCInst DelaySlotInst;
#endif

  //
  // the following variables are cached for performance reasons.
  //
  const unsigned BIdx : 21;
  const unsigned TT   : 3; /* terminator type */
  const unsigned IC   : 1; /* is call? */
  const unsigned LJ   : 1; /* longjmp? */
        unsigned OD   : 1; /* (nonzero) out degree? */
        unsigned DT   : 1; /* (has) dynamic target? */
  const unsigned IL   : 4; /* instruction length */

  static constexpr unsigned MaxInstLen = 16;

  template <bool MT, bool MinSize>
  [[clang::always_inline]]
  explicit trapped_t(jv_base_t<MT, MinSize> &jv,
                     B::ref Bin,
                     disas_t &disas,
                     basic_block_index_t BBIdx,
                     binary_index_t BIdx,
                     const auto &bbprop)
      : BBIdx(BBIdx),
        TermAddr(bbprop.Term.Addr),
        BIdx(static_cast<unsigned>(BIdx)),
        TT(static_cast<unsigned>(bbprop.Term.Type)),
        IC(static_cast<unsigned>(IsTerminatorCall(bbprop.Term.Type))),
        LJ(static_cast<unsigned>(bbprop.Term._indirect_jump.IsLj)),
        OD(static_cast<unsigned>(({
          auto &b = jv.Binaries.at(BIdx);
          auto &ICFG = b.Analysis.ICFG;

          ICFG.template out_degree<false>(ICFG.template vertex<false>(BBIdx)) != 0;
        }))),
        DT(static_cast<unsigned>(bbprop.hasDynTarget())),
        IL(static_cast<unsigned>(({
          auto &b = jv.Binaries.at(BIdx);
          auto &ICFG = b.Analysis.ICFG;

          constexpr unsigned N = MaxInstLen *
#if defined(__mips64) || defined(__mips__)
                       2
#else
                       1
#endif
              ;

          std::vector<uint8_t> InstBytes;
          InstBytes.resize(N);

          {
            const void *Ptr = B::toMappedAddr(Bin, bbprop.Term.Addr);
            aassert(Ptr);
            __builtin_memcpy_inline(&InstBytes[0], Ptr, N); /* FIXME exceeding end of section */
          }

          uint64_t InstLen;
          bool Disassembled = disas.DisAsm->getInstruction(
              this->Inst, InstLen, InstBytes, TermAddr, llvm::nulls());
          aasserta(Disassembled);

#if defined(__mips64) || defined(__mips__)
          {
            uint64_t DelaySlotInstLen;
            bool Disassembled = disas.DisAsm->getInstruction(
                this->DelaySlotInst, DelaySlotInstLen,
                llvm::ArrayRef<uint8_t>(&InstBytes[4], 4), TermAddr + 4,
                llvm::nulls());
            aasserta(Disassembled);
          }
          __builtin_memcpy_inline(&DelaySlotInsn, &InstBytes[4], sizeof(DelaySlotInsn));
#endif
          aasserta(InstLen <= 0xf);

          InstLen;
        }))) {}
};

template <bool MT, bool MinSize>
class ptrace_emulator_t : public VerboseThing {
  jv_base_t<MT, MinSize> &jv;
  disas_t &disas;

public:
  ptrace::tracee_state_t tracee_state;

#if defined(__mips64) || defined(__mips__)
  uintptr_t ExecutableRegionAddress = 0;
#endif

public:
  explicit ptrace_emulator_t(jv_base_t<MT, MinSize> &jv, disas_t &disas)
      : jv(jv), disas(disas) {}

  uintptr_t single_step(const pid_t child, const uintptr_t saved_pc,
                        const trapped_t &);
};

}

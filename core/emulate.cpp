#if (defined(__x86_64__)  && defined(TARGET_X86_64))  || \
    (defined(__i386__)    && defined(TARGET_I386))    || \
    (defined(__aarch64__) && defined(TARGET_AARCH64)) || \
    (defined(__mips64)    && defined(TARGET_MIPS64))  || \
    (defined(__mips__)    && defined(TARGET_MIPS32))
#include "emulate.h"
#include "ptrace.h"

#include <vector>

#include <boost/format.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/enum.hpp>
#include <boost/preprocessor/seq/for_each_i.hpp>
#include <boost/preprocessor/seq/for_each_product.hpp>
#include <boost/preprocessor/seq/seq.hpp>
#include <boost/preprocessor/tuple/elem.hpp>

#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/WithColor.h>

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

#define WARN_ON(...)                                                           \
  do {                                                                         \
  } while (false)

using llvm::WithColor;

namespace jove {

typedef boost::format fmt;

static std::string StringOfMCInst(disas_t &disas, const llvm::MCInst &Inst) {
  std::string res;

  {
    llvm::raw_string_ostream ss(res);

    disas.IP->printInst(&Inst, 0x0 /* XXX */, "", *disas.STI, ss);

#if 1
    ss << '\n';
    ss << "[opcode: " << Inst.getOpcode() << ']';
    for (unsigned i = 0; i < Inst.getNumOperands(); ++i) {
      const llvm::MCOperand &opnd = Inst.getOperand(i);

      char buff[0x100];
      if (opnd.isReg())
        snprintf(buff, sizeof(buff), "<reg %u>", opnd.getReg());
      else if (opnd.isImm())
        snprintf(buff, sizeof(buff), "<imm %" PRId64 ">", opnd.getImm());
#if 0
      else if (opnd.isFPImm())
        snprintf(buff, sizeof(buff), "<imm %lf>", opnd.getFPImm());
#endif
      else if (opnd.isExpr())
        snprintf(buff, sizeof(buff), "<expr>");
      else if (opnd.isInst())
        snprintf(buff, sizeof(buff), "<inst>");
      else
        snprintf(buff, sizeof(buff), "<unknown>");

      ss << (fmt(" %u:%s") % i % buff).str();
    }

    ss << '\n';
#endif
  }

  return res;
}

template <bool MT, bool MinSize>
trapped_t::trapped_t(ptrace_emulator_t<MT, MinSize> &emu,
                     basic_block_index_t BBIdx,
                     binary_index_t BIdx,
                     pid_t child,
                     void *const ptr,
                     B::ref Bin) {
  auto &b = emu.jv.Binaries.at(BIdx);
  auto &ICFG = b.Analysis.ICFG;
  auto &bbprop = ICFG[ICFG.template vertex(BBIdx)];
  const bool isCall = IsTerminatorCall(bbprop.Term.Type);

  this->BBIdx = BBIdx;
  this->TermAddr = bbprop.Term.Addr;
  this->BIdx = static_cast<unsigned>(BIdx);
  this->TT = static_cast<unsigned>(bbprop.Term.Type);
  this->IC = static_cast<unsigned>(isCall);
  this->LJ = static_cast<unsigned>(bbprop.Term._indirect_jump.IsLj);
  this->OD = static_cast<unsigned>(
      ICFG.template out_degree<false>(ICFG.template vertex<false>(BBIdx)) != 0);
  this->DT = static_cast<unsigned>(bbprop.hasDynTarget());


#if defined(__mips64) || defined(__mips__)
#define THE_N 8
#else
#define THE_N THE_MAX_INST_LEN
#endif


  size_t N = THE_N;
  while(unlikely(!B::toMappedAddr(Bin, bbprop.Term.Addr + (N-1)))) { /* partially exceeding end of section FIXME */

#define N_CASE(n, i, data)                            \
  --N;                                                \
  if (B::toMappedAddr(Bin, bbprop.Term.Addr + (N-1))) \
    break;

  BOOST_PP_REPEAT(THE_N, N_CASE, void)

#undef N_CASE

    throw std::runtime_error((fmt("no data at address 0x%lx in %s\n") % this->TermAddr % b.Name.c_str()).str());
  }

  aassert(N);

#undef THE_N

  std::vector<std::byte> InstBytes;
  ptrace::memcpy_from(child, InstBytes, ptr, 2*N);

  //llvm::errs() << InstBytes.size() << '\n';

  aassert(!InstBytes.empty());
  {
    const void *Ptr = B::toMappedAddr(Bin, bbprop.Term.Addr);
    aassert(Ptr);
    __builtin_memcpy_inline(&InstBytes[0], Ptr, IsX86Target ? 1 : 4);
  }

#ifdef NDEBUG
  llvm::MCInst Inst;
#else
  llvm::MCInst &Inst = this->Inst;
#endif
  uint64_t InstLen;
  aassert(emu.disas.DisAsm->getInstruction(Inst, InstLen, llvm::ArrayRef<uint8_t>(reinterpret_cast<const uint8_t *>(InstBytes.data()), N), TermAddr,
                                           llvm::nulls()));

  aassert(InstLen <= 0xf);

  this->IL = InstLen;

#if 0
  llvm::errs() << StringOfMCInst(emu.disas, Inst) << '\n';
#endif

#if defined(__mips64) || defined(__mips__)
  aassert(InstBytes.size() >= 8);
  llvm::MCInst DelaySlotInst;

  uint64_t DelaySlotInstLen;
  aassert(emu.disas.DisAsm->getInstruction(
      DelaySlotInst, DelaySlotInstLen,
      llvm::ArrayRef<uint8_t>(&InstBytes[4], 4), TermAddr + 4, llvm::nulls()));
  __builtin_memcpy_inline(&this->DelaySlotInsn, &InstBytes[4], sizeof(this->DelaySlotInsn));
#endif

  try {
    this->single_step_proc =
        ptrace_emulation::load_single_step_proc(*this, Inst
#if defined(__mips64) || defined(__mips__)
                                              , DelaySlotInst
#endif
        );
    return;
  } catch (unsupported_opcode_exception &) {
    WithColor::error() << llvm::formatv("{0}: <unsupported> {1}\n",
                                        __PRETTY_FUNCTION__,
                                        StringOfMCInst(emu.disas, Inst));
  } catch (std::out_of_range &) {
    WithColor::error() << llvm::formatv("{0}: <out-of-range> {1}\n",
                                        __PRETTY_FUNCTION__,
                                        StringOfMCInst(emu.disas, Inst));
  }
  _exit(1);
}

template <typename... Args>
using single_step_map_t =
    boost::unordered::unordered_flat_map<std::tuple<Args...>,
                                         single_step_proc_t>;

// XXX
__attribute__((unused)) static const unsigned Reg0 = 0;
__attribute__((unused)) static const unsigned Reg1 = 0;
__attribute__((unused)) static const unsigned Reg2 = 0;
__attribute__((unused)) static const unsigned Reg3 = 0;
__attribute__((unused)) static const unsigned Reg4 = 0;
__attribute__((unused)) static const unsigned RetReg0 = 0;
__attribute__((unused)) static const unsigned DelaySlotOpcode = 0;

#include "emulate.cpp.inc"

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))
#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                   \
  template trapped_t::trapped_t(                                     \
      ptrace_emulator_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),    \
                        GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &, \
      basic_block_index_t, binary_index_t, pid_t child, void *const ptr, B::ref);
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

#if defined(__mips64) || defined(__mips__)

uint32_t code_cave_idx_of_reg(unsigned r) {
  switch (r) {
    case llvm::Mips::ZERO: return 0;
    case llvm::Mips::AT:   return 1;
    case llvm::Mips::V0:   return 2;
    case llvm::Mips::V1:   return 3;
    case llvm::Mips::A0:   return 4;
    case llvm::Mips::A1:   return 5;
    case llvm::Mips::A2:   return 6;
    case llvm::Mips::A3:   return 7;
    case llvm::Mips::T0:   return 8;
    case llvm::Mips::T1:   return 9;
    case llvm::Mips::T2:   return 10;
    case llvm::Mips::T3:   return 11;
    case llvm::Mips::T4:   return 12;
    case llvm::Mips::T5:   return 13;
    case llvm::Mips::T6:   return 14;
    case llvm::Mips::T7:   return 15;
    case llvm::Mips::S0:   return 16;
    case llvm::Mips::S1:   return 17;
    case llvm::Mips::S2:   return 18;
    case llvm::Mips::S3:   return 19;
    case llvm::Mips::S4:   return 20;
    case llvm::Mips::S5:   return 21;
    case llvm::Mips::S6:   return 22;
    case llvm::Mips::S7:   return 23;
    case llvm::Mips::T8:   return 24;
    case llvm::Mips::T9:   return 25;
    case llvm::Mips::K0:   return 26;
    case llvm::Mips::K1:   return 27;
    case llvm::Mips::GP:   return 28;
    case llvm::Mips::SP:   return 29;
    case llvm::Mips::FP:   return 30;
    case llvm::Mips::RA:   return 31;

    default:
      __builtin_trap();
      __builtin_unreachable();
  }
}

unsigned reg_of_idx(unsigned idx) {
  switch (idx) {
    case 0:    return llvm::Mips::ZERO;
    case 1:    return llvm::Mips::AT;
    case 2:    return llvm::Mips::V0;
    case 3:    return llvm::Mips::V1;
    case 4:    return llvm::Mips::A0;
    case 5:    return llvm::Mips::A1;
    case 6:    return llvm::Mips::A2;
    case 7:    return llvm::Mips::A3;
    case 8:    return llvm::Mips::T0;
    case 9:    return llvm::Mips::T1;
    case 10:   return llvm::Mips::T2;
    case 11:   return llvm::Mips::T3;
    case 12:   return llvm::Mips::T4;
    case 13:   return llvm::Mips::T5;
    case 14:   return llvm::Mips::T6;
    case 15:   return llvm::Mips::T7;
    case 16:   return llvm::Mips::S0;
    case 17:   return llvm::Mips::S1;
    case 18:   return llvm::Mips::S2;
    case 19:   return llvm::Mips::S3;
    case 20:   return llvm::Mips::S4;
    case 21:   return llvm::Mips::S5;
    case 22:   return llvm::Mips::S6;
    case 23:   return llvm::Mips::S7;
    case 24:   return llvm::Mips::T8;
    case 25:   return llvm::Mips::T9;
    case 26:   return llvm::Mips::K0;
    case 27:   return llvm::Mips::K1;
    case 28:   return llvm::Mips::GP;
    case 29:   return llvm::Mips::SP;
    case 30:   return llvm::Mips::FP;
    case 31:   return llvm::Mips::RA;

    default:
      __builtin_trap();
      __builtin_unreachable();
  }
}

uint32_t encoding_of_jump_to_reg(unsigned r) {
  switch (r) {
   case llvm::Mips::ZERO: return 0x00000008;
   case llvm::Mips::AT:   return 0x00200008;
   case llvm::Mips::V0:   return 0x00400008;
   case llvm::Mips::V1:   return 0x00600008;
   case llvm::Mips::A0:   return 0x00800008;
   case llvm::Mips::A1:   return 0x00a00008;
   case llvm::Mips::A2:   return 0x00c00008;
   case llvm::Mips::A3:   return 0x00e00008;
   case llvm::Mips::T0:   return 0x01000008;
   case llvm::Mips::T1:   return 0x01200008;
   case llvm::Mips::T2:   return 0x01400008;
   case llvm::Mips::T3:   return 0x01600008;
   case llvm::Mips::T4:   return 0x01800008;
   case llvm::Mips::T5:   return 0x01a00008;
   case llvm::Mips::T6:   return 0x01c00008;
   case llvm::Mips::T7:   return 0x01e00008;
   case llvm::Mips::S0:   return 0x02000008;
   case llvm::Mips::S1:   return 0x02200008;
   case llvm::Mips::S2:   return 0x02400008;
   case llvm::Mips::S3:   return 0x02600008;
   case llvm::Mips::S4:   return 0x02800008;
   case llvm::Mips::S5:   return 0x02a00008;
   case llvm::Mips::S6:   return 0x02c00008;
   case llvm::Mips::S7:   return 0x02e00008;
   case llvm::Mips::T8:   return 0x03000008;
   case llvm::Mips::T9:   return 0x03200008;
   case llvm::Mips::K0:   return 0x03400008;
   case llvm::Mips::K1:   return 0x03600008;
   case llvm::Mips::GP:   return 0x03800008;
   case llvm::Mips::SP:   return 0x03a00008;
   case llvm::Mips::FP:   return 0x03c00008;
   case llvm::Mips::RA:   return 0x03e00008;
   default:
                          __builtin_trap();
                          __builtin_unreachable();
  }
}

#endif

}

#endif

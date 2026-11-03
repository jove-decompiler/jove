#pragma once
#include "jove/jove.h"
#include "flow.h"
#include "calls.h"
#include "B.h"
#include "helper.h"
#include "tcg.h"

namespace jove {

// returns whether the block was actually analyzed
template <typename extra_t>
bool AnalyzeBasicBlock(B::cached::type<extra_t> &cb,
                       bbprop_t &bbprop,
                       tcg_t<extra_t> &tcg,
                       tcg_helpers_t &helpers,
                       analyzer_options_t &options) {
  if (!bbprop.Analysis.Stale.test(boost::memory_order_acquire))
    return false;

  BOOST_SCOPE_DEFER [&] {
    bbprop.Analysis.Stale.clear(boost::memory_order_release);
  };

  const bool IsCOFF = B::is_coff(cb.first.get());

  const auto Addr = bbprop.Addr;
  const auto Size = bbprop.Size;

  tcg_global_set_reset(bbprop.Analysis.live.use);
  tcg_global_set_reset(bbprop.Analysis.live.def);
#ifdef TCG_BITSET
  tcg_global_set_reset(bbprop.Analysis.live.out.Set);
#else
  bbprop.Analysis.live.out.store(0, boost::memory_order_relaxed);
#endif
  tcg_global_set_reset(bbprop.Analysis.reach.def);

  unsigned size = 0;
  jove::terminator_info_t T;
  do {
    unsigned len;
    try {
      std::tie(len, T) = tcg.translate(cb, Addr + size, Addr + Size);
    } catch (const illegal_op_exception &) {
      break;
    }

    tcg.for_each_operation([&](void *op) {
      tcg_global_set_t iglbs, oglbs;
      std::tie(iglbs, oglbs) = tcg.analyze_operation(helpers, op);

      bbprop.Analysis.live.use |= (iglbs & ~bbprop.Analysis.live.def);
      bbprop.Analysis.live.def |= (oglbs & ~bbprop.Analysis.live.use);

      bbprop.Analysis.reach.def |= oglbs;
    });

    size += len;
  } while (size < Size);

#if 0
  if (false /* options::PrintDefAndUse */) {
    llvm::outs() << (fmt("%#lx") % Addr).str() << '\n';

    uint64_t InstLen;
    for (uintptr_t A = Addr; A < Addr + Size; A += InstLen) {
      std::ptrdiff_t Offset = A - (*sectit).first.lower();

      llvm::MCInst Inst;
      bool Disassembled = DisAsm->getInstruction(
          Inst, InstLen, sectprop.contents.slice(Offset), A, llvm::nulls());
      if (!Disassembled) {
        WithColor::error() << "failed to disassemble "
                           << (fmt("%#lx") % Addr).str() << '\n';
        break;
      }

      IP->printInst(&Inst, A, "", *STI, llvm::outs());
      llvm::outs() << '\n';
    }

    llvm::outs() << '\n';

    llvm::outs() << "live.def:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, bbprop.Analysis.live.def);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << s->temps[glb].name;
    }
    llvm::outs() << '\n';

    llvm::outs() << "live.use:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, bbprop.Analysis.live.use);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << s->temps[glb].name;
    }
    llvm::outs() << '\n';

    llvm::outs() << "reach.def:";
    {
      std::vector<unsigned> glbv;
      explode_tcg_global_set(glbv, bbprop.Analysis.reach.def);
      for (unsigned glb : glbv)
        llvm::outs() << ' ' << s->temps[glb].name;
    }
    llvm::outs() << '\n';
  }
#endif

  return true;
}

using invalidated_t =
    boost::container::vector<boost::concurrent_flat_set<function_index_t>>;

struct analyzer_options_t : public VerboseThing {
  unsigned Conservative = 1;
  unsigned Precision = 0;

  bool ForCBE = false;
  unsigned DynTargetInlineThreshold = 8;

  tcg_global_set_t PinnedEnvGlbs = InitPinnedEnvGlbs;
};

template <bool MT, bool MinSize>
struct analyzer_t {
  using jv_t = jv_base_t<MT, MinSize>;
  using binary_t = binary_base_t<MT, MinSize>;
  using icfg_t = ip_icfg_base_t<MT>;
  using bb_t = typename ip_icfg_base_t<MT>::vertex_descriptor;
  using exit_vertex_pair_t = std::pair<flow_vertex_t, bool>;

  struct binary_state_t {
    B::cached::type<> cb;

    binary_state_t(const binary_t &b) { B::cached::create(cb, b.data()); }
  };

  struct function_state_t {
    binary_t::bb_vec_t bbvec;
    binary_t::bb_vec_t exit_bbvec;

    function_state_t(const function_t &f, const binary_t &b) {
      basic_blocks_of_function(f, b, bbvec);
      exit_basic_blocks_of_function(f, b, bbvec, exit_bbvec);
    }
  };

  analyzer_options_t &options;

  SafeLLVMContext &SafeContext;

  tcg_helpers_t &helpers;

  jv_file_t &jv_file;
  jv_t &jv;

  jv_state_t<binary_state_t, function_state_t, void,
             MT, MinSize,
             DefaultLvl0StateOpts | StateOpt::Eager,
             DefaultLvl1StateOpts | StateOpt::Eager> state;

  using cg_t = call_graph_builder_t<MT, MinSize>;

  const bool IsCOFF;

  boost::concurrent_flat_set<dynamic_target_t> &inflight;
  std::atomic<uint64_t> &done;

  analyzer_t(analyzer_options_t &,
             SafeLLVMContext &,
             tcg_helpers_t &,
             jv_file_t &,
             jv_t &,
             boost::concurrent_flat_set<dynamic_target_t> &inflight,
             std::atomic<uint64_t> &done);

  void examine_callers(void);
  void examine_blocks(void);

  void identify_ABIs(void);
  void identify_Sjs(void);

  void refine_analyses(void);

  template <typename extra_t>
  int analyze_blocks(
      tcg_t<extra_t> &tcg,
      boost::optional<invalidated_t &> invalidated = boost::none) {
    std::atomic<unsigned> count = 0;

    for_each_basic_block( /* FIXME (parunseq) */
        jv, [&](binary_t &b, bb_t bb) {
            auto &ICFG = b.Analysis.ICFG;
            auto &bbprop = ICFG[bb];
            if (AnalyzeBasicBlock(state.for_binary(b).cb,
                                  bbprop,
                                  tcg,
                                  helpers,
                                  options)) {
              count.fetch_add(1u, std::memory_order_relaxed);
              if (invalidated) {
                auto &bin_invalidated = (*invalidated).at(index_of_binary(b));

                const auto &ParentsVec = bbprop.Parents.template get<MT>();

                std::for_each(maybe_par_unseq,
                              ParentsVec.cbegin(),
                              ParentsVec.cend(),
                              [&](function_index_t FIdx) {
                                bin_invalidated.insert(FIdx);
                              });
              }
            }
        });

    if (options.IsVerbose())
    if (unsigned c = count.load())
      llvm::errs() << llvm::formatv("Analyzed {0} basic block{1}.\n", c,
                                    c == 1 ? "" : "s");

    //
    // if libs are foreign, we won't necessarily see all the dynamic targets in
    // those libraries, period. bootstrap might give us those targets, or it might
    // not. therefore, unless told otherwise, do the following: assume that any
    // function call which crosses binaries could lead to code for which we have
    // *not* seen all the targets for.
    //
    if (options.Conservative >= 1)
      for_each_function_if(
          maybe_par_unseq, jv, [](function_t &f) { return f.IsABI; },
          [](function_t &f, binary_t &b) {
            auto &ICFG = b.Analysis.ICFG;
            assert(is_basic_block_index_valid(f.Entry));
            ICFG[basic_block_of_index(f.Entry, ICFG)].Analysis.live.use |= CallConvArgs;
          });

    return 0;
  }

  template <bool BottomUp = false>
  int analyze_functions(boost::optional<invalidated_t &> invalidated = boost::none);

  int analyze_function(function_t &,
      boost::optional<boost::concurrent_flat_set<function_index_t> &> = boost::none);

private:
  flow_vertex_t copy_function_cfg(
             flow_graph_t &G,
             function_t &f,
             flow_vertex_t *Orig2CopyMap,
             std::vector<exit_vertex_pair_t> &exitVertices,
             boost::unordered::unordered_flat_map<function_t *, std::pair<flow_vertex_t, std::vector<exit_vertex_pair_t>>> &memoize);

  std::optional<std::pair<tcg_global_set_t, tcg_global_set_t>>
  DynTargetsSummary(const DynTargets_t<MT, MinSize> &, bool IsABI);
};

}

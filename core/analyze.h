#pragma once
#include "jove/jove.h"
#include "flow.h"
#include "calls.h"
#include "B.h"

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <memory>

namespace jove {

struct tiny_code_generator_t;

struct analyzer_options_t : public VerboseThing {
  unsigned Precision = 0;
  unsigned Conservative = 1;
  bool ForCBE = false;

  tcg_global_set_t PinnedEnvGlbs = InitPinnedEnvGlbs;
};

struct helper_function_t {
  llvm::Function *F = nullptr;
  int EnvArgNo = -1;

  struct {
    bool Simple = false;
    tcg_global_set_t InGlbs, OutGlbs;
  } Analysis;
};

using helper_func_map_t =
    boost::unordered::unordered_flat_map<uintptr_t, helper_function_t>;

struct helpers_context_t {
  std::mutex mtx;
  helper_func_map_t map;
};

template <bool MT, bool MinSize>
struct analyzer_t {
  using jv_t = jv_base_t<MT, MinSize>;
  using binary_t = binary_base_t<MT, MinSize>;
  using icfg_t = ip_icfg_base_t<MT>;
  using bb_t = typename ip_icfg_base_t<MT>::vertex_descriptor;
  using exit_vertex_pair_t = std::pair<flow_vertex_t, bool>;

  struct binary_state_t {
    B::unique_ptr Bin;

    binary_state_t(const binary_t &b) { Bin = B::Create(b.data()); }
  };

  struct function_state_t {
    binary_t::bb_vec_t bbvec;
    binary_t::bb_vec_t exit_bbvec;

    function_state_t(const function_t &f, const binary_t &b) {
      basic_blocks_of_function(f, b, bbvec);
      exit_basic_blocks_of_function(f, b, bbvec, exit_bbvec);
    }
  };

  const analyzer_options_t &options;
 
  tiny_code_generator_t &TCG;
  jv_file_t &jv_file;
  jv_t &jv;

  jv_state_t<binary_state_t, function_state_t, void,
    AreWeMT, /* MultiThreaded */
    true,    /* LazyInitialization */
    true,    /* Eager */
    true,    /* BoundsChecking */
    true,    /* SubjectToChange */
    MT, MinSize> state;

  call_graph_builder_t<MT, MinSize> cg;

  const bool IsCOFF;

  llvm::LLVMContext &Context;
  std::unique_ptr<llvm::Module> Module; /* initialized from starter bitcode */
  helpers_context_t helpers;

  boost::concurrent_flat_set<dynamic_target_t> &inflight;
  std::atomic<uint64_t> &done;

  analyzer_t(const analyzer_options_t &,
             tiny_code_generator_t &,
             llvm::LLVMContext &,
             jv_file_t &,
             jv_t &,
             boost::concurrent_flat_set<dynamic_target_t> &inflight,
             std::atomic<uint64_t> &done);

  void examine_callers(void);
  void examine_blocks(void);

  void identify_ABIs(void);
  void identify_Sjs(void);

  int analyze_blocks(void);
  template <bool BottomUp = false>
  int analyze_functions(void);

  int analyze_function(function_t &);

private:
  flow_vertex_t copy_function_cfg(
             flow_graph_t &G,
             function_t &f,
             std::vector<exit_vertex_pair_t> &exitVertices,
             boost::unordered::unordered_flat_map<function_t *, std::pair<flow_vertex_t, std::vector<exit_vertex_pair_t>>> &memoize);

  std::optional<std::pair<tcg_global_set_t, tcg_global_set_t>>
  DynTargetsSummary(const DynTargets_t<MT, MinSize> &, bool IsABI);
};

}

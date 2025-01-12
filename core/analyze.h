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

struct analyzer_options_t {
  unsigned Precision = 0;
  unsigned Conservative = 1;
  bool ForCBE = false;
  bool Verbose = false;
  bool VeryVerbose = false;

  tcg_global_set_t PinnedEnvGlbs = InitPinnedEnvGlbs;
};

template <bool MT>
struct analyzer_t {
  using exit_vertex_pair_t = std::pair<flow_vertex_t, bool>;

  struct binary_state_t {
    std::unique_ptr<llvm::object::Binary> Bin;

    binary_state_t(const auto &b) { Bin = B::Create(b.data()); }
  };

  struct function_state_t {
    basic_block_vec_t bbvec;
    basic_block_vec_t exit_bbvec;

    bool IsLeaf;

    bool IsSj, IsLj;

    function_state_t(const function_t &f, const auto &b) {
      basic_blocks_of_function(f, b, bbvec);
      exit_basic_blocks_of_function(f, b, bbvec, exit_bbvec);

      IsLeaf = IsLeafFunction(f, b, bbvec, exit_bbvec);
      IsSj = IsFunctionSetjmp(f, b, bbvec);
      IsLj = IsFunctionLongjmp(f, b, bbvec);
    }
  };

  const analyzer_options_t &options;
  
  tiny_code_generator_t &TCG;
  jv_base_t<MT> &jv;

  jv_state_t<binary_state_t, function_state_t, void, true, true, false, true,
             MT>
      state;

  call_graph_builder_t<MT> cg;

  const bool IsCOFF;

  std::unique_ptr<llvm::LLVMContext> Context;
  std::unique_ptr<llvm::Module> Module;

  boost::concurrent_flat_set<dynamic_target_t> &inflight;
  std::atomic<uint64_t> &done;

  analyzer_t(const analyzer_options_t &,
             tiny_code_generator_t &,
             jv_base_t<MT> &,
             boost::concurrent_flat_set<dynamic_target_t> &inflight,
             std::atomic<uint64_t> &done);

  void update_callers(void);
  void update_parents(void);

  void identify_ABIs(void);
  void identify_Sjs(void);

  int analyze_blocks(void);
  int analyze_functions(void);

  int analyze_function(function_t &);

private:
  flow_vertex_t copy_function_cfg(
             flow_graph_t &G,
             function_t &f,
             std::vector<exit_vertex_pair_t> &exitVertices,
             boost::unordered::unordered_flat_map<function_t *, std::pair<flow_vertex_t, std::vector<exit_vertex_pair_t>>> &memoize);

  std::optional<std::pair<tcg_global_set_t, tcg_global_set_t>>
  DynTargetsSummary(const bbprop_t &bbprop, bool IsABI);
};

}

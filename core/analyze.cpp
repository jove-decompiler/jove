#include "analyze.h"
#include "B.h"
#include "locator.h"
#include "llvm.h"

#ifndef JOVE_NO_BACKEND

#include <boost/graph/copy.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/graph/strong_components.hpp>
#include <boost/graph/create_condensation_graph.hpp>
#include <boost/graph/topological_sort.hpp>

#include <tbb/parallel_for_each.h>
#include <tbb/flow_graph.h>

#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

using llvm::WithColor;

namespace jove {

template <bool MT, bool MinSize>
analyzer_t<MT, MinSize>::analyzer_t(
    const analyzer_options_t &options,
    tiny_code_generator_t &TCG,
    llvm::LLVMContext &Context,
    jv_t &jv,
    boost::concurrent_flat_set<dynamic_target_t> &inflight,
    std::atomic<uint64_t> &done)
    : options(options), TCG(TCG), jv(jv), state(jv), cg(jv),
      IsCOFF(B::is_coff(*state.for_binary(jv.Binaries.at(0)).Bin)),
      Context(Context),
      inflight(inflight), done(done) {
  //
  // create LLVM module (necessary to analyze helpers)
  //
  std::string path_to_bitcode = locator_t::starter_bitcode(false, IsCOFF);

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> BufferOr =
      llvm::MemoryBuffer::getFile(path_to_bitcode);
  if (!BufferOr)
    throw std::runtime_error(std::string("failed to open ") + path_to_bitcode +
                             BufferOr.getError().message());

  llvm::Expected<std::unique_ptr<llvm::Module>> moduleOr =
      llvm::parseBitcodeFile(BufferOr.get()->getMemBufferRef(), Context);
  if (!moduleOr)
    throw std::runtime_error(std::string("could not parse helper bitcode: ") +
                             llvm::toString(moduleOr.takeError()));

  Module = std::move(moduleOr.get());
}

template <bool MT, bool MinSize>
void analyzer_t<MT, MinSize>::update_callers(void) {
  for_each_basic_block(
      maybe_par_unseq, jv,
      [&](binary_t &b, bb_t bb) {
        auto &ICFG = b.Analysis.ICFG;
        bbprop_t &bbprop = ICFG[bb];
        taddr_t TermAddr = bbprop.Term.Addr;

        if (bbprop.Term.Type == TERMINATOR::CALL) {
          assert(TermAddr);

          function_t &callee = b.Analysis.Functions.at(bbprop.Term._call.Target);
          callee.Callers(jv).Insert(caller_t(index_of_binary(b), TermAddr));
          return;
        }

        if (auto MaybeDynTargets = bbprop.getDynamicTargets(jv)) {
          auto &DynTargets = *MaybeDynTargets;

          DynTargets.ForEach(maybe_par_unseq, [&](const dynamic_target_t &X) {
            assert(TermAddr);

            function_t &f = function_of_target(X, jv);
            f.Callers(jv).Insert(caller_t(index_of_binary(b, jv), TermAddr));
          });
        }
      });
}


template <bool MT, bool MinSize>
void analyzer_t<MT, MinSize>::update_parents(void) {
  for_each_function(maybe_par_unseq, jv,
                    [&](function_t &f, binary_t &b) {
    const function_index_t FIdx = index_of_function_in_binary(f, b);

    const auto &bbvec = state.for_function(f).bbvec;

    auto &ICFG = b.Analysis.ICFG;
    std::for_each(maybe_par_unseq,
                  bbvec.begin(),
                  bbvec.end(),
                  [&](bb_t bb) {
                    ICFG[bb].Parents.insert(FIdx, b);
                  });
  });
}

template <bool MT, bool MinSize>
void analyzer_t<MT, MinSize>::identify_ABIs(void) {
  //
  // If a function is called from a different binary, it is an ABI.
  //
  for_each_basic_block(maybe_par_unseq, jv, [&](binary_t &b, bb_t bb) {
    auto &bbprop = b.Analysis.ICFG[bb];

    auto MaybeDynTargets = bbprop.getDynamicTargets(jv);
    if (!MaybeDynTargets)
      return;
    auto &DynTargets = *MaybeDynTargets;

    const binary_index_t BIdx = index_of_binary(b, jv);

    if (DynTargets.AnyOf(
            [&](const dynamic_target_t &X) { return X.first != BIdx; }))
      DynTargets.ForEach(maybe_par_unseq, [&](const dynamic_target_t &X) {
        racy::set(function_of_target(X, jv).IsABI);
      });
  });
}


template <bool MT, bool MinSize>
void analyzer_t<MT, MinSize>::identify_Sjs(void) {
  for_each_function(
      maybe_par_unseq, jv, [&](function_t &f, binary_t &b) {
        function_index_t FIdx = index_of_function_in_binary(f, b);

        function_state_t &x = state.for_function(f);

        if (!x.exit_bbvec.empty())
          f.Returns = true;

        if (x.IsSj) {
          f.Callers(jv).ForEach([&](const caller_t &caller) -> void {
            block_t caller_block = block_for_caller_in_binary(caller, b, jv);
            if (caller_block.first != index_of_binary(b))
              return;

            auto &caller_b = jv.Binaries.at(caller_block.first);
            bb_t caller_bb = basic_block_of_index(caller_block.second, caller_b);

            auto &caller_ICFG = caller_b.Analysis.ICFG;
            bbprop_t &caller_bbprop = caller_ICFG[caller_bb];

            if (caller_bbprop.Term.Type == TERMINATOR::INDIRECT_JUMP)
              racy::set(caller_bbprop.Sj);
          });
        }
      });
}


template <bool MT, bool MinSize>
int analyzer_t<MT, MinSize>::analyze_blocks(void) {
  std::atomic<unsigned> count = 0;

  for_each_basic_block(maybe_par_unseq, jv,
                       [&](binary_t &b, bb_t bb) {
    auto &ICFG = b.Analysis.ICFG;
    if (AnalyzeBasicBlock(TCG, helper_func_map, *Module,
                          *state.for_binary(b).Bin, b.Name.c_str(), ICFG[bb],
                          options))
      count.fetch_add(1u, std::memory_order_relaxed);
  });

  if (options.IsVerbose())
  if (unsigned c = count.load())
    WithColor::note() << llvm::formatv("Analyzed {0} basic block{1}.\n", c,
                                       c == 1 ? "" : "s");

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

template <bool MT, bool MinSize>
int analyzer_t<MT, MinSize>::analyze_functions(void) {
  const unsigned N = boost::num_vertices(cg.G);

  // which component each vertex in the graph belongs to
  std::vector<call_graph_t::vertices_size_type> CompMap(N);

  auto CompPropMap = boost::make_iterator_property_map(
      CompMap.begin(), boost::get(boost::vertex_index, cg.G));

  const auto sc_num = boost::strong_components(cg.G, CompPropMap);

  std::vector<std::vector<call_node_t>> components;
  boost::build_component_lists(cg.G, sc_num, CompPropMap, components);

  // create the DAG of the SCCs
  call_graph_t CGCondensed;
  boost::create_condensation_graph(cg.G, components, CompPropMap, CGCondensed);

  tbb::flow::graph flow_graph;

  std::unique_ptr<std::atomic<unsigned>[]> counts(
      new std::atomic<unsigned>[boost::num_vertices(CGCondensed)]);

  for (auto v : boost::make_iterator_range(boost::vertices(CGCondensed)))
    counts[boost::get(boost::vertex_index, CGCondensed, v)].store(
        0, std::memory_order_relaxed);

  tbb::flow::function_node<call_node_t> analyze_node(
      flow_graph, tbb::flow::unlimited,
      [this, &counts, &analyze_node, &CGCondensed,
       &components](call_node_t v) -> void {
        auto &scc_verts =
            components.at(boost::get(boost::vertex_index, CGCondensed, v));
        tbb::parallel_for_each(
            scc_verts.begin(), scc_verts.end(), [&](call_node_t V) {
              analyze_function(function_of_target(cg.G[V], jv));
            });

        for (auto succ : boost::make_iterator_range(
                 boost::adjacent_vertices(v, CGCondensed))) {
          unsigned c =
              counts[boost::get(boost::vertex_index, CGCondensed, succ)]
                  .fetch_add(1u, std::memory_order_relaxed) + 1u;

          if (c == boost::in_degree(succ, CGCondensed))
            analyze_node.try_put(succ);
        }
      });

  for (auto v : boost::make_iterator_range(boost::vertices(CGCondensed))) {
    if (boost::in_degree(v, CGCondensed) == 0) {
      analyze_node.try_put(v);
    }
  }

  flow_graph.wait_for_all();

  return 0;
}

template <bool MT, bool MinSize>
int analyzer_t<MT, MinSize>::analyze_function(function_t &f) {
  if (!f.Analysis.Stale.load(std::memory_order_acquire))
    return 0;

  dynamic_target_t X(target_of_function(f));

  if (options.IsVeryVerbose())
    inflight.insert(X);

  BOOST_SCOPE_DEFER [&] {
    if (options.IsVerbose()) {
      done.fetch_add(1u, std::memory_order_relaxed);
      if (options.IsVeryVerbose())
        inflight.erase(X);
    }

    f.Analysis.Stale.store(false, std::memory_order_release);
  };

  {
    flow_graph_t G;

    boost::unordered::unordered_flat_map<
        function_t *, std::pair<flow_vertex_t, std::vector<exit_vertex_pair_t>>>
        memoize;

    std::vector<exit_vertex_pair_t> exitVertices;
    flow_vertex_t entryV = copy_function_cfg(G, f, exitVertices, memoize);

    //
    // build vector of vertices in DFS order
    //
    flow_vertex_vec_t Vertices;
    verticesInDfsOrder(G, Vertices);

    livenessComputeFixpoint(G, Vertices);
    f.Analysis.args = G[entryV].IN & ~(NotArgs | options.PinnedEnvGlbs);

    //
    // all non-ABI functions will be passed the stack pointer.
    //
    if (!f.IsABI)
      f.Analysis.args.set(tcg_stack_pointer_index);

    reachingComputeFixpoint(G, Vertices);

    if (f.Returns)
      assert(!exitVertices.empty());

    if (exitVertices.empty()) {
      f.Analysis.rets.reset();
    } else {
      f.Analysis.rets =
          std::accumulate(
              exitVertices.begin(),
              exitVertices.end(),
              ~tcg_global_set_t(),
              [&](tcg_global_set_t res, exit_vertex_pair_t Pair) -> tcg_global_set_t {
                flow_vertex_t V;
                bool IsABI;

                std::tie(V, IsABI) = Pair;

                res &= G[V].OUT;

                if (IsABI)
                  res &= CallConvRets;

                return res;
              }) &
          ~(NotRets | options.PinnedEnvGlbs);

      //
      // all non-ABI functions with an exit block will return the stack pointer.
      //
      if (!f.IsABI)
        f.Analysis.rets.set(tcg_stack_pointer_index);
    }
  }

#if 0
  if (f.IsABI) {
    //
    // for ABI's, if we need a return register whose index > 0, then we will
    // infer that all the preceeding return registers are live as well
    //
    std::vector<unsigned> glbv;
    explode_tcg_global_set(glbv, f.Analysis.rets);
    std::sort(glbv.begin(), glbv.end(), [](unsigned a, unsigned b) {
      return std::find(CallConvRetArray.begin(), CallConvRetArray.end(), a) <
             std::find(CallConvRetArray.begin(), CallConvRetArray.end(), b);
    });

    auto rit = std::accumulate(
        glbv.begin(), glbv.end(), CallConvRetArray.crend(),
        [](CallConvArgArrayTy::const_reverse_iterator res, unsigned glb) {
          return std::min(res, std::find(CallConvRetArray.crbegin(),
                                         CallConvRetArray.crend(), glb));
        });

    if (rit != CallConvRetArray.crend()) {
      unsigned idx = std::distance(CallConvRetArray.cbegin(), rit.base()) - 1;
      for (unsigned i = 0; i <= idx; ++i)
        f.Analysis.rets.set(CallConvRetArray[i]);
    }
#elif 0
    // XXX TODO
    assert(!CallConvRetArray.empty());
    if (f.Analysis.rets[CallConvRetArray.front()]) {
      f.Analysis.rets.reset();
      f.Analysis.rets.set(CallConvRetArray.front());
    } else {
      f.Analysis.rets.reset();
    }
  }
#endif

  //
  // for ABI's, if we need a register parameter whose index > 0, then we will
  // infer that all the preceeding paramter registers are live as well
  //
  if (f.IsABI) {
    std::vector<unsigned> glbv;
    explode_tcg_global_set(glbv, f.Analysis.args);

    auto rit = std::accumulate(
        glbv.begin(), glbv.end(), CallConvArgArray.crend(),
        [](CallConvArgArrayTy::const_reverse_iterator res, unsigned glb) {
          return std::min(res, std::find(CallConvArgArray.crbegin(),
                                         CallConvArgArray.crend(), glb));
        });

    if (rit != CallConvArgArray.crend()) {
      unsigned idx = std::distance(CallConvArgArray.cbegin(), rit.base()) - 1;
      for (unsigned i = 0; i <= idx; ++i)
        f.Analysis.args.set(CallConvArgArray[i]);
    }
  }
  return 0;
}

template <bool MT, bool MinSize>
flow_vertex_t analyzer_t<MT, MinSize>::copy_function_cfg(
    flow_graph_t &G,
    function_t &f,
    std::vector<exit_vertex_pair_t> &exitVertices,
    boost::unordered::unordered_flat_map<
        function_t *, std::pair<flow_vertex_t, std::vector<exit_vertex_pair_t>>>
        &memoize) {
  binary_index_t BIdx = binary_index_of_function(f, jv); /* XXX */
  auto &b = jv.Binaries.at(BIdx);
  auto &ICFG = b.Analysis.ICFG;

  auto &bbvec = state.for_function(f).bbvec;
  auto &exit_bbvec = state.for_function(f).exit_bbvec;

  //
  // make sure basic blocks have been analyzed
  //
  for (bb_t bb : bbvec)
    AnalyzeBasicBlock(TCG, helper_func_map, *Module, *state.for_binary(b).Bin,
                      b.Name.c_str(), ICFG[bb], options);

  if (!IsLeafFunction(f, b, bbvec, exit_bbvec)) {
    //
    // have we already copied this function's CFG?
    //
    auto it = memoize.find(&f);
    if (it != memoize.end()) {
      exitVertices = (*it).second.second;
      return (*it).second.first;
    }
  }

  assert(!bbvec.empty());

  //
  // copy the function's CFG into the flow graph, maintaining a mapping from the
  // CFG's basic blocks to the flow graph vertices
  //
  G.m_vertices.reserve(G.m_vertices.size() + bbvec.size());

  std::unique_ptr<flow_vertex_t[]> Orig2CopyMap( /* look ma, no memset */
      new flow_vertex_t[boost::num_vertices(ICFG.container())]);

  auto Orig2CopyPropMap = boost::make_iterator_property_map(
      Orig2CopyMap.get(),
      boost::get(boost::vertex_index, ICFG.container()));

#if 0
  const unsigned N_1 = boost::num_vertices(G);
#endif
  {

    struct vertex_copier {
      const icfg_t::type &ICFG;
      flow_graph_t &G;

      vertex_copier(const icfg_t::type &ICFG, flow_graph_t &G)
          : ICFG(ICFG), G(G) {}

      void operator()(bb_t bb, flow_vertex_t V) const {
        G[V].Analysis = &ICFG[bb].Analysis;
      }
    };

    struct edge_copier {
      void operator()(const icfg_t::edge_descriptor, flow_edge_t) const {}
    };

    vertex_copier vc(ICFG.container(), G);
    edge_copier ec;

    boost::copy_component(
        ICFG.container(), bbvec.front(), G,
        boost::orig_to_copy(Orig2CopyPropMap).vertex_copy(vc).edge_copy(ec));
  }
#if 0
  const unsigned N_2 = boost::num_vertices(G);

  llvm::errs() << llvm::formatv("|G|={0} for {1},{2}\n", N_2 - N_1, BIdx, index_of_function(f));
#endif

  auto Orig2Copy = [&](bb_t bb) -> flow_vertex_t {
    return boost::get(Orig2CopyPropMap, bb);
  };

  flow_vertex_t res = Orig2Copy(bbvec.front());

  exitVertices.resize(exit_bbvec.size());
  std::transform(exit_bbvec.begin(),
                 exit_bbvec.end(),
                 exitVertices.begin(),
                 [&](bb_t bb) -> exit_vertex_pair_t {
                   return exit_vertex_pair_t(Orig2Copy(bb), false);
                 });

  memoize.insert({&f, {res, exitVertices}});


  //
  // this recursive function's duty is also to inline calls to functions and
  // indirect jumps
  //
  for (bb_t bb : bbvec) {
    const bbprop_t &bbprop = ICFG[bb];

    flow_vertex_t V = Orig2Copy(bb);

    switch (ICFG[bb].Term.Type) {
    case TERMINATOR::INDIRECT_CALL: {
      const bool Returns = boost::out_degree(bb, ICFG.container()) != 0;

      boost::clear_out_edges(V, G); /* if there were any, they're gone now */

      flow_vertex_t succV = boost::graph_traits<flow_graph_t>::null_vertex();
      unsigned savedSuccInDeg;
      if (Returns) {
        assert(boost::out_degree(bb, ICFG.container()) == 1);

        succV = Orig2Copy(
            *boost::adjacent_vertices(bb, ICFG.container()).first);
        savedSuccInDeg = boost::in_degree(succV, G);
      }

      if (auto MaybeDynTargets = bbprop.getDynamicTargets(jv)) {
      auto &DynTargets = *MaybeDynTargets;

      bool IsABI = DynTargets.AnyOf([&](dynamic_target_t X) {
        return function_of_target(X, jv).IsABI;
      });

      if (auto Summary = DynTargetsSummary(DynTargets, IsABI)) {
        bb_analysis_t &TheAnalysis =
            G[boost::graph_bundle].extra.emplace_front();

        std::tie(TheAnalysis.live.use, TheAnalysis.reach.def) = *Summary;

        flow_vertex_t dummyV = boost::add_vertex(G);
        G[dummyV].Analysis = &TheAnalysis;

        boost::add_edge(V, dummyV, G);

        if (Returns) {
          flow_edge_t E = boost::add_edge(dummyV, succV, G).first;

          if (IsABI)
            G[E].reach.mask = CallConvRets;
        }
      } else {
      bool FirstOne = true;
      auto process_dynamic_target =
        [&](const dynamic_target_t &DynTarget) -> void {
#if 0
        if (options.Precision == 0) {
          if (!FirstOne)
            return;
          FirstOne = false;
        }
#endif

          function_t &callee = function_of_target(DynTarget, jv);

#if 0
          if (callee.Analysis.Stale) {
#endif
          std::vector<exit_vertex_pair_t> calleeExitVertices;
          flow_vertex_t calleeEntryV = copy_function_cfg(
              G, callee, calleeExitVertices, memoize);

          boost::add_edge(V, calleeEntryV, G);

          if (Returns) {
            for (const auto &calleeExitVertPair : calleeExitVertices) {
              flow_vertex_t exitV;
              bool IsABI;

              std::tie(exitV, IsABI) = calleeExitVertPair;

              flow_edge_t E = boost::add_edge(exitV, succV, G).first;

              if (callee.IsABI || IsABI)
                G[E].reach.mask = CallConvRets;
            }
          }
#if 0
          } else { /* we've already analyzed! */
            bb_analysis_t &TheAnalysis =
                G[boost::graph_bundle].extra.emplace_front();
            TheAnalysis.live.use = callee.Analysis.args;
            TheAnalysis.reach.def = callee.Analysis.rets;

            flow_vertex_t dummyV = boost::add_vertex(G);
            G[dummyV].Analysis = &TheAnalysis;

            boost::add_edge(V, dummyV, G);

            flow_edge_t E = boost::add_edge(dummyV, succV, G).first;

            if (callee.IsABI)
              G[E].reach.mask = CallConvRets;
          }
#endif
        };

      if constexpr (MT) { /* XXX prevent reentrancy */
        DynTargets_t<MT, MinSize> copy(DynTargets);
        DynTargets_t<false, MinSize> DynTargets_(std::move(copy));

        DynTargets_.ForEach(process_dynamic_target);
      } else {
        DynTargets.ForEach(process_dynamic_target);
      }
      }
      }

      if (Returns && boost::in_degree(succV, G) == savedSuccInDeg) {
        //
        // we know that this instruction returns, even if we don't know how
        //
        flow_vertex_t dummyV = boost::add_vertex(G);

        static const bb_analysis_t DummyAnalysis(
            tcg_global_set_t(), tcg_global_set_t(), CallConvRets);

        G[dummyV].Analysis = &DummyAnalysis;

        flow_edge_t E = boost::add_edge(V, dummyV, G).first;
        boost::add_edge(dummyV, succV, G).first;

        G[E].reach.mask = CallConvRets; /* assume ABI */
      }

      break;
    }

    case TERMINATOR::CALL: {
      function_index_t CalleeIdx = ICFG[bb].Term._call.Target;
      if (!is_function_index_valid(CalleeIdx)) {
        assert(boost::out_degree(bb, ICFG.container()) == 0);
        continue;
      }
      function_t &callee = b.Analysis.Functions.at(CalleeIdx);

      const bool Returns = boost::out_degree(bb, ICFG.container()) != 0;

      boost::clear_out_edges(V, G); /* if there were any, they're gone now */

      flow_vertex_t succV = boost::graph_traits<flow_graph_t>::null_vertex();
      unsigned savedSuccInDeg;
      if (Returns) {
        assert(boost::out_degree(bb, ICFG.container()) == 1);

        succV = Orig2Copy(
            *boost::adjacent_vertices(bb, ICFG.container()).first);
        savedSuccInDeg = boost::in_degree(succV, G);
      }

#if 0 /* the following breaks vararg on x86_64 (eax) */
      if (options.Precision == 0 && callee.IsABI) {
        static const bb_analysis_t DummyAnalysis = {
            .live = {.def = {}, .use = CallConvArgs},
            .reach = {.def = CallConvRets}};

        flow_vertex_t dummyV = boost::add_vertex(G);
        G[dummyV].Analysis = &DummyAnalysis;

        boost::add_edge(V, dummyV, G);

        if (Returns) {
          flow_edge_t E = boost::add_edge(dummyV, succV, G).first;

          assert(callee.IsABI);
          G[E].reach.mask = CallConvRets;
        }
      } else if (__atomic_load_n(&callee.Analysis.Stale, __ATOMIC_ACQUIRE)) {
#else
      if (callee.Analysis.Stale.load(std::memory_order_acquire)) {
#endif
      std::vector<exit_vertex_pair_t> calleeExitVertices;
      flow_vertex_t calleeEntryV =
          copy_function_cfg(G, callee, calleeExitVertices, memoize);

      boost::add_edge(V, calleeEntryV, G);

      if (Returns) {
        for (const auto &calleeExitVertPair : calleeExitVertices) {
          flow_vertex_t exitV;
          bool IsABI;

          std::tie(exitV, IsABI) = calleeExitVertPair;

          flow_edge_t E = boost::add_edge(exitV, succV, G).first;
          if (callee.IsABI || IsABI)
            G[E].reach.mask = CallConvRets;
        }
      }
          } else { /* we've already analyzed! */
            bb_analysis_t &TheAnalysis =
                G[boost::graph_bundle].extra.emplace_front();
            TheAnalysis.live.use = callee.Analysis.args;
            TheAnalysis.reach.def = callee.Analysis.rets;

            flow_vertex_t dummyV = boost::add_vertex(G);
            G[dummyV].Analysis = &TheAnalysis;

            boost::add_edge(V, dummyV, G);

          if (Returns) {
            flow_edge_t E = boost::add_edge(dummyV, succV, G).first;

            if (callee.IsABI)
              G[E].reach.mask = CallConvRets;
          }
          }

      if (Returns && boost::in_degree(succV, G) == savedSuccInDeg) {
        //
        // we know that this instruction returns, even if we don't know how
        //
        flow_vertex_t dummyV = boost::add_vertex(G);

        static const bb_analysis_t DummyAnalysis(
            tcg_global_set_t(), tcg_global_set_t(), CallConvRets);

        G[dummyV].Analysis = &DummyAnalysis;

        flow_edge_t E = boost::add_edge(V, dummyV, G).first;
        boost::add_edge(dummyV, succV, G).first;
      }

      break;
    }

    case TERMINATOR::INDIRECT_JUMP: {
      {
        auto it = std::find_if(exitVertices.begin(),
                               exitVertices.end(),
                               [&](exit_vertex_pair_t pair) -> bool {
                                 return pair.first == V;
                               }); /* must be exit block */
        if (it == exitVertices.end())
          continue;
        exitVertices.erase(it); /* exit blocks of callees replace exit block */
      }

      auto MaybeDynTargets = ICFG[bb].getDynamicTargets(jv);
      assert(MaybeDynTargets);
      auto &DynTargets = *MaybeDynTargets;

      const unsigned savedNumExitVerts = exitVertices.size();

      bool IsABI = DynTargets.AnyOf([&](dynamic_target_t X) {
        return function_of_target(X, jv).IsABI;
      });

      if (auto Summary = DynTargetsSummary(DynTargets, IsABI)) {
        bb_analysis_t &TheAnalysis =
            G[boost::graph_bundle].extra.emplace_front();
        std::tie(TheAnalysis.live.use, TheAnalysis.reach.def) = *Summary;

        flow_vertex_t dummyV = boost::add_vertex(G);
        G[dummyV].Analysis = &TheAnalysis;

        flow_edge_t E = boost::add_edge(V, dummyV, G).first;
        if (IsABI)
          G[E].reach.mask = CallConvRets; /* assume ABI */

        bool Returns = DynTargets.AnyOf([&](dynamic_target_t X) {
          return !state.for_function(function_of_target(X, jv)).exit_bbvec.empty();
        });

        if (Returns)
          exitVertices.emplace_back(dummyV, IsABI);
      } else {
      bool FirstOne = true;
      auto process_dynamic_target =
        [&](const dynamic_target_t &DynTarget) -> void {
#if 0
        if (options.Precision == 0) {
          if (!FirstOne)
            return;
          FirstOne = false;
        }
#endif

        function_t &callee = function_of_target(DynTarget, jv);

        std::vector<exit_vertex_pair_t> calleeExitVertices;
        flow_vertex_t calleeEntryV =
            copy_function_cfg(G, callee, calleeExitVertices, memoize);

        boost::add_edge(V, calleeEntryV, G);

        for (const auto &calleeExitVertPair : calleeExitVertices) {
          flow_vertex_t exitV;
          bool IsABI;
          std::tie(exitV, IsABI) = calleeExitVertPair;

          exitVertices.emplace_back(exitV, callee.IsABI);
        }
      };

      if constexpr (MT) { /* XXX prevent reentrancy */
        DynTargets_t<MT, MinSize> copy(DynTargets);
        DynTargets_t<false, MinSize> DynTargets_(std::move(copy));

        DynTargets_.ForEach(process_dynamic_target);
      } else {
        DynTargets.ForEach(process_dynamic_target);
      }

      }

      if (savedNumExitVerts == exitVertices.size()) {
        //
        // hallucinate an exit block.
        //
        flow_vertex_t dummyV = boost::add_vertex(G);

        static const bb_analysis_t DummyAnalysis(
            tcg_global_set_t(), tcg_global_set_t(), CallConvRets);

        G[dummyV].Analysis = &DummyAnalysis;

        flow_edge_t E = boost::add_edge(V, dummyV, G).first;
        G[E].reach.mask = CallConvRets; /* assume ABI */

        exitVertices.emplace_back(dummyV, true /* abi */);
      }
      break;
    }

    default:
      continue;
    }
  }

  //
  // does f return even if we don't know how?
  //
  if (f.Returns && exitVertices.empty()) {
    flow_vertex_t dummyV = boost::add_vertex(G);

    static const bb_analysis_t DummyAnalysis(
        tcg_global_set_t(), tcg_global_set_t(), CallConvRets);

    G[dummyV].Analysis = &DummyAnalysis;

    exitVertices.emplace_back(dummyV, true);
  }

  return res;
}

template <bool MT, bool MinSize>
std::optional<std::pair<tcg_global_set_t, tcg_global_set_t>>
analyzer_t<MT, MinSize>::DynTargetsSummary(
    const DynTargets_t<MT, MinSize> &DynTargets, bool IsABI) {
  bool AllNotStale = DynTargets.AllOf([&](dynamic_target_t X) {
    function_t &callee = function_of_target(X, jv);
    return !callee.Analysis.Stale.load(std::memory_order_acquire);
  });

  if (AllNotStale) {
    auto args = DynTargets.template Accumulate<tcg_global_set_t>(
        tcg_global_set_t(), [&](tcg_global_set_t res, dynamic_target_t X) {
          return res | function_of_target(X, jv).Analysis.args;
        });
    auto rets = DynTargets.template Accumulate<tcg_global_set_t>(
        tcg_global_set_t(), [&](tcg_global_set_t res, dynamic_target_t X) {
          return res | function_of_target(X, jv).Analysis.rets;
        });
    return std::make_pair(args, rets);
  } else {
#if 0 /* the following breaks vararg on x86_64 (eax) */
    if (IsABI) {
      return std::make_pair(CallConvArgs, CallConvRets);
    } else if (DynTargets.AnyOf([&](dynamic_target_t X) {
                 function_t &callee = function_of_target(X, jv);
                 return !__atomic_load_n(&callee.Analysis.Stale,
                                         __ATOMIC_ACQUIRE);
               })) {
      tcg_global_set_t args, rets;
      DynTargets.ForEachWhile([&](dynamic_target_t X) -> bool {
        function_t &callee = function_of_target(X, jv);
        if (!callee.Analysis.Stale) {
          function_t &callee = function_of_target(X, jv);

          args = callee.Analysis.args;
          rets = callee.Analysis.rets;

          return false;
        }

        return true;
      });
      return std::make_pair(args, rets);
    }
#endif
  }
  return std::nullopt;
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))
#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template struct analyzer_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),         \
                             GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>;
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
#endif /* JOVE_NO_BACKEND */

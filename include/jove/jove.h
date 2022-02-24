#pragma once
#include <cstdint>
#include <vector>
#include <map>
#include <boost/graph/adjacency_list.hpp>
#include <boost/serialization/nvp.hpp>
#include <numeric>
#include <limits>
#include <algorithm>
#include <boost/icl/split_interval_map.hpp>

#if defined(TARGET_AARCH64)
#include <jove/tcgconstants-aarch64.h>
#elif defined(TARGET_X86_64)
#include <jove/tcgconstants-x86_64.h>
#elif defined(TARGET_I386)
#include <jove/tcgconstants-i386.h>
#elif defined(TARGET_MIPS64)
#include <jove/tcgconstants-mips64.h>
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPSEL)
#include <jove/tcgconstants-mipsel.h>
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPS)
#include <jove/tcgconstants-mips.h>
#else
#error "unknown target"
#endif

namespace jove {

enum class TERMINATOR : uint8_t {
  UNKNOWN,
  UNCONDITIONAL_JUMP,
  CONDITIONAL_JUMP,
  INDIRECT_CALL,
  INDIRECT_JUMP,
  CALL,
  RETURN,
  UNREACHABLE,
  NONE
};

typedef uint32_t binary_index_t;
typedef uint32_t function_index_t;
typedef uint32_t basic_block_index_t;

typedef std::pair<binary_index_t, function_index_t> dynamic_target_t;

typedef boost::icl::split_interval_map<tcg_uintptr_t, basic_block_index_t> bbmap_t;
typedef std::unordered_map<tcg_uintptr_t, function_index_t> fnmap_t;

constexpr binary_index_t
    invalid_binary_index = std::numeric_limits<binary_index_t>::max();
constexpr function_index_t
    invalid_function_index = std::numeric_limits<function_index_t>::max();
constexpr basic_block_index_t
    invalid_basic_block_index = std::numeric_limits<basic_block_index_t>::max();
constexpr dynamic_target_t
    invalid_dynamic_target(invalid_binary_index,
                           invalid_function_index);

constexpr bool is_binary_index_valid(binary_index_t idx) {
  return idx != invalid_binary_index;
}
constexpr bool is_function_index_valid(function_index_t idx) {
  return idx != invalid_function_index;
}
constexpr bool is_basic_block_index_valid(basic_block_index_t idx) {
  return idx != invalid_basic_block_index;
}
constexpr bool is_dynamic_target_valid(dynamic_target_t X) {
  return is_binary_index_valid(X.first) &&
         is_function_index_valid(X.second);
}

struct basic_block_properties_t {
  tcg_uintptr_t Addr;
  uint32_t Size;

  struct {
    tcg_uintptr_t Addr;
    TERMINATOR Type;

    struct {
      function_index_t Target;

      bool Returns;
    } _call;

    struct {
      bool IsLj;
    } _indirect_jump;

    struct {
      bool Returns;
    } _indirect_call;

    struct {
      bool Returns;
    } _return;
  } Term;

  std::set<dynamic_target_t> DynTargets;
  bool DynTargetsComplete; // XXX

  bool Sj;

  struct {
    struct {
      /* let def_B be the set of variables defined (i.e. definitely */
      /* assigned values) in B prior to any use of that variable in B */
      tcg_global_set_t def;

      /* let use_B be the set of variables whose values may be used in B */
      /* prior to any definition of the variable */
      tcg_global_set_t use;
    } live;

    struct {
      /* the set of globals assigned values in B */
      tcg_global_set_t def;
    } reach;

    bool Stale;
  } Analysis;

#ifndef JOVE_EXTRA_BB_PROPERTIES
#define JOVE_EXTRA_BB_PROPERTIES
#endif

  JOVE_EXTRA_BB_PROPERTIES;

#undef JOVE_EXTRA_BB_PROPERTIES

  bool IsSingleInstruction(void) const { return Addr == Term.Addr; }

  void InvalidateAnalysis(void) {
    this->Analysis.Stale = true;
  }

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &BOOST_SERIALIZATION_NVP(Addr)
       &BOOST_SERIALIZATION_NVP(Size)
       &BOOST_SERIALIZATION_NVP(Term.Addr)
       &BOOST_SERIALIZATION_NVP(Term.Type)
       &BOOST_SERIALIZATION_NVP(Term._call.Target)
       &BOOST_SERIALIZATION_NVP(Term._call.Returns)
       &BOOST_SERIALIZATION_NVP(Term._indirect_jump.IsLj)
       &BOOST_SERIALIZATION_NVP(Term._indirect_call.Returns)
       &BOOST_SERIALIZATION_NVP(Term._return.Returns)
       &BOOST_SERIALIZATION_NVP(DynTargets)
       &BOOST_SERIALIZATION_NVP(DynTargetsComplete)
       &BOOST_SERIALIZATION_NVP(Sj)
       &BOOST_SERIALIZATION_NVP(Analysis.live.def)
       &BOOST_SERIALIZATION_NVP(Analysis.live.use)
       &BOOST_SERIALIZATION_NVP(Analysis.reach.def)
       &BOOST_SERIALIZATION_NVP(Analysis.Stale);
  }
};

typedef boost::adjacency_list<boost::setS,             /* OutEdgeList */
                              boost::vecS,             /* VertexList */
                              boost::bidirectionalS,   /* Directed */
                              basic_block_properties_t /* VertexProperties */>
    interprocedural_control_flow_graph_t;

typedef interprocedural_control_flow_graph_t icfg_t;

typedef interprocedural_control_flow_graph_t::vertex_descriptor basic_block_t;
typedef interprocedural_control_flow_graph_t::edge_descriptor control_flow_t;

inline basic_block_t NullBasicBlock(void) {
  return boost::graph_traits<
      interprocedural_control_flow_graph_t>::null_vertex();
}

inline bool IsDefinitelyTailCall(const icfg_t &ICFG, basic_block_t bb) {
  assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

#ifdef WARN_ON
  WARN_ON(boost::out_degree(bb, ICFG) > 0);
#endif

  return !ICFG[bb].DynTargets.empty();
}

inline bool IsExitBlock(const icfg_t &ICFG, basic_block_t bb) {
  auto T = ICFG[bb].Term.Type;

  return T == TERMINATOR::RETURN ||
        (T == TERMINATOR::INDIRECT_JUMP &&
         IsDefinitelyTailCall(ICFG, bb));
}

struct function_t {
  basic_block_index_t Entry;

  struct {
    tcg_global_set_t args;
    tcg_global_set_t rets;

    bool Stale;
  } Analysis;

  bool IsABI, IsSignalHandler, Returns;

  void InvalidateAnalysis(void) {
    this->Analysis.Stale = true;
  }

#ifndef JOVE_EXTRA_FN_PROPERTIES
#define JOVE_EXTRA_FN_PROPERTIES
#endif

  JOVE_EXTRA_FN_PROPERTIES;

#undef JOVE_EXTRA_FN_PROPERTIES

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &BOOST_SERIALIZATION_NVP(Entry)
       &BOOST_SERIALIZATION_NVP(Analysis.args)
       &BOOST_SERIALIZATION_NVP(Analysis.rets)
       &BOOST_SERIALIZATION_NVP(Analysis.Stale)
       &BOOST_SERIALIZATION_NVP(IsABI)
       &BOOST_SERIALIZATION_NVP(IsSignalHandler)
       &BOOST_SERIALIZATION_NVP(Returns);
  }
};

struct binary_t {
  std::string Path;
  std::string Data;

  bool IsDynamicLinker, IsExecutable, IsVDSO;

  bool IsPIC;

  bool IsDynamicallyLoaded;

  struct {
    function_index_t EntryFunction;
    std::vector<function_t> Functions;
    interprocedural_control_flow_graph_t ICFG;

    std::map<tcg_uintptr_t, std::set<dynamic_target_t>> RelocDynTargets;
    std::map<tcg_uintptr_t, std::set<dynamic_target_t>> IFuncDynTargets;
    std::map<std::string, std::set<dynamic_target_t>> SymDynTargets;
  } Analysis;

#ifndef JOVE_EXTRA_BIN_PROPERTIES
#define JOVE_EXTRA_BIN_PROPERTIES
#endif

  JOVE_EXTRA_BIN_PROPERTIES;

#undef JOVE_EXTRA_BIN_PROPERTIES

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &BOOST_SERIALIZATION_NVP(Path)
       &BOOST_SERIALIZATION_NVP(Data)
       &BOOST_SERIALIZATION_NVP(IsDynamicLinker)
       &BOOST_SERIALIZATION_NVP(IsExecutable)
       &BOOST_SERIALIZATION_NVP(IsVDSO)
       &BOOST_SERIALIZATION_NVP(IsPIC)
       &BOOST_SERIALIZATION_NVP(IsDynamicallyLoaded)
       &BOOST_SERIALIZATION_NVP(Analysis.EntryFunction)
       &BOOST_SERIALIZATION_NVP(Analysis.Functions)
       &BOOST_SERIALIZATION_NVP(Analysis.ICFG)
       &BOOST_SERIALIZATION_NVP(Analysis.RelocDynTargets)
       &BOOST_SERIALIZATION_NVP(Analysis.IFuncDynTargets)
       &BOOST_SERIALIZATION_NVP(Analysis.SymDynTargets);
  }
};

struct decompilation_t {
  std::vector<binary_t> Binaries;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &BOOST_SERIALIZATION_NVP(Binaries);
  }
};

inline const char *string_of_terminator(TERMINATOR TermTy) {
  switch (TermTy) {
  case TERMINATOR::UNKNOWN:
    return "UNKNOWN";
  case TERMINATOR::UNCONDITIONAL_JUMP:
    return "UNCONDITIONAL_JUMP";
  case TERMINATOR::CONDITIONAL_JUMP:
    return "CONDITIONAL_JUMP";
  case TERMINATOR::INDIRECT_CALL:
    return "INDIRECT_CALL";
  case TERMINATOR::INDIRECT_JUMP:
    return "INDIRECT_JUMP";
  case TERMINATOR::CALL:
    return "CALL";
  case TERMINATOR::RETURN:
    return "RETURN";
  case TERMINATOR::UNREACHABLE:
    return "UNREACHABLE";
  case TERMINATOR::NONE:
    return "NONE";
  }
}

inline const char *description_of_terminator(TERMINATOR TermTy) {
  switch (TermTy) {
  case TERMINATOR::UNKNOWN:
    return "<?>";
  case TERMINATOR::UNCONDITIONAL_JUMP:
    return "<unconditional jump>";
  case TERMINATOR::CONDITIONAL_JUMP:
    return "<conditional jump>";
  case TERMINATOR::INDIRECT_CALL:
    return "<indirect call>";
  case TERMINATOR::INDIRECT_JUMP:
    return "<indirect jump>";
  case TERMINATOR::CALL:
    return "<call>";
  case TERMINATOR::RETURN:
    return "<return>";
  case TERMINATOR::UNREACHABLE:
    return "<unreachable>";
  case TERMINATOR::NONE:
    return "<none>";
  }
}

struct terminator_info_t {
  TERMINATOR Type;
  tcg_uintptr_t Addr;

  union {
    struct {
      tcg_uintptr_t Target;
    } _unconditional_jump;

    struct {
      tcg_uintptr_t Target;
      tcg_uintptr_t NextPC;
    } _conditional_jump;

    struct {
      tcg_uintptr_t Target;
      tcg_uintptr_t NextPC;
    } _call;

    struct {
      tcg_uintptr_t NextPC;
    } _indirect_call;

    struct {
      /* deliberately left empty */
    } _indirect_jump;

    struct {
      /* deliberately left empty */
    } _return;

    struct {
      /* deliberately left empty */
    } _unreachable;

    struct {
      tcg_uintptr_t NextPC;
    } _none;
  };
};

template <typename Iter, typename Pred, typename Op>
static inline void for_each_if(Iter first, Iter last, Pred p, Op op) {
  while (first != last) {
    if (p(*first))
      op(*first);
    ++first;
  }
}

static inline void for_each_binary(decompilation_t &decompilation,
                                   std::function<void(binary_t &)> proc) {
  std::for_each(decompilation.Binaries.begin(),
                decompilation.Binaries.end(),
                proc);
}

static inline void for_each_binary_if(decompilation_t &decompilation,
                                      std::function<bool(binary_t &)> pred,
                                      std::function<void(binary_t &)> proc) {
  for_each_if(decompilation.Binaries.begin(),
              decompilation.Binaries.end(),
              pred, proc);
}

static inline void for_each_function(decompilation_t &decompilation,
                                     std::function<void(function_t &)> proc) {
  for_each_binary(decompilation, [&](binary_t &binary) {
    std::for_each(binary.Analysis.Functions.begin(),
                  binary.Analysis.Functions.end(), proc);
  });
}

static inline void for_each_function_in_binary(binary_t &binary,
                                               std::function<void(function_t &)> proc) {
  std::for_each(binary.Analysis.Functions.begin(),
                binary.Analysis.Functions.end(), proc);
}

static inline void for_each_function_if(decompilation_t &decompilation,
                                        std::function<bool(function_t &)> pred,
                                        std::function<void(function_t &)> proc) {
  for_each_binary(decompilation, [&](binary_t &binary) {
    for_each_if(binary.Analysis.Functions.begin(),
                binary.Analysis.Functions.end(),
                pred, proc);
  });
}

static inline void for_each_basic_block(decompilation_t &decompilation,
                                        std::function<void(binary_t &, basic_block_t)> proc) {
  for_each_binary(decompilation, [&](binary_t &binary) {
    icfg_t::vertex_iterator it, it_end;
    std::tie(it, it_end) = boost::vertices(binary.Analysis.ICFG);

    std::for_each(it, it_end,
                  [&](basic_block_t bb) { proc(binary, bb); });
  });
}

static inline void for_each_basic_block_in_binary(decompilation_t &decompilation,
                                                  binary_t &binary,
                                                  std::function<void(basic_block_t)> proc) {
  auto &ICFG = binary.Analysis.ICFG;

  icfg_t::vertex_iterator it, it_end;
  std::tie(it, it_end) = boost::vertices(ICFG);

  std::for_each(it, it_end, [&](basic_block_t bb) { proc(bb); });
}

static inline basic_block_index_t index_of_basic_block(const icfg_t &ICFG, basic_block_t bb) {
  boost::property_map<icfg_t, boost::vertex_index_t>::type bb2idx =
      boost::get(boost::vertex_index, ICFG);
  return bb2idx[bb];
}

/* XXX this is O(n)... */
static inline binary_index_t binary_index_of_function(decompilation_t &decompilation,
                                                      function_t &f) {
  for (binary_index_t BIdx = 0; BIdx < decompilation.Binaries.size(); ++BIdx) {
    auto &fns = decompilation.Binaries[BIdx].Analysis.Functions;

    if (&f >= &fns[0] && &f < &fns[fns.size()])
      return BIdx; /* found */
  }

  abort();
}

static inline void construct_bbmap(decompilation_t &decompilation,
                                   binary_t &binary,
                                   bbmap_t &out) {
  auto &ICFG = binary.Analysis.ICFG;

  for_each_basic_block_in_binary(decompilation, binary, [&](basic_block_t bb) {
    const auto &bbprop = ICFG[bb];

    boost::icl::interval<tcg_uintptr_t>::type intervl =
        boost::icl::interval<tcg_uintptr_t>::right_open(bbprop.Addr,
                                                        bbprop.Addr + bbprop.Size);
    assert(out.find(intervl) == out.end());

    out.add({intervl, 1+index_of_basic_block(ICFG, bb)});
  });
}

static inline void construct_fnmap(decompilation_t &decompilation,
                                   binary_t &binary,
                                   fnmap_t &out) {
  for_each_function_in_binary(binary, [&](function_t &f) {
    basic_block_t entry_bb = boost::vertex(f.Entry, binary.Analysis.ICFG);
    tcg_uintptr_t A = binary.Analysis.ICFG[entry_bb].Addr;

    assert(out.find(A) == out.end());

    unsigned FIdx = &f - &binary.Analysis.Functions[0];

    out.insert({A, FIdx});
  });
}

}

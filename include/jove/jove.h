#pragma once
#ifdef __cplusplus
#include <cstdint>
#include <vector>
#include <map>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/serialization/nvp.hpp>
#include <numeric>
#include <limits>
#include <algorithm>
#include <boost/icl/split_interval_map.hpp>
#endif /* __cplusplus */

#if defined(TARGET_AARCH64)
#include <jove/tcgconstants-aarch64.h>
#elif defined(TARGET_X86_64)
#include <jove/tcgconstants-x86_64.h>
#elif defined(TARGET_I386)
#include <jove/tcgconstants-i386.h>
#elif defined(TARGET_MIPS64)
#include <jove/tcgconstants-mips64.h>
#elif defined(TARGET_MIPSEL)
#include <jove/tcgconstants-mipsel.h>
#elif defined(TARGET_MIPS)
#include <jove/tcgconstants-mips.h>
#else
#error "unknown target"
#endif

#ifdef __cplusplus

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

constexpr bool IsMIPSTarget =
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
    true
#else
    false
#endif
    ;

static const char *TargetStaticLinkerEmulation =
#if defined(TARGET_X86_64)
                      "elf_x86_64"
#elif defined(TARGET_I386)
                      "elf_i386"
#elif defined(TARGET_AARCH64)
                      "aarch64linux"
#elif defined(TARGET_MIPS64)
                      "elf64ltsmip"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPSEL)
                      "elf32ltsmip"
#elif defined(TARGET_MIPS32) && defined(TARGET_MIPS)
                      "elf32btsmip"
#else
#error
#endif
                  ;

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

  mutable void *userdata = nullptr;

  template <typename StateTy>
  StateTy &state() const {
    if (!this->userdata)
      this->userdata = new StateTy;

    return *reinterpret_cast<StateTy *>(this->userdata);
  }
};

#define state_for_basic_block(bb) bb.state<basic_block_state_t>()

typedef boost::adjacency_list<boost::setS,             /* OutEdgeList */
                              boost::vecS,             /* VertexList */
                              boost::bidirectionalS,   /* Directed */
                              basic_block_properties_t /* VertexProperties */>
    interprocedural_control_flow_graph_t;

typedef interprocedural_control_flow_graph_t icfg_t;

typedef interprocedural_control_flow_graph_t::vertex_descriptor basic_block_t;
typedef interprocedural_control_flow_graph_t::edge_descriptor control_flow_t;

typedef std::vector<basic_block_t> basic_block_vec_t;

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

inline bool IsAmbiguousIndirectJump(const icfg_t &ICFG, basic_block_t bb) {
  assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

  return !ICFG[bb].DynTargets.empty() && boost::out_degree(bb, ICFG) > 0;
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

  void InvalidateBasicBlockAnalyses(void) {
    auto it_pair = boost::vertices(Analysis.ICFG);
    for (auto it = it_pair.first; it != it_pair.second; ++it)
      Analysis.ICFG[*it].InvalidateAnalysis();
  }

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

struct jv_t {
  std::vector<binary_t> Binaries;

  void InvalidateFunctionAnalyses(void) {
    for (binary_t &b : Binaries)
      for (function_t &f : b.Analysis.Functions)
        f.InvalidateAnalysis();
  }

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

static inline void for_each_binary(jv_t &jv,
                                   std::function<void(binary_t &)> proc) {
  std::for_each(jv.Binaries.begin(),
                jv.Binaries.end(),
                proc);
}

static inline void for_each_binary(const jv_t &jv,
                                   std::function<void(const binary_t &)> proc) {
  std::for_each(jv.Binaries.begin(),
                jv.Binaries.end(),
                proc);
}

static inline void for_each_binary_if(jv_t &jv,
                                      std::function<bool(binary_t &)> pred,
                                      std::function<void(binary_t &)> proc) {
  for_each_if(jv.Binaries.begin(),
              jv.Binaries.end(),
              pred, proc);
}

static inline void for_each_function(jv_t &jv,
                                     std::function<void(function_t &, binary_t &)> proc) {
  for_each_binary(jv, [&](binary_t &binary) {
    std::for_each(binary.Analysis.Functions.begin(),
                  binary.Analysis.Functions.end(),
                  [&](function_t &f) { proc(f, binary); });
  });
}

static inline void for_each_function_in_binary(binary_t &binary,
                                               std::function<void(function_t &)> proc) {
  std::for_each(binary.Analysis.Functions.begin(),
                binary.Analysis.Functions.end(), proc);
}

static inline void for_each_function_if(jv_t &jv,
                                        std::function<bool(function_t &)> pred,
                                        std::function<void(function_t &, binary_t &)> proc) {
  for_each_binary(jv, [&](binary_t &b) {
    for_each_if(b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(),
                pred, [&](function_t &f) { proc(f, b); });
  });
}

static inline void for_each_basic_block(jv_t &jv,
                                        std::function<void(binary_t &, basic_block_t)> proc) {
  for_each_binary(jv, [&](binary_t &binary) {
    icfg_t::vertex_iterator it, it_end;
    std::tie(it, it_end) = boost::vertices(binary.Analysis.ICFG);

    std::for_each(it, it_end,
                  [&](basic_block_t bb) { proc(binary, bb); });
  });
}

static inline void for_each_basic_block_in_binary(jv_t &jv,
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
static inline binary_index_t binary_index_of_function(const function_t &f,
                                                      const jv_t &jv) {
  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    auto &fns = jv.Binaries[BIdx].Analysis.Functions;

    if (&f >= &fns[0] && &f < &fns[fns.size()])
      return BIdx; /* found */
  }

  abort();
}

static inline binary_index_t index_of_binary(const binary_t &b,
                                             const jv_t &jv) {
  if (!(&b >= &jv.Binaries[0] &&
        &b < &jv.Binaries[jv.Binaries.size()]))
    abort();

  return &b - &jv.Binaries[0];
}

static inline function_index_t index_of_function_in_binary(const function_t &f,
                                                           const binary_t &b) {
  if (!(&f >= &b.Analysis.Functions[0] &&
        &f < &b.Analysis.Functions[b.Analysis.Functions.size()]))
    abort();

  return &f - &b.Analysis.Functions[0];
}

static inline binary_t &binary_of_function(const function_t &f,
                                           jv_t &jv) {
  return jv.Binaries.at(binary_index_of_function(f, jv));
}

static inline const binary_t &binary_of_function(const function_t &f,
                                                 const jv_t &jv) {
  return jv.Binaries.at(binary_index_of_function(f, jv));
}

static inline function_t &function_of_target(dynamic_target_t X,
                                             jv_t &jv) {
  binary_index_t BIdx;
  function_index_t FIdx;
  std::tie(BIdx, FIdx) = X;

  return jv.Binaries.at(BIdx).Analysis.Functions.at(FIdx);
}

static inline void basic_blocks_of_function(const function_t &f,
                                            const binary_t &b,
                                            basic_block_vec_t &out) {
  const auto &ICFG = b.Analysis.ICFG;

  struct bb_visitor : public boost::default_dfs_visitor {
    basic_block_vec_t &out;

    bb_visitor(basic_block_vec_t &out) : out(out) {}

    void discover_vertex(basic_block_t bb, const icfg_t &) const {
      out.push_back(bb);
    }
  };

  if (!is_basic_block_index_valid(f.Entry))
    abort();

  std::map<basic_block_t, boost::default_color_type> color;
  bb_visitor vis(out);
  depth_first_visit(
      ICFG, boost::vertex(f.Entry, ICFG), vis,
      boost::associative_property_map<
          std::map<basic_block_t, boost::default_color_type>>(color));
}

static inline void exit_basic_blocks_of_function(const function_t &f,
                                                 const binary_t &b,
                                                 const basic_block_vec_t &bbvec,
                                                 basic_block_vec_t &out) {
  const auto &ICFG = b.Analysis.ICFG;

  out.reserve(bbvec.size());

  std::copy_if(bbvec.begin(),
               bbvec.end(),
               std::back_inserter(out),
               [&](basic_block_t bb) -> bool { return IsExitBlock(ICFG, bb); });
}

inline bool does_function_return_fast(const icfg_t &ICFG,
                                      const basic_block_vec_t &bbvec) {
  return std::any_of(bbvec.begin(),
                     bbvec.end(),
                     [&](basic_block_t bb) -> bool {
                       return IsExitBlock(ICFG, bb);
                     });
}

inline bool does_function_return(const function_t &f,
                                 const binary_t &b) {
  basic_block_vec_t bbvec;
  basic_blocks_of_function(f, b, bbvec);

  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(bbvec.begin(),
                     bbvec.end(),
                     [&](basic_block_t bb) -> bool {
                       return IsExitBlock(ICFG, bb);
                     });
}

inline bool IsLeafFunction(const function_t &f,
                           const binary_t &b,
                           const basic_block_vec_t &bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  if (!std::none_of(bbvec.begin(),
                    bbvec.end(),
                    [&](basic_block_t bb) -> bool {
                      auto T = ICFG[bb].Term.Type;
                      return (T == TERMINATOR::INDIRECT_JUMP &&
                              boost::out_degree(bb, ICFG) == 0)
                           || T == TERMINATOR::INDIRECT_CALL
                           || T == TERMINATOR::CALL;
                    }))
    return false;

  {
    basic_block_vec_t exit_bbvec;
    exit_basic_blocks_of_function(f, b, bbvec, exit_bbvec);

    return std::all_of(exit_bbvec.begin(),
                       exit_bbvec.end(),
                       [&](basic_block_t bb) -> bool {
                         auto T = ICFG[bb].Term.Type;
                         return T == TERMINATOR::RETURN
                             || T == TERMINATOR::UNREACHABLE;
                       });
  }
}

inline bool IsFunctionSetjmp(const function_t &f,
                             const binary_t &b,
                             const basic_block_vec_t &bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(bbvec.begin(),
                     bbvec.end(),
                     [&](basic_block_t bb) -> bool {
                       return ICFG[bb].Sj;
                     });
}

inline bool IsFunctionLongjmp(const function_t &f,
                              const binary_t &b,
                              const basic_block_vec_t &bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(bbvec.begin(),
                     bbvec.end(),
                     [&](basic_block_t bb) -> bool {
                       auto &Term = ICFG[bb].Term;
                       return Term.Type == TERMINATOR::INDIRECT_JUMP &&
                              Term._indirect_jump.IsLj;
                     });
}

static inline basic_block_t basic_block_of_index(basic_block_index_t BBIdx,
                                                 const icfg_t &ICFG) {
  return boost::vertex(BBIdx, ICFG);
}

static inline basic_block_t basic_block_of_index(basic_block_index_t BBIdx,
                                                 const binary_t &binary) {
  const auto &ICFG = binary.Analysis.ICFG;
  return basic_block_of_index(BBIdx, ICFG);
}

static inline basic_block_t index_of_basic_block_at_address(tcg_uintptr_t Addr,
                                                            const binary_t &binary,
                                                            const bbmap_t &bbmap) {
  assert(Addr);

  auto it = bbmap.find(Addr);
  if (it == bbmap.end())
    abort();

  return -1+(*it).second;
}

static inline basic_block_t basic_block_at_address(tcg_uintptr_t Addr,
                                                   const binary_t &b,
                                                   const bbmap_t &bbmap) {
  return basic_block_of_index(index_of_basic_block_at_address(Addr, b, bbmap), b);
}

static inline bool exists_basic_block_at_address(tcg_uintptr_t Addr,
                                                 const binary_t &binary,
                                                 const bbmap_t &bbmap) {
  assert(Addr);

  return bbmap.find(Addr) != bbmap.end();
}

// NOTE: this function excludes tail calls.
static inline bool exists_indirect_jump_at_address(tcg_uintptr_t Addr,
                                                   const binary_t &binary,
                                                   const bbmap_t &bbmap) {
  assert(Addr);
  if (exists_basic_block_at_address(Addr, binary, bbmap)) {
    const auto &ICFG = binary.Analysis.ICFG;
    basic_block_t bb = basic_block_at_address(Addr, binary, bbmap);
    if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP &&
        ICFG[bb].DynTargets.empty())
      return true;
  }

  return false;
}

static inline tcg_uintptr_t entry_address_of_function(const function_t &f,
                                                      const binary_t &binary) {
  if (!is_basic_block_index_valid(f.Entry))
    abort();

  const auto &ICFG = binary.Analysis.ICFG;
  return ICFG[basic_block_of_index(f.Entry, binary)].Addr;
}

static inline void construct_bbmap(jv_t &jv,
                                   binary_t &binary,
                                   bbmap_t &out) {
  auto &ICFG = binary.Analysis.ICFG;

  for_each_basic_block_in_binary(jv, binary, [&](basic_block_t bb) {
    const auto &bbprop = ICFG[bb];

    boost::icl::interval<tcg_uintptr_t>::type intervl =
        boost::icl::interval<tcg_uintptr_t>::right_open(bbprop.Addr,
                                                        bbprop.Addr + bbprop.Size);
    assert(out.find(intervl) == out.end());

    out.add({intervl, 1+index_of_basic_block(ICFG, bb)});
  });
}

static inline void construct_fnmap(jv_t &jv,
                                   binary_t &binary,
                                   fnmap_t &out) {
  for_each_function_in_binary(binary, [&](function_t &f) {
    if (!is_basic_block_index_valid(f.Entry))
      return;

    auto &ICFG = binary.Analysis.ICFG;

    tcg_uintptr_t Addr = ICFG[basic_block_of_index(f.Entry, ICFG)].Addr;

    assert(out.find(Addr) == out.end());

    function_index_t FIdx = index_of_function_in_binary(f, binary);

    out.insert({Addr, FIdx});
  });
}

static inline void identify_ABIs(jv_t &jv) {
  //
  // If a function is called from a different binary, it is an ABI.
  //
  for_each_basic_block(jv, [&](binary_t &b, basic_block_t bb) {
    auto &DynTargets = b.Analysis.ICFG[bb].DynTargets;
    binary_index_t BIdx = &b - &jv.Binaries[0];

    if (std::any_of(
            DynTargets.begin(),
            DynTargets.end(),
            [&](dynamic_target_t X) -> bool { return X.first != BIdx; }))
      std::for_each(DynTargets.begin(),
                    DynTargets.end(),
                    [&](dynamic_target_t X) {
                      function_of_target(X, jv).IsABI = true;
                    });
  });

  // XXX unnecessary?
  for_each_binary(jv, [&](auto &binary) {
    auto &IFuncDynTargets = binary.Analysis.IFuncDynTargets;

    std::for_each(
        IFuncDynTargets.begin(),
        IFuncDynTargets.end(),
        [&](const auto &pair) {
          std::for_each(pair.second.begin(),
                        pair.second.end(),
              [&](dynamic_target_t X) {
                function_of_target(X, jv).IsABI = true;
              });
        });
  });
}

template <typename BinaryStateTy, typename FunctionStateTy = int>
struct jv_state_t {
  const jv_t &jv;
  std::vector<std::pair<BinaryStateTy, std::vector<FunctionStateTy>>> stuff;

  jv_state_t(const jv_t &jv)
      : jv(jv) {
    update();
  }

  BinaryStateTy &for_binary(const binary_t &binary) {
    return stuff.at(index_of_binary(binary, jv)).first;
  }

  FunctionStateTy &for_function(const function_t &function) {
    binary_index_t BIdx = binary_index_of_function(function, jv);
    std::vector<FunctionStateTy> &function_state_vec = stuff.at(BIdx).second;

    const binary_t &binary = jv.Binaries.at(BIdx);
    function_index_t FIdx = index_of_function_in_binary(function, binary);

    return function_state_vec.at(FIdx);
  }

  void update(void) {
    unsigned N = jv.Binaries.size();
    if (stuff.size() >= N)
      return;

    stuff.resize(N);

    for_each_binary(jv, [&](const binary_t &binary) {
      stuff.at(index_of_binary(binary, jv))
          .second.resize(binary.Analysis.Functions.size());
    });
  }
};

}

#endif /* __cplusplus */

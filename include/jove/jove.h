#pragma once

#ifndef JOVE_EXTRA_BB_PROPERTIES
#define JOVE_EXTRA_BB_PROPERTIES
#endif

#ifndef JOVE_EXTRA_FN_PROPERTIES
#define JOVE_EXTRA_FN_PROPERTIES
#endif

#ifndef JOVE_EXTRA_BIN_PROPERTIES
#define JOVE_EXTRA_BIN_PROPERTIES
#endif

#include <cstdint>
#include <vector>
#include <map>
#include <boost/graph/adjacency_list.hpp>
#include <boost/serialization/nvp.hpp>
#include <numeric>
#include <limits>

#if defined(__aarch64__)
#include <jove/arch/aarch64/tcgconstants.h>
#elif defined(__x86_64__)
#include <jove/arch/x86_64/tcgconstants.h>
#elif defined(__i386__)
#include <jove/arch/i386/tcgconstants.h>
#elif defined(__mips64)
#include <jove/arch/mips64el/tcgconstants.h>
#elif defined(__mips__)
#include <jove/arch/mipsel/tcgconstants.h>
#else
#error "TODO"
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

constexpr binary_index_t invalid_binary_index =
    std::numeric_limits<binary_index_t>::max();
constexpr function_index_t invalid_function_index =
    std::numeric_limits<function_index_t>::max();
constexpr basic_block_index_t invalid_basic_block_index =
    std::numeric_limits<basic_block_index_t>::max();

inline bool is_binary_index_valid(binary_index_t idx) {
  return idx != invalid_binary_index;
}
inline bool is_function_index_valid(function_index_t idx) {
  return idx != invalid_function_index;
}
inline bool is_basic_block_index_valid(basic_block_index_t idx) {
  return idx != invalid_basic_block_index;
}

struct basic_block_properties_t {
  uintptr_t Addr;
  unsigned Size;

  struct {
    uintptr_t Addr;
    TERMINATOR Type;

    struct {
      function_index_t Target;
    } _call;
  } Term;

  std::set<std::pair<binary_index_t, function_index_t>> DynTargets;
  bool DynTargetsComplete; // XXX

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

  JOVE_EXTRA_BB_PROPERTIES;

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
       &BOOST_SERIALIZATION_NVP(DynTargets)
       &BOOST_SERIALIZATION_NVP(DynTargetsComplete)
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

struct function_t {
  basic_block_index_t Entry;

  struct {
    tcg_global_set_t args;
    tcg_global_set_t rets;

    bool Stale;
  } Analysis;

  bool IsABI;

  void InvalidateAnalysis(void) {
    this->Analysis.Stale = true;
  }

  JOVE_EXTRA_FN_PROPERTIES;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &BOOST_SERIALIZATION_NVP(Entry)
       &BOOST_SERIALIZATION_NVP(Analysis.args)
       &BOOST_SERIALIZATION_NVP(Analysis.rets)
       &BOOST_SERIALIZATION_NVP(Analysis.Stale)
       &BOOST_SERIALIZATION_NVP(IsABI);
  }
};

struct binary_t {
  std::string Path;
  std::vector<uint8_t> Data;

  bool IsDynamicLinker, IsExecutable, IsVDSO;

  struct {
    function_index_t EntryFunction;
    std::vector<function_t> Functions;
    interprocedural_control_flow_graph_t ICFG;

    std::map<uintptr_t, std::set<std::pair<binary_index_t, function_index_t>>>
        RelocDynTargets;
    std::map<uintptr_t, std::set<std::pair<binary_index_t, function_index_t>>>
        IFuncDynTargets;
    std::map<std::string, std::set<std::pair<binary_index_t, function_index_t>>>
        SymDynTargets;
  } Analysis;

  JOVE_EXTRA_BIN_PROPERTIES;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &BOOST_SERIALIZATION_NVP(Path)
       &BOOST_SERIALIZATION_NVP(Data)
       &BOOST_SERIALIZATION_NVP(IsDynamicLinker)
       &BOOST_SERIALIZATION_NVP(IsExecutable)
       &BOOST_SERIALIZATION_NVP(IsVDSO)
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
  uintptr_t Addr;

  union {
    struct {
      uintptr_t Target;
    } _unconditional_jump;

    struct {
      uintptr_t Target;
      uintptr_t NextPC;
    } _conditional_jump;

    struct {
      uintptr_t Target;
      uintptr_t NextPC;
    } _call;

    struct {
      uintptr_t NextPC;
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
      uintptr_t NextPC;
    } _none;
  };
};

}

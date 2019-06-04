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
#include <boost/graph/adjacency_list.hpp>
#include <numeric>

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

  JOVE_EXTRA_BB_PROPERTIES;

  bool IsSingleInstruction(void) const { return Addr == Term.Addr; }

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Addr
       &Size
       &Term.Addr
       &Term.Type
       &Term._call.Target
       &DynTargets;
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

  JOVE_EXTRA_FN_PROPERTIES;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Entry;
  }
};

struct binary_t {
  std::string Path;
  std::vector<uint8_t> Data;

  bool IsDynamicLinker, IsExecutable;

  struct {
    function_index_t EntryFunction;
    std::vector<function_t> Functions;
    interprocedural_control_flow_graph_t ICFG;
    std::map<uintptr_t, std::set<function_index_t>> IFuncRelocDynTargets;
  } Analysis;

  JOVE_EXTRA_BIN_PROPERTIES;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Path
       &Data
       &IsDynamicLinker
       &IsExecutable
       &Analysis.EntryFunction
       &Analysis.Functions
       &Analysis.ICFG
       &Analysis.IFuncRelocDynTargets;
  }
};

struct decompilation_t {
  std::vector<binary_t> Binaries;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Binaries;
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

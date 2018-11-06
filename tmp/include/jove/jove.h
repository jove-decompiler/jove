#pragma once
#include <cstdint>
#include <vector>
#include <boost/graph/adjacency_list.hpp>

//#include <boost/icl/separate_interval_set.hpp>
//#include <boost/archive/text_oarchive.hpp>
//#include <boost/archive/text_iarchive.hpp>

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

typedef uint16_t binary_index_t;
typedef uint32_t function_index_t;
typedef uint32_t basic_block_index_t;

constexpr binary_index_t invalid_binary_index = 0xffff;
constexpr function_index_t invalid_function_index = 0xffffffff;
constexpr basic_block_index_t invalid_basic_block_index = 0xffffffff;

struct basic_block_properties_t {
  std::uintptr_t Addr;
  std::ptrdiff_t Size;

  struct {
    std::uintptr_t Addr;
    TERMINATOR Type;

    struct {
      std::vector<function_index_t> Local;
      std::vector<std::pair<binary_index_t, function_index_t>> NonLocal;
    } Callees;
  } Term;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Addr &Size &Term.Addr &Term.Type &Term.Callees.Local &Term.Callees
        .NonLocal;
  }
};

typedef boost::adjacency_list<boost::setS,             /* OutEdgeList */
                              boost::vecS,             /* VertexList */
                              boost::bidirectionalS,   /* Directed */
                              basic_block_properties_t /* VertexProperties */>
    interprocedural_control_flow_graph_t;

typedef interprocedural_control_flow_graph_t::vertex_descriptor basic_block_t;

inline basic_block_t NullBasicBlock(void) {
  return boost::graph_traits<
      interprocedural_control_flow_graph_t>::null_vertex();
}

struct function_t {
  basic_block_index_t Entry;

  struct {
    struct {
      std::vector<std::pair<unsigned, unsigned>> Arguments;
      std::vector<std::pair<unsigned, unsigned>> LocalVars;
    } Stack;
  } Analysis;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Entry &Analysis.Stack.Arguments &Analysis.Stack.LocalVars;
  }
};

struct binary_t {
  std::string Path;
  std::vector<uint8_t> Data;

  struct {
    std::vector<function_t> Functions;
    interprocedural_control_flow_graph_t ICFG;
  } Analysis;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Path &Data &Analysis.Functions &Analysis.ICFG;
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
  std::uintptr_t Addr;

  union {
    struct {
      std::uintptr_t Target;
    } _unconditional_jump;

    struct {
      std::uintptr_t Target;
      std::uintptr_t NextPC;
    } _conditional_jump;

    struct {
      std::uintptr_t Target;
      std::uintptr_t NextPC;
    } _call;

    struct {
      std::uintptr_t NextPC;
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
      /* deliberately left empty */
    } _none;
  };
};

}

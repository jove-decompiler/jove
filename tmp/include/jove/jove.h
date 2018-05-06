#pragma once
#include <cstdint>
#include <boost/graph/adjacency_list.hpp>
#include <set>
#include <vector>

//#include <boost/icl/separate_interval_set.hpp>
//#include <boost/archive/text_oarchive.hpp>
//#include <boost/archive/text_iarchive.hpp>

namespace jove {

enum class TERMINATOR : unsigned {
  UNKNOWN,
  UNCONDITIONAL_JUMP,
  CONDITIONAL_JUMP,
  INDIRECT_CALL,
  INDIRECT_JUMP,
  CALL,
  RETURN
};

struct basic_block_properties_t {
  std::uintptr_t Addr;
  std::ptrdiff_t Size;

  struct {
    TERMINATOR Type;

    struct {
      std::set<std::uintptr_t> Local;

      std::set<std::pair<std::string, std::uintptr_t>> NonLocal;
    } Callees;
  } Term;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Addr &Term.Type &Term.Callees.Local &Term.Callees.NonLocal;
  }
};

struct function_properties_t {
  struct {
    struct {
      std::set<std::pair<unsigned, unsigned>> Arguments;
      std::set<std::pair<unsigned, unsigned>> LocalVars;
    } Stack;
  } Analysis;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Analysis.Stack.Arguments &Analysis.Stack.LocalVars;
  }
};

typedef boost::adjacency_list<
    boost::setS,              /* OutEdgeList */
    boost::listS,             /* VertexList */
    boost::bidirectionalS,    /* Directed */
    basic_block_properties_t, /* VertexProperties */
    boost::no_property,       /* EdgeProperties */
    function_properties_t     /* GraphProperties */> function_t;

typedef function_t::vertex_descriptor basic_block_t;

struct binary_t {
  std::vector<uint8_t> Data;

  struct {
    std::map<std::uintptr_t, function_t> Functions;
  } Analysis;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Data &Analysis.Functions;
  }
};

struct decompilation_t {
  std::map<std::string, binary_t> Binaries;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Binaries;
  }
};

inline const char *string_of_terminator(TERMINATOR TermTy) {
  if (TermTy == TERMINATOR::UNCONDITIONAL_JUMP) {
    return "UNCONDITIONAL_JUMP";
  } else if (TermTy == TERMINATOR::CONDITIONAL_JUMP) {
    return "CONDITIONAL_JUMP";
  } else if (TermTy == TERMINATOR::INDIRECT_CALL) {
    return "INDIRECT_CALL";
  } else if (TermTy == TERMINATOR::INDIRECT_JUMP) {
    return "INDIRECT_JUMP";
  } else if (TermTy == TERMINATOR::CALL) {
    return "CALL";
  } else if (TermTy == TERMINATOR::RETURN) {
    return "RETURN";
  } else {
    return "UNKNOWN";
  }
}

struct terminator_info_t {
  TERMINATOR Type;

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
  };
};

}

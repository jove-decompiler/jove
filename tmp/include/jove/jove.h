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
  UNCONDITIONAL_JUMP,
  CONDITIONAL_JUMP,
  INDIRECT_CALL,
  INDIRECT_JUMP,
  CALL,
  RETURN
};

struct basic_block_properties_t {
  std::uintptr_t Addr;
  std::ptrdiff_t Len;

  struct {
    TERMINATOR Type;

    struct {
      std::set<std::uintptr_t> Local;

      std::set<std::pair<std::string, std::uintptr_t>> NonLocal;
    } Callees;
  } Term;

  template <class Archive>
  void serialize(Archive &ar, const unsigned int) {
    ar &Addr &Len &Term.Type &Term.Callees.Local &Term.Callees.NonLocal;
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

}

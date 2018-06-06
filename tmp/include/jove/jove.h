#pragma once
#include <cstdint>
#define BOOST_INTERPROCESS_SHARED_DIR_FUNC
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/containers/set.hpp>
#include <boost/unordered_map.hpp>
#include <boost/unordered_set.hpp>
#include "jove/macros.h"

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

struct basic_block_t {
  uint64_t Addr;
  uint16_t Size;

  struct {
    uint8_t Size;
    TERMINATOR Type;
  } Term;
};

typedef uint16_t binary_index_t;
typedef uint32_t function_index_t;
typedef uint32_t basic_block_index_t;

typedef boost::interprocess::allocator<
    char, boost::interprocess::managed_shared_memory::segment_manager>
    shmstring_alloc_t;

typedef boost::interprocess::basic_string<char, std::char_traits<char>,
                                          shmstring_alloc_t>
    shmstring_t;

class index_t {
  boost::interprocess::managed_shared_memory segment;

  _DECLARE_INTERPROCESS_MUTEX(mtx)
  _DECLARE_SHARED_MEMORY_MAP(binary_index_map, shmstring_t, binary_index_t)

public:
  index_t()
      : segment(boost::interprocess::open_or_create, "index", 0x100000 /* 1 MiB */),
        _DEFINE_INTERPROCESS_MUTEX(mtx),
        _DEFINE_SHARED_MEMORY_MAP(binary_index_map, 32)
  {}
};

class analysis_t {
  boost::interprocess::managed_shared_memory segment;

  boost::interprocess::interprocess_mutex &mtx;

  boost::interprocess::vector<
      basic_block_t,
      boost::interprocess::allocator<
          basic_block_t,
          boost::interprocess::managed_shared_memory::segment_manager>>
      BBVec;

public:
  analysis_t(const std::string& hash) {
  }
};

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

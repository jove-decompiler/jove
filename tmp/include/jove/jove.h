#pragma once
#include <cstdint>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/containers/set.hpp>
#include <boost/functional/hash.hpp>
#include <boost/unordered_map.hpp>
#include <boost/unordered_set.hpp>
#include <boost/array.hpp>
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

typedef uint16_t binary_index_t;
typedef uint32_t function_index_t;
typedef uint32_t basic_block_index_t;
typedef uint16_t section_index_t;

struct function_t {
  basic_block_index_t Entry;
};

struct basic_block_t {
  uint64_t Addr;
  uint32_t Size;

  struct {
    uint8_t Size;
    TERMINATOR Type;
  } Term;
};

struct section_t {
  uint64_t Addr;
  uint32_t Size;

  shmstring_t Name;
};

constexpr unsigned SHA3_256_DIGEST_SIZE = 256 / 8;
typedef boost::array<uint8_t, SHA3_256_DIGEST_SIZE> sha3_digest_t;

class index_t {
  boost::interprocess::managed_shared_memory segment;

  _DECLARE_INTERPROCESS_MUTEX(mtx)
  _DECLARE_SHARED_MEMORY_MAP(binary_index_map, sha3_digest_t, binary_index_t)

public:
  index_t()
      : segment(boost::interprocess::open_or_create, "index",
                0x100000 /* 1 MiB */),
      _DEFINE_INTERPROCESS_MUTEX(mtx),
      _DEFINE_SHARED_MEMORY_MAP(binary_index_map, 32) {}
};

class analysis_t {
  boost::interprocess::managed_shared_memory segment;

  _DECLARE_INTERPROCESS_MUTEX(mtx)
  _DECLARE_SHARED_MEMORY_VECTOR(BBVec, basic_block_t)

  typedef boost::interprocess::allocator<
      basic_block_index_t,
      boost::interprocess::managed_shared_memory::segment_manager>
      basic_block_index_set_alloc_t;
  typedef boost::interprocess::set<basic_block_index_t,
                                   std::less<basic_block_index_t>,
                                   basic_block_index_set_alloc_t>
      basic_block_index_set_t;

  _DECLARE_SHARED_MEMORY_MAP(InEdgesMap, basic_block_index_t,
                             basic_block_index_set_t)
  _DECLARE_SHARED_MEMORY_MAP(OutEdgesMap, basic_block_index_t,
                             basic_block_index_set_t)

  _DECLARE_SHARED_MEMORY_VECTOR(FnVec, function_t)

  _DECLARE_SHARED_MEMORY_MAP(AddrBBMap, uint64_t, basic_block_index_t)
  _DECLARE_SHARED_MEMORY_MAP(AddrFnMap, uint64_t, function_index_t)

public:
  analysis_t(const sha3_digest_t &digest)
      : segment(boost::interprocess::open_or_create, "analysis",
                0x100000000 /* 4 GiB */),
        _DEFINE_INTERPROCESS_MUTEX(mtx),
        _DEFINE_SHARED_MEMORY_VECTOR(BBVec),
        _DEFINE_SHARED_MEMORY_MAP(InEdgesMap, 16),
        _DEFINE_SHARED_MEMORY_MAP(OutEdgesMap, 16),
        _DEFINE_SHARED_MEMORY_VECTOR(FnVec),
        _DEFINE_SHARED_MEMORY_MAP(AddrBBMap, 16),
        _DEFINE_SHARED_MEMORY_MAP(AddrFnMap, 16) {}
};

#if 0
typedef boost::interprocess::allocator<
    char, boost::interprocess::managed_shared_memory::segment_manager>
    shmstring_alloc_t;

typedef boost::interprocess::basic_string<char, std::char_traits<char>,
                                          shmstring_alloc_t>
    shmstring_t;
#endif

constexpr binary_index_t invalid_binary_index = 0xffff;
constexpr function_index_t invalid_function_index = 0xffffffff;
constexpr basic_block_index_t invalid_basic_block_index = 0xffffffff;

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
